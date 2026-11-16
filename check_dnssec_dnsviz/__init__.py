import argparse
import json
import subprocess
import sys
from datetime import datetime as dt
from pathlib import Path

from pynag.Plugins import PluginHelper, critical, ok, unknown, warning

ZONE_STATUS_OK = ("NOERROR",)
PROOF_STATUS_OK = ("VALID",)
RRSIG_STATUS_OK = ("VALID",)
DS_STATUS_OK = ("VALID",)
DELEGATION_STATUS_OK = ("SECURE",)
DELEGATION_STATUS_WARN = ("INSECURE",)


class RRSIGStats:
    def __init__(self):
        self._max_expiration = None
        self._min_inception = None

    @property
    def max_expiration(self):
        return self._max_expiration

    @property
    def min_inception(self):
        return self._min_inception

    @property
    def expiration_hours(self):
        return int((self.max_expiration - dt.now()).total_seconds() / 3600)

    @property
    def inception_hours(self):
        return int((dt.now() - self.min_inception).total_seconds() / 3600)

    def update_expiration(self, date):
        expiration = dt.strptime(date, "%Y-%m-%d %H:%M:%S %Z")
        if self._max_expiration is None:
            self._max_expiration = expiration
        else:
            self._max_expiration = max(expiration, self._max_expiration)

    def update_inception(self, date):
        inception = dt.strptime(date, "%Y-%m-%d %H:%M:%S %Z")
        if self._min_inception is None:
            self._min_inception = inception
        else:
            self._min_inception = min(inception, self._min_inception)


class DNSviz:
    def __init__(
        self, plugin, zone, resolver=None, authoritative=False, debug=False, dnsviz=None
    ):
        if dnsviz is None:
            self._dnsviz = str(Path(sys.argv[0]).resolve().parent / Path("dnsviz"))
        else:
            self._dnsviz = dnsviz

        self._plugin = plugin
        self._zone = zone
        self._resolver = resolver
        self._authoritative = authoritative
        self._debug = debug
        self._stats = {}

    @property
    def dnsviz(self):
        return self._dnsviz

    @property
    def plugin(self):
        return self._plugin

    @property
    def zone(self):
        return self._zone

    @property
    def resolver(self):
        return self._resolver

    @property
    def authoritative(self):
        return self._authoritative

    @property
    def debug(self):
        return self._debug

    @property
    def stats(self):
        return self._stats

    def _check_rrsig(self, rrsigs, query):
        if type(rrsigs) is dict:
            rrsigs = [rrsigs]

        valid_rrsigs = [
            rrsig for rrsig in rrsigs if rrsig.get("status") in RRSIG_STATUS_OK
        ]

        if valid_rrsigs:
            for rrsig in valid_rrsigs:
                signer = rrsig.get("signer")
                if signer not in self.stats:
                    self.stats[signer] = RRSIGStats()

                self.stats[signer].update_expiration(rrsig.get("expiration"))
                self.stats[signer].update_inception(rrsig.get("inception"))
        else:
            self.plugin.add_status(critical)
            for rrsig in rrsigs:
                status = rrsig.get("status")
                key_tag = rrsig.get("key_tag")
                self.plugin.add_summary(
                    f'RRSIG status of query "{query}" is {status} (RRSIG key {key_tag})'
                )

    def _check_proof(self, proofs, query):
        if type(proofs) is dict:
            proofs = [proofs]

        valid_proofs = [
            proof for proof in proofs if proof.get("status") in PROOF_STATUS_OK
        ]

        if not valid_proofs:
            self.plugin.add_status(critical)
            for proof in proofs:
                status = proof.get("status")
                self.plugin.add_summary(
                    f'NSEC/NSEC3 status of query "{query}" is {status}'
                )

    def get_dnsviz_results(self):
        probe_arguments = [
            "probe",
            self.zone,
            "-E",
        ]
        if self.authoritative:
            probe_arguments.append("-A")
        elif self.resolver is not None:
            probe_arguments.append("-s")
            probe_arguments.append(self.resolver)

        probe = subprocess.run(
            [self.dnsviz, *probe_arguments],
            capture_output=True,
            text=True,
            check=True,
        )
        if probe.returncode:
            self.plugin.add_status(unknown)
            self.plugin.set_long_output(probe.stderr)
            self.plugin.exit()

        grok = subprocess.run(
            [self.dnsviz, "grok"],
            capture_output=True,
            text=True,
            input=probe.stdout,
            check=True,
        )
        if grok.returncode:
            self.plugin.add_status(unknown)
            self.plugin.set_long_output(grok.stderr)
            self.plugin.exit()

        return json.loads(grok.stdout)

    def check_dnssec(self):
        if self.debug:
            print(f'Checking DNSSEC status for zone "{self.zone}"')

        result = self.get_dnsviz_results()

        for zone_name, zone_result in result.items():
            self.check_zone_result(zone_name, zone_result)

    def check_zone_result(self, zone_name, zone_result):
        if self.debug:
            print(f'Checking results for zone "{zone_name}"')

        if (status := zone_result.get("status")) not in ZONE_STATUS_OK:
            self.plugin.add_summary(f'Status of zone "{zone_name}" is {status}')
            self.plugin.add_status(critical)
            return

        check_queries = True

        if zone_name != ".":
            check_queries = self.check_delegation_result(
                zone_name, zone_result.get("delegation")
            )

        if check_queries:
            for query, query_result in zone_result.get("queries", {}).items():
                self.check_query_result(query, query_result)

    def check_query_result(self, query, query_result):
        if self.debug:
            print(f'Checking results for query "{query}"')

        if answer := query_result.get("answer"):
            if rrsigs := answer[0].get("rrsig"):
                self._check_rrsig(rrsigs, query)
            elif answer[0].get("type") != "DS":
                self.plugin.add_summary(f'Answer for query "{query}" is unsigned')
                self.plugin.add_status(critical)

        elif nodata := query_result.get("nodata", query_result.get("nxdomain")):
            if proofs := nodata[0].get("proof"):
                self._check_proof(proofs, query)
            else:
                self.plugin.add_summary(
                    f'NODATA/NXDOMAIN answer for query "{query}" does not provide proof of non-existence'
                )
                self.plugin.add_status(critical)

        else:
            self.plugin.add_summary(
                f'Neither answer nor NODATA/NXDOMAIN received for query "{query}"'
            )
            self.plugin.add_status(unknown)

    def check_delegation_result(self, zone_name, delegation_result):
        if self.debug:
            print(f'Checking delegation for zone "{zone_name}"')

        status = delegation_result.get("status")
        if status not in DELEGATION_STATUS_OK:
            if status in DELEGATION_STATUS_WARN:
                self.plugin.add_status(warning)
            else:
                self.plugin.add_status(critical)
            self.plugin.add_summary(
                f'Delegation status for zone "{zone_name}" is {status}'
            )

        if ds_records := delegation_result.get("ds"):
            valid_ds_records = [
                ds_record
                for ds_record in ds_records
                if ds_record.get("status") in DS_STATUS_OK
            ]

            if not valid_ds_records:
                self.plugin.add_status(warning)
                for ds_record in ds_records:
                    self.plugin.add_summary(
                        f'DS status for zone "{zone_name}" is {ds_record.get("status")}'
                    )

            if errors := delegation_result.get("errors"):
                for error in errors:
                    self.plugin.add_summary(error.get("description"))

        else:
            if proofs := delegation_result.get("insecurity_proof"):
                self._check_proof(proofs[0], proofs[0].get("id"))
            else:
                self.plugin.add_summary(
                    f'Delegation for zone "{zone_name}" does not provide proof of insecurity'
                )
                self.plugin.add_status(critical)

        return status in DELEGATION_STATUS_OK


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Provide debug output"
    )
    parser.add_argument(
        "--zone",
        "-z",
        type=str,
        required=True,
        help="Zone to check the DNSSEC validity for",
    )
    resolvers = parser.add_mutually_exclusive_group()
    resolvers.add_argument(
        "--resolver",
        "-r",
        type=str,
        help="Resolver to use for DNS queries",
    )
    resolvers.add_argument(
        "--authoritative",
        "-A",
        action="store_true",
        help="Use the authoritative servers for the zone",
    )
    parser.add_argument(
        "--expire-warn",
        "-w",
        type=str,
        help="Warning threshold for the expiry time in hours",
        default="72:",
    )
    parser.add_argument(
        "--expire-crit",
        "-c",
        type=str,
        help="Critical threshold for the expiry time in hours",
        default="48:",
    )
    parser.add_argument(
        "--dnsviz",
        "-D",
        type=str,
        help="Path to the DNSviz command line program",
    )

    args = parser.parse_args()

    plugin = PluginHelper()

    dnsviz = DNSviz(
        plugin=plugin,
        zone=args.zone,
        resolver=args.resolver,
        authoritative=args.authoritative,
        debug=args.debug,
        dnsviz=args.dnsviz,
    )

    plugin.add_status(ok)

    dnsviz.check_dnssec()

    for signer, stats in dnsviz.stats.items():
        if signer == ".":
            zone_label = "root"
        else:
            zone_label = signer.rstrip(".").replace(".", "_")

        plugin.add_metric(
            label=f"{zone_label}_expiration_hours",
            value=stats.expiration_hours,
            uom="h",
            warn=args.expire_warn,
            crit=args.expire_crit,
        )
        plugin.add_metric(
            label=f"{zone_label}_inception_hours", value=stats.inception_hours, uom="h"
        )

    plugin.check_all_metrics()

    if plugin.get_status() == ok:
        plugin.add_summary("DNSSEC status is OK")

    plugin.exit()


if __name__ == "__main__":
    main()

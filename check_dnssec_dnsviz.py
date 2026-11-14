#!/opt/plugins/venv/bin/python3

import argparse
import json
from pynag.Plugins import PluginHelper, ok, critical, warning, unknown

import subprocess

ZONE_STATUS_OK = ("NOERROR",)
PROOF_STATUS_OK = ("VALID",)
RRSIG_STATUS_OK = ("VALID",)
DS_STATUS_OK = ("VALID",)
DELEGATION_STATUS_OK = ("SECURE",)
DELEGATION_STATUS_WARN = ("INSECURE",)


class DNSviz:
    def __init__(self, plugin, zone, resolver=None, authoritative=False, debug=False):
        self._plugin = plugin
        self._zone = zone
        self._resolver = resolver
        self._authoritative = authoritative
        self._debug = debug

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

    def _check_rrsig(self, rrsigs, query):
        if type(rrsigs) is dict:
            rrsigs = [rrsigs]

        valid_rrsigs = [rrsig for rrsig in rrsigs if rrsig.get("status") in RRSIG_STATUS_OK]

        if not valid_rrsigs:
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
            
        valid_proofs = [proof for proof in proofs if proof.get("status") in PROOF_STATUS_OK]

        if not valid_proofs:
            self.plugin.add_status(critical)
            for proof in proofs:
                status = proof.get("status")
                self.plugin.add_summary(f'NSEC/NSEC3 status of query "{query}" is {status}')

    def get_dnsviz_results(self):
        dnsviz_executable = "/bin/dnsviz"
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
            [dnsviz_executable, *probe_arguments],
            capture_output=True,
            text=True,
        )
        if probe.returncode:
            self.plugin.add_status(unknown)
            self.plugin.set_long_output(probe.stderr)
            self.plugin.exit()

        grok = subprocess.run(
            [dnsviz_executable, "grok"],
            capture_output=True,
            text=True,
            input=probe.stdout,
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
            else:
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
            valid_ds_records = [ds_record for ds_record in ds_records if ds_record.get("status") in DS_STATUS_OK]

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

    args = parser.parse_args()

    plugin = PluginHelper()

    dnsviz = DNSviz(
        plugin=plugin,
        zone=args.zone,
        resolver=args.resolver,
        authoritative=args.authoritative,
        debug=args.debug,
    )

    plugin.add_status(ok)

    dnsviz.check_dnssec()

    if plugin.get_status() == ok:
        plugin.add_summary("DNSSEC status is OK")

    plugin.exit()


if __name__ == "__main__":
    main()

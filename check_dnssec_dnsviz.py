#!/usr/bin/env python3

import argparse
import json
from pynag.Plugins import PluginHelper, ok, critical, warning, unknown

from subprocess import Popen, PIPE

ZONE_STATUS_OK = ("NOERROR",)
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

    def _check_rrsig(self, rrsig, query, proof=None):
        status = rrsig.get("status")
        key_tag = rrsig.get("key_tag")

        if status not in RRSIG_STATUS_OK:
            self.plugin.add_summary(
                f'RRSIG status of query "{query}" is {status} (RRSIG key {key_tag})'
            )
            self.plugin.add_status(critical)

    def _check_nodata_proof(self, rrsig):
        pass

    def check_dnssec(self):
        if self.debug:
            print(f'Checking DNSSEC status for zone "{self.zone}"')

        result = get_dnsviz_results(zone=self.zone, resolver=self.resolver, authoritative=self.authoritative)

        for zone_name, zone_result in result.items():
            self.check_zone_result(zone_name, zone_result)

    def check_query_result(self, query, query_result):
        if self.debug:
            print(f'Checking results for query "{query}"')

        if answer := query_result.get("answer"):
            if rrsigs := answer[0].get("rrsig"):
                for rrsig in rrsigs:
                    self._check_rrsig(rrsig, query)
            else:
                self.plugin.add_summary(f'Answer for query "{query}" is unsigned')
                self.plugin.add_status(warning)

        elif nodata := query_result.get("nodata"):
            if proofs := nodata[0].get("proof"):
                for proof in proofs:
                    self._check_nodata_proof(proof)
            else:
                self.plugin.add_summary(
                    f'NODATA answer for query "{query}" does not provide proof of non-existence'
                )
                self.plugin.add_status(warning)

        elif nxdomain := query_result.get("nxdomain"):
            if proofs := nxdomain[0].get("proof"):
                for proof in proofs:
                    self._check_nodata_proof(proof)
            else:
                self.plugin.add_summary(
                    f'NXDOMAIN answer for query "{query}" does not provide proof of non-existence'
                )
                self.plugin.add_status(warning)

        else:
            self.plugin.add_summary(
                f'Neither answer nor NODATA nor NXDOMAIN received for query "{query}"'
            )
            self.plugin.add_status(unknown)

    def check_delegation(self, zone_name, delegation_result):
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
            for ds in ds_records:
                if (ds_status := ds.get("status")) not in DS_STATUS_OK:
                    self.plugin.add_status(warning)
                    self.plugin.add_summary(
                        f'DS status for zone "{zone_name}" is {ds_status}'
                    )

            if errors := delegation_result.get("errors"):
                for error in errors:
                    self.plugin.add_summary(error.get("description"))

        return status in DELEGATION_STATUS_OK

    def check_zone_result(self, zone_name, zone_result):
        if self.debug:
            print(f'Checking results for zone "{zone_name}"')

        if (status := zone_result.get("status")) not in ZONE_STATUS_OK:
            self.plugin.add_summary(f'Status of zone "{zone_name}" is {status}')
            self.plugin.add_status(critical)

        check_queries = True

        if zone_name != ".":
            check_queries = self.check_delegation(
                zone_name, zone_result.get("delegation")
            )

        if check_queries:
            for query, query_result in zone_result.get("queries", {}).items():
                self.check_query_result(query, query_result)


def get_dnsviz_results(zone, resolver=None, authoritative=False):
    dnsviz_executable = "/bin/dnsviz"
    probe_arguments = [
        "probe",
        zone,
        "-E",
    ]
    if authoritative:
        probe_arguments.append("-A")
    elif resolver is not None:
        probe_arguments.append("-s")
        probe_arguments.append(resolver)

    probe = Popen(
        [dnsviz_executable, *probe_arguments],
        stdout=PIPE,
        stdin=PIPE,
        stderr=PIPE,
        text=True,
    )
    probe_data = probe.communicate()[0]

    grok = Popen(
        [dnsviz_executable, "grok"], stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True
    )
    grok_data = grok.communicate(input=probe_data)[0]

    return json.loads(grok_data)


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

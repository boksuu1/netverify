import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__, dnscheck, httpcheck, report, tlscheck

CHECKS = {"dns": dnscheck.run, "tls": tlscheck.run, "http": httpcheck.run}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netverify", description="Check whether this network tampers with your traffic.")
    for name in CHECKS:
        parser.add_argument("--" + name, action="store_true", help=f"run {name} checks only")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("-t", "--timeout", type=float, default=4, help="seconds per request")
    parser.add_argument("--no-color", action="store_true", help="plain output")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    selected = [name for name in CHECKS if getattr(args, name)] or list(CHECKS)
    with ThreadPoolExecutor(len(selected)) as pool:
        groups = list(pool.map(lambda name: CHECKS[name](args.timeout), selected))
    findings = [item for group in groups for item in group]

    if args.json:
        print(report.render_json(findings))
    else:
        print(report.render_text(findings, sys.stdout.isatty() and not args.no_color))
    return report.EXIT[report.verdict(findings)]

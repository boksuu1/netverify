import json

from .core import worst

VERDICTS = {
    "ok": "HONEST - no tampering detected",
    "warn": "MOSTLY HONEST - review the warnings",
    "fail": "SUSPICIOUS - this network appears to tamper with your traffic",
    "skip": "INCONCLUSIVE - not enough checks could run",
}
COLORS = {"ok": "32", "warn": "33", "fail": "31", "skip": "90"}
EXIT = {"ok": 0, "warn": 1, "fail": 2, "skip": 3}


def verdict(findings):
    total = worst(f["status"] for f in findings)
    skipped = sum(f["status"] == "skip" for f in findings)
    if total != "fail" and skipped * 2 >= len(findings):
        return "skip"
    return total


def paint(text, status, color):
    return f"\033[{COLORS[status]}m{text}\033[0m" if color else text


def render_text(findings, color):
    lines = []
    for f in findings:
        tag = paint(f["status"].upper().ljust(4), f["status"], color)
        lines.append(f"{tag}  {f['check']:<14} {f['summary']}")
    final = verdict(findings)
    lines.append("")
    lines.append(paint(VERDICTS[final], final, color))
    return "\n".join(lines)


def render_json(findings):
    return json.dumps({"verdict": verdict(findings), "findings": findings}, indent=2)

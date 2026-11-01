import re
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .core import attempt, finding, worst

PORTALS = [
    ("http://connectivitycheck.gstatic.com/generate_204", 204, b""),
    ("http://detectportal.firefox.com/success.txt", 200, b"success"),
]
TARGET = "example.com"
LIMIT = 262144


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, timeout):
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "netverify"})
    try:
        with opener.open(request, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            return response.status, headers, response.read(LIMIT)
    except urllib.error.HTTPError as error:
        headers = {k.lower(): v for k, v in error.headers.items()}
        return error.code, headers, error.read(LIMIT)


def judge_portal(status, body, want_status, want_body):
    if status == want_status and body.strip() == want_body:
        return "ok", "expected response"
    if 300 <= status < 400:
        return "fail", f"redirected (HTTP {status})"
    if status == 200:
        return "fail", "unexpected page instead of the probe response"
    return "warn", f"unexpected HTTP {status}"


def normalize(body):
    return re.sub(rb"\s+", b" ", body).strip()


def injected(body):
    return len(re.findall(rb"<(?:script|iframe)", body.lower()))


def judge_injection(plain, secure):
    status, headers, body = plain
    if 300 <= status < 400:
        host = urlparse(headers.get("location", "")).hostname or ""
        if host.endswith(TARGET):
            return "ok", "plain HTTP redirects to HTTPS"
        return "fail", "plain HTTP is redirected to another site"
    if normalize(body) == normalize(secure[2]):
        return "ok", "plain HTTP matches HTTPS"
    if injected(body) > injected(secure[2]):
        return "fail", "extra script or iframe on plain HTTP"
    return "warn", "plain HTTP differs from HTTPS"


def run(timeout):
    probes = {}
    for url, want_status, want_body in PORTALS:
        result = attempt(fetch, url, timeout)
        if result is None:
            probes[url] = {"status": "skip", "note": "no response"}
        else:
            status, note = judge_portal(result[0], result[2], want_status, want_body)
            probes[url] = {"status": status, "note": note}
    status = worst(p["status"] for p in probes.values())
    summary = {"ok": "no captive portal", "skip": "no data"}.get(status, "captive portal or interception suspected")
    findings = [finding("http.portal", status, summary, probes)]

    plain = attempt(fetch, "http://" + TARGET, timeout)
    secure = attempt(fetch, "https://" + TARGET, timeout)
    if plain is None or secure is None or secure[0] != 200:
        findings.append(finding("http.inject", "skip", "comparison unavailable"))
    else:
        state, note = judge_injection(plain, secure)
        findings.append(finding("http.inject", state, note))
    return findings

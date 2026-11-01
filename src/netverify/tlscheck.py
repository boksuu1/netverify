import socket
import ssl

from .core import finding

HOSTS = ["github.com", "www.wikipedia.org", "www.google.com", "www.amazon.com"]


def fetch_issuer(host, timeout):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                issuer = dict(pair for rdn in tls.getpeercert()["issuer"] for pair in rdn)
    except ssl.SSLCertVerificationError as error:
        return {"host": host, "valid": False, "issuer": "", "error": error.verify_message}
    except OSError as error:
        return {"host": host, "valid": None, "issuer": "", "error": str(error)}
    name = issuer.get("organizationName") or issuer.get("commonName") or "unknown"
    return {"host": host, "valid": True, "issuer": name, "error": ""}


def judge(results):
    reached = [r for r in results if r["valid"] is not None]
    if len(reached) < 2:
        return "skip", "too few sites reachable"
    invalid = [r["host"] for r in reached if not r["valid"]]
    if len(invalid) >= 2:
        return "fail", "certificate verification failed for " + ", ".join(invalid)
    if invalid:
        return "warn", "certificate verification failed for " + invalid[0]
    issuers = {r["issuer"] for r in reached}
    if len(reached) >= 3 and len(issuers) == 1:
        return "fail", "every site is signed by the same issuer: " + next(iter(issuers))
    return "ok", "certificates verified, issuers differ as expected"


def run(timeout):
    results = [fetch_issuer(host, timeout) for host in HOSTS]
    status, summary = judge(results)
    return [finding("tls.certs", status, summary, {"hosts": results})]

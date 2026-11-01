import ipaddress
import json
import random
import socket
import ssl
import struct
import urllib.request

from .core import attempt, finding, worst

DOMAINS = ["example.com", "wikipedia.org", "github.com"]
UDP_SERVERS = ["1.1.1.1", "8.8.8.8"]
DOH_URL = "https://cloudflare-dns.com/dns-query?name={}&type=A"


def build_query(name, txid):
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = name.encode("idna").split(b".")
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def skip_name(data, offset):
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def parse_response(data):
    txid, flags, questions, answers = struct.unpack("!HHHH", data[:8])
    offset = 12
    for _ in range(questions):
        offset = skip_name(data, offset) + 4
    ips = set()
    for _ in range(answers):
        offset = skip_name(data, offset)
        rtype, _, _, length = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and length == 4:
            ips.add(socket.inet_ntoa(data[offset:offset + 4]))
        offset += length
    return txid, flags & 0xF, ips


def udp_query(server, name, timeout):
    txid = random.randint(0, 0xFFFF)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(build_query(name, txid), (server, 53))
        data, _ = sock.recvfrom(4096)
    reply_id, _, ips = parse_response(data)
    if reply_id != txid:
        raise OSError("transaction id mismatch")
    return ips


def doh_query(name, timeout):
    request = urllib.request.Request(DOH_URL.format(name), headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.load(response)
    return {a["data"] for a in data.get("Answer", []) if a.get("type") == 1}


def system_query(name):
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return set()
    return {info[4][0] for info in infos}


def is_bogus(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
        or address.is_multicast
    )


def probe(ip, host, timeout):
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host):
                return "valid"
    except ssl.SSLCertVerificationError:
        return "invalid"
    except OSError:
        return "unreachable"


def judge(host, got, ref, timeout):
    if not got:
        return "fail", "no answer while the reference resolved"
    bogus = sorted(ip for ip in got if is_bogus(ip))
    if bogus and not any(is_bogus(ip) for ip in ref):
        return "fail", "private or reserved address " + ", ".join(bogus)
    if got & ref:
        return "ok", "answers match"
    outcomes = [probe(ip, host, timeout) for ip in sorted(got)[:2]]
    if "valid" in outcomes:
        return "ok", "different address with a valid certificate"
    if "invalid" in outcomes:
        return "fail", "address presents an invalid certificate"
    return "warn", "address differs and could not be verified"


def compare(host, got, ref, timeout):
    if got is None or not ref:
        status, note = "skip", "no data"
    else:
        status, note = judge(host, got, ref, timeout)
    return {"status": status, "note": note, "got": sorted(got or []), "ref": sorted(ref or [])}


def aggregate(check, results, good, bad):
    status = worst(item["status"] for item in results.values())
    summary = {"ok": good, "skip": "no data"}.get(status, bad)
    return finding(check, status, summary, results)


def run(timeout):
    resolver, intercept = {}, {}
    udp_seen = False
    for domain in DOMAINS:
        system = attempt(system_query, domain)
        doh = attempt(doh_query, domain, timeout)
        udp = None
        for server in UDP_SERVERS:
            udp = attempt(udp_query, server, domain, timeout)
            if udp is not None:
                udp_seen = True
                break
        resolver[domain] = compare(domain, system, doh or udp, timeout)
        intercept[domain] = compare(domain, udp, doh, timeout)

    findings = [
        aggregate("dns.resolver", resolver, "system resolver agrees with DoH", "system resolver answers look wrong")
    ]
    if udp_seen:
        findings.append(
            aggregate("dns.intercept", intercept, "plain DNS agrees with DoH", "plain DNS looks intercepted")
        )
    else:
        findings.append(finding("dns.intercept", "skip", "UDP/53 to public resolvers is unavailable"))

    name = "nv-%08x.example.com" % random.getrandbits(32)
    answers = attempt(system_query, name)
    if answers is None:
        findings.append(finding("dns.nxdomain", "skip", "test could not run"))
    elif answers:
        summary = "a non-existent domain resolved to " + ", ".join(sorted(answers))
        findings.append(finding("dns.nxdomain", "fail", summary, {"probe": name}))
    else:
        findings.append(finding("dns.nxdomain", "ok", "non-existent domains return NXDOMAIN", {"probe": name}))
    return findings

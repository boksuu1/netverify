# netverify

Checks whether the network you are on tampers with your traffic: DNS, TLS, captive portals, HTTP injection.

    ./netverify

No install, no dependencies, Python 3.9+.

## Usage

    ./netverify            all checks
    ./netverify --dns      DNS only (also --tls, --http)
    ./netverify --json     JSON output
    ./netverify -t 10      timeout in seconds

Exit code: 0 honest, 1 warnings, 2 tampering suspected, 3 inconclusive.

## Checks

| check | catches |
|-------|---------|
| dns.resolver | spoofed or blocked answers from the system resolver (compared with DNS-over-HTTPS) |
| dns.intercept | plain DNS to public resolvers answered differently from DoH |
| dns.nxdomain | ISPs resolving non-existent domains |
| tls.certs | forged certificates, one issuer signing every site |
| http.portal | captive portals and forced redirects |
| http.inject | scripts injected into plain HTTP pages |

A DNS answer that differs from the reference is accepted when that address presents a valid certificate for the domain, so CDN rotation does not raise alarms.

## Global command

    pipx install .

## Tests

    python3 -m unittest discover -s tests

## License

MIT

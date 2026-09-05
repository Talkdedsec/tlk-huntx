# Security policy

## Authorized use only

huntx is for testing systems you own or are explicitly permitted to test — a bug
bounty program in scope, a signed engagement, your own infrastructure. Running it
against systems without authorization may be illegal. The tool enforces a scope
gate, a request budget, and rate limiting, and blocks state-changing methods by
default; do not use it to circumvent those protections on targets you are not
allowed to test.

huntx is detection-oriented: it proves a vulnerability exists, it does not exploit
it or cause damage.

## Reporting a vulnerability in huntx

If you find a security issue in huntx itself, please do not open a public issue.
Email the maintainer at 292909750+Talkdedsec@users.noreply.github.com with:

- a description of the issue and its impact,
- steps to reproduce,
- the version or commit affected.

You will get an acknowledgement, and a fix will be coordinated before public
disclosure.

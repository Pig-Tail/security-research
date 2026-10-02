# GHSA-w3h6-4frq-fgm7 — OpenCTI: SSRF via response-controlled pagination URL in JSON ingestion

- **Advisory:** [GHSA-w3h6-4frq-fgm7](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-w3h6-4frq-fgm7)
- **Severity:** High · CWE-918 / CWE-295 — no CVE assigned
- **Affected:** `opencti` (npm) `< 7.260604.0` · **Patched:** `7.260604.0`
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

A Server-Side Request Forgery in the JSON ingestion **pagination** feature lets an authenticated
user holding `INGESTION_SETINGESTIONS` make the OpenCTI server issue HTTP requests to arbitrary
internal URLs.

What distinguishes it from ordinary feed SSRF is where the target comes from. The destination is
not the statically configured feed URL — it is extracted **at runtime from the API response body**
via a user-configured JSONPath expression (`pagination_with_sub_page_attribute_path`). The feed
configuration an operator reviews can be entirely benign; the malicious URL is injected later, by
the response, on the next page fetch.

## Root cause

The URL for each subsequent page is pulled out of the incoming response using the operator's
JSONPath and then queried **directly, with no validation** against private IP ranges, loopback
addresses, or cloud metadata endpoints. On top of that, TLS certificate verification was disabled
by default on this code path, so the hop could not even be trusted to be the host it claimed.

## Impact

- Exfiltration of cloud provider metadata and credentials — AWS/GCP metadata at
  `169.254.169.254`.
- Reaching unauthenticated internal backend services: Elasticsearch, Redis, RabbitMQ.
- Internal port scanning by observing response and error behaviour.
- **Evasion of feed configuration review.** This is the differentiating property: a static audit of
  the configured feeds cannot catch a target that only materialises inside a pagination response.

## Fix

Fixed in `7.260604.0` with a configurable **URI deny list** for ingestion feeds, plus configuration
options to enforce TLS certificate validation. See the
[URI deny list documentation](https://docs.opencti.io/latest/usage/import/advanced-feed-configuration/?h=deny#uri-deny-list).

Worth noting for anyone upgrading: a deny list is a blocklist, so the protection is only as good as
its entries. Operators should confirm theirs covers loopback, link-local (`169.254.0.0/16`), the
RFC1918 ranges and the hostnames of their own backing services, and should turn on TLS validation
explicitly rather than assuming the upgrade did it.

> **Write-up only.** No PoC is published here: reproducing it requires an attacker-controlled HTTP
> server returning a crafted pagination attribute plus an OpenCTI instance with ingestion
> configured, and the interesting half of that harness is a redirector pointed at internal
> infrastructure. Refer to the advisory for detail and verify by patch level.

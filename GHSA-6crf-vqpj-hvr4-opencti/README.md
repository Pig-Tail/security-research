# GHSA-6crf-vqpj-hvr4 — OpenCTI: unauthenticated resource exhaustion via pre-auth body parsing in the TAXII push endpoint

- **Advisory:** [GHSA-6crf-vqpj-hvr4](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-6crf-vqpj-hvr4)
- **Severity:** High · CWE-400 — no CVE assigned
- **Affected:** `opencti` (npm) `< 7.260520.0` · **Patched:** `7.260520.0`
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

The TAXII 2.1 push endpoint `POST /taxii2/root/collections/:id/objects/` **fully parses the JSON
request body before performing any authentication check**. With the default 50 MB body limit, an
unauthenticated attacker can force the server to deserialize up to 50 MB of JSON per request.
Concurrent requests saturate CPU and Node.js heap, degrading or denying service for every user of
the platform — with no credentials at all.

The ordering is the whole bug. Body parsing is work the server performs *on behalf of* a caller it
has not yet identified, so every protection that lives after authentication is irrelevant to it.

## Impact

- **No credentials required.** The attack surface is the public internet wherever the TAXII port is
  exposed, and any internal segment that can reach the platform otherwise.
- **Service disruption.** Repeated concurrent large-body requests exhaust the Node.js heap; the
  GraphQL API becomes unresponsive for all users, connectors and automated ingestors — not just for
  the TAXII consumer.
- **Rate limiting does not help.** Application-layer rate limiting runs *post-auth*, so it never
  sees the requests that cause the damage. This is the part that makes the finding worth reporting
  rather than filing as capacity planning: the obvious mitigation is structurally bypassed.
- **Cost amplification.** On auto-scaling infrastructure the load triggers scale-out events, turning
  a denial-of-service attempt into a billing one.

## Fix

Fixed in `7.260520.0`. The correct shape is to authenticate — or at minimum enforce a much smaller
body cap and reject unauthenticated callers — *before* the JSON body is deserialized, so that an
anonymous request can never buy itself 50 MB of parsing work.

> **Write-up only.** No PoC is published here. The defect needs no exploit code — it is a large
> JSON body sent to one endpoint without credentials — and a working harness is indistinguishable
> from a denial-of-service tool. Anyone verifying their own patch level should compare the parse
> order in the TAXII route against `7.260520.0` rather than load-test a live instance.

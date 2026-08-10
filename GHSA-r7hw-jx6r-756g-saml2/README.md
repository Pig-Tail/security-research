# GHSA-r7hw-jx6r-756g — Incomplete fix of CVE-2026-49283: unsigned embedded Response bypasses HTTP-Artifact signature verification

- **Advisory:** [GHSA-r7hw-jx6r-756g](https://github.com/simplesamlphp/saml2/security/advisories/GHSA-r7hw-jx6r-756g)
- **Severity:** High · CWE-287, CWE-347
- **Affected:** `>= 6.2.2, <= 6.2.3` and `< 7.0.0-rc1` · **Patched:** `6.2.4`, `7.0.0-rc2`
- **Prior advisory (regressed fix):** CVE-2026-49283 / GHSA-6929-8p9f-26jx ("HTTP-Artifact TLS validator confusion allows cross-IdP authentication bypass")
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure (incomplete-fix follow-up, patch-audit axis).

## Summary

CVE-2026-49283 was fixed so `HTTPArtifact::receive()` verifies the embedded SAML `Response` using
the IdP metadata signing keys. The shipped fix only reaches that verification when the embedded
`Response` **is signed**:

```php
if (!$samlResponse->isSigned()) {
    return $samlResponse;                         // unsigned embedded Response returned UNVERIFIED
}
return $this->verifyMessageSignature($samlResponse, $idpMetadata);   // only runs when signed
```

An attacker who controls one trusted-federation IdP returns a validly-signed **outer**
`ArtifactResponse` (signed with their own real key — passes the mandatory outer check) that wraps
an **unsigned** embedded `<samlp:Response>` whose `<Issuer>` names a different IdP. Because the
embedded message is never signed, `isSigned()` is false, `verifyMessageSignature()` never runs, and
the forged `Response` is returned as successfully received — with no binding between the embedded
`<Issuer>` and the artifact issuer even on the signed path.

## Root cause

Asymmetric guard: the outer `ArtifactResponse` is mandatorily signed
(`if ($artifactResponse->isSigned() !== true) throw`), but the embedded `Response` is optional
(`if (!$samlResponse->isSigned()) return`). Introduced by a v6.2.2 refactor; the official
CVE-2026-49283 fix in v6.2.1 did not contain this short-circuit.

## Proof of Concept

`poc/PocArtifact001Test.php` is a PHPUnit test that drives the real shipped
`verifyArtifactResponseSignature()` / `verifyMessageSignature()` private methods (via reflection,
the same technique the maintainers' own `HTTPArtifactTest` uses) and reproduces `receive()`'s
verbatim post-resolution decision. It builds a validly-signed outer `ArtifactResponse` (signed by
`IdP-B`, the artifact issuer) wrapping an **unsigned** embedded `Response`, and asserts:

- the outer signature verifies against `IdP-B`'s metadata (the mandatory check passes),
- `verifyMessageSignature()` is **skipped** for the unsigned embedded `Response`,
- the unsigned embedded `Response` is returned as `receive()`'s result unverified,
- a negative control confirms the real verifier would reject that same unsigned message —
  proving the short-circuit, not a permissive verifier, is why it's accepted.

To run against a checkout of the vulnerable tree (`v6.2.2`–`v6.2.3`):

```sh
git clone https://github.com/simplesamlphp/saml2.git
cd saml2 && git checkout v6.2.3
# composer 2.8.x needs a platform override for xml-common's installer plugin:
composer config platform.composer-plugin-api 2.9.0
composer install --no-plugins --ignore-platform-req=ext-bcmath
cp /path/to/poc/PocArtifact001Test.php tests/SAML2/Binding/
vendor/bin/phpunit --no-coverage tests/SAML2/Binding/PocArtifact001Test.php
```

Expected (benign) output:

```
[POC] SAML2-ARTIFACT-001 CONFIRMED: signed outer ArtifactResponse (IdP-B) + UNSIGNED embedded Response
      => receive() returns it with verifyMessageSignature() SKIPPED; the real verifier would reject it.
OK (1 test, 5 assertions)
```

No network access, no destructive payloads — purely in-process reflection against the real
verification methods with mock/stub SAML objects.

## Fix

`6.2.4` / `7.0.0-rc2`: contributor `monkeyiq` split `receive()`'s tail into a new
`handleReceivedArtifactResponse()` method (for testability) and made embedded-Response
authentication **mandatory and issuer-bound** — mirroring the outer pattern, plus a check that the
embedded `<Issuer>` equals the artifact issuer's metadata entityID. Two new regression tests
(`tests/SAML2/Binding/HTTPArtifactNefTest.php`) cover the unsigned case and the impersonation
(wrong-issuer) case.

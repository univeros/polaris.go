<?php

/**
 * Interop between the Go agent SDK and upstream's PHP code (polaris-core at ../polaris-core, or
 * $POLARIS_CORE), with upstream's own classes:
 *
 *   php agent/testdata/interop.php receipts > agent/testdata/php-receipts.json
 *       Receipt chains hashed by Polaris\Agents\Receipts and signed as Receipts::sign does
 *       (lcobucci/jwt, RS256 and EdDSA), for the Go verifier (TestReceiptsSignedByThePHPServerVerify).
 *
 *   php agent/testdata/interop.php verify < cases.json
 *       Go-signed request JWTs verified by the server's Polaris\Agents\RequestJwt (after the agent's
 *       JWK passed Polaris\Agents\AgentKeys::publicJwk), private_key_jwt assertions checked as
 *       Polaris\OAuth\Clients does, Go-exported keys loaded by Polaris\Agent\AgentKey::fromArray.
 *       Run by the Go test TestPHPVerifiesWhatGoSigns; prints "ok <n>" or the failures (exit 1).
 */

declare(strict_types=1);

$core = getenv('POLARIS_CORE') ?: __DIR__ . '/../../../polaris-core';
require $core . '/vendor/autoload.php';

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Polaris\Agent\AgentKey;
use Polaris\Agents\AgentException;
use Polaris\Agents\AgentKeys;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Receipt;
use Polaris\Agents\Receipts;
use Polaris\Agents\RequestJwt;
use Polaris\Agents\Settings;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Clock\NativeClock;

function b64u(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

/** @return array{Signer, InMemory, InMemory, array<string, string>} */
function serverKey(string $alg): array
{
    if ($alg === 'EdDSA') {
        $pair = sodium_crypto_sign_keypair();
        $public = sodium_crypto_sign_publickey($pair);

        return [new Signer\Eddsa(), InMemory::base64Encoded(base64_encode(sodium_crypto_sign_secretkey($pair))), InMemory::base64Encoded(base64_encode($public)),
            ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => b64u($public), 'alg' => 'EdDSA', 'kid' => 'server-key', 'use' => 'sig']];
    }
    $rsa = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($rsa, $pem);
    $details = openssl_pkey_get_details($rsa);

    return [new Signer\Rsa\Sha256(), InMemory::plainText($pem), InMemory::plainText($details['key']),
        ['kty' => 'RSA', 'n' => b64u($details['rsa']['n']), 'e' => b64u($details['rsa']['e']), 'alg' => 'RS256', 'kid' => 'server-key', 'use' => 'sig']];
}

function receipts(): void
{
    $chains = [];
    foreach (['RS256', 'EdDSA'] as $alg) {
        [$signer, $private, $public, $jwk] = serverKey($alg);
        $configuration = Configuration::forAsymmetricSigner($signer, $private, $public);
        $rows = [
            ['grant' => 'g1', 'capability' => 'billing.refund/café', 'outcome' => 'success', 'before' => 100, 'after' => 99],
            ['grant' => 'g1', 'capability' => 'billing.refund/café', 'outcome' => 'failed', 'before' => 99, 'after' => 99],
            ['grant' => null, 'capability' => null, 'outcome' => 'sealed', 'before' => null, 'after' => null],
        ];
        $previous = null;
        $chain = [];
        foreach ($rows as $i => $row) {
            $receipt = new Receipt();
            $receipt->id = sprintf('01a13054-4bde-7b39-bb5f-0df132b99d%02d', $i);
            $receipt->agentId = '01a13054-4bc7-7a59-906d-f1abc48d3b9e';
            $receipt->seq = $i + 1;
            $receipt->grantId = $row['grant'];
            $receipt->capability = $row['capability'];
            $receipt->inputHash = Receipts::inputHash(['amount' => 10 + $i, 'note' => 'ünïcode/✓']);
            $receipt->outcome = $row['outcome'];
            $receipt->budgetBefore = $row['before'];
            $receipt->budgetAfter = $row['after'];
            $receipt->prevHash = $previous?->hash;
            $receipt->createdAt = new DateTimeImmutable('@' . (1791812193 + $i));
            $receipt->hash = Receipts::hashOf($receipt);
            // As Receipts::sign.
            $receipt->signature = $configuration->builder()
                ->issuedBy('https://auth.polaris.test')
                ->issuedAt($receipt->createdAt)
                ->withHeader('kid', 'server-key')
                ->withHeader('typ', Receipts::TYP)
                ->withClaim('receipt_hash', $receipt->hash)
                ->withClaim('receipt_id', $receipt->id)
                ->withClaim('agent_id', $receipt->agentId)
                ->withClaim('seq', $receipt->seq)
                ->getToken($configuration->signer(), $configuration->signingKey())->toString();
            $chain[] = $receipt->toArray();
            $previous = $receipt;
        }
        $chains[] = ['alg' => $alg, 'jwks' => [$jwk], 'receipts' => $chain];
    }
    echo json_encode(['generator' => 'php', 'chains' => $chains], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
}

function verify(): int
{
    $input = json_decode((string) stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    $failures = [];
    $checked = 0;
    $verifier = new RequestJwt(new Settings('https://auth.polaris.test'), new Psr16Cache(new ArrayAdapter()), new NativeClock());
    foreach ($input['requests'] as $i => $case) {
        $checked++;
        try {
            $agent = new Agent();
            $agent->id = $case['agent_id'];
            $agent->publicJwk = AgentKeys::publicJwk($case['jwk']);
            if ($agent->publicJwk['kid'] !== $case['jwk']['kid']) {
                $failures[] = "request $i: the server keeps kid {$agent->publicJwk['kid']}";
            }
            $verified = $verifier->verify($case['jwt'], $agent, $case['method'], $case['url'], $case['body']);
            if ($verified['capabilities'] !== $case['capabilities']) {
                $failures[] = "request $i: capabilities " . json_encode($verified['capabilities']);
            }
            if ($case['tamper'] ?? false) {
                $failures[] = "request $i: a tampered request verified";
            }
        } catch (AgentException $exception) {
            if (!($case['tamper'] ?? false)) {
                $failures[] = "request $i: {$exception->error}: {$exception->detail}";
            }
        }
    }
    foreach ($input['assertions'] as $i => $case) {
        $checked++;
        try {
            // As Polaris\OAuth\Clients::authenticateByAssertion.
            JWT::$leeway = 60;
            $header = json_decode(JWT::urlsafeB64Decode(explode('.', $case['jwt'])[0]), true);
            $claims = (array) JWT::decode($case['jwt'], JWK::parseKeySet(['keys' => [$case['jwk']]], (string) $header['alg']));
            if ($claims['iss'] !== $case['agent_id'] || $claims['sub'] !== $case['agent_id'] || $claims['aud'] !== $case['token_endpoint'] || !is_int($claims['exp']) || !is_string($claims['jti'] ?? null)) {
                $failures[] = "assertion $i: claims " . json_encode($claims);
            }
        } catch (Throwable $exception) {
            $failures[] = "assertion $i: " . $exception->getMessage();
        }
    }
    foreach ($input['stored_keys'] as $i => $case) {
        $checked++;
        $key = AgentKey::fromArray(json_decode($case['stored'], true, 512, JSON_THROW_ON_ERROR));
        if ($key->publicJwk !== $case['jwk'] || $key->kid !== $case['jwk']['kid']) {
            $failures[] = "stored key $i: PHP reads " . json_encode($key->publicJwk);
        }
        // And the other way: a key the PHP SDK made, for Go to import.
    }
    $php = [];
    foreach (['ES256', 'EdDSA'] as $alg) {
        $key = AgentKey::generate($alg);
        $php[] = ['stored' => json_encode($key->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), 'jwk' => $key->publicJwk];
    }
    if ($failures !== []) {
        fwrite(STDERR, implode("\n", $failures) . "\n");

        return 1;
    }
    echo json_encode(['ok' => $checked, 'php_keys' => $php], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), "\n";

    return 0;
}

exit(match ($argv[1] ?? '') {
    'receipts' => (static function (): int {
        receipts();

        return 0;
    })(),
    'verify' => verify(),
    default => (static function (): int {
        fwrite(STDERR, "usage: php interop.php receipts|verify\n");

        return 2;
    })(),
});

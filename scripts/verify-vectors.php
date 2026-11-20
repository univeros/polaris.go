<?php

/**
 * Cross-language vectors (docs/port/spec.md §6.3), PHP side of the Go → PHP direction.
 *
 * Run from the polaris-go root after `POLARIS_UPDATE_VECTORS=1 go test ./security/ ./token/`:
 * `php scripts/verify-vectors.php`. It checks every testdata/vectors/go-*.json file with
 * upstream's classes and exits non-zero on the first mismatch.
 */

declare(strict_types=1);

require __DIR__ . '/vectors.php';

use Polaris\Security\Argon2idPasswordHasher;
use Polaris\Security\Pepper;
use Polaris\Security\SodiumEncrypter;
use Polaris\Token\LcobucciTokenParser;
use Polaris\Token\PolarisTokenParser;

$failures = [];
$checked = 0;
$fail = static function (string $what) use (&$failures): void {
    $failures[] = $what;
};

function goVector(string $name): array
{
    $path = VECTOR_DIR . "/go-$name.json";
    if (!is_file($path)) {
        fwrite(STDERR, "missing $path (run: POLARIS_UPDATE_VECTORS=1 go test ./security/ ./token/)\n");
        exit(2);
    }
    $data = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    if (($data['generator'] ?? null) !== 'go') {
        fwrite(STDERR, "$path was not written by Go\n");
        exit(2);
    }

    return $data;
}

$hasher = new Argon2idPasswordHasher();
foreach (goVector('argon2id')['hashes'] as $entry) {
    $checked++;
    if (!$hasher->verify($entry['password'], $entry['hash'])) {
        $fail("argon2id: Go hash of '{$entry['password']}' does not verify: {$entry['hash']}");
    }
    if ($hasher->verify($entry['password'] . 'x', $entry['hash'])) {
        $fail("argon2id: wrong password verifies against {$entry['hash']}");
    }
    if ($hasher->needsRehash($entry['hash']) !== $entry['needs_rehash']) {
        $fail("argon2id: needsRehash disagrees for {$entry['hash']}");
    }
}

$pepperVector = goVector('pepper');
$pepper = new Pepper($pepperVector['app_key']);
foreach ($pepperVector['cases'] as $case) {
    $checked++;
    if (!hash_equals($pepper->hash($case['context'], $case['value']), $case['hash'])) {
        $fail("pepper: Go digest differs for context '{$case['context']}'");
    }
}

foreach (goVector('encrypter')['cases'] as $case) {
    $checked++;
    try {
        if ((new SodiumEncrypter($case['app_key']))->decrypt($case['payload']) !== $case['plaintext']) {
            $fail("encrypter: Go payload decrypts to another plaintext ('{$case['plaintext']}')");
        }
    } catch (Throwable $e) {
        $fail("encrypter: Go payload rejected: {$e->getMessage()}");
    }
}

$jwt = goVector('jwt');
foreach ($jwt['cases'] as $case) {
    $checked++;
    if (mint($case) !== $case['token']) {
        $fail("jwt {$case['name']}: PHP mints different bytes from the same inputs");
    }
    if (checks($case, $case['token']) != $case['checks']) {
        $fail("jwt {$case['name']}: upstream parsers disagree with Go's accept/reject results");
    }
    // Tickets carry a purpose claim, which only the plain lcobucci parser accepts.
    $parser = isset($case['claims']['purpose']) ? new LcobucciTokenParser(tokenConfig($case), clockAt($case['now'])) : new PolarisTokenParser(tokenConfig($case), clockAt($case['now']));
    try {
        $parsed = $parser->parse($case['token']);
    } catch (Throwable $e) {
        $fail("jwt {$case['name']}: upstream rejects the Go token: {$e->getMessage()}");
        continue;
    }
    foreach ($case['claims'] as $name => $value) {
        if (in_array($name, ['', 'iss', 'aud', 'iat', 'nbf', 'exp'], true)) {
            continue;
        }
        if ($parsed->getMetadata((string) $name) !== $value) {
            $fail("jwt {$case['name']}: claim '$name' differs after parsing");
        }
    }
}
foreach (goVector('oauth-jwt')['cases'] as $case) {
    $checked++;
    if (oauthMint($case) !== $case['token']) {
        $fail("oauth-jwt {$case['name']}: Jwt::mint gives different bytes from the same inputs");
    }
    if (oauthChecks($case, $case['token']) != $case['checks']) {
        $fail("oauth-jwt {$case['name']}: Jwt::verify disagrees with Go's accept/reject results");
    }
}
foreach (goVector('receipt')['cases'] as $case) {
    $checked++;
    if (receiptSign($case) !== $case['token']) {
        $fail("receipt {$case['name']}: Receipts::sign gives different bytes from the same receipt");
    }
    if (receiptChecks($case, $case['token']) != $case['checks']) {
        $fail("receipt {$case['name']}: Jwt::verify disagrees with Go's accept/reject results");
    }
}
$checked++;
if (jwksDocument($jwt['jwks']['alg'], $jwt['jwks']['keys']) !== $jwt['jwks']['document']) {
    $fail('jwks: Go document differs from JwkSet::fromPublicKeys');
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "verify-vectors: $checked Go vectors accepted by polaris-core\n");

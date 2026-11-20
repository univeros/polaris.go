<?php

/**
 * Cross-language vectors (docs/port/spec.md §6.3), PHP side.
 *
 * Run from the polaris-go root: `php scripts/vectors.php`. It loads polaris-core from
 * ../polaris-core/vendor and writes testdata/vectors/{argon2id,pepper,encrypter,jwt}.json with
 * fixed inputs (fixed APP_KEY, the test-only keys in testdata/vectors/keys.json, frozen time).
 * The Go tests in security/ and token/ verify every one of them.
 *
 * It also writes oauth-jwt.json: tokens from the OAuth provider's Jwt::mint and the verdicts of
 * Jwt::verify (60 s leeway, kid-selected key) at fixed instants, and receipt.json: agent receipt
 * signatures from the real (private) Receipts::sign.
 *
 * scripts/verify-vectors.php includes this file for its helpers and checks the go-*.json files
 * the Go tests write (POLARIS_UPDATE_VECTORS=1 go test ./security/ ./token/).
 */

declare(strict_types=1);

require __DIR__ . '/../../polaris-core/vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Polaris\Agents\Model\Receipt;
use Polaris\Agents\Receipts;
use Polaris\Config\Secrets;
use Polaris\Exception\InvalidTokenException;
use Polaris\OAuth\Jwt;
use Polaris\OAuth\OAuthException;
use Polaris\Security\Argon2idPasswordHasher;
use Polaris\Security\Pepper;
use Polaris\Security\SodiumEncrypter;
use Polaris\Token\AccessTokenClaims;
use Polaris\Token\JwkSet;
use Polaris\Token\JwtSignerFactory;
use Polaris\Token\LcobucciTokenParser;
use Polaris\Token\PolarisTokenGenerator;
use Polaris\Token\PolarisTokenParser;
use Polaris\Token\TokenConfiguration;
use Psr\Clock\ClockInterface;

const VECTOR_DIR = __DIR__ . '/../testdata/vectors';
const APP_KEY = 'polaris-cross-language-vector-app-key-0123456789';
const JSON_FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

/** Offsets (seconds from the minting instant) at which each token is checked. */
const CHECK_OFFSETS = ['before' => -1, 'at' => 0, 'last' => 'ttl-1', 'expiry' => 'ttl'];

function keys(): array
{
    static $keys = null;

    return $keys ??= json_decode((string) file_get_contents(VECTOR_DIR . '/keys.json'), true, 512, JSON_THROW_ON_ERROR);
}

/** @return array{public: string, private: string} */
function keyPair(string $name): array
{
    $keys = keys();
    if ($name === 'eddsa') {
        return ['public' => base64_decode($keys['eddsa']['public_base64'], true), 'private' => base64_decode($keys['eddsa']['secret_base64'], true)];
    }

    return ['public' => $keys[$name]['public'], 'private' => $keys[$name]['private']];
}

function clockAt(string $unixMicro): ClockInterface
{
    $now = DateTimeImmutable::createFromFormat('U.u', $unixMicro);
    if ($now === false) {
        throw new RuntimeException("Bad instant $unixMicro");
    }

    return new class ($now) implements ClockInterface {
        public function __construct(private readonly DateTimeImmutable $now)
        {
        }

        public function now(): DateTimeImmutable
        {
            return $this->now;
        }
    };
}

function instantPlus(string $unixMicro, int $seconds): string
{
    [$sec, $usec] = explode('.', $unixMicro);

    return ((int) $sec + $seconds) . '.' . $usec;
}

/** @param array<string, mixed> $case */
function tokenConfig(array $case): TokenConfiguration
{
    $pair = keyPair($case['keys']);

    return new TokenConfiguration(
        $pair['public'],
        $case['ttl'],
        JwtSignerFactory::create($case['alg']),
        $case['issuer'],
        null,
        $pair['private'],
        $case['audience'] === '' ? null : $case['audience'],
    );
}

/** @param array<string, mixed> $case */
function mint(array $case): string
{
    return (new PolarisTokenGenerator(tokenConfig($case), clockAt($case['now']), $case['kid']))->generate($case['claims']);
}

/**
 * Runs upstream's parsers over a token at each check instant.
 *
 * @param array<string, mixed> $case
 *
 * @return array<string, array{access: bool, verify: bool}>
 */
function checks(array $case, string $token): array
{
    $results = [];
    foreach (CHECK_OFFSETS as $label => $offset) {
        $seconds = is_int($offset) ? $offset : ($offset === 'ttl' ? $case['ttl'] : $case['ttl'] - 1);
        $clock = clockAt(instantPlus($case['now'], $seconds));
        $results[$label] = [
            'access' => accepts(fn() => (new PolarisTokenParser(tokenConfig($case), $clock))->parse($token)),
            'verify' => accepts(fn() => (new LcobucciTokenParser(tokenConfig($case), $clock))->parse($token)),
        ];
    }

    return $results;
}

function accepts(callable $parse): bool
{
    try {
        $parse();

        return true;
    } catch (InvalidTokenException) {
        return false;
    }
}

/** @param list<array{kid: string, keys: string}> $keys */
function jwksDocument(string $alg, array $keys): string
{
    $byKid = [];
    foreach ($keys as $key) {
        $byKid[$key['kid']] = keyPair($key['keys'])['public'];
    }

    return json_encode(JwkSet::fromPublicKeys($byKid, $alg), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

function writeVector(string $name, array $data): void
{
    file_put_contents(VECTOR_DIR . "/$name.json", json_encode($data, JSON_FLAGS) . "\n");
    fwrite(STDOUT, "wrote testdata/vectors/$name.json\n");
}

/** @return list<array<string, mixed>> */
function jwtCases(): array
{
    $base = ['issuer' => 'https://auth.polaris.test', 'ttl' => 900, 'regenerate' => true];
    $full = (new AccessTokenClaims(
        subject: '0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b',
        jwtId: '0197a1b2-c3d4-7e5f-8a9b-000000000001',
        sessionId: '0197a1b2-c3d4-7e5f-8a9b-000000000002',
        organizationId: '0197a1b2-c3d4-7e5f-8a9b-000000000003',
        roles: ['owner', 'admin'],
        scope: ['members.invite', 'org.update'],
        emailVerified: true,
        mfa: true,
        amr: ['pwd', 'otp'],
        authTime: 1_780_833_000,
        extra: ['impersonated_by' => 'operator-1', 'act' => ['sub' => 'agent-7', 'kind' => 'agent'], 'cnf' => ['jkt' => 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs']],
    ))->toClaims();
    $minimal = (new AccessTokenClaims(subject: 'user-1', jwtId: 'jti-1'))->toClaims();

    return [
        [...$base, 'name' => 'rs256-access-full', 'alg' => 'RS256', 'keys' => 'rsa', 'kid' => 'kid-2026-01', 'audience' => 'https://api.polaris.test', 'now' => '1780833600.000000', 'claims' => $full],
        [...$base, 'name' => 'rs256-microseconds-no-audience', 'alg' => 'RS256', 'keys' => 'rsa', 'kid' => 'kid-2026-01', 'audience' => '', 'now' => '1780833600.123456', 'claims' => $minimal],
        [...$base, 'name' => 'eddsa-escaping', 'alg' => 'EdDSA', 'keys' => 'eddsa', 'kid' => 'ed-1', 'audience' => '', 'now' => '1780833600.500000', 'ttl' => 60,
            'claims' => [...$minimal, 'note' => "a/b <tag> & ü \u{2028} \x01 \"q\" \\", 'ratio' => 0.5, 'big' => 1e20, 'nested' => [[1, 2], ['k' => null]], 'empty' => []]],
        [...$base, 'name' => 'rs256-purpose-ticket', 'alg' => 'RS256', 'keys' => 'rsa', 'kid' => 'kid-2026-01', 'audience' => 'https://api.polaris.test', 'now' => '1780833600.000000', 'ttl' => 300,
            'claims' => ['sub' => 'user-1', 'jti' => 'ticket-1', 'purpose' => 'login_mfa', 'iss' => 'ignored', 'exp' => 1, '' => 'dropped']],
        [...$base, 'name' => 'rs256-alternate-key', 'alg' => 'RS256', 'keys' => 'rsa_alternate', 'kid' => 'kid-2025-12', 'audience' => 'https://api.polaris.test', 'now' => '1780833600.000000', 'claims' => $minimal],
    ];
}

/** A well-signed token with no time claims, built with lcobucci directly (PolarisTokenRejectionTest). */
function noExpiryCase(): array
{
    $pair = keyPair('rsa');
    $lcobucci = Configuration::forAsymmetricSigner(new Sha256(), InMemory::plainText($pair['private']), InMemory::plainText($pair['public']));
    $token = $lcobucci->builder()
        ->issuedBy('https://auth.polaris.test')
        ->permittedFor('https://api.polaris.test')
        ->relatedTo('user-1')
        ->getToken($lcobucci->signer(), $lcobucci->signingKey())
        ->toString();
    $case = ['name' => 'rs256-no-time-claims', 'alg' => 'RS256', 'keys' => 'rsa', 'kid' => '', 'issuer' => 'https://auth.polaris.test',
        'audience' => 'https://api.polaris.test', 'ttl' => 900, 'now' => '1780833600.000000', 'claims' => [], 'regenerate' => false];

    return [...$case, 'token' => $token, 'checks' => checks($case, $token)];
}

/**
 * The OAuth provider's Jwt over one side's keys: ['keys' => pair, 'kid' => …, 'previous_keys' =>
 * pair or '', 'previous_kid' => …].
 *
 * @param array<string, string> $side
 */
function oauthJwt(array $side, string $alg, string $issuer, string $at): Jwt
{
    $pair = keyPair($side['keys']);
    $previous = ($side['previous_keys'] ?? '') === '' ? null : keyPair($side['previous_keys'])['public'];
    $config = new TokenConfiguration($pair['public'], 900, JwtSignerFactory::create($alg), $issuer, null, $pair['private'], null);
    $secrets = new Secrets(APP_KEY, $pair['private'], $pair['public'], $side['kid'], $previous, $previous === null ? null : $side['previous_kid']);

    return new Jwt($config, $secrets, clockAt($at));
}

/** @param array<string, mixed> $case */
function oauthMint(array $case): string
{
    $expiresAt = DateTimeImmutable::createFromFormat('U.u', $case['expires_at']);

    return oauthJwt($case['minter'], $case['alg'], $case['issuer'], $case['now'])
        ->mint($case['claims'], $expiresAt, $case['typ'] === '' ? [] : ['typ' => $case['typ']]);
}

/**
 * Jwt::verify's verdict at each check instant.
 *
 * @param array<string, mixed> $case
 *
 * @return array<string, bool>
 */
function oauthChecks(array $case, string $token): array
{
    $results = [];
    foreach ($case['check_at'] as $at) {
        try {
            oauthJwt($case['verifier'], $case['alg'], $case['issuer'], $at)->verify($token);
            $results[$at] = true;
        } catch (OAuthException) {
            $results[$at] = false;
        }
    }

    return $results;
}

/** @return list<array<string, mixed>> */
function oauthCases(): array
{
    $current = ['keys' => 'rsa', 'kid' => 'kid-2026-01', 'previous_keys' => '', 'previous_kid' => ''];
    $rotating = ['keys' => 'rsa', 'kid' => 'kid-2026-01', 'previous_keys' => 'rsa_alternate', 'previous_kid' => 'kid-2025-12'];
    $ed = ['keys' => 'eddsa', 'kid' => 'ed-1', 'previous_keys' => '', 'previous_kid' => ''];
    $base = ['issuer' => 'https://auth.polaris.test', 'regenerate' => true];
    // Instants: past the iat leeway, at its edge, at issue, inside and past the exp leeway.
    $window = static fn(string $now, string $exp): array => [instantPlus($now, -61), instantPlus($now, -60), $now, instantPlus($exp, 59), instantPlus($exp, 60)];
    $accessClaims = ['iss' => 'dropped', 'sub' => 'user-1', 'jti' => 'at-0197a1b2', 'aud' => 'https://rs.example', 'client_id' => 'client-1',
        'scope' => 'openid profile', 'cnf' => ['jkt' => 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'], 'exp' => 5];

    return [
        [...$base, 'name' => 'at-jwt-rs256', 'alg' => 'RS256', 'typ' => 'at+jwt', 'now' => '1780833600.250000', 'expires_at' => '1780833900.250000',
            'minter' => $current, 'verifier' => $current, 'claims' => $accessClaims, 'check_at' => $window('1780833600.250000', '1780833900.250000')],
        [...$base, 'name' => 'id-token-eddsa-audience-list', 'alg' => 'EdDSA', 'typ' => '', 'now' => '1780833600.000000', 'expires_at' => '1780837200.000000',
            'minter' => $ed, 'verifier' => $ed, 'check_at' => $window('1780833600.000000', '1780837200.000000'),
            'claims' => ['sub' => 'user-1', 'aud' => ['client-1', 'client-2'], 'nonce' => 'n-0S6_WzA2Mj', 'auth_time' => 1780833500,
                'at_hash' => 'MTIzNDU2Nzg5MDEyMzQ1Ng', 'email' => 'ana/b@example.com', 'name' => 'Ana Ñúñez']],
        [...$base, 'name' => 'id-token-single-audience', 'alg' => 'RS256', 'typ' => '', 'now' => '1780833600.000001', 'expires_at' => '1780834200.000000',
            'minter' => $current, 'verifier' => $current, 'claims' => ['sub' => 'user-1', 'aud' => ['client-1'], 'jti' => 'id-1'],
            'check_at' => $window('1780833600.000001', '1780834200.000000')],
        [...$base, 'name' => 'at-jwt-previous-key', 'alg' => 'RS256', 'typ' => 'at+jwt', 'now' => '1780833600.000000', 'expires_at' => '1780833900.000000',
            'minter' => ['keys' => 'rsa_alternate', 'kid' => 'kid-2025-12', 'previous_keys' => '', 'previous_kid' => ''], 'verifier' => $rotating,
            'claims' => $accessClaims, 'check_at' => $window('1780833600.000000', '1780833900.000000')],
        [...$base, 'name' => 'at-jwt-unknown-kid', 'alg' => 'RS256', 'typ' => 'at+jwt', 'now' => '1780833600.000000', 'expires_at' => '1780833900.000000',
            'minter' => [...$current, 'kid' => 'kid-unknown'], 'verifier' => $rotating,
            'claims' => $accessClaims, 'check_at' => $window('1780833600.000000', '1780833900.000000')],
    ];
}

/**
 * Receipts::sign over one receipt, called on an instance built without its database: sign()
 * only reads the token configuration and the kid.
 *
 * @param array<string, mixed> $case
 */
function receiptSign(array $case): string
{
    $pair = keyPair($case['keys']);
    $config = new TokenConfiguration($pair['public'], 900, JwtSignerFactory::create($case['alg']), $case['issuer'], null, $pair['private'], null);
    $secrets = new Secrets(APP_KEY, $pair['private'], $pair['public'], $case['kid']);
    $receipt = new Receipt();
    $receipt->id = $case['receipt']['id'];
    $receipt->agentId = $case['receipt']['agent_id'];
    $receipt->seq = $case['receipt']['seq'];
    $receipt->hash = $case['receipt']['hash'];
    $receipt->createdAt = DateTimeImmutable::createFromFormat('U.u', $case['receipt']['created_at']);
    $receipts = (new ReflectionClass(Receipts::class))->newInstanceWithoutConstructor();

    return Closure::bind(function () use ($config, $secrets, $receipt): string {
        $this->config = $config;
        $this->secrets = $secrets;

        return $this->sign($receipt);
    }, $receipts, Receipts::class)();
}

/** @return list<array<string, mixed>> */
function receiptCases(): array
{
    $side = ['keys' => 'rsa', 'kid' => 'kid-2026-01', 'previous_keys' => '', 'previous_kid' => ''];
    $ed = ['keys' => 'eddsa', 'kid' => 'ed-1', 'previous_keys' => '', 'previous_kid' => ''];

    return [
        ['name' => 'receipt-rs256', 'alg' => 'RS256', 'issuer' => 'https://auth.polaris.test', 'keys' => 'rsa', 'kid' => 'kid-2026-01', 'verifier' => $side,
            'receipt' => ['id' => '0197a1b2-c3d4-7e5f-8a9b-0000000000a1', 'agent_id' => 'agent-7', 'seq' => 42, 'hash' => hash('sha256', 'receipt-42'), 'created_at' => '1780833600.123456'],
            'check_at' => ['1780833538.123456', '1780833600.123456', '1880833600.000000']],
        ['name' => 'receipt-eddsa-whole-second', 'alg' => 'EdDSA', 'issuer' => 'https://auth.polaris.test', 'keys' => 'eddsa', 'kid' => 'ed-1', 'verifier' => $ed,
            'receipt' => ['id' => 'r-1', 'agent_id' => 'agent-1', 'seq' => 1, 'hash' => hash('sha256', 'receipt-1'), 'created_at' => '1780833600.000000'],
            'check_at' => ['1780833539.000000', '1780833540.000000', '1880833600.000000']],
    ];
}

/** @param array<string, mixed> $case @return array<string, bool> */
function receiptChecks(array $case, string $token): array
{
    $results = [];
    foreach ($case['check_at'] as $at) {
        try {
            oauthJwt($case['verifier'], $case['alg'], $case['issuer'], $at)->verify($token, Receipts::TYP);
            $results[$at] = true;
        } catch (OAuthException) {
            $results[$at] = false;
        }
    }

    return $results;
}

function main(): void
{
    // Default cost once (it is slow under the race detector); the rest at low cost.
    $default = new Argon2idPasswordHasher();
    $lowCost = new Argon2idPasswordHasher(['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]);
    $hashes = [['password' => 'correct horse battery staple', 'hash' => $default->hash('correct horse battery staple')]];
    foreach (['', 'pässwörd 🔑', str_repeat('long-', 40)] as $password) {
        $hashes[] = ['password' => $password, 'hash' => $lowCost->hash($password)];
    }
    $hashes[] = ['password' => 'two-lanes', 'hash' => password_hash('two-lanes', PASSWORD_ARGON2ID, ['memory_cost' => 16, 'time_cost' => 2, 'threads' => 2])];
    $hashes[] = ['password' => 'argon2i', 'hash' => password_hash('argon2i', PASSWORD_ARGON2I, ['memory_cost' => 1024, 'time_cost' => 2, 'threads' => 1])];
    $hashes[] = ['password' => 'bcrypt', 'hash' => password_hash('bcrypt', PASSWORD_BCRYPT, ['cost' => 4])];
    foreach ($hashes as $i => $entry) {
        $hashes[$i]['needs_rehash'] = $default->needsRehash($entry['hash']);
    }
    writeVector('argon2id', ['generator' => 'php', 'hashes' => $hashes]);

    $pepper = new Pepper(APP_KEY);
    $digests = [];
    foreach ([['refresh', 'rt_9Kq2-token'], ['otp', '123456'], ['recovery', 'abcde-fghij'], ['', ''], ['invite', 'ünïcødé ✓']] as [$context, $value]) {
        $digests[] = ['context' => $context, 'value' => $value, 'hash' => $pepper->hash($context, $value)];
    }
    writeVector('pepper', ['generator' => 'php', 'app_key' => APP_KEY, 'cases' => $digests]);

    $payloads = [];
    foreach ([[APP_KEY, 'JBSWY3DPEHPK3PXP'], [APP_KEY, ''], [APP_KEY, 'üñí©ødé 🔐'], [APP_KEY, str_repeat('0123456789', 100)], ['k', 'short key']] as [$key, $plain]) {
        $payloads[] = ['app_key' => $key, 'plaintext' => $plain, 'payload' => (new SodiumEncrypter($key))->encrypt($plain)];
    }
    writeVector('encrypter', ['generator' => 'php', 'cases' => $payloads]);

    $cases = [];
    foreach (jwtCases() as $case) {
        $token = mint($case);
        $cases[] = [...$case, 'token' => $token, 'checks' => checks($case, $token)];
    }
    $cases[] = noExpiryCase();
    $jwksKeys = [['kid' => 'kid-2026-01', 'keys' => 'rsa'], ['kid' => 'kid-2025-12', 'keys' => 'rsa_alternate']];
    writeVector('jwt', [
        'generator' => 'php',
        'cases' => $cases,
        'jwks' => ['alg' => 'RS256', 'keys' => $jwksKeys, 'document' => jwksDocument('RS256', $jwksKeys)],
    ]);

    $oauth = [];
    foreach (oauthCases() as $case) {
        $token = oauthMint($case);
        $oauth[] = [...$case, 'token' => $token, 'checks' => oauthChecks($case, $token)];
    }
    writeVector('oauth-jwt', ['generator' => 'php', 'cases' => $oauth]);

    $receipts = [];
    foreach (receiptCases() as $case) {
        $token = receiptSign($case);
        $receipts[] = [...$case, 'token' => $token, 'checks' => receiptChecks($case, $token)];
    }
    writeVector('receipt', ['generator' => 'php', 'cases' => $receipts]);
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    main();
}

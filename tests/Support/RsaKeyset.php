<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Tests\Support;

use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * In-memory RSA key pair that plays the SSO Server: signs RS256 tokens and
 * publishes the matching JWKS.
 */
final class RsaKeyset
{
    /**
     * @param  array{n: string, e: string}  $publicComponents
     */
    private function __construct(
        public readonly OpenSSLAsymmetricKey $privateKey,
        public readonly string $kid,
        public readonly array $publicComponents,
    ) {}

    public static function generate(string $kid = 'key-1'): self
    {
        $options = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];

        // Windows builds of OpenSSL need an explicit config file.
        if (is_file(__DIR__.'/openssl.cnf')) {
            $options['config'] = __DIR__.'/openssl.cnf';
        }

        $key = openssl_pkey_new($options);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($key === false || $details === false) {
            throw new RuntimeException('Failed to generate RSA test key: '.openssl_error_string());
        }

        return new self($key, $kid, [
            'n' => self::base64UrlEncode($details['rsa']['n']),
            'e' => self::base64UrlEncode($details['rsa']['e']),
        ]);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function sign(array $claims): string
    {
        return JWT::encode($claims, $this->privateKey, 'RS256', $this->kid);
    }

    /**
     * @return array{keys: array<int, array<string, string>>}
     */
    public function jwks(): array
    {
        return ['keys' => [[
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->kid,
            'n' => $this->publicComponents['n'],
            'e' => $this->publicComponents['e'],
        ]]];
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}

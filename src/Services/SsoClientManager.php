<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Services;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoClient\Contracts\SsoUserSynchronizerContract;
use JeffersonGoncalves\SsoClient\Events\UserSynchronizedEvent;
use JeffersonGoncalves\SsoClient\Exceptions\InvalidSignatureException;
use JeffersonGoncalves\SsoClient\Exceptions\InvalidStateException;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientMismatchException;
use JeffersonGoncalves\SsoClient\Exceptions\SsoServerUnreachableException;
use JeffersonGoncalves\SsoClient\Exceptions\TokenExpiredException;
use JeffersonGoncalves\SsoClient\Exceptions\TokenReplayedException;
use Throwable;

class SsoClientManager
{
    public const SIGNATURE_HEADER = 'X-SSO-Signature';

    public const TIMESTAMP_HEADER = 'X-SSO-Timestamp';

    public const SESSION_STATE = 'sso-client.state';

    public const SESSION_VERIFIER = 'sso-client.code_verifier';

    public const SESSION_SUB = 'sso-client.sub';

    public const SESSION_AUTHENTICATED_AT = 'sso-client.authenticated_at';

    public function __construct(
        protected ConfigRepository $config,
        protected CacheRepository $cache,
        protected HttpFactory $http,
        protected AuthFactory $auth,
        protected SsoUserSynchronizerContract $synchronizer,
    ) {}

    /**
     * Start the Authorization Code + PKCE flow: store state and code_verifier
     * in the session and return the Server's authorize URL.
     */
    public function authorizationUrl(Session $session): string
    {
        $state = Str::random(40);
        $verifier = Str::random(64);

        $session->put([
            self::SESSION_STATE => $state,
            self::SESSION_VERIFIER => $verifier,
        ]);

        return $this->endpoint('authorize').'?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId(),
            'redirect_uri' => $this->redirectUri(),
            'state' => $state,
            'code_challenge' => self::base64UrlEncode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ]);
    }

    /**
     * Validate the callback, exchange the code, synchronize and log the user in.
     *
     * @throws SsoClientException
     */
    public function handleCallback(Request $request): Authenticatable
    {
        $session = $request->session();

        // pull(): state and verifier are single-use even when validation fails.
        $expectedState = $session->pull(self::SESSION_STATE);
        $verifier = $session->pull(self::SESSION_VERIFIER);
        $state = $request->query('state');

        if (! is_string($expectedState) || ! is_string($state) || ! hash_equals($expectedState, $state)) {
            throw new InvalidStateException('Invalid SSO state.');
        }

        $code = $request->query('code');

        if (! is_string($code) || $code === '' || ! is_string($verifier)) {
            throw new SsoClientException('Missing authorization code.');
        }

        $claims = $this->exchangeCode($code, $verifier);

        $user = $this->synchronizer->synchronize($claims);

        UserSynchronizedEvent::dispatch($user, $claims);

        $this->guard()->login($user);
        $session->regenerate();

        // Lets a later Single Logout webhook (keyed by "sub") revoke this session.
        $session->put([
            self::SESSION_SUB => $claims['sub'],
            self::SESSION_AUTHENTICATED_AT => microtime(true),
        ]);

        return $user;
    }

    /**
     * Exchange the authorization code for verified claims, using the
     * configured verification mode.
     *
     * @return array<string, mixed>
     *
     * @throws SsoClientException
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $response = $this->send(fn (PendingRequest $http): Response => $http->asForm()->post($this->endpoint('token'), [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId(),
            'client_secret' => $this->secret(),
            'code' => $code,
            'redirect_uri' => $this->redirectUri(),
            'code_verifier' => $codeVerifier,
        ]));

        if ($response->failed()) {
            $error = $response->json('error');
            $message = "SSO token exchange failed with HTTP {$response->status()}".(is_string($error) ? " ({$error})." : '.');

            throw $response->status() === 401
                ? new SsoClientMismatchException($message)
                : new SsoClientException($message);
        }

        $token = $response->json('access_token');

        if (! is_string($token) || $token === '') {
            throw new SsoClientException('SSO token response has no "access_token".');
        }

        return $this->config->get('sso-client.verification') === 'userinfo'
            ? $this->fetchUserInfo($token)
            : $this->verifyAccessToken($token);
    }

    /**
     * Validate an RS256 access token locally against the server's JWKS.
     *
     * @return array<string, mixed>
     *
     * @throws SsoClientException
     */
    public function verifyAccessToken(string $token): array
    {
        $claims = $this->decodeJwt($token);

        foreach (['sub', 'jti'] as $claim) {
            if (! isset($claims[$claim]) || ! is_string($claims[$claim]) || $claims[$claim] === '') {
                throw new SsoClientException("SSO token is missing the \"{$claim}\" claim.");
            }
        }

        // firebase/php-jwt only enforces exp when present: require it.
        if (! isset($claims['exp']) || ! is_numeric($claims['exp'])) {
            throw new TokenExpiredException('SSO token is missing "exp".');
        }

        if (($claims['iss'] ?? null) !== $this->issuer()) {
            throw new SsoClientMismatchException('SSO token "iss" does not match sso-client.issuer.');
        }

        if (! in_array($this->clientId(), (array) ($claims['aud'] ?? []), true)) {
            throw new SsoClientMismatchException('SSO token "aud" does not include sso-client.client_id.');
        }

        // Remember the jti for as long as the token could still be accepted.
        if (! $this->consumeOnce($claims['jti'], (int) $claims['exp'] + $this->leeway() - time())) {
            throw new TokenReplayedException('SSO token was already used.');
        }

        return $claims;
    }

    /**
     * Resolve the claims through GET /sso/userinfo; the server rejects tokens
     * of users that logged out, and signs the response with the client secret.
     *
     * @return array<string, mixed>
     *
     * @throws SsoClientException
     */
    public function fetchUserInfo(string $token): array
    {
        $response = $this->send(fn (PendingRequest $http): Response => $http->withToken($token)->get($this->endpoint('userinfo')));

        if ($response->failed()) {
            throw new SsoClientException("SSO userinfo failed with HTTP {$response->status()}.");
        }

        $this->verifySignature(
            $response->body(),
            $response->header(self::TIMESTAMP_HEADER),
            $response->header(self::SIGNATURE_HEADER),
        );

        $claims = $response->json();

        if (! is_array($claims) || ! isset($claims['sub']) || ! is_string($claims['sub']) || $claims['sub'] === '') {
            throw new SsoClientException('SSO userinfo response has no "sub".');
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * Verify X-SSO-Signature = hex HMAC-SHA256("{timestamp}.{raw body}", client_secret)
     * and reject timestamps outside sso-client.signature_tolerance.
     *
     * @throws InvalidSignatureException|TokenExpiredException
     */
    public function verifySignature(string $payload, ?string $timestamp, ?string $signature): void
    {
        if (! is_string($timestamp) || ! ctype_digit($timestamp) || ! is_string($signature) || $signature === ''
            || ! hash_equals(hash_hmac('sha256', $timestamp.'.'.$payload, $this->secret()), $signature)) {
            throw new InvalidSignatureException('Invalid X-SSO-Signature.');
        }

        if (abs(time() - (int) $timestamp) > $this->signatureTolerance()) {
            throw new TokenExpiredException('X-SSO-Timestamp is outside the tolerance window.');
        }
    }

    /**
     * Mark an id as used. Cache::add() is atomic, so two concurrent requests
     * with the same jti cannot both get true.
     */
    public function consumeOnce(string $jti, int $ttlSeconds): bool
    {
        return $this->cache->add('sso-client:jti:'.hash('sha256', $jti), true, max($ttlSeconds, 1));
    }

    /**
     * Single Logout: every local session of this server user that started
     * before now is revoked (enforced by the sso.auth middleware).
     */
    public function logoutSubject(string $sub): void
    {
        $this->cache->put(
            $this->logoutCacheKey($sub),
            microtime(true),
            now()->addMinutes((int) $this->config->get('session.lifetime', 120)),
        );
    }

    public function isRevoked(Session $session): bool
    {
        $sub = $session->get(self::SESSION_SUB);

        if (! is_string($sub)) {
            return false;
        }

        $loggedOutAt = $this->cache->get($this->logoutCacheKey($sub));

        return is_numeric($loggedOutAt)
            && (float) $loggedOutAt >= (float) $session->get(self::SESSION_AUTHENTICATED_AT, 0);
    }

    public function clientId(): string
    {
        return (string) $this->config->get('sso-client.client_id');
    }

    public function signatureTolerance(): int
    {
        return (int) $this->config->get('sso-client.signature_tolerance', 300);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws SsoClientException
     */
    protected function decodeJwt(string $token): array
    {
        $keys = $this->keySet();
        $kid = $this->jwtKid($token);

        // Unknown kid = server rotated its keys: refetch the JWKS once.
        if ($kid !== null && ! isset($keys[$kid])) {
            $keys = $this->keySet(refresh: true);
        }

        JWT::$leeway = $this->leeway();

        try {
            // Every Key is pinned to RS256, so any other "alg" header is rejected.
            $decoded = JWT::decode($token, $keys);
        } catch (ExpiredException $e) {
            throw new TokenExpiredException('SSO token has expired.', previous: $e);
        } catch (Throwable $e) {
            throw new InvalidSignatureException("Invalid SSO token: {$e->getMessage()}", previous: $e);
        }

        /** @var array<string, mixed> */
        return json_decode((string) json_encode($decoded), true);
    }

    /**
     * @return array<string, Key>
     */
    protected function keySet(bool $refresh = false): array
    {
        $cacheKey = 'sso-client:jwks';

        if ($refresh) {
            $this->cache->forget($cacheKey);
        }

        /** @var array<string, mixed> $jwks */
        $jwks = $this->cache->remember($cacheKey, (int) $this->config->get('sso-client.jwks_cache_ttl', 300), function (): array {
            $response = $this->send(fn (PendingRequest $http): Response => $http->get($this->endpoint('jwks')));
            $jwks = $response->json();

            if ($response->failed() || ! is_array($jwks) || ! isset($jwks['keys'])) {
                throw new SsoClientException("Unable to fetch SSO JWKS (HTTP {$response->status()}).");
            }

            return $jwks;
        });

        try {
            return JWK::parseKeySet($jwks, 'RS256');
        } catch (Throwable $e) {
            throw new SsoClientException("Invalid SSO JWKS: {$e->getMessage()}", previous: $e);
        }
    }

    protected function jwtKid(string $token): ?string
    {
        try {
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode(explode('.', $token)[0]));
        } catch (Throwable) {
            return null;
        }

        return is_object($header) && isset($header->kid) && is_string($header->kid) ? $header->kid : null;
    }

    /**
     * @param  callable(PendingRequest): Response  $callback
     *
     * @throws SsoServerUnreachableException
     */
    protected function send(callable $callback): Response
    {
        $http = $this->http
            ->timeout((int) $this->config->get('sso-client.http_timeout', 5))
            ->acceptJson()
            // Only network failures are retried: the server burns the code on any 4xx.
            ->retry(3, 100, fn (Throwable $e): bool => $e instanceof ConnectionException, throw: false);

        try {
            return $callback($http);
        } catch (ConnectionException $e) {
            throw new SsoServerUnreachableException("SSO Server unreachable: {$e->getMessage()}", previous: $e);
        }
    }

    protected function guard(): StatefulGuard
    {
        $guard = $this->auth->guard($this->config->get('sso-client.guard'));

        if (! $guard instanceof StatefulGuard) {
            throw new SsoClientException('sso-client.guard must be a stateful (session) guard.');
        }

        return $guard;
    }

    protected function secret(): string
    {
        $secret = (string) $this->config->get('sso-client.client_secret');

        if ($secret === '') {
            throw new SsoClientException('sso-client.client_secret is not configured.');
        }

        return $secret;
    }

    protected function endpoint(string $name): string
    {
        return $this->serverUrl().'/'.ltrim((string) $this->config->get("sso-client.endpoints.{$name}"), '/');
    }

    protected function serverUrl(): string
    {
        return rtrim((string) $this->config->get('sso-client.server_url'), '/');
    }

    protected function issuer(): string
    {
        return (string) ($this->config->get('sso-client.issuer') ?: $this->serverUrl());
    }

    protected function redirectUri(): string
    {
        return (string) ($this->config->get('sso-client.redirect_uri') ?: route('sso-client.callback'));
    }

    protected function leeway(): int
    {
        return (int) $this->config->get('sso-client.leeway', 30);
    }

    protected function logoutCacheKey(string $sub): string
    {
        return 'sso-client:logout:'.hash('sha256', $sub);
    }

    protected static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}

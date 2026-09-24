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
use Illuminate\Session\SessionManager;
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

    public const SESSION_STATE = 'sso-client.state';

    public const SESSION_VERIFIER = 'sso-client.code_verifier';

    public const SESSION_SID = 'sso-client.sid';

    public function __construct(
        protected ConfigRepository $config,
        protected CacheRepository $cache,
        protected HttpFactory $http,
        protected AuthFactory $auth,
        protected SessionManager $sessions,
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

        if (is_string($request->query('error'))) {
            throw new SsoClientException("SSO Server returned error \"{$request->query('error')}\".");
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

        $sid = $claims['sid'] ?? null;

        if (is_string($sid) && $sid !== '') {
            $session->put(self::SESSION_SID, $sid);
            $this->cache->put(
                $this->sidCacheKey($sid),
                $session->getId(),
                now()->addMinutes((int) $this->config->get('session.lifetime', 120)),
            );
        }

        return $user;
    }

    /**
     * Exchange the authorization code for verified, not-yet-used claims.
     *
     * @return array<string, mixed>
     *
     * @throws SsoClientException
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $body = json_encode([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri(),
            'client_id' => $this->clientId(),
            'code_verifier' => $codeVerifier,
        ], JSON_THROW_ON_ERROR);

        $response = $this->send(fn (PendingRequest $http): Response => $http
            ->withHeaders([self::SIGNATURE_HEADER => $this->sign($body)])
            ->withBody($body, 'application/json')
            ->post($this->endpoint('token')));

        if ($response->failed()) {
            throw new SsoClientException("SSO token exchange failed with HTTP {$response->status()}.");
        }

        if ($this->config->get('sso-client.verification') === 'hmac') {
            $this->verifySignature($response->body(), $response->header(self::SIGNATURE_HEADER));
            $claims = $response->json();
        } else {
            $token = $response->json('token');

            if (! is_string($token)) {
                throw new SsoClientException('SSO token response has no "token".');
            }

            $claims = $this->decodeJwt($token);
        }

        if (! is_array($claims)) {
            throw new SsoClientException('SSO token response is not a JSON object.');
        }

        /** @var array<string, mixed> $claims */
        $this->validateClaims($claims);

        return $claims;
    }

    /**
     * @throws InvalidSignatureException
     */
    public function verifySignature(string $payload, ?string $signature): void
    {
        if (! is_string($signature) || $signature === '' || ! hash_equals($this->sign($payload), $signature)) {
            throw new InvalidSignatureException('Invalid X-SSO-Signature.');
        }
    }

    public function sign(string $payload): string
    {
        $secret = (string) $this->config->get('sso-client.client_secret');

        if ($secret === '') {
            throw new SsoClientException('sso-client.client_secret is not configured.');
        }

        return hash_hmac('sha256', $payload, $secret);
    }

    /**
     * Mark a token/webhook id as used. Cache::add() is atomic, so two
     * concurrent requests with the same jti cannot both pass.
     *
     * @throws TokenReplayedException
     */
    public function consumeOnce(string $jti, int $ttlSeconds): void
    {
        if (! $this->cache->add('sso-client:jti:'.hash('sha256', $jti), true, max($ttlSeconds, 1))) {
            throw new TokenReplayedException('SSO token was already used.');
        }
    }

    /**
     * Destroy the local session bound to the Server session id (Single Logout).
     */
    public function logoutSession(string $sid): bool
    {
        $sessionId = $this->cache->pull($this->sidCacheKey($sid));

        if (! is_string($sessionId) || $sessionId === '') {
            return false;
        }

        // ponytail: cookie session driver keeps state client-side and cannot be destroyed here.
        return $this->sessions->driver()->getHandler()->destroy($sessionId);
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
        $jwks = $this->cache->remember($cacheKey, (int) $this->config->get('sso-client.jwks_cache_ttl', 3600), function (): array {
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
     * @param  array<string, mixed>  $claims
     *
     * @throws SsoClientException
     */
    protected function validateClaims(array $claims): void
    {
        foreach (['sub', 'jti'] as $claim) {
            if (! isset($claims[$claim]) || ! is_string($claims[$claim]) || $claims[$claim] === '') {
                throw new SsoClientException("SSO token is missing the \"{$claim}\" claim.");
            }
        }

        if (! isset($claims['exp'], $claims['iat']) || ! is_numeric($claims['exp']) || ! is_numeric($claims['iat'])) {
            throw new TokenExpiredException('SSO token is missing "exp"/"iat".');
        }

        $now = time();

        if ((int) $claims['exp'] + $this->leeway() < $now || (int) $claims['iat'] - $this->leeway() > $now) {
            throw new TokenExpiredException('SSO token is outside its validity window.');
        }

        if (($claims['iss'] ?? null) !== $this->serverUrl()) {
            throw new SsoClientMismatchException('SSO token "iss" does not match sso-client.server_url.');
        }

        $aud = (array) ($claims['aud'] ?? []);

        if (! in_array($this->clientId(), $aud, true)) {
            throw new SsoClientMismatchException('SSO token "aud" does not include sso-client.client_id.');
        }

        // Remember the jti for as long as the token could still be accepted.
        $this->consumeOnce($claims['jti'], (int) $claims['exp'] + $this->leeway() - $now);
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
            // Only network failures are retried: a 4xx on a one-time code must not be replayed.
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

    protected function endpoint(string $name): string
    {
        return $this->serverUrl().'/'.ltrim((string) $this->config->get("sso-client.endpoints.{$name}"), '/');
    }

    protected function serverUrl(): string
    {
        return rtrim((string) $this->config->get('sso-client.server_url'), '/');
    }

    protected function clientId(): string
    {
        return (string) $this->config->get('sso-client.client_id');
    }

    protected function redirectUri(): string
    {
        return (string) ($this->config->get('sso-client.redirect_uri') ?: route('sso-client.callback'));
    }

    protected function leeway(): int
    {
        return (int) $this->config->get('sso-client.leeway', 30);
    }

    protected function sidCacheKey(string $sid): string
    {
        return 'sso-client:sid:'.hash('sha256', $sid);
    }

    protected static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}

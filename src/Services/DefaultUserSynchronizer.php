<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoClient\Contracts\SsoUserSynchronizerContract;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;

/**
 * Create-or-update the local Eloquent user from the SSO claims, matching on
 * sso-client.user.identifier. Bind your own SsoUserSynchronizerContract for
 * in-memory users, role mapping or tables without a "password" column.
 */
class DefaultUserSynchronizer implements SsoUserSynchronizerContract
{
    public function __construct(
        protected ConfigRepository $config,
    ) {}

    public function synchronize(array $ssoPayload): Authenticatable
    {
        /** @var array<string, string> $map */
        $map = (array) $this->config->get('sso-client.user.attributes', []);
        $identifier = (string) $this->config->get('sso-client.user.identifier', 'email');

        $attributes = [];

        foreach ($map as $column => $claim) {
            $value = data_get($ssoPayload, $claim);

            if ($value !== null) {
                $attributes[$column] = $value;
            }
        }

        if (! isset($attributes[$identifier]) || ! is_scalar($attributes[$identifier]) || $attributes[$identifier] === '') {
            throw new SsoClientException("SSO payload has no value for the \"{$identifier}\" identifier.");
        }

        $user = $this->modelClass()::query()->firstOrNew([$identifier => $attributes[$identifier]]);
        $user->forceFill($attributes);

        if (! $user->exists) {
            // Local password login is never used for SSO users; the column is usually NOT NULL.
            $user->forceFill(['password' => Hash::make(Str::random(64))]);
        }

        $user->save();

        /** @var Model&Authenticatable $user */
        return $user;
    }

    /**
     * @return class-string<Model>
     */
    protected function modelClass(): string
    {
        $class = $this->config->get('sso-client.user.model') ?? $this->config->get('auth.providers.users.model');

        if (! is_string($class) || ! is_subclass_of($class, Model::class) || ! is_subclass_of($class, Authenticatable::class)) {
            throw new SsoClientException('sso-client.user.model must be an Eloquent Authenticatable model.');
        }

        return $class;
    }
}

<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoClient\Contracts\SsoUserSynchronizerContract;
use JeffersonGoncalves\SsoClient\Exceptions\AccountLinkingException;
use JeffersonGoncalves\SsoClient\Exceptions\SsoClientException;

/**
 * Create-or-update the local Eloquent user from the SSO claims, linked by the
 * server's immutable "sub" (sso-client.user.sso_id_column). Emails are never
 * trusted to take over an existing, unlinked account unless explicitly
 * allowed. Bind your own SsoUserSynchronizerContract for in-memory users,
 * role mapping or tables without a "password" column.
 */
class DefaultUserSynchronizer implements SsoUserSynchronizerContract
{
    public function __construct(
        protected ConfigRepository $config,
    ) {}

    public function synchronize(array $ssoPayload): Authenticatable
    {
        $sub = $ssoPayload['sub'] ?? null;

        if (! is_string($sub) || $sub === '') {
            throw new SsoClientException('SSO payload has no "sub".');
        }

        $attributes = $this->mapAttributes($ssoPayload);
        $ssoIdColumn = $this->config->get('sso-client.user.sso_id_column', 'sso_id');

        $user = is_string($ssoIdColumn) && $ssoIdColumn !== ''
            ? $this->resolveLinked($ssoIdColumn, $sub, $attributes)
            : $this->resolveByEmail($attributes);

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
     * @param  array<string, mixed>  $attributes  Mapped columns; receives the sso_id column.
     */
    protected function resolveLinked(string $ssoIdColumn, string $sub, array &$attributes): Model
    {
        $query = $this->modelClass()::query();

        $linked = (clone $query)->where($ssoIdColumn, $sub)->first();

        if ($linked !== null) {
            return $linked;
        }

        $attributes[$ssoIdColumn] = $sub;
        $email = $attributes[$this->emailColumn()] ?? null;
        $existing = $email === null ? null : (clone $query)->where($this->emailColumn(), $email)->first();

        if ($existing === null) {
            return $query->newModelInstance();
        }

        // Linked to another server user: never re-link, whatever the flag says.
        if ($existing->getAttribute($ssoIdColumn) !== null
            || ! $this->config->get('sso-client.user.link_existing_users_by_email', false)) {
            throw new AccountLinkingException('The SSO email belongs to an existing local account that is not linked to this SSO user.');
        }

        return $existing;
    }

    /**
     * Legacy mode (sso_id_column = null): the email is the only identifier.
     *
     * @param  array<string, mixed>  $attributes
     */
    protected function resolveByEmail(array $attributes): Model
    {
        $email = $attributes[$this->emailColumn()] ?? null;

        if (! is_scalar($email) || $email === '') {
            throw new SsoClientException('SSO payload has no email to match the local user.');
        }

        return $this->modelClass()::query()->firstOrNew([$this->emailColumn() => $email]);
    }

    /**
     * @param  array<string, mixed>  $ssoPayload
     * @return array<string, mixed>
     */
    protected function mapAttributes(array $ssoPayload): array
    {
        $attributes = [];

        foreach ((array) $this->config->get('sso-client.user.attributes', []) as $column => $claim) {
            $value = data_get($ssoPayload, (string) $claim);

            if ($value !== null) {
                $attributes[(string) $column] = $value;
            }
        }

        return $attributes;
    }

    protected function emailColumn(): string
    {
        return (string) $this->config->get('sso-client.user.email_column', 'email');
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

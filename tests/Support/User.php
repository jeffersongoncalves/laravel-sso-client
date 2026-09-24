<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SsoClient\Tests\Support;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['password' => 'hashed'];
    }
}

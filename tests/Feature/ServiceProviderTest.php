<?php

declare(strict_types=1);

use Illuminate\Support\ServiceProvider;

it('publishes the config and the sso_id migration under the documented tags', function (string $tag, string $file): void {
    $sources = array_keys(ServiceProvider::pathsToPublish(null, $tag));

    expect($sources)->toHaveCount(1)
        ->and(str_replace('\\', '/', $sources[0]))->toEndWith($file);
})->with([
    ['sso-client-config', 'config/sso-client.php'],
    ['sso-client-migrations', 'database/migrations/add_sso_id_to_users_table.php.stub'],
]);

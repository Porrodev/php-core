<?php

use Porro\Core\LockFile;

it('reads names, versions and whether packages are direct or dev', function () {
    $lock = LockFile::read(__DIR__.'/fixtures/app');

    expect($lock->hash)->toBe(hash('sha256', file_get_contents(__DIR__.'/fixtures/app/composer.lock')))
        ->and($lock->packages)->toBe([
            ['name' => 'laravel/framework', 'version' => 'v12.31.0', 'dev' => false, 'direct' => true],
            ['name' => 'livewire/livewire', 'version' => 'v3.5.6', 'dev' => false, 'direct' => true],
            ['name' => 'symfony/console', 'version' => 'v7.3.1', 'dev' => false, 'direct' => false],
            ['name' => 'pestphp/pest', 'version' => 'v3.8.0', 'dev' => true, 'direct' => true],
        ]);
});

it('returns nothing when there is no lock file', function () {
    expect(LockFile::read(sys_get_temp_dir().'/porro-missing'))->toBeNull();
});

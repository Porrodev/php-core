<?php

use Porro\Core\NpmLockFile;
use Porro\Core\Report;

$fixtures = __DIR__.'/fixtures/npm';

it('reads package-lock.json, keeping nested copies and skipping workspace links', function () use ($fixtures) {
    $lock = NpmLockFile::read("{$fixtures}/npm-v3");

    expect($lock->file)->toBe('package-lock.json')
        ->and($lock->hash)->toBe(hash('sha256', file_get_contents("{$fixtures}/npm-v3/package-lock.json")))
        ->and($lock->packages)->toBe([
            ['name' => 'alpinejs', 'version' => '3.14.1', 'dev' => false, 'direct' => true],
            ['name' => 'axios', 'version' => '1.7.7', 'dev' => false, 'direct' => true],
            ['name' => 'laravel-vite-plugin', 'version' => '1.0.5', 'dev' => true, 'direct' => true],
            ['name' => 'rollup', 'version' => '3.29.5', 'dev' => true, 'direct' => false],
            ['name' => 'rollup', 'version' => '4.24.0', 'dev' => true, 'direct' => false],
            ['name' => 'vite', 'version' => '5.4.8', 'dev' => true, 'direct' => true],
        ]);
});

it('reads pnpm v9 lock files, using package.json for dev', function () use ($fixtures) {
    expect(NpmLockFile::read("{$fixtures}/pnpm")->packages)->toBe([
        ['name' => '@vue/reactivity', 'version' => '3.1.5', 'dev' => false, 'direct' => false],
        ['name' => 'alpinejs', 'version' => '3.14.1', 'dev' => false, 'direct' => true],
        ['name' => 'vite', 'version' => '5.4.8', 'dev' => true, 'direct' => true],
    ]);
});

it('reads pnpm v6 dev markers', function () {
    $packages = NpmLockFile::parsePnpm("lockfileVersion: '6.0'\n\npackages:\n\n  /vite@5.0.0:\n    resolution: {integrity: x}\n    dev: true\n\n  /alpinejs@3.13.0:\n    resolution: {integrity: y}\n    dev: false\n");

    expect($packages)->toBe([
        ['name' => 'vite', 'version' => '5.0.0', 'dev' => true],
        ['name' => 'alpinejs', 'version' => '3.13.0', 'dev' => false],
    ]);
});

it('reads classic and Berry yarn.lock files', function (string $folder) use ($fixtures) {
    expect(NpmLockFile::read("{$fixtures}/{$folder}")->packages)->toBe([
        ['name' => '@vue/reactivity', 'version' => '3.1.5', 'dev' => false, 'direct' => false],
        ['name' => 'alpinejs', 'version' => '3.14.1', 'dev' => false, 'direct' => true],
    ]);
})->with(['yarn', 'yarn-berry']);

it('returns nothing without an npm lock file', function () {
    expect(NpmLockFile::read(__DIR__.'/fixtures/app'))->toBeNull();
});

it('adds the npm lock to the report, with packages only when asked', function () use ($fixtures) {
    $lock = NpmLockFile::read("{$fixtures}/npm-v3");

    $hashOnly = (new Report('porro/laravel-connector', 'laravel'))->npmLock($lock, false);
    $full = (new Report('porro/laravel-connector', 'laravel'))->npmLock($lock, true);
    $none = (new Report('porro/laravel-connector', 'laravel'))->npmLock(null, false);

    expect($hashOnly->toArray()['npm_lock'])->toBe(['hash' => $lock->hash, 'packages' => null])
        ->and($hashOnly->includesNpmPackages())->toBeFalse()
        ->and($full->includesNpmPackages())->toBeTrue()
        ->and($full->npmLockHash())->toBe($lock->hash)
        ->and($none->toArray()['npm_lock'])->toBeNull();
});

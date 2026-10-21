<?php

use Porro\Core\Report;
use Porro\Core\System;

it('reads the OS release, kernel, pending reboot and a fingerprint', function () {
    expect(System::read(__DIR__.'/fixtures/system'))->toBe([
        'fingerprint' => hash_hmac('sha256', '0123456789abcdef0123456789abcdef', 'porro-server-fingerprint'),
        'os' => ['id' => 'ubuntu', 'version_id' => '24.04', 'version_codename' => 'noble', 'pretty_name' => 'Ubuntu 24.04.3 LTS'],
        'kernel' => '6.8.0-45-generic',
        'reboot_required' => true,
    ]);
});

it('never sends the raw machine id', function () {
    expect(json_encode(System::read(__DIR__.'/fixtures/system')))->not->toContain('0123456789abcdef0123456789abcdef');
});

it('leaves out what it can’t read', function () {
    expect(System::read(sys_get_temp_dir().'/porro-no-such-root'))->toBe([
        'fingerprint' => null,
        'os' => null,
        'kernel' => null,
        'reboot_required' => false,
    ]);
});

it('adds the system block to every report', function () {
    $report = (new Report('porro/laravel-connector', 'laravel'))->toArray();

    expect($report)->toHaveKey('system')
        ->and($report['system'])->toHaveKeys(['fingerprint', 'os', 'kernel', 'reboot_required'])
        ->and($report['system']['kernel'])->toBe(php_uname('r'));
});

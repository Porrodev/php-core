<?php

use Porro\Core\Client;
use Porro\Core\Report;
use Porro\Core\SiteKey;
use Porro\Core\System;

/**
 * A throwaway server root with the given files, for one test.
 *
 * @param  array<string, string>  $files
 */
function serverRoot(array $files): string
{
    $root = sys_get_temp_dir().'/porro-system-'.bin2hex(random_bytes(6));

    foreach ($files as $path => $contents) {
        is_dir(dirname("{$root}/{$path}")) || mkdir(dirname("{$root}/{$path}"), recursive: true);
        file_put_contents("{$root}/{$path}", $contents);
    }

    return $root;
}

it('reads the OS release, kernel, pending reboot and a fingerprint', function () {
    expect(System::read(__DIR__.'/fixtures/system'))->toMatchArray([
        'fingerprint' => hash_hmac('sha256', '0123456789abcdef0123456789abcdef', 'porro-server-fingerprint'),
        'os' => ['id' => 'ubuntu', 'version_id' => '24.04', 'version_codename' => 'noble', 'pretty_name' => 'Ubuntu 24.04.3 LTS'],
        'kernel' => '6.8.0-45-generic',
        'reboot_required' => true,
    ]);
});

it('never sends the raw machine id', function () {
    expect(json_encode(System::read(__DIR__.'/fixtures/system')))->not->toContain('0123456789abcdef0123456789abcdef');
});

it('lists installed packages from dpkg’s status file with their source package', function () {
    expect(System::read(__DIR__.'/fixtures/system')['packages'])->toBe([
        ['name' => 'libc6', 'version' => '2.39-0ubuntu8.3', 'source' => 'glibc', 'arch' => 'amd64'],
        ['name' => 'libc6', 'version' => '2.39-0ubuntu8.3', 'source' => 'glibc', 'arch' => 'i386'],
        ['name' => 'libssl3t64', 'version' => '3.0.13-0ubuntu3.4', 'source' => 'openssl', 'arch' => 'amd64'],
        // Held packages are still installed; the source's own version comes along when it differs.
        ['name' => 'libudev1', 'version' => '1:255.4-1ubuntu8.4', 'source' => 'systemd', 'arch' => 'amd64', 'source_version' => '255.4-1ubuntu8.4'],
        // Where it came from, when the package says.
        ['name' => 'nginx', 'version' => '1.27.3-1~noble', 'source' => 'nginx', 'arch' => 'amd64', 'origin' => 'nginx'],
        // No Source field: the source is the package itself.
        ['name' => 'openssl', 'version' => '3.0.13-0ubuntu3.4', 'source' => 'openssl', 'arch' => 'amd64'],
        ['name' => 'php8.5-fpm', 'version' => '8.5.1-1+ubuntu24.04.1+deb.sury.org+1', 'source' => 'php8.5', 'arch' => 'amd64'],
        ['name' => 'unattended-upgrades', 'version' => '2.9.1+nmu4ubuntu1', 'source' => 'unattended-upgrades', 'arch' => 'all'],
    ]);
});

it('leaves out removed and half-configured packages', function () {
    $names = array_column(System::read(__DIR__.'/fixtures/system')['packages'], 'name');

    expect($names)->not->toContain('apache2')
        ->and($names)->not->toContain('tzdata');
});

it('hashes the package list so it only changes when the packages do', function () {
    $system = System::read(__DIR__.'/fixtures/system');

    expect($system['packages_hash'])->toBe(hash('sha256', json_encode($system['packages'], JSON_UNESCAPED_SLASHES)))
        ->and(System::read(__DIR__.'/fixtures/system')['packages_hash'])->toBe($system['packages_hash']);

    $status = file_get_contents(__DIR__.'/fixtures/system/var/lib/dpkg/status');
    $upgraded = serverRoot(['var/lib/dpkg/status' => str_replace('3.0.13-0ubuntu3.4', '3.0.13-0ubuntu3.5', $status)]);
    // The same packages in another order.
    $reordered = serverRoot(['var/lib/dpkg/status' => implode("\n\n", array_reverse(explode("\n\n", trim($status))))."\n"]);

    expect(System::read($upgraded)['packages_hash'])->not->toBe($system['packages_hash'])
        ->and(System::read($reordered)['packages_hash'])->toBe($system['packages_hash']);
});

it('reads whether unattended-upgrades is on and when it last ran, in the server’s timezone', function () {
    expect(System::read(__DIR__.'/fixtures/system')['unattended_upgrades'])->toBe([
        'enabled' => true,
        // Ignores the commented-out "0" in 50unattended-upgrades.
        'last_run_at' => '2026-10-20T06:31:47+01:00',
    ]);
});

it('says unattended-upgrades is off when APT doesn’t run it or it isn’t installed', function () {
    $status = file_get_contents(__DIR__.'/fixtures/system/var/lib/dpkg/status');

    $off = serverRoot([
        'etc/apt/apt.conf.d/20auto-upgrades' => "APT::Periodic::Unattended-Upgrade \"1\";\n",
        'etc/apt/apt.conf.d/99porro-test' => "APT::Periodic::Unattended-Upgrade \"0\";\n",
    ]);
    $unset = serverRoot(['etc/apt/apt.conf.d/70debconf' => "// nothing\n"]);
    $missing = serverRoot([
        'etc/apt/apt.conf.d/20auto-upgrades' => "APT::Periodic::Unattended-Upgrade \"1\";\n",
        'var/lib/dpkg/status' => preg_replace('/\n\nPackage: unattended-upgrades.*?(?=\n\n)/s', '', $status),
    ]);

    expect(System::read($off)['unattended_upgrades']['enabled'])->toBeFalse()
        ->and(System::read($unset)['unattended_upgrades']['enabled'])->toBeFalse()
        ->and(System::read($missing)['unattended_upgrades']['enabled'])->toBeFalse();
});

it('leaves out what it can’t read', function () {
    expect(System::read(sys_get_temp_dir().'/porro-no-such-root'))->toBe([
        'fingerprint' => null,
        'os' => null,
        'kernel' => null,
        'reboot_required' => false,
        'packages' => null,
        'packages_hash' => null,
        'unattended_upgrades' => ['enabled' => null, 'last_run_at' => null],
    ]);
});

it('adds the system block to every report', function () {
    $report = (new Report('porro/laravel-connector', 'laravel'))->toArray();

    expect($report)->toHaveKey('system')
        ->and($report['system'])->toHaveKeys(['fingerprint', 'os', 'kernel', 'reboot_required', 'packages', 'packages_hash', 'unattended_upgrades'])
        ->and($report['system']['kernel'])->toBe(php_uname('r'));
});

it('sends the package hash but holds the list back until asked', function () {
    $report = (new Report('porro/laravel-connector', 'laravel'))->system(System::read(__DIR__.'/fixtures/system'));

    expect($report->toArray()['system']['packages'])->toBeNull()
        ->and($report->systemPackagesHash())->toBe(System::read(__DIR__.'/fixtures/system')['packages_hash'])
        ->and($report->includesSystemPackages())->toBeFalse();

    $report->systemPackages(true);

    expect($report->toArray()['system']['packages'])->toHaveCount(8)
        ->and($report->includesSystemPackages())->toBeTrue();
});

it('sends the package list only when Porro doesn’t have it', function () {
    $calls = [];
    $transport = function (string $url, array $headers, string $body) use (&$calls) {
        $calls[] = json_decode($body, true);

        // Porro wants the list until it has this hash.
        return [202, json_encode(['ok' => true, 'need_system_packages' => ! is_array(end($calls)['system']['packages'])])];
    };
    $client = new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', $transport, retries: 0);
    $report = fn () => (new Report('porro/laravel-connector', 'laravel'))->system(System::read(__DIR__.'/fixtures/system'));

    // A new or changed list: sent once more with the packages.
    expect($client->send($report())->ok)->toBeTrue()
        ->and($calls)->toHaveCount(2)
        ->and($calls[0]['system']['packages'])->toBeNull()
        ->and($calls[1]['system']['packages'])->toHaveCount(8);

    // Porro has it: just the hash.
    $calls = [];
    $transport = function (string $url, array $headers, string $body) use (&$calls) {
        $calls[] = json_decode($body, true);

        return [202, '{"ok":true,"need_system_packages":false}'];
    };
    $client = new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', $transport, retries: 0);

    expect($client->send($report())->ok)->toBeTrue()
        ->and($calls)->toHaveCount(1)
        ->and($calls[0]['system']['packages'])->toBeNull()
        ->and($calls[0]['system']['packages_hash'])->not->toBeNull();
});

it('doesn’t ask twice when the server has no package list', function () {
    $calls = 0;
    $transport = function () use (&$calls) {
        $calls++;

        return [202, '{"ok":true,"need_system_packages":true}'];
    };
    $client = new Client(SiteKey::parse(siteKey()['token']), 'https://porro.test', $transport, retries: 0);

    $client->send((new Report('porro/laravel-connector', 'laravel'))->system(System::read(sys_get_temp_dir().'/porro-no-such-root')));

    expect($calls)->toBe(1);
});

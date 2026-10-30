<?php

use Porro\Core\Cron;
use Porro\Core\CronResult;
use Porro\Core\CrontabIo;

class FakeCrontab extends CrontabIo
{
    public function __construct(public string $contents = '', public bool $works = true) {}

    public function available(): bool
    {
        return $this->works;
    }

    public function read(): string
    {
        return $this->contents;
    }

    public function write(string $contents): bool
    {
        $this->contents = $contents;

        return true;
    }
}

it('builds a line that runs from the project folder with the given PHP', function () {
    expect(Cron::line('*/15 * * * *', '/home/forge/client site', 'craft porro/report', '/usr/bin/php8.3'))
        ->toBe("*/15 * * * * cd '/home/forge/client site' && '/usr/bin/php8.3' craft porro/report > /dev/null 2>&1 # porro");
});

it('adds the line to an existing crontab, keeping what is there', function () {
    $io = new FakeCrontab("MAILTO=ops@example.com\n0 3 * * * /usr/bin/backup\n");
    $line = Cron::line('* * * * *', '/var/www/app', 'artisan schedule:run', 'php');

    expect(Cron::install($line, '/var/www/app', 'artisan schedule:run', $io))->toBe(CronResult::Installed)
        ->and($io->contents)->toBe("MAILTO=ops@example.com\n0 3 * * * /usr/bin/backup\n{$line}\n");
});

it('never adds a second copy, including one the agency added by hand', function (string $existing) {
    $io = new FakeCrontab($existing);
    $line = Cron::line('* * * * *', '/var/www/app', 'artisan schedule:run', 'php');

    expect(Cron::install($line, '/var/www/app', 'artisan schedule:run', $io))->toBe(CronResult::AlreadyInstalled)
        ->and($io->contents)->toBe($existing);
})->with([
    'ours' => "* * * * * cd '/var/www/app' && 'php' artisan schedule:run > /dev/null 2>&1 # porro\n",
    'by hand' => "* * * * * cd /var/www/app && php artisan schedule:run >> /dev/null 2>&1\n",
]);

it('ignores a commented-out entry', function () {
    $io = new FakeCrontab("# * * * * * cd /var/www/app && php artisan schedule:run\n");

    expect(Cron::install('x', '/var/www/app', 'artisan schedule:run', $io))->toBe(CronResult::Installed);
});

it('says when the server does not allow it', function () {
    expect(Cron::install('x', '/var/www/app', 'artisan schedule:run', new FakeCrontab(works: false)))->toBe(CronResult::Unavailable);
});

it('uses plain php by default, so a PHP upgrade on the server never breaks the line', function () {
    expect(Cron::line('* * * * *', '/var/www/app', 'artisan schedule:run'))
        ->toBe("* * * * * cd '/var/www/app' && 'php' artisan schedule:run > /dev/null 2>&1 # porro");
});

it('matches a Forge line that points at the current symlink', function () {
    $root = sys_get_temp_dir().'/porro-site-'.bin2hex(random_bytes(3));
    mkdir("{$root}/releases/42", recursive: true);
    touch("{$root}/releases/42/artisan");
    symlink("{$root}/releases/42", "{$root}/current");

    $forge = "* * * * * php8.3 {$root}/current/artisan schedule:run >> /dev/null 2>&1\n";

    expect(Cron::hasEntry($forge, "{$root}/releases/42", 'artisan schedule:run'))->toBeTrue()
        ->and(Cron::hasEntry($forge, sys_get_temp_dir(), 'artisan schedule:run'))->toBeFalse();
});

it('finds the scheduler in the system cron files too', function () {
    $etc = sys_get_temp_dir().'/porro-etc-'.bin2hex(random_bytes(3));
    mkdir("{$etc}/cron.d", recursive: true);
    file_put_contents("{$etc}/cron.d/site", "* * * * * forge cd /var/www/app && php artisan schedule:run\n");

    expect(Cron::isScheduled('/var/www/app', 'artisan schedule:run', new FakeCrontab(works: false), $etc))->toBeTrue()
        ->and(Cron::isScheduled('/var/www/other', 'artisan schedule:run', new FakeCrontab(works: false), $etc))->toBeFalse()
        ->and(Cron::isScheduled('/var/www/app', 'artisan schedule:run', new FakeCrontab(works: false), $etc.'/missing'))->toBeNull();
});

/**
 * A zero-downtime site: releases/<id> folders and a current symlink to
 * the live one, as Forge, Envoyer and Deployer lay them out.
 */
function zeroDowntimeSite(string ...$releases): string
{
    $root = sys_get_temp_dir().'/porro-site-'.bin2hex(random_bytes(3));

    foreach ($releases as $release) {
        mkdir("{$root}/releases/{$release}", recursive: true);
    }

    symlink("{$root}/releases/".end($releases), "{$root}/current");

    return $root;
}

it('points the line at the current symlink, not the release folder', function () {
    $root = zeroDowntimeSite('41', '42');

    expect(Cron::stableDirectory("{$root}/releases/42"))->toBe("{$root}/current")
        ->and(Cron::line('* * * * *', "{$root}/releases/42", 'artisan schedule:run'))
        ->toBe("* * * * * cd '{$root}/current' && 'php' artisan schedule:run > /dev/null 2>&1 # porro");
});

it('leaves the folder alone when it is not the live release', function () {
    $root = zeroDowntimeSite('41', '42');
    mkdir("{$root}/app");

    expect(Cron::stableDirectory("{$root}/releases/41"))->toBe("{$root}/releases/41")
        ->and(Cron::stableDirectory("{$root}/app"))->toBe("{$root}/app")
        ->and(Cron::stableDirectory('/var/www/missing/releases/1'))->toBe('/var/www/missing/releases/1');
});

it('does not count a line for a pruned or older release of the same site', function () {
    $root = zeroDowntimeSite('41', '43');

    $pruned = "*/15 * * * * cd '{$root}/releases/40' && 'php' craft porro/report --scheduled > /dev/null 2>&1 # porro\n";
    $older = "*/15 * * * * cd '{$root}/releases/41' && 'php' craft porro/report --scheduled > /dev/null 2>&1 # porro\n";
    $current = "*/15 * * * * cd '{$root}/current' && 'php' craft porro/report --scheduled > /dev/null 2>&1 # porro\n";

    expect(Cron::hasEntry($pruned, "{$root}/releases/43", 'craft porro/report'))->toBeFalse()
        ->and(Cron::hasEntry($older, "{$root}/releases/43", 'craft porro/report'))->toBeFalse()
        ->and(Cron::hasEntry($current, "{$root}/releases/43", 'craft porro/report'))->toBeTrue();
});

it('replaces its own stale line for this site instead of adding a second', function () {
    $root = zeroDowntimeSite('41', '43');
    $other = "*/15 * * * * cd '/home/forge/other.com/releases/7' && 'php' craft porro/report --scheduled > /dev/null 2>&1 # porro";
    $io = new FakeCrontab(implode("\n", [
        'MAILTO=ops@example.com',
        "*/15 * * * * cd '{$root}/releases/40' && '/usr/bin/php8.2' craft porro/report --scheduled > /dev/null 2>&1 # porro",
        $other,
        '0 3 * * * /usr/bin/backup',
    ])."\n");

    $line = Cron::line('*/15 * * * *', "{$root}/releases/43", 'craft porro/report --scheduled');

    expect(Cron::install($line, "{$root}/releases/43", 'craft porro/report', $io))->toBe(CronResult::Installed)
        ->and($io->contents)->toBe("MAILTO=ops@example.com\n{$other}\n0 3 * * * /usr/bin/backup\n{$line}\n");

    expect(Cron::install($line, "{$root}/releases/43", 'craft porro/report', $io))->toBe(CronResult::AlreadyInstalled);
});

it('updates its own line for the same folder when the line has changed', function () {
    $io = new FakeCrontab("* * * * * cd '/var/www/app' && '/usr/bin/php8.2' artisan schedule:run > /dev/null 2>&1 # porro\n");
    $line = Cron::line('* * * * *', '/var/www/app', 'artisan schedule:run');

    expect(Cron::install($line, '/var/www/app', 'artisan schedule:run', $io))->toBe(CronResult::Installed)
        ->and($io->contents)->toBe("{$line}\n");
});

it('drops its stale line but adds nothing when the agency already added one by hand', function () {
    $root = zeroDowntimeSite('41', '43');
    $hand = "* * * * * php8.3 {$root}/current/artisan schedule:run >> /dev/null 2>&1";
    $io = new FakeCrontab("* * * * * cd '{$root}/releases/41' && 'php' artisan schedule:run > /dev/null 2>&1 # porro\n{$hand}\n");

    $line = Cron::line('* * * * *', "{$root}/releases/43", 'artisan schedule:run');

    expect(Cron::install($line, "{$root}/releases/43", 'artisan schedule:run', $io))->toBe(CronResult::AlreadyInstalled)
        ->and($io->contents)->toBe("{$hand}\n");
});

it('never touches lines it did not add, even stale ones', function () {
    $root = zeroDowntimeSite('41', '43');
    $hand = "* * * * * cd {$root}/releases/41 && php artisan schedule:run >> /dev/null 2>&1";
    $io = new FakeCrontab("{$hand}\n");

    $line = Cron::line('* * * * *', "{$root}/releases/43", 'artisan schedule:run');

    expect(Cron::install($line, "{$root}/releases/43", 'artisan schedule:run', $io))->toBe(CronResult::Installed)
        ->and($io->contents)->toBe("{$hand}\n{$line}\n");
});

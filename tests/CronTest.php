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

it('builds a line that runs from the project folder with this PHP', function () {
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

it('uses the PHP binary that is running now', function () {
    expect(Cron::phpBinary())->toBe(PHP_BINARY);
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

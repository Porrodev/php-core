<?php

use Porro\Core\Report;
use Porro\Core\ReportThrottle;

function arrayThrottle(array &$store): ReportThrottle
{
    $add = function (string $key, int $value, int $ttl) use (&$store) {
        if (isset($store[$key]) && $store[$key]['expires'] > time()) {
            return false;
        }

        $store[$key] = ['value' => $value, 'expires' => time() + $ttl];

        return true;
    };
    $set = function (string $key, int $value, int $ttl) use (&$store) {
        $store[$key] = ['value' => $value, 'expires' => time() + $ttl];
    };

    return new ReportThrottle($add, $set);
}

it('lets one backup report through per interval', function () {
    $store = [];
    $throttle = arrayThrottle($store);

    expect($throttle->claim())->toBeTrue()
        ->and($throttle->claim())->toBeFalse()
        ->and($store[ReportThrottle::KEY]['expires'] - time())->toBe(ReportThrottle::INTERVAL);

    $store[ReportThrottle::KEY]['expires'] = time() - 1;

    expect($throttle->claim())->toBeTrue();
});

it('holds backup reports while cron, deploys and events send', function (string $trigger, int $ttl) {
    $store = [];
    $throttle = arrayThrottle($store);

    $throttle->sent($trigger);

    expect($throttle->claim())->toBeFalse()
        ->and($store[ReportThrottle::KEY]['expires'] - time())->toBe($ttl);
})->with([
    'cron' => [Report::TRIGGER_SCHEDULE, ReportThrottle::INTERVAL + ReportThrottle::CRON_GRACE],
    'deploy' => [Report::TRIGGER_DEPLOY, ReportThrottle::INTERVAL],
    'event' => [Report::TRIGGER_EVENT, ReportThrottle::INTERVAL],
]);

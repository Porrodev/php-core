<?php

/**
 * Refreshes resources/probes/candidates.json from OWASP CRS, CISA KEV and
 * nuclei templates. Run by .github/workflows/probe-sources.yml weekly.
 *
 *   php tools/probe-sources.php [--summary=path/to/pr-body.md]
 *
 * Leaves the file alone when the candidate paths are the same as before,
 * so a source version bump on its own doesn't open a pull request.
 */

use Porro\Tools\ProbeSources\Changes;
use Porro\Tools\ProbeSources\Generator;
use Porro\Tools\ProbeSources\StreamHttp;

require __DIR__.'/../vendor/autoload.php';

$options = getopt('', ['summary:']);
$target = __DIR__.'/../resources/probes/candidates.json';

$old = is_file($target) ? json_decode((string) file_get_contents($target), true) : null;
$token = getenv('GITHUB_TOKEN') ?: null;

$new = (new Generator(new StreamHttp($token), new DateTimeImmutable('today', new DateTimeZone('UTC'))))->build();
$changes = new Changes(is_array($old) ? $old : null, $new);

if ($old === null || $changes->any()) {
    @mkdir(dirname($target), 0755, true);
    file_put_contents($target, json_encode($new, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n");
}

if (isset($options['summary'])) {
    file_put_contents((string) $options['summary'], $changes->markdown());
}

fwrite(STDOUT, count($changes->added).' new, '.count($changes->removed)." gone\n");

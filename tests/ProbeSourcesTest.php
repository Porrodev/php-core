<?php

use Porro\Core\Activity\Probes;
use Porro\Tools\ProbeSources\Categoriser;
use Porro\Tools\ProbeSources\Changes;
use Porro\Tools\ProbeSources\CrsDataFile;
use Porro\Tools\ProbeSources\Generator;
use Porro\Tools\ProbeSources\Http;
use Porro\Tools\ProbeSources\NucleiTemplate;

/**
 * Answers the generator's requests from tests/fixtures/probe-sources, and
 * 404s anything it doesn't know.
 *
 * @param  array<string, string>  $extra  url => body
 */
function probeSourcesHttp(array $extra = []): Http
{
    $fixtures = __DIR__.'/fixtures/probe-sources/';
    $crs = 'https://raw.githubusercontent.com/coreruleset/coreruleset/v4.30.0/rules/';

    $routes = $extra + [
        'https://api.github.com/repos/coreruleset/coreruleset/releases/latest' => '{"tag_name": "v4.30.0"}',
        'https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest' => '{"tag_name": "v10.5.1"}',
        $crs.'restricted-files.data' => file_get_contents($fixtures.'restricted-files.data'),
        $crs.'lfi-os-files.data' => file_get_contents($fixtures.'lfi-os-files.data'),
        $crs.'scanners-user-agents.data' => file_get_contents($fixtures.'scanners-user-agents.data'),
        Generator::KEV_URL => file_get_contents($fixtures.'kev.json'),
        'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/v10.5.1/http/cves/2026/CVE-2026-0001.yaml' => file_get_contents($fixtures.'CVE-2026-0001.yaml'),
    ];

    return new class($routes) implements Http
    {
        /** @var list<string> */
        public array $requested = [];

        /** @param array<string, string> $routes */
        public function __construct(private readonly array $routes) {}

        public function get(string $url): ?string
        {
            $this->requested[] = $url;

            return $this->routes[$url] ?? null;
        }
    };
}

function probeSourcesGenerator(?Http $http = null): Generator
{
    return new Generator($http ?? probeSourcesHttp(), new DateTimeImmutable('2026-10-28'));
}

describe('probe sources: CRS data files', function () {
    it('reads entries and skips comments, blanks and duplicates', function () {
        $entries = CrsDataFile::parse(file_get_contents(__DIR__.'/fixtures/probe-sources/restricted-files.data'));

        expect($entries)->toBe([
            '.htaccess', '.htpasswd', '.bash_', '.npmrc', '.env', '.travis.yml', '/etc/shadow', 'composer.json', '.ansible/vault',
        ]);
    });

    it('turns an entry into a request path', function () {
        expect(CrsDataFile::toPath('etc/passwd'))->toBe('/etc/passwd')
            ->and(CrsDataFile::toPath('/etc/shadow'))->toBe('/etc/shadow');
    });
});

describe('probe sources: nuclei templates', function () {
    it('reads paths from path lists and raw requests', function () {
        $yaml = file_get_contents(__DIR__.'/fixtures/probe-sources/CVE-2026-0001.yaml');

        expect(NucleiTemplate::paths($yaml))->toBe([
            '/gateway/api/v1/config/export',
            '/remote/logincheck',
            '/gateway/cgi/sessions.cgi',
        ]);
    });

    it('reads the template name', function () {
        $yaml = file_get_contents(__DIR__.'/fixtures/probe-sources/CVE-2026-0001.yaml');

        expect(NucleiTemplate::name($yaml))->toBe('Example Gateway - Unauthenticated Config Read')
            ->and(NucleiTemplate::name("id: x\nhttp: []\n"))->toBeNull();
    });
});

describe('probe sources: generator', function () {
    it('lists CRS paths that Probes does not match yet', function () {
        $crs = probeSourcesGenerator()->crs();

        expect($crs['tag'])->toBe('v4.30.0')
            ->and($crs['license'])->toBe('Apache-2.0')
            ->and(array_column($crs['entries'], 'category', 'path'))->toBe([
                '/.ansible/vault' => Probes::FILES,
                '/.bash_' => Probes::FILES,
                '/.htaccess' => Probes::FILES,
                '/composer.json' => Probes::FILES,
                '/etc/motd' => Probes::TRAVERSAL,
                '/windows/system32/license.rtf' => Probes::TRAVERSAL,
            ])
            ->and($crs['files']['restricted-files.data'])->toBe([
                'source_url' => 'https://github.com/coreruleset/coreruleset/blob/v4.30.0/rules/restricted-files.data',
                'entries' => 9,
                'covered' => 5,
            ])
            ->and($crs['entries'][0]['source_url'])->toBe('https://github.com/coreruleset/coreruleset/blob/v4.30.0/rules/restricted-files.data')
            ->and($crs['user_agents']['entries'])->toBe(['nikto', 'sqlmap']);
    });

    it('takes recent KEV CVEs and their nuclei template paths', function () {
        $http = probeSourcesHttp();
        $kev = probeSourcesGenerator($http)->kev();

        expect($kev['catalog_version'])->toBe('2026.10.27')
            ->and($kev['cves'])->toBe(2)
            ->and($kev['no_template'])->toBe(['CVE-2026-0002'])
            ->and($kev['covered'])->toBe(1)
            ->and($kev['nuclei'])->toMatchArray(['ref' => 'v10.5.1', 'license' => 'MIT'])
            ->and(array_column($kev['entries'], 'category', 'path'))->toBe([
                '/gateway/api/v1/config/export' => Probes::APPLIANCE,
                '/gateway/cgi/sessions.cgi' => Probes::APPLIANCE,
            ])
            ->and($kev['entries'][0])->toMatchArray([
                'cve' => 'CVE-2026-0001',
                'vendor' => 'Example',
                'template' => 'Example Gateway - Unauthenticated Config Read',
                'source_url' => 'https://github.com/projectdiscovery/nuclei-templates/blob/v10.5.1/http/cves/2026/CVE-2026-0001.yaml',
            ])
            // The CVE from 2022 is outside the window and never looked up.
            ->and($http->requested)->not->toContain('https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/v10.5.1/http/cves/2019/CVE-2019-0003.yaml');
    });

    it('only ever suggests a Probes category', function () {
        $doc = probeSourcesGenerator()->build();

        foreach ([...$doc['crs']['entries'], ...$doc['kev']['entries']] as $entry) {
            expect(Categoriser::categories())->toContain($entry['category']);
        }
    });

    it('fails loudly when a source is missing', function () {
        probeSourcesGenerator(probeSourcesHttp([Generator::KEV_URL => '{"nope": true}']))->kev();
    })->throws(RuntimeException::class, 'KEV feed');

    it('fails loudly without a release tag', function () {
        probeSourcesGenerator(probeSourcesHttp([
            'https://api.github.com/repos/coreruleset/coreruleset/releases/latest' => '{"tag_name": "../main"}',
        ]))->crs();
    })->throws(RuntimeException::class, 'release tag');
});

describe('probe sources: categories', function () {
    it('suggests a category from the path shape first', function (string $path, string $category) {
        expect(Categoriser::suggest($path, Probes::APPLIANCE))->toBe($category);
    })->with([
        ['/static/../../etc/hosts', Probes::TRAVERSAL],
        ['/.gitmodules', Probes::VCS],
        ['/wp-json/wp/v2/users', Probes::WORDPRESS],
        ['/tools/phpmyadmin/index.php', Probes::DB_ADMIN],
        ['/uploads/wso2.php', Probes::WEBSHELL],
        ['/cgi-bin/admin.cgi', Probes::EXPLOIT],
        ['/struts/index.action', Probes::JAVA],
        ['/logs/debug.log', Probes::DEBUG],
        ['/config/database.sql.gz', Probes::SECRETS],
        ['/api/2.0/mlflow/webhooks', Probes::INFRASTRUCTURE],
        ['/.yarnrc.yml', Probes::FILES],
        ['/gateway/login', Probes::APPLIANCE],
    ]);

    it('falls back to the KEV vendor, then the default', function () {
        expect(Categoriser::suggest('/rest/api/thing', Probes::APPLIANCE, 'Atlassian'))->toBe(Probes::JAVA)
            ->and(Categoriser::suggest('/rest/api/thing', Probes::APPLIANCE, 'Fortinet'))->toBe(Probes::APPLIANCE);
    });
});

describe('probe sources: pull request body', function () {
    it('lists what is new and what has gone', function () {
        $new = probeSourcesGenerator()->build();
        $old = $new;
        $old['crs']['entries'] = array_values(array_filter($old['crs']['entries'], fn ($e) => $e['path'] !== '/.htaccess'));
        $old['kev']['entries'][] = ['path' => '/old|path', 'category' => Probes::APPLIANCE, 'cve' => 'CVE-2026-9999', 'source_url' => 'x'];

        $changes = new Changes($old, $new);
        $body = $changes->markdown();

        expect($changes->any())->toBeTrue()
            ->and(array_column($changes->added, 'path'))->toBe(['/.htaccess'])
            ->and(array_column($changes->removed, 'path'))->toBe(['/old|path'])
            ->and($body)->toContain('**1 new, 1 gone**')
            ->and($body)->toContain('| CRS | `/.htaccess` | `files` | [restricted-files.data](https://github.com/coreruleset/coreruleset/blob/v4.30.0/rules/restricted-files.data) |')
            ->and($body)->toContain('- KEV `/old\|path`')
            ->and($body)->toContain('`v4.30.0` (Apache-2.0)')
            ->and($body)->toContain('`v10.5.1` (MIT)');
    });

    it('sees no change when the candidates are the same', function () {
        $doc = probeSourcesGenerator()->build();
        $bumped = $doc;
        $bumped['kev']['catalog_version'] = '2026.10.28';

        expect((new Changes($doc, $bumped))->any())->toBeFalse()
            ->and(count((new Changes(null, $doc))->added))->toBe(count($doc['crs']['entries']) + count($doc['kev']['entries']));
    });
});

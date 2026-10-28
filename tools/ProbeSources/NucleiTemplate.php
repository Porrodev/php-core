<?php

namespace Porro\Tools\ProbeSources;

/**
 * The request paths in a ProjectDiscovery nuclei template, read without a
 * YAML parser. Templates give paths two ways: "{{BaseURL}}/x" entries under
 * "path:", and request lines ("GET /x HTTP/1.1") inside "raw:" blocks.
 */
final class NucleiTemplate
{
    /**
     * Unique paths in template order, query strings dropped (Probes ignores
     * them). "/" and paths that are only a template variable are left out:
     * they say nothing about what the scanner wants.
     *
     * @return list<string>
     */
    public static function paths(string $yaml): array
    {
        $found = [];

        foreach (preg_split('/\R/', $yaml) ?: [] as $line) {
            if (preg_match('#^\s*(?:-\s*)?["\']?(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d#', $line, $m)) {
                $found[] = $m[1];
            } elseif (preg_match('#\{\{(?:BaseURL|RootURL)\}\}([^"\'\s]*)#', $line, $m)) {
                $found[] = $m[1];
            }
        }

        $paths = [];

        foreach ($found as $path) {
            $path = substr($path, 0, strcspn($path, '?#'));

            if ($path === '' || $path === '/' || preg_match('#^/?\{\{[^}]+\}\}$#', $path)) {
                continue;
            }

            $paths['/'.ltrim($path, '/')] = true;
        }

        return array_keys($paths);
    }

    /**
     * The template's info.name, for the PR table.
     */
    public static function name(string $yaml): ?string
    {
        return preg_match('#^info:\R(?:[ \t].*\R)*?[ \t]+name:\s*(.+)$#m', $yaml, $m)
            ? trim($m[1], " \t\"'")
            : null;
    }
}

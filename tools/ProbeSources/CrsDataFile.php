<?php

namespace Porro\Tools\ProbeSources;

/**
 * An OWASP CRS .data file: one entry per line, "#" lines are comments.
 * CRS matches these as substrings, so an entry like ".bash_" is a prefix,
 * not a whole file name.
 */
final class CrsDataFile
{
    /**
     * @return list<string>
     */
    public static function parse(string $contents): array
    {
        $entries = [];

        foreach (preg_split('/\R/', $contents) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $entries[$line] = true;
        }

        return array_keys($entries);
    }

    /**
     * An entry as a request path: CRS writes most without the leading slash.
     */
    public static function toPath(string $entry): string
    {
        return '/'.ltrim($entry, '/');
    }
}

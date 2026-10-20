<?php

namespace Porro\Core;

/**
 * Reads and writes the current user's crontab through the `crontab`
 * command. Kept separate so tests can swap it for an in-memory one.
 */
class CrontabIo
{
    public function available(): bool
    {
        if (! function_exists('proc_open') || DIRECTORY_SEPARATOR === '\\') {
            return false;
        }

        [$code] = $this->run('command -v crontab');

        return $code === 0;
    }

    /**
     * The crontab's contents; empty when the user has none yet.
     */
    public function read(): string
    {
        [$code, $output] = $this->run('crontab -l');

        // "no crontab for user" exits non-zero; that just means empty.
        return $code === 0 ? $output : '';
    }

    public function write(string $contents): bool
    {
        [$code] = $this->run('crontab -', $contents);

        return $code === 0;
    }

    /**
     * @return array{0: int, 1: string}
     */
    protected function run(string $command, ?string $input = null): array
    {
        $process = @proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);

        if (! is_resource($process)) {
            return [1, ''];
        }

        if ($input !== null) {
            fwrite($pipes[0], $input);
        }

        fclose($pipes[0]);
        $output = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($process), $output];
    }
}

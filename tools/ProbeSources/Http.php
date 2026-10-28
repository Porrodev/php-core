<?php

namespace Porro\Tools\ProbeSources;

/**
 * The generator's only way out to the network, so tests can hand it
 * fixtures instead.
 */
interface Http
{
    /**
     * The response body, or null when the URL answers 404.
     *
     * @throws \RuntimeException on any other failure
     */
    public function get(string $url): ?string;
}

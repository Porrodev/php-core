<?php

namespace Porro\Core\Activity;

/**
 * Where a connector keeps blocklist or safelist entries: a database
 * table, so every server of a multi-server site sees the same list.
 */
interface EntryStore
{
    /**
     * @return list<Entry>
     */
    public function all(): array;

    /**
     * Adds the entry, or replaces the one with the same cidr.
     */
    public function put(Entry $entry): void;

    public function remove(string $cidr): void;
}

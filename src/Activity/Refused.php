<?php

namespace Porro\Core\Activity;

use RuntimeException;

/**
 * A block or safelist change the safety rules don't allow. The message
 * is written for the person who asked; the reason is for code.
 */
final class Refused extends RuntimeException
{
    public const INVALID = 'invalid';

    public const TOO_WIDE = 'too_wide';

    public const PROTECTED = 'protected';

    public const OWN_IP = 'own_ip';

    public const SAFELISTED = 'safelisted';

    public const FULL = 'full';

    public const NEEDS_CONFIRM = 'needs_confirm';

    public const NO_LABEL = 'no_label';

    public const FROM_CONFIG = 'from_config';

    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}

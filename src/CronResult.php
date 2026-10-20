<?php

namespace Porro\Core;

enum CronResult: string
{
    case Installed = 'installed';
    case AlreadyInstalled = 'already_installed';
    case Unavailable = 'unavailable';
    case Failed = 'failed';
}

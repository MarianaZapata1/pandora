<?php

namespace XF\Authentication;

use function boolval;

abstract class AbstractAuth
{
    protected $data = [];

    public function __construct(array $data = [])
    {
        $this->data = $data;
        $this->setup();
    }

    protected function setup() {}

    abstract public function authenticate($userId, $password);

    abstract public function generate($password);

    abstract public function getAuthenticationName();

    protected function getDefaultOptions()
    {
        return [];
    }

    public function hasPassword()
    {
        return true;
    }

    public function isUpgradable()
    {
        return true;
    }

    protected function isLegacyHash()
    {
        $hash = $this->data['hash'] ?? null;

        if ($hash === null)
        {
            return false;
        }

        return boolval(preg_match('/^(?:\$(P|H)\$|[^\$])/i', $hash));
    }
}

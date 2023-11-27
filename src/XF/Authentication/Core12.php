<?php

namespace XF\Authentication;

use function intval, is_string;

class Core12 extends AbstractAuth
{
    protected const ALGORITHM = PASSWORD_BCRYPT;

    protected function getDefaultOptions()
    {
        $config = \XF::config();

        return [
            'algo' => self::ALGORITHM,
            'options' => isset($config['auth']) ? $config['auth'] : ['cost' => $config['passwordIterations']],
        ];
    }

    protected function getHandler()
    {
        return new PasswordHash(\XF::config('passwordIterations'), false);
    }

    public function generate($password)
    {
        $options = $this->getDefaultOptions();

        $password = $this->truncatePassword($password);

        $hash = password_hash($password, $options['algo'], $options['options']);

        return [
            'hash' => $hash,
        ];
    }

    public function authenticate($userId, $password)
    {
        if (!is_string($password) || $password === '' || empty($this->data))
        {
            return false;
        }

        $password = $this->truncatePassword($password);

        if ($this->isLegacyHash())
        {
            return $this->getHandler()->CheckPassword($password, $this->data['hash']);
        }
        else
        {
            return password_verify($password, $this->data['hash']);
        }
    }

    public function isUpgradable()
    {
        if (!empty($this->data['hash']))
        {
            $hash = $this->data['hash'];
            $options = $this->getDefaultOptions();

            if ($this->isLegacyHash())
            {
                $expectedIterations = min(intval($options['options']['cost']), 30);

                preg_match('/^\$(P|H)\$(.)/i',  $hash, $match);
                $iterations = $this->getHandler()->reverseItoA64($match[2]) - 5; // 5 iterations removed in PHP 5

                return $expectedIterations !== $iterations;
            }
            else
            {
                return password_needs_rehash($hash, $options['algo'], $options['options']);
            }
        }

        return true;
    }

    protected function truncatePassword(string $password): string
    {
        return substr($password, 0, 4096);
    }

    public function getAuthenticationName()
    {
        return 'XF:Core12';
    }
}

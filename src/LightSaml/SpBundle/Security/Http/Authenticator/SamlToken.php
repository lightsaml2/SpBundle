<?php

/*
 * This file is part of the LightSAML SP-Bundle package.
 *
 * (c) Milos Tomic <tmilos@lightsaml.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace LightSaml\SpBundle\Security\Http\Authenticator;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

class SamlToken extends AbstractToken
{
    public function __construct(UserInterface $user, array $roles, array $attributes) {
        parent::__construct($roles);
        $this->setUser($user);
        $this->setAttributes($attributes);
    }

    public function isAuthenticated(): bool {
        return count($this->getRoleNames()) > 0;
    }

    public function getCredentials(): mixed {
        // deprecated
    }
}

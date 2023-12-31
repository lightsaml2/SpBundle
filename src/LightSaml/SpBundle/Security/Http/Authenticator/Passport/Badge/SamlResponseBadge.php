<?php

namespace LightSaml\SpBundle\Security\Http\Authenticator\Passport\Badge;

use LightSaml\Model\Protocol\Response;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

class SamlResponseBadge implements BadgeInterface {

    public function __construct(private readonly Response $response) { }

    public function getResponse(): Response {
        return $this->response;
    }

    public function isResolved(): bool {
        return true;
    }
}
<?php

/*
 * This file is part of the LightSAML SP-Bundle package.
 *
 * (c) Milos Tomic <tmilos@lightsaml.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace LightSaml\SpBundle\Controller;

use LightSaml\Build\Container\BuildContainerInterface;
use LightSaml\Builder\Profile\ProfileBuilderInterface;
use LightSaml\Builder\Profile\WebBrowserSso\Sp\SsoSpSendAuthnRequestProfileBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class DefaultController extends AbstractController
{

    public function __construct(private readonly BuildContainerInterface $buildContainer, private readonly ProfileBuilderInterface $metadataProfileBuilder, private readonly SsoSpSendAuthnRequestProfileBuilderFactory $requestProfileBuilderFactory)
    {
    }

    public function metadataAction(): ?Response {
        $profile = $this->metadataProfileBuilder;
        $context = $profile->buildContext();
        $action = $profile->buildAction();

        $action->execute($context);

        return $context->getHttpResponseContext()->getResponse();
    }

    public function discoveryAction(): RedirectResponse|Response {
        $parties = $this->buildContainer->getPartyContainer()->getIdpEntityDescriptorStore()->all();

        if (1 == count($parties)) {
            return $this->redirect($this->generateUrl('lightsaml_sp.login', ['idp' => $parties[0]->getEntityID()]));
        }

        return $this->render('@LightSamlSp/discovery.html.twig', [
            'parties' => $parties,
        ]);
    }

    public function loginAction(Request $request): RedirectResponse|Response|null {
        $idpEntityId = $request->get('idp');
        if (null === $idpEntityId) {
            return $this->redirect($this->generateUrl($this->getParameter('lightsaml_sp.route.discovery')));
        }

        $profile = $this->requestProfileBuilderFactory->get($idpEntityId);
        $context = $profile->buildContext();
        $action = $profile->buildAction();

        $action->execute($context);

        return $context->getHttpResponseContext()->getResponse();
    }

    public function sessionsAction(): Response {
        $ssoState = $this->buildContainer->getStoreContainer()->getSsoStateStore()->get();

        return $this->render('@LightSamlSp/sessions.html.twig', [
            'sessions' => $ssoState->getSsoSessions(),
        ]);
    }
}

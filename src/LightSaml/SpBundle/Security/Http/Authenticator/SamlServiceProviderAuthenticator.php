<?php

namespace LightSaml\SpBundle\Security\Http\Authenticator;

use Exception;
use LightSaml\Build\Container\BuildContainerInterface;
use LightSaml\Builder\Profile\ProfileBuilderInterface;
use LightSaml\Model\Protocol\Response as SamlResponse;
use LightSaml\SpBundle\Security\Http\Authenticator\Passport\Badge\SamlResponseBadge;
use LightSaml\SpBundle\Security\User\AttributeMapperInterface;
use LightSaml\SpBundle\Security\User\UserCreatorInterface;
use LightSaml\SpBundle\Security\User\UsernameMapperInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

class SamlServiceProviderAuthenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface {

    public function __construct(private readonly string $loginPath, private readonly string $checkPath, private readonly UsernameMapperInterface $usernameMapper, private readonly ProfileBuilderInterface $profileBuilder, private readonly BuildContainerInterface $buildContainer,
                                private readonly UserProviderInterface $userProvider, private readonly AttributeMapperInterface $attributeMapper, private readonly HttpUtils $httpUtils,
                                private readonly AuthenticationSuccessHandlerInterface $successHandler, private readonly AuthenticationFailureHandlerInterface $failureHandler, private readonly ?UserCreatorInterface $userCreator = null) {
    }

    public function supports(Request $request): ?bool {
        return $this->httpUtils->checkRequestPath($request, $this->checkPath);
    }

    public function authenticate(Request $request): Passport {
        // Get SAML response from request
        $samlResponse = $this->getInboundSamlResponse();

        // Resolve username/identifier
        $username = $this->usernameMapper->getUsername($samlResponse);

        return new SelfValidatingPassport(
            new UserBadge(
                $username,
                function (string $identifier) use ($samlResponse) {
                    try {
                        return $this->userProvider->loadUserByIdentifier($identifier);
                    } catch (UserNotFoundException $exception) {
                        if($this->userCreator !== null) {
                            return $this->userCreator->createUser($samlResponse);
                        } else {
                            throw $exception;
                        }
                    }
                }
            ),
            [
                new SamlResponseBadge($samlResponse)
            ]
        );
    }

    /**
     * @throws Exception
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface {
        /** @var SamlResponseBadge $responseBadge */
        $responseBadge = $passport->getBadge(SamlResponseBadge::class);

        if($responseBadge === null) {
            throw new Exception('Badge must be present.');
        }

        return new SamlToken(
            $passport->getUser(),
            $passport->getUser()->getRoles(),
            $this->attributeMapper->getAttributes($responseBadge->getResponse())
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response {
        return $this->successHandler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response {
        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    private function getInboundSamlResponse(): ?SamlResponse {
        $context = $this->profileBuilder->buildContext();
        $action = $this->profileBuilder->buildAction();

        $action->execute($context);

        if($context->getInboundContext()->getMessage() === null || !$context->getInboundMessage() instanceof SamlResponse) {
            return null;
        }

        $message = $context->getInboundMessage();

        if(!$message instanceof SamlResponse) {
            return null;
        }

        return $message;
    }

    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse {
        $uri = $this->httpUtils->generateUri($request, $this->loginPath);

        $parties = $this->buildContainer->getPartyContainer()->getIdpEntityDescriptorStore()->all();
        if(count($parties) === 1) {
            $uri .= '?idp=' . $parties[0]->getEntityID();
        }

        return new RedirectResponse($uri);
    }
}
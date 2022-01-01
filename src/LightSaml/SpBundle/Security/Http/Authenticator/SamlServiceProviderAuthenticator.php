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
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

class SamlServiceProviderAuthenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface {

    private string $loginPath;
    private string $checkPath;

    private UsernameMapperInterface $usernameMapper;
    private ProfileBuilderInterface $profileBuilder;
    private BuildContainerInterface $buildContainer;
    private UserProviderInterface $userProvider;
    private ?UserCreatorInterface $userCreator;
    private AttributeMapperInterface $attributeMapper;
    private HttpUtils $httpUtils;

    private AuthenticationSuccessHandlerInterface $successHandler;
    private AuthenticationFailureHandlerInterface $failureHandler;

    public function __construct(string $loginPath, string $checkPath, UsernameMapperInterface $usernameMapper, ProfileBuilderInterface $profileBuilder, BuildContainerInterface $buildContainer,
                                UserProviderInterface $userProvider,  AttributeMapperInterface $attributeMapper, HttpUtils $httpUtils,
                                AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, ?UserCreatorInterface $userCreator = null) {
        $this->loginPath = $loginPath;
        $this->checkPath = $checkPath;
        $this->usernameMapper = $usernameMapper;
        $this->profileBuilder = $profileBuilder;
        $this->buildContainer = $buildContainer;
        $this->userProvider = $userProvider;
        $this->userCreator = $userCreator;
        $this->attributeMapper = $attributeMapper;
        $this->httpUtils = $httpUtils;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
    }

    public function supports(Request $request): ?bool {
        return $this->httpUtils->checkRequestPath($request, $this->checkPath);
    }

    public function authenticate(Request $request) {
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
     * Only for compatiblity reasons
     *
     * @param Passport $passport
     * @param string $firewallName
     * @return TokenInterface
     */
    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface {
        return $this->createToken($passport, $firewallName);
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

        return $context->getInboundMessage();
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
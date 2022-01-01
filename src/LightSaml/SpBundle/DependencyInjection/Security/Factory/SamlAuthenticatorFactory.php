<?php

/*
 * This file is part of the LightSAML SP-Bundle package.
 *
 * (c) Milos Tomic <tmilos@lightsaml.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace LightSaml\SpBundle\DependencyInjection\Security\Factory;

use LightSaml\SpBundle\Security\Http\Authenticator\SamlServiceProviderAuthenticator;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class SamlAuthenticatorFactory extends AbstractFactory implements AuthenticatorFactoryInterface
{
    public const PRIORITY = -10;

    public function __construct() {
        $this->addOption('username_mapper', 'lightsaml_sp.username_mapper.simple');
        $this->addOption('user_creator', null);
        $this->addOption('attribute_mapper', 'lightsaml_sp.attribute_mapper.simple');
    }

    public function getPosition(): string {
        return 'form';
    }

    public function getPriority(): int {
        return self::PRIORITY;
    }

    public function getKey(): string {
        return 'saml';
    }

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
         return null;
    }

    protected function createEntryPoint($container, $id, $config, $defaultEntryPointId)
    {
        return null;
    }

    protected function getListenerId(): string {
        return 'security.authentication.listener.lightsaml';
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string {
        $authenticatorId = 'security.authenticator.lightsaml.' . $firewallName;
        $authenticator = (new ChildDefinition(SamlServiceProviderAuthenticator::class))
            ->replaceArgument('$loginPath', $config['login_path'])
            ->replaceArgument('$checkPath', $config['check_path'])
            ->replaceArgument('$usernameMapper', new Reference($config['username_mapper']))
            ->replaceArgument('$userProvider', new Reference($userProviderId))
            ->replaceArgument('$attributeMapper', new Reference($config['attribute_mapper']))
            ->replaceArgument('$successHandler', new Reference($this->createAuthenticationSuccessHandler($container, $firewallName, $config)))
            ->replaceArgument('$failureHandler', new Reference($this->createAuthenticationFailureHandler($container, $firewallName, $config)));

        if(isset($config['user_creator']) && !empty($config['user_creator'])) {
            $authenticator->replaceArgument('$userCreator', new Reference($config['user_creator']));
        }

        $container->setDefinition($authenticatorId, $authenticator);

        return $authenticatorId;
    }
}

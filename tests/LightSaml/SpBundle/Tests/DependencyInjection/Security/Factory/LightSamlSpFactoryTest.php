<?php

namespace LightSaml\SpBundle\Tests\DependencyInjection\Security\Factory;

use LightSaml\SpBundle\DependencyInjection\Security\Factory\SamlAuthenticatorFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\BooleanNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ScalarNode;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use Symfony\Component\DependencyInjection\Reference;

class LightSamlSpFactoryTest extends TestCase
{
    public function test_constructs_without_arguments()
    {
        new SamlAuthenticatorFactory();
        $this->assertTrue(true);
    }

    public function test_key()
    {
        $factory = new SamlAuthenticatorFactory();
        $this->assertEquals('saml', $factory->getKey());
    }

    public function test_position()
    {
        $factory = new SamlAuthenticatorFactory();
        $this->assertEquals('form', $factory->getPosition());
    }

    public function configuration_provider()
    {
        return [
            ['username_mapper', ScalarNode::class, 'lightsaml_sp.username_mapper.simple'],
            ['user_creator', ScalarNode::class, null],
            ['attribute_mapper', ScalarNode::class, 'lightsaml_sp.attribute_mapper.simple']
        ];
    }

    /**
     * @dataProvider configuration_provider
     */
    public function test_configuration($configurationName, $type, $defaultValue)
    {
        $factory = new SamlAuthenticatorFactory();
        $treeBuilder = new TreeBuilder('name');
        $factory->addConfiguration($treeBuilder->getRootNode());
        $children = $treeBuilder->buildTree()->getChildren();
        $this->assertArrayHasKey($configurationName, $children);

        $this->assertEquals($defaultValue, $children[$configurationName]->getDefaultValue());
    }

    public function test_creates_authentication_provider_service()
    {
        $containerBuilder = new ContainerBuilder(new ParameterBag());
        $config = $this->getDefaultConfig();
        $factory = new SamlAuthenticatorFactory();
        $providerId = $factory->createAuthenticator($containerBuilder, 'main', $config, 'user.provider.id');
        $this->assertTrue($containerBuilder->hasDefinition($providerId));
    }

    public function test_injects_user_provider_to_auth_provider()
    {
        $containerBuilder = new ContainerBuilder(new ParameterBag());
        $config = $this->getDefaultConfig();
        $factory = new SamlAuthenticatorFactory();
        $providerId = $factory->createAuthenticator($containerBuilder, 'main', $config, $userProvider = 'user.provider.id');
        $definition = $containerBuilder->getDefinition($providerId);
        /** @var Reference $reference */
        $reference = $definition->getArgument('$userProvider');
        $this->assertInstanceOf(Reference::class, $reference);
        $this->assertEquals($userProvider, (string) $reference);
    }

    public function test_injects_username_mapper_to_auth_provider()
    {
        $containerBuilder = new ContainerBuilder(new ParameterBag());
        $config = $this->getDefaultConfig();
        $factory = new SamlAuthenticatorFactory();
        $providerId = $factory->createAuthenticator($containerBuilder, 'main', $config, $userProvider = 'user.provider.id');
        $definition = $containerBuilder->getDefinition($providerId);
        /** @var Reference $reference */
        $reference = $definition->getArgument('$usernameMapper');
        $this->assertInstanceOf(Reference::class, $reference);
        $this->assertEquals($config['username_mapper'], (string) $reference);
    }

    public function test_injects_user_creator_to_auth_provider()
    {
        $containerBuilder = new ContainerBuilder(new ParameterBag());
        $config = $this->getDefaultConfig();
        $factory = new SamlAuthenticatorFactory();
        $providerId = $factory->createAuthenticator($containerBuilder, 'main', $config, $userProvider = 'user.provider.id');
        $definition = $containerBuilder->getDefinition($providerId);
        /** @var Reference $reference */
        $reference = $definition->getArgument('$userCreator');
        $this->assertInstanceOf(Reference::class, $reference);
        $this->assertEquals($config['user_creator'], (string) $reference);
    }

    public function test_injects_attribute_mapper_to_auth_provider()
    {
        $containerBuilder = new ContainerBuilder(new ParameterBag());
        $config = $this->getDefaultConfig();
        $factory = new SamlAuthenticatorFactory();
        $providerId = $factory->createAuthenticator($containerBuilder, 'main', $config, $userProvider = 'user.provider.id');
        $definition = $containerBuilder->getDefinition($providerId);
        /** @var Reference $reference */
        $reference = $definition->getArgument('$attributeMapper');
        $this->assertInstanceOf(Reference::class, $reference);
        $this->assertEquals($config['attribute_mapper'], (string) $reference);
    }

    /**
     * @return array
     */
    private function getDefaultConfig()
    {
        return [
            'username_mapper' => 'lightsaml_sp.username_mapper.simple',
            'user_creator' => 'some.user.creator',
            'attribute_mapper' => 'some.attribute.mapper',
            'remember_me' => true,
            'provider' => 'some.provider',
            'success_handler' => 'success_handler',
            'failure_handler' => 'failure_handler',
            'check_path' => '/login_check',
            'use_forward' => false,
            'require_previous_session' => true,
            'always_use_default_target_path' => false,
            'default_target_path' => '/',
            'login_path' => '/login',
            'target_path_parameter' => '_target_path',
            'use_referer' => false,
            'failure_path' => null,
            'failure_forward' => false,
            'failure_path_parameter' => '_failure_path',
        ];
    }
}

<?php

namespace LightSaml\SpBundle\Tests\DependencyInjection;

use LightSaml\SpBundle\DependencyInjection\LightSamlSpExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;

class LightSamlSpExtensionTest extends TestCase
{
    public function test_loads_with_empty_configuration()
    {
        $configs = array();
        $containerBuilder = new ContainerBuilder(new ParameterBag());
        $extension = new LightSamlSpExtension();
        $extension->load($configs, $containerBuilder);

        $this->assertTrue(true);
    }

    public function loads_service_provider()
    {
        return [
            ['lightsaml_sp.username_mapper.simple'],
            ['lightsaml_sp.attribute_mapper.simple'],
        ];
    }
    /**
     * @dataProvider loads_service_provider
     */
    public function test_loads_service($serviceId)
    {
        $configs = array();
        $containerBuilder = new ContainerBuilder(new ParameterBag());
        $extension = new LightSamlSpExtension();
        $extension->load($configs, $containerBuilder);

        $this->assertTrue($containerBuilder->hasDefinition($serviceId) || $containerBuilder->hasAlias($serviceId));
    }
}

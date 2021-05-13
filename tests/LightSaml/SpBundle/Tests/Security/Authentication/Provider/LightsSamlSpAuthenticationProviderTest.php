<?php

namespace LightSaml\SpBundle\Tests\Security\Authentication\Provider;

use LightSaml\ClaimTypes;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Assertion\Subject;
use LightSaml\Model\Protocol\Response;
use LightSaml\SamlConstants;
use LightSaml\SpBundle\Security\Authentication\Provider\LightsSamlSpAuthenticationProvider;
use LightSaml\SpBundle\Security\Authentication\Token\SamlSpResponseToken;
use LightSaml\SpBundle\Security\Authentication\Token\SamlSpToken;
use LightSaml\SpBundle\Security\Authentication\Token\SamlSpTokenFactoryInterface;
use LightSaml\SpBundle\Security\User\AttributeMapperInterface;
use LightSaml\SpBundle\Security\User\UserCreatorInterface;
use LightSaml\SpBundle\Security\User\UsernameMapperInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

class LightsSamlSpAuthenticationProviderTest extends TestCase
{
    public function test_constructs_with_provider_key()
    {
        new LightsSamlSpAuthenticationProvider('main');
    }

    public function test_constructs_with_all_arguments()
    {
        new LightsSamlSpAuthenticationProvider(
            'main',
            $this->getUserProviderMock(),
            false,
            $this->getUserCheckerMock(),
            $this->getUsernameMapperMock(),
            $this->getUserCreatorMock(),
            $this->getAttributeMapperMock()
        );
    }

    public function test_supports_saml_sp_response_token()
    {
        $provider = new LightsSamlSpAuthenticationProvider($providerKey = 'main');
        $this->assertTrue($provider->supports(new SamlSpResponseToken(new Response(), $providerKey)));
    }

    public function test_supports_saml_sp_token()
    {
        $provider = new LightsSamlSpAuthenticationProvider($providerKey = 'main');
        $this->assertTrue($provider->supports(new SamlSpToken([], $providerKey, [], 'user')));
    }

    public function test_supports_reauthentication()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock()
        );

        $user = 'some.user';
        $roles = ['ROLE_USER'];
        $attributes = ['a' =>1, 'b' => 'bbb'];
        $inToken = new SamlSpToken($roles, $providerKey, $attributes, $user);

        /** @var SamlSpToken $outToken */
        $outToken = $provider->authenticate($inToken);
        $this->assertInstanceOf(SamlSpToken::class, $outToken);
        $this->assertEquals($user, $outToken->getUser());
        $this->assertEquals($roles, $outToken->getRoleNames());
        $this->assertEquals($providerKey, $outToken->getProviderKey());
        $this->assertEquals($attributes, $outToken->getAttributes());
    }

    public function test_creates_authenticated_token_with_user_and_his_roles()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock()
        );

        $user = $this->getUserMock();
        $user->expects($this->any())
            ->method('getRoles')
            ->willReturn($expectedRoles = ['foo', 'bar']);

        $usernameMapperMock->expects($this->once())
            ->method('getUsername')
            ->willReturn($expectedUsername = 'some.username');

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->with($expectedUsername)
            ->willReturn($user);

        $authenticatedToken = $provider->authenticate(new SamlSpResponseToken(new Response(), $providerKey));

        $this->assertInstanceOf(SamlSpToken::class, $authenticatedToken);
        $this->assertTrue($authenticatedToken->isAuthenticated());
        $this->assertEquals($expectedRoles, $authenticatedToken->getRoleNames());
        $this->assertSame($user, $authenticatedToken->getUser());
    }

    public function test_calls_user_creator_if_user_does_not_exist()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            null,
            false,
            null,
            null,
            $userCreatorMock = $this->getUserCreatorMock()
        );

        $user = $this->getUserMock();
        $user->expects($this->any())
            ->method('getRoles')
            ->willReturn($expectedRoles = ['foo', 'bar']);

        $token = new SamlSpResponseToken(new Response(), $providerKey);

        $userCreatorMock->expects($this->once())
            ->method('createUser')
            ->with($token->getResponse())
            ->willReturn($user);

        $authenticatedToken = $provider->authenticate($token);

        $this->assertInstanceOf(SamlSpToken::class, $authenticatedToken);
        $this->assertTrue($authenticatedToken->isAuthenticated());
        $this->assertEquals($expectedRoles, $authenticatedToken->getRoleNames());
        $this->assertSame($user, $authenticatedToken->getUser());
    }

    public function test_throws_authentication_exception_if_user_does_not_exists_and_its_not_created()
    {
        $this->expectExceptionMessage("Unable to resolve user");
        $this->expectException(\Symfony\Component\Security\Core\Exception\AuthenticationException::class);
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock(),
            $userCreatorMock = $this->getUserCreatorMock()
        );

        $user = $this->getUserMock();
        $user->expects($this->any())
            ->method('getRoles')
            ->willReturn($expectedRoles = ['foo', 'bar']);

        $usernameMapperMock->expects($this->once())
            ->method('getUsername')
            ->willReturn($expectedUsername = 'some.username');

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->with($expectedUsername)
            ->willThrowException(new UsernameNotFoundException());

        $token = new SamlSpResponseToken(new Response(), $providerKey);

        $userCreatorMock->expects($this->once())
            ->method('createUser')
            ->with($token->getResponse())
            ->willReturn(null);

        $provider->authenticate($token);
    }

    public function test_creates_authenticated_token_with_default_user_from_name_id_when_force_is_true_and_name_id_format_not_transient()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            true,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock(),
            $userCreatorMock = $this->getUserCreatorMock()
        );

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->willThrowException(new UsernameNotFoundException());

        $token = new SamlSpResponseToken(new Response(), $providerKey);

        $userCreatorMock->expects($this->once())
            ->method('createUser')
            ->with($token->getResponse())
            ->willReturn(null);

        $token->getResponse()->addAssertion(
            (new Assertion())->setSubject(
                (new Subject())->setNameID(
                    new NameID($nameIdValue = 'some.name.id', SamlConstants::NAME_ID_FORMAT_PERSISTENT)
                )
            )
        );

        $usernameMapperMock->expects($this->exactly(2))
            ->method('getUsername')
            ->willReturn($nameIdValue);

        $authenticatedToken = $provider->authenticate($token);

        $this->assertTrue($authenticatedToken->isAuthenticated());
        $this->assertTrue(is_string($authenticatedToken->getUser()));
        $this->assertEquals($nameIdValue, $authenticatedToken->getUser());
    }

    public function test_creates_authenticated_token_with_default_user_from_attribute_email_when_force_is_true_and_no_name_id()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            true,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock(),
            $userCreatorMock = $this->getUserCreatorMock()
        );

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->willThrowException(new UsernameNotFoundException());

        $token = new SamlSpResponseToken(new Response(), $providerKey);

        $userCreatorMock->expects($this->once())
            ->method('createUser')
            ->with($token->getResponse())
            ->willReturn(null);

        $token->getResponse()->addAssertion(
            (new Assertion())->addItem(
                (new AttributeStatement())
                ->addAttribute(new Attribute(ClaimTypes::PPID, 'foo'))
                ->addAttribute(new Attribute(ClaimTypes::EMAIL_ADDRESS, $email = 'email@domain.com'))
            )
        );

        $usernameMapperMock->expects($this->exactly(2))
            ->method('getUsername')
            ->willReturn($email);

        $authenticatedToken = $provider->authenticate($token);

        $this->assertTrue($authenticatedToken->isAuthenticated());
        $this->assertTrue(is_string($authenticatedToken->getUser()));
        $this->assertEquals($email, $authenticatedToken->getUser());
    }

    public function test_creates_authenticated_token_with_attributes_from_attribute_mapper()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock(),
            null,
            $attributeMapperMock = $this->getAttributeMapperMock()
        );

        $user = $this->getUserMock();
        $user->expects($this->any())
            ->method('getRoles')
            ->willReturn(['foo', 'bar']);

        $usernameMapperMock->expects($this->once())
            ->method('getUsername')
            ->willReturn($expectedUsername = 'foo@example.com');

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->willReturn($user);

        $attributeMapperMock->expects($this->once())
            ->method('getAttributes')
            ->with($this->isInstanceOf(SamlSpToken::class))
            ->willReturn($expectedAttributes = ['a', 'b', 'c']);

        $authenticatedToken = $provider->authenticate(new SamlSpResponseToken(new Response(), $providerKey));

        $this->assertInstanceOf(SamlSpToken::class, $authenticatedToken);
        $this->assertEquals($expectedAttributes, $authenticatedToken->getAttributes());
    }

    public function test_calls_user_checker_if_provided()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            $userCheckerMock = $this->getUserCheckerMock(),
            $usernameMapperMock = $this->getUsernameMapperMock()
        );

        $user = $this->getUserMock();
        $user->expects($this->any())
            ->method('getRoles')
            ->willReturn($expectedRoles = ['foo', 'bar']);

        $usernameMapperMock->expects($this->once())
            ->method('getUsername')
            ->willReturn($expectedUsername = 'bla@example.com');

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->willReturn($user);

        $userCheckerMock->expects($this->once())
            ->method('checkPreAuth')
            ->with($user);

        $userCheckerMock->expects($this->once())
            ->method('checkPostAuth')
            ->with($user);

        $provider->authenticate(new SamlSpResponseToken(new Response(), $providerKey));
    }

    public function test_calls_token_factory_if_provided()
    {
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock(),
            null,
            null,
            $tokenFactoryMock = $this->getTokenFactoryMock()
        );

        $responseToken = new SamlSpResponseToken(new Response(), $providerKey);

        $user = $this->getUserMock();
        $user->expects($this->any())
            ->method('getRoles')
            ->willReturn($expectedRoles = ['foo', 'bar']);

        $usernameMapperMock->expects($this->once())
            ->method('getUsername')
            ->willReturn($expectedUsername = 'bla@example.net');

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->willReturn($user);

        $tokenFactoryMock->expects($this->once())
            ->method('create')
            ->with($providerKey, $this->isType('array'), $user, $responseToken);

        $provider->authenticate($responseToken);
    }

    public function test_throws_logic_exception_on_unsupported_token()
    {
        $this->expectExceptionMessage("Unsupported token");
        $this->expectException(\LogicException::class);
        $provider = new LightsSamlSpAuthenticationProvider('main');
        $provider->authenticate($this->getMockBuilder(TokenInterface::class)->getMock());
    }

    public function test_throws_logic_exception_if_user_provider_returns_non_user_interface()
    {
        $this->expectExceptionMessage("User provider must return instance of UserInterface");
        $this->expectException(\LogicException::class);
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock()
        );

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->willReturn(new \stdClass());

        $usernameMapperMock
            ->method('getUsername')
            ->willReturn('foo@bla.org');

        $provider->authenticate(new SamlSpResponseToken(new Response(), $providerKey));
    }

    public function test_throws_logic_exception_if_user_creator_returns_non_null_and_non_user_interface()
    {
        $this->expectExceptionMessage("User creator must return instance of UserInterface or null");
        $this->expectException(\LogicException::class);
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            null,
            false,
            null,
            null,
            $userCreatorMock = $this->getUserCreatorMock()
        );

        $userCreatorMock->expects($this->once())
            ->method('createUser')
            ->willReturn(new \stdClass());

        $token = new SamlSpResponseToken(new Response(), $providerKey);

        $provider->authenticate($token);
    }

    public function test_throws_logic_exception_if_attribute_mapper_does_not_return_array()
    {
        $this->expectExceptionMessage("Attribute mapper must return array");
        $this->expectException(\LogicException::class);
        $provider = new LightsSamlSpAuthenticationProvider(
            $providerKey = 'main',
            $userProviderMock = $this->getUserProviderMock(),
            false,
            null,
            $usernameMapperMock = $this->getUsernameMapperMock(),
            null,
            $attributeMapperMock = $this->getAttributeMapperMock()
        );

        $usernameMapperMock->method('getUsername')
            ->willReturn('foo@bla.org');

        $user = $this->getUserMock();
        $user->expects($this->any())
            ->method('getRoles')
            ->willReturn(['foo', 'bar']);

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->willReturn($user);

        $attributeMapperMock->expects($this->once())
            ->method('getAttributes')
            ->willReturn('foo');

        $provider->authenticate(new SamlSpResponseToken(new Response(), $providerKey));
    }

    public function test_throws_authentication_exception_when_unable_to_resolve_user()
    {
        $this->expectExceptionMessage("Unable to resolve user");
        $this->expectException(\Symfony\Component\Security\Core\Exception\AuthenticationException::class);
        $provider = new LightsSamlSpAuthenticationProvider('main', null, false);
        $provider->authenticate(new SamlSpResponseToken(new Response(), 'main'));
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Symfony\Component\Security\Core\User\UserCheckerInterface
     */
    private function getUserCheckerMock()
    {
        return $this->getMockBuilder(\Symfony\Component\Security\Core\User\UserCheckerInterface::class)->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Symfony\Component\Security\Core\User\UserInterface
     */
    private function getUserMock()
    {
        return $this->getMockBuilder(\Symfony\Component\Security\Core\User\UserInterface::class)->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Symfony\Component\Security\Core\User\UserProviderInterface
     */
    private function getUserProviderMock()
    {
        return $this->getMockBuilder(\Symfony\Component\Security\Core\User\UserProviderInterface::class)->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\LightSaml\SpBundle\Security\User\UsernameMapperInterface
     */
    private function getUsernameMapperMock()
    {
        return $this->getMockBuilder(UsernameMapperInterface::class)->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\LightSaml\SpBundle\Security\User\UserCreatorInterface
     */
    private function getUserCreatorMock()
    {
        return $this->getMockBuilder(UserCreatorInterface::class)->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\LightSaml\SpBundle\Security\User\AttributeMapperInterface
     */
    private function getAttributeMapperMock()
    {
        return $this->getMockBuilder(AttributeMapperInterface::class)->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|SamlSpTokenFactoryInterface
     */
    private function getTokenFactoryMock()
    {
        return $this->getMockBuilder(SamlSpTokenFactoryInterface::class)->getMock();
    }
}

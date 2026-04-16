<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Tests\TestCase;

class ProviderTest extends TestCase
{
    public function testConfigIsLoaded()
    {
        $this->assertNotNull(config('firewall'));
        $this->assertIsArray(config('firewall.middleware'));
    }

    public function testMiddlewareAliasesAreRegistered()
    {
        $router = $this->app->make('router');

        $middlewares = [
            'firewall.agent',
            'firewall.bot',
            'firewall.ip',
            'firewall.geo',
            'firewall.lfi',
            'firewall.php',
            'firewall.referrer',
            'firewall.rfi',
            'firewall.session',
            'firewall.sqli',
            'firewall.swear',
            'firewall.url',
            'firewall.whitelist',
            'firewall.xss',
        ];

        $aliases = $router->getMiddleware();

        foreach ($middlewares as $name) {
            $this->assertArrayHasKey($name, $aliases, "Middleware alias '{$name}' not registered");
        }
    }

    public function testMiddlewareGroupIsRegistered()
    {
        $router = $this->app->make('router');
        $groups = $router->getMiddlewareGroups();

        $this->assertArrayHasKey('firewall.all', $groups);
    }

    public function testTranslationsAreLoaded()
    {
        $this->assertNotEmpty(trans('firewall::responses.block.message'));
    }

    public function testCommandIsRegistered()
    {
        $this->artisan('firewall:unblockip')->assertSuccessful();
    }
}

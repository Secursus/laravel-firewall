<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Xss;
use Secursus\Firewall\Tests\TestCase;

class RouteFilterTest extends TestCase
{
    public function testShouldSkipWhenRouteIsExcepted()
    {
        config(['firewall.middleware.xss.methods' => ['all']]);
        config(['firewall.middleware.xss.routes' => [
            'only' => [],
            'except' => ['*'],
        ]]);

        $this->app->request->query->set('foo', '<script>alert(1)</script>');

        // Should be skipped because route matches except pattern
        $this->assertEquals('next', (new Xss())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldSkipWhenMethodNotInConfig()
    {
        config(['firewall.middleware.xss.methods' => ['post']]);

        $this->app->request->query->set('foo', '<script>alert(1)</script>');

        // GET request, but only POST is configured
        $this->assertEquals('next', (new Xss())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldSkipWhenWhitelisted()
    {
        config(['firewall.middleware.xss.methods' => ['all']]);
        config(['firewall.whitelist' => ['127.0.0.0/24']]);

        $this->app->request->query->set('foo', '<script>alert(1)</script>');

        $this->assertEquals('next', (new Xss())->handle($this->app->request, $this->getNextClosure()));
    }
}

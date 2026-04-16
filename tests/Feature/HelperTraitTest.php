<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Xss;
use Secursus\Firewall\Tests\TestCase;

class HelperTraitTest extends TestCase
{
    public function testIsWhitelistReturnsTrueForWhitelistedIp()
    {
        config(['firewall.whitelist' => ['127.0.0.0/24']]);

        $middleware = new Xss();
        $middleware->request = $this->app->request;
        $middleware->middleware = 'xss';

        $this->assertTrue($middleware->isWhitelist());
    }

    public function testIsWhitelistReturnsFalseForNonWhitelistedIp()
    {
        config(['firewall.whitelist' => ['10.0.0.0/8']]);

        $middleware = new Xss();
        $middleware->request = $this->app->request;
        $middleware->middleware = 'xss';

        $this->assertFalse($middleware->isWhitelist());
    }

    public function testIsMethodReturnsTrueForAll()
    {
        config(['firewall.middleware.xss.methods' => ['all']]);

        $middleware = new Xss();
        $middleware->request = $this->app->request;
        $middleware->middleware = 'xss';

        $this->assertTrue($middleware->isMethod());
    }

    public function testIsMethodReturnsTrueForMatchingMethod()
    {
        config(['firewall.middleware.xss.methods' => ['get']]);

        $middleware = new Xss();
        $middleware->request = $this->app->request;
        $middleware->middleware = 'xss';

        $this->assertTrue($middleware->isMethod());
    }

    public function testIsMethodReturnsFalseForNonMatchingMethod()
    {
        config(['firewall.middleware.xss.methods' => ['post']]);

        $middleware = new Xss();
        $middleware->request = $this->app->request;
        $middleware->middleware = 'xss';

        $this->assertFalse($middleware->isMethod());
    }

    public function testIsDisabledReturnsTrueWhenDisabled()
    {
        config(['firewall.middleware.xss.enabled' => false]);

        $middleware = new Xss();
        $middleware->middleware = 'xss';

        $this->assertTrue($middleware->isDisabled());
    }

    public function testIsEnabledReturnsTrueWhenEnabled()
    {
        config(['firewall.middleware.xss.enabled' => true]);

        $middleware = new Xss();
        $middleware->middleware = 'xss';

        $this->assertTrue($middleware->isEnabled());
    }

    public function testIpReturnsCfConnectingIpWhenPresent()
    {
        $this->app->request->headers->set('CF_CONNECTING_IP', '203.0.113.50');

        $middleware = new Xss();
        $middleware->request = $this->app->request;

        $this->assertSame('203.0.113.50', $middleware->ip());
    }

    public function testIpReturnsRequestIpWhenNoCf()
    {
        $middleware = new Xss();
        $middleware->request = $this->app->request;

        $this->assertSame('127.0.0.1', $middleware->ip());
    }

    public function testLogCreatesRecord()
    {
        $middleware = new Xss();
        $middleware->request = $this->app->request;
        $middleware->middleware = 'xss';
        $middleware->user_id = 0;

        $log = $middleware->log();

        $this->assertNotNull($log);
        $this->assertSame('127.0.0.1', $log->ip);
        $this->assertSame('xss', $log->middleware);
    }

    public function testIsInputReturnsTrue()
    {
        $middleware = new Xss();
        $middleware->middleware = 'xss';

        // By default, no input filtering is configured
        $this->assertTrue($middleware->isInput('foo'));
    }

    public function testIsInputExcept()
    {
        config(['firewall.middleware.xss.inputs' => [
            'only' => [],
            'except' => ['password'],
        ]]);

        $middleware = new Xss();
        $middleware->middleware = 'xss';

        $this->assertTrue($middleware->isInput('username'));
        $this->assertFalse($middleware->isInput('password'));
    }

    public function testIsInputOnly()
    {
        config(['firewall.middleware.xss.inputs' => [
            'only' => ['search'],
            'except' => [],
        ]]);

        $middleware = new Xss();
        $middleware->middleware = 'xss';

        $this->assertTrue($middleware->isInput('search'));
        $this->assertFalse($middleware->isInput('other'));
    }
}

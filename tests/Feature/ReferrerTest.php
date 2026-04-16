<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Referrer;
use Secursus\Firewall\Tests\TestCase;

class ReferrerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.referrer.methods' => ['all']]);
    }

    public function testShouldAllowWhenNoBlockedReferrers()
    {
        $this->assertEquals('next', (new Referrer())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldAllowWhenReferrerNotBlocked()
    {
        config(['firewall.middleware.referrer.blocked' => ['http://evil.com']]);

        $this->app->request->server->set('HTTP_REFERER', 'http://google.com');

        $this->assertEquals('next', (new Referrer())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockWhenReferrerBlocked()
    {
        config(['firewall.middleware.referrer.blocked' => ['http://evil.com']]);

        $this->app->request->server->set('HTTP_REFERER', 'http://evil.com');

        $this->assertEquals('403', (new Referrer())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }
}

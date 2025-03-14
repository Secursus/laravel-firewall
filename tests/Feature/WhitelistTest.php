<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Whitelist;
use Secursus\Firewall\Tests\TestCase;

class WhitelistTest extends TestCase
{
    public function testShouldAllow()
    {
        config(['firewall.whitelist' => ['127.0.0.0/24']]);

        $this->assertEquals('next', (new Whitelist())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldAllowMultiple()
    {
        config(['firewall.whitelist' => ['127.0.0.0/24', '127.0.0.1']]);

        $this->assertEquals('next', (new Whitelist())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlock()
    {
        $this->assertEquals('403', (new Whitelist())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }
}

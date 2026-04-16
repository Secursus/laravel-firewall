<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Session;
use Secursus\Firewall\Tests\TestCase;

class SessionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.session.methods' => ['all']]);
    }

    public function testShouldAllow()
    {
        $this->assertEquals('next', (new Session())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockSerializationAttack()
    {
        $this->app->request->query->set('foo', '|O:8:"stdClass":1:{s:4:"test";s:4:"test";}');

        $this->assertEquals('403', (new Session())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockArraySerialization()
    {
        $this->app->request->query->set('foo', '|a:2:{i:0;s:4:"test";i:1;s:5:"hello";}');

        $this->assertEquals('403', (new Session())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }
}

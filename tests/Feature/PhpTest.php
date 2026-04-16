<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Php;
use Secursus\Firewall\Tests\TestCase;

class PhpTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.php.methods' => ['all']]);
    }

    public function testShouldAllow()
    {
        $this->assertEquals('next', (new Php())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockPhpProtocol()
    {
        $this->app->request->query->set('foo', 'php://input');

        $this->assertEquals('403', (new Php())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockPharProtocol()
    {
        $this->app->request->query->set('foo', 'phar://malicious.phar');

        $this->assertEquals('403', (new Php())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockZlibProtocol()
    {
        $this->app->request->query->set('foo', 'zlib://payload');

        $this->assertEquals('403', (new Php())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldAllowNormalInput()
    {
        $this->app->request->query->set('foo', 'this is a normal php discussion');

        $this->assertEquals('next', (new Php())->handle($this->app->request, $this->getNextClosure()));
    }
}

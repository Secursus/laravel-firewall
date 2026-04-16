<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Url;
use Secursus\Firewall\Tests\TestCase;

class UrlTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.url.methods' => ['all']]);
    }

    public function testShouldAllowWhenNoInspections()
    {
        $this->assertEquals('next', (new Url())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldAllowWhenUrlNotInInspections()
    {
        config(['firewall.middleware.url.inspections' => ['admin/*']]);

        $this->assertEquals('next', (new Url())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockWhenUrlMatchesInspection()
    {
        config(['firewall.middleware.url.inspections' => ['*']]);

        $this->assertEquals('403', (new Url())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }
}

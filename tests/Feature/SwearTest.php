<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Swear;
use Secursus\Firewall\Tests\TestCase;

class SwearTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.swear.methods' => ['all']]);
    }

    public function testShouldAllowWhenNoSwearWords()
    {
        $this->assertEquals('next', (new Swear())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldAllowCleanInput()
    {
        config(['firewall.middleware.swear.words' => ['badword']]);

        $this->app->request->query->set('comment', 'this is a clean message');

        $this->assertEquals('next', (new Swear())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockSwearWord()
    {
        config(['firewall.middleware.swear.words' => ['badword']]);

        $this->app->request->query->set('comment', 'this is a badword in text');

        $this->assertEquals('403', (new Swear())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldNotMatchPartialWord()
    {
        config(['firewall.middleware.swear.words' => ['bad']]);

        $this->app->request->query->set('comment', 'badminton is a sport');

        $this->assertEquals('next', (new Swear())->handle($this->app->request, $this->getNextClosure()));
    }
}

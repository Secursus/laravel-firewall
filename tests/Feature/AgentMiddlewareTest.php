<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Agent;
use Secursus\Firewall\Tests\TestCase;

class AgentMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.agent.enabled' => true]);
        config(['firewall.middleware.agent.methods' => ['all']]);
    }

    protected function setUserAgent(string $ua): void
    {
        $this->app->request->headers->set('User-Agent', $ua);
    }

    public function testShouldAllowNormalBrowser()
    {
        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('next', (new Agent())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockEmptyUserAgent()
    {
        $this->setUserAgent('');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockMaliciousPhpInject()
    {
        $this->setUserAgent('Mozilla/5.0 <?php echo "hacked"; ?>');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockDashUserAgent()
    {
        $this->setUserAgent('-');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockSerializationAttempt()
    {
        $this->setUserAgent('}__test|O:8:"stdClass":0:{}');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockBrowserWhenConfigured()
    {
        config(['firewall.middleware.agent.browsers' => [
            'allow' => [],
            'block' => ['Chrome'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldAllowBrowserWhenOnlyAllowList()
    {
        config(['firewall.middleware.agent.browsers' => [
            'allow' => ['Chrome'],
            'block' => [],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('next', (new Agent())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockBrowserNotInAllowList()
    {
        config(['firewall.middleware.agent.browsers' => [
            'allow' => ['Firefox'],
            'block' => [],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockPlatformWhenConfigured()
    {
        config(['firewall.middleware.agent.platforms' => [
            'allow' => [],
            'block' => ['Windows'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockDeviceWhenConfigured()
    {
        config(['firewall.middleware.agent.devices' => [
            'allow' => [],
            'block' => ['Mobile'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldAllowDesktopWhenMobileBlocked()
    {
        config(['firewall.middleware.agent.devices' => [
            'allow' => [],
            'block' => ['Mobile'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('next', (new Agent())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockPropertyWhenConfigured()
    {
        config(['firewall.middleware.agent.properties' => [
            'allow' => [],
            'block' => ['Chrome'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('403', (new Agent())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldSkipWhenDisabled()
    {
        config(['firewall.middleware.agent.enabled' => false]);

        $this->setUserAgent('');

        $this->assertEquals('next', (new Agent())->handle($this->app->request, $this->getNextClosure()));
    }
}

<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Bot;
use Secursus\Firewall\Tests\TestCase;

class BotMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.bot.enabled' => true]);
        config(['firewall.middleware.bot.methods' => ['all']]);
    }

    protected function setUserAgent(string $ua): void
    {
        $this->app->request->headers->set('User-Agent', $ua);
    }

    public function testShouldAllowNormalBrowser()
    {
        $this->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        $this->assertEquals('next', (new Bot())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldAllowRobotWhenNoCrawlerConfig()
    {
        config(['firewall.middleware.bot.crawlers' => null]);

        $this->setUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

        $this->assertEquals('next', (new Bot())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockRobotInBlockList()
    {
        // CrawlerDetect returns "Googlebot" for this UA
        config(['firewall.middleware.bot.crawlers' => [
            'allow' => [],
            'block' => ['Googlebot'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

        $this->assertEquals('403', (new Bot())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockRobotNotInAllowList()
    {
        // CrawlerDetect returns "Googlebot", allow list only has "Bingbot"
        config(['firewall.middleware.bot.crawlers' => [
            'allow' => ['Bingbot'],
            'block' => [],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

        $this->assertEquals('403', (new Bot())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldAllowRobotInAllowList()
    {
        // CrawlerDetect returns "Googlebot"
        config(['firewall.middleware.bot.crawlers' => [
            'allow' => ['Googlebot'],
            'block' => [],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

        $this->assertEquals('next', (new Bot())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldSkipWhenDisabled()
    {
        config(['firewall.middleware.bot.enabled' => false]);

        config(['firewall.middleware.bot.crawlers' => [
            'allow' => [],
            'block' => ['Googlebot'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

        $this->assertEquals('next', (new Bot())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldDetectSemrushBot()
    {
        // CrawlerDetect returns "Semrush" for SemrushBot
        config(['firewall.middleware.bot.crawlers' => [
            'allow' => [],
            'block' => ['Semrush'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)');

        $this->assertEquals('403', (new Bot())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldDetectAhrefsBot()
    {
        // CrawlerDetect returns "Ahrefs" for AhrefsBot
        config(['firewall.middleware.bot.crawlers' => [
            'allow' => [],
            'block' => ['Ahrefs'],
        ]]);

        $this->setUserAgent('Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)');

        $this->assertEquals('403', (new Bot())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }
}

<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Notifications\AttackDetected;
use Secursus\Firewall\Notifications\Notifiable;
use Secursus\Firewall\Models\Ip;
use Secursus\Firewall\Models\Log;
use Secursus\Firewall\Tests\TestCase;

class SlackNotificationTest extends TestCase
{
    protected $log;
    protected bool $hasBlockKit;

    protected function setUp(): void
    {
        parent::setUp();

        $this->hasBlockKit = class_exists(\Illuminate\Notifications\Slack\SlackMessage::class);

        $this->log = Log::create([
            'ip' => '192.168.1.100',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 42,
            'url' => 'http://example.com/vulnerable?foo=bar',
            'referrer' => 'http://example.com',
            'request' => 'foo=<script>alert(1)</script>',
        ]);

        Ip::create([
            'ip' => '192.168.1.100',
            'log_id' => $this->log->id,
        ]);

        config(['firewall.notifications' => [
            'mail' => ['enabled' => false, 'queue' => 'default'],
            'slack' => [
                'enabled' => true,
                'from' => 'Firewall',
                'emoji' => ':fire:',
                'channel' => '#security',
                'to' => 'https://hooks.slack.com/test',
                'queue' => 'default',
            ],
        ]]);
    }

    public function testToSlackReturnsCorrectInstance()
    {
        $notification = new AttackDetected($this->log);
        $slack = $notification->toSlack(new Notifiable());

        if ($this->hasBlockKit) {
            $this->assertInstanceOf(\Illuminate\Notifications\Slack\SlackMessage::class, $slack);
        } else {
            $this->assertInstanceOf(\Illuminate\Notifications\Messages\SlackMessage::class, $slack);
        }
    }

    public function testToSlackBlockKitContainsCorrectData()
    {
        if (! $this->hasBlockKit) {
            $this->markTestSkipped('Block Kit (slack-notification-channel v3) not installed');
        }

        $notification = new AttackDetected($this->log);
        $slack = $notification->toSlack(new Notifiable());

        $payload = $slack->toArray();

        $this->assertNotEmpty($payload['text'] ?? '');
        $this->assertNotEmpty($payload['blocks'] ?? []);
        $this->assertSame('header', $payload['blocks'][0]['type']);

        $blocksJson = json_encode($payload['blocks']);
        $this->assertStringContainsString('192.168.1.100', $blocksJson);
        $this->assertStringContainsString('Xss', $blocksJson);
        $this->assertStringContainsString('42', $blocksJson);
        $this->assertStringContainsString('example.com', $blocksJson);
    }

    public function testToSlackBlockKitWithBlockedIp()
    {
        if (! $this->hasBlockKit) {
            $this->markTestSkipped('Block Kit (slack-notification-channel v3) not installed');
        }

        $notification = new AttackDetected($this->log);
        $slack = $notification->toSlack(new Notifiable());

        $blocksJson = json_encode($slack->toArray()['blocks']);
        $this->assertStringContainsString('Yes', $blocksJson);
    }

    public function testToSlackBlockKitWithoutBlockedIp()
    {
        if (! $this->hasBlockKit) {
            $this->markTestSkipped('Block Kit (slack-notification-channel v3) not installed');
        }

        $log = Log::create([
            'ip' => '10.0.0.99',
            'level' => 'low',
            'middleware' => 'sqli',
            'user_id' => 0,
            'url' => 'http://example.com/test',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        $notification = new AttackDetected($log);
        $this->assertNull($notification->ip);

        $slack = $notification->toSlack(new Notifiable());
        $blocksJson = json_encode($slack->toArray()['blocks']);
        $this->assertStringContainsString('No', $blocksJson);
    }

    public function testToSlackLegacyMessage()
    {
        if ($this->hasBlockKit) {
            $this->markTestSkipped('Legacy Slack (v2) not installed — v3 Block Kit is active');
        }

        $notification = new AttackDetected($this->log);
        $slack = $notification->toSlack(new Notifiable());

        $this->assertInstanceOf(\Illuminate\Notifications\Messages\SlackMessage::class, $slack);
    }

    public function testToSlackViaChannelsIncludesSlack()
    {
        $notification = new AttackDetected($this->log);
        $channels = $notification->via(new Notifiable());

        $this->assertContains('slack', $channels);
    }

    public function testToElasticNotification()
    {
        config(['firewall.notifications.elastic' => [
            'enabled' => true,
            'host' => 'localhost',
            'port' => 9200,
            'scheme' => 'https',
            'user' => 'elastic',
            'pass' => 'secret',
            'index' => 'firewall',
            'queue' => 'default',
        ]]);

        $notification = new AttackDetected($this->log);
        $elastic = $notification->toElastic(new Notifiable());

        $this->assertSame('localhost', $elastic->host);
        $this->assertSame(9200, $elastic->port);
        $this->assertSame('https', $elastic->scheme);
        $this->assertSame('elastic', $elastic->user);
        $this->assertSame('secret', $elastic->pass);
        $this->assertSame('firewall', $elastic->index);
        $this->assertSame('192.168.1.100', $elastic->fields['ip']);
        $this->assertSame('xss', $elastic->fields['middleware']);
        $this->assertSame(42, $elastic->fields['user_id']);
    }

    public function testViaElasticChannel()
    {
        config(['firewall.notifications.elastic' => [
            'enabled' => true,
            'host' => 'localhost',
            'port' => 9200,
            'scheme' => 'https',
            'user' => 'elastic',
            'pass' => 'secret',
            'index' => 'firewall',
            'queue' => 'default',
        ]]);

        $notification = new AttackDetected($this->log);
        $channels = $notification->via(new Notifiable());

        $this->assertContains(
            \Secursus\Firewall\Notifications\Channel\ElasticChannel::class,
            $channels
        );
    }
}

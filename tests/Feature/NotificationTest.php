<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Notifications\AttackDetected;
use Secursus\Firewall\Notifications\Notifiable;
use Secursus\Firewall\Models\Ip;
use Secursus\Firewall\Models\Log;
use Secursus\Firewall\Tests\TestCase;
use Illuminate\Notifications\Messages\MailMessage;

class NotificationTest extends TestCase
{
    protected $log;

    protected function setUp(): void
    {
        parent::setUp();

        $this->log = Log::create([
            'ip' => '192.168.1.100',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com/test?foo=bar',
            'referrer' => 'http://example.com',
            'request' => 'foo=<script>alert(1)</script>',
        ]);

        Ip::create([
            'ip' => '192.168.1.100',
            'log_id' => $this->log->id,
        ]);

        config(['firewall.notifications' => [
            'mail' => [
                'enabled' => true,
                'from' => 'firewall@example.com',
                'name' => 'Firewall',
                'to' => 'admin@example.com',
                'queue' => 'default',
            ],
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

    public function testNotificationCanBeCreated()
    {
        $notification = new AttackDetected($this->log);

        $this->assertSame($this->log->id, $notification->log->id);
        $this->assertNotNull($notification->ip);
        $this->assertSame('192.168.1.100', $notification->ip->ip);
    }

    public function testNotificationViaChannels()
    {
        $notification = new AttackDetected($this->log);
        $channels = $notification->via(new Notifiable());

        $this->assertContains('mail', $channels);
        $this->assertContains('slack', $channels);
    }

    public function testNotificationViaExcludesDisabled()
    {
        config(['firewall.notifications.slack.enabled' => false]);

        $notification = new AttackDetected($this->log);
        $channels = $notification->via(new Notifiable());

        $this->assertContains('mail', $channels);
        $this->assertNotContains('slack', $channels);
    }

    public function testNotificationToMail()
    {
        $notification = new AttackDetected($this->log);
        $mail = $notification->toMail(new Notifiable());

        $this->assertInstanceOf(MailMessage::class, $mail);
    }

    public function testNotificationToSlack()
    {
        $notification = new AttackDetected($this->log);
        $slack = $notification->toSlack(new Notifiable());

        // Should return either the Block Kit SlackMessage or the legacy one
        $this->assertNotNull($slack);

        $validClasses = [
            \Illuminate\Notifications\Slack\SlackMessage::class,
            \Illuminate\Notifications\Messages\SlackMessage::class,
        ];

        $isValidClass = false;
        foreach ($validClasses as $class) {
            if ($slack instanceof $class) {
                $isValidClass = true;
                break;
            }
        }

        $this->assertTrue($isValidClass, 'toSlack() did not return a valid SlackMessage instance');
    }

    public function testNotificationViaQueues()
    {
        $notification = new AttackDetected($this->log);
        $queues = $notification->viaQueues();

        $this->assertIsArray($queues);
        $this->assertArrayHasKey('mail', $queues);
        $this->assertArrayHasKey('slack', $queues);
    }

    public function testNotificationWithMiddlewareOverride()
    {
        config(['firewall.middleware.xss.notifications' => [
            'mail' => [
                'enabled' => false,
            ],
        ]]);

        $notification = new AttackDetected($this->log);
        $channels = $notification->via(new Notifiable());

        $this->assertNotContains('mail', $channels);
        $this->assertContains('slack', $channels);
    }

    public function testNotificationWithoutBlockedIp()
    {
        // Create a log without a matching IP
        $log = Log::create([
            'ip' => '10.0.0.1',
            'level' => 'medium',
            'middleware' => 'sqli',
            'user_id' => 0,
            'url' => 'http://example.com/test',
            'referrer' => 'NULL',
            'request' => 'foo=1 UNION SELECT',
        ]);

        $notification = new AttackDetected($log);
        $this->assertNull($notification->ip);

        // toSlack should still work without an IP
        $slack = $notification->toSlack(new Notifiable());
        $this->assertNotNull($slack);
    }
}

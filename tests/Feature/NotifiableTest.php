<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Notifications\Notifiable;
use Secursus\Firewall\Tests\TestCase;

class NotifiableTest extends TestCase
{
    public function testRouteNotificationForMail()
    {
        config(['firewall.notifications.mail.to' => 'test@example.com']);

        $notifiable = new Notifiable();

        $this->assertSame('test@example.com', $notifiable->routeNotificationForMail());
    }

    public function testRouteNotificationForSlack()
    {
        config(['firewall.notifications.slack.to' => 'https://hooks.slack.com/xxx']);

        $notifiable = new Notifiable();

        $this->assertSame('https://hooks.slack.com/xxx', $notifiable->routeNotificationForSlack());
    }

    public function testGetKey()
    {
        $notifiable = new Notifiable();

        $this->assertSame(1, $notifiable->getKey());
    }
}

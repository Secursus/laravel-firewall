<?php

namespace Secursus\Firewall\Listeners;

use Secursus\Firewall\Events\AttackDetected as Event;
use Secursus\Firewall\Notifications\AttackDetected;
use Secursus\Firewall\Notifications\Notifiable;
use Throwable;

class NotifyUsers
{
    /**
     * Handle the event.
     *
     * @param Event $event
     *
     * @return void
     */
    public function handle(Event $event)
    {
        try {
            (new Notifiable)->notify(new AttackDetected($event->log));
        } catch (Throwable $e) {
            report($e);
        }
    }
}

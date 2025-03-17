<?php

namespace Secursus\Firewall\Notifications\Channel;

use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class ElasticChannel
{
    /**
     * Send the given notification.
     *
     * @param  mixed  $notifiable
     * @param  \Illuminate\Notifications\Notification  $notification
     * @return void
     */
    public function send($notifiable, Notification $notification)
    {
        $message = $notification->toElastic($notifiable);

        $base_url = $message->scheme . '://' . $message->host . ':' . $message->port;
        $client = Http::withHeaders(['Content-Type' => 'application/json',])
            ->withBasicAuth($message->user, $message->pass)
            ->baseUrl($base_url)
        ;

        $client->post(
            '/' . $message->index . '/_doc/',
            $message->fields
        );
    }
}

<?php

namespace Secursus\Firewall\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Messages\SlackMessage;
use Illuminate\Notifications\Notification;
use Secursus\Firewall\Models\Ip;
use Secursus\Firewall\Notifications\Channel\ElasticChannel;
use Secursus\Firewall\Notifications\Message\ElasticMessage;

class AttackDetected extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * The log model.
     *
     * @var object
     */
    public $log;

    /**
     * The Ip model.
     *
     * @var null|object
     */
    public $ip;

    /**
     * The notification config.
     */
    public array $notifications;

    /**
     * Create a notification instance.
     *
     * @param  object  $log
     */
    public function __construct($log)
    {
        $ip = config('firewall.models.ip', Ip::class);
        $this->log = $log;
        $this->ip = $ip::firstWhere('log_id', $log->id);

        $notifications = config('firewall.notifications');
        $notifications_middleware = config('firewall.middleware.' . $log->middleware . '.notifications');

        if ($notifications_middleware) {
            $this->notifications = array_replace_recursive($notifications, $notifications_middleware);
        } else {
            $this->notifications = $notifications;
        }
    }

    /**
     * Get the notification's channels.
     *
     * @param  mixed  $notifiable
     * @return array|string
     */
    public function via($notifiable)
    {
        $channels = [];

        foreach ($this->notifications as $channel => $settings) {
            if (empty($settings['enabled'])) {
                continue;
            }

            if ($channel === 'elastic') {
                $channel = ElasticChannel::class;
            }

            $channels[] = $channel;
        }

        return $channels;
    }

    /**
     * Get the notification's queues.
     * @return array|string
     */

    public function viaQueues(): array
    {
        return array_map(fn ($channel) => $channel['queue'] ?? 'default', $this->notifications);
    }

    /**
     * Build the mail representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return \Illuminate\Notifications\Messages\MailMessage
     */
    public function toMail($notifiable)
    {
        $domain = request()->getHttpHost();

        $subject = trans('firewall::notifications.mail.subject', [
            'domain' => $domain,
        ]);

        $message = trans('firewall::notifications.mail.message', [
            'domain' => $domain,
            'middleware' => ucfirst($this->log->middleware),
            'ip' => $this->log->ip,
            'url' => $this->log->url,
        ]);

        return (new MailMessage)
            ->from($this->notifications['mail']['from'], $this->notifications['mail']['name'])
            ->subject($subject)
            ->line($message);
    }

    /**
     * Get the Slack representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return SlackMessage
     */
    public function toSlack($notifiable)
    {
        $message = trans('firewall::notifications.slack.message', [
            'domain' => request()->getHttpHost(),
        ]);

        return (new SlackMessage)
            ->error()
            ->from($this->notifications['slack']['from'], $this->notifications['slack']['emoji'])
            ->to($this->notifications['slack']['channel'])
            ->content($message)
            ->attachment(function ($attachment) {
                $fields = [
                    'IP' => $this->log->ip,
                    'Type' => ucfirst($this->log->middleware),
                    'User ID' => $this->log->user_id,
                    'URL' => $this->log->url,
                ];

                if ($this->ip) {
                    $fields['Blocked'] = ($this->ip->blocked) ? 'Yes' : 'No';
                } else {
                    $fields['Blocked'] = 'No';
                }

                $attachment->fields($fields);
            });
    }

    /**
     * Get the Elastic representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return ElasticMessage
     */
    public function toElastic($notifiable)
    {
        return (new ElasticMessage())
            ->host($this->notifications['elastic']['host'])
            ->port($this->notifications['elastic']['port'])
            ->scheme($this->notifications['elastic']['scheme'])
            ->user($this->notifications['elastic']['user'])
            ->pass($this->notifications['elastic']['pass'])
            ->index($this->notifications['elastic']['index'])
            ->fields([
                '@timestamp' => $this->log->created_at,
                'domain_url' => env('APP_URL'),
                'domain_name' => env('APP_NAME'),
                'ip' => $this->log->ip,
                'level' => $this->log->level,
                'middleware' => $this->log->middleware,
                'user_id' => $this->log->user_id,
                'url' => $this->log->url,
                'referrer' => $this->log->referrer,
                'request' => $this->log->request,
                'blocked' => ($this->ip) ? $this->ip->blocked : 0,
            ])
        ;
    }
}

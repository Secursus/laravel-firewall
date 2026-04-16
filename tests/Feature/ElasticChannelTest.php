<?php

namespace Secursus\Firewall\Tests\Feature;

use Illuminate\Support\Facades\Http;
use Secursus\Firewall\Notifications\AttackDetected;
use Secursus\Firewall\Notifications\Channel\ElasticChannel;
use Secursus\Firewall\Notifications\Notifiable;
use Secursus\Firewall\Models\Ip;
use Secursus\Firewall\Models\Log;
use Secursus\Firewall\Tests\TestCase;

class ElasticChannelTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.notifications' => [
            'mail' => ['enabled' => false, 'queue' => 'default'],
            'slack' => ['enabled' => false, 'queue' => 'default'],
            'elastic' => [
                'enabled' => true,
                'host' => 'es.example.com',
                'port' => 9200,
                'scheme' => 'https',
                'user' => 'elastic',
                'pass' => 's3cret',
                'index' => 'firewall-logs',
                'queue' => 'default',
            ],
        ]]);
    }

    public function testSendPostsToElasticsearch()
    {
        Http::fake([
            'https://es.example.com:9200/*' => Http::response(['result' => 'created'], 201),
        ]);

        $log = Log::create([
            'ip' => '10.20.30.40',
            'level' => 'high',
            'middleware' => 'sqli',
            'user_id' => 5,
            'url' => 'http://example.com/admin',
            'referrer' => 'http://example.com',
            'request' => 'id=1 UNION SELECT',
        ]);

        Ip::create(['ip' => '10.20.30.40', 'log_id' => $log->id]);

        $notification = new AttackDetected($log);
        $notifiable = new Notifiable();

        $channel = new ElasticChannel();
        $channel->send($notifiable, $notification);

        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'firewall-logs/_doc/')
                && $request->method() === 'POST'
                && $request->data()['ip'] === '10.20.30.40'
                && $request->data()['middleware'] === 'sqli'
                && $request->data()['user_id'] === 5
                && $request->hasHeader('Authorization');
        });
    }

    public function testSendUsesCorrectBaseUrl()
    {
        Http::fake();

        $log = Log::create([
            'ip' => '1.2.3.4',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        $notification = new AttackDetected($log);
        $channel = new ElasticChannel();
        $channel->send(new Notifiable(), $notification);

        Http::assertSent(function ($request) {
            return str_starts_with($request->url(), 'https://es.example.com:9200/');
        });
    }

    public function testSendIncludesBasicAuth()
    {
        Http::fake();

        $log = Log::create([
            'ip' => '1.2.3.4',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        $notification = new AttackDetected($log);
        $channel = new ElasticChannel();
        $channel->send(new Notifiable(), $notification);

        Http::assertSent(function ($request) {
            $auth = $request->header('Authorization');
            // Basic auth header = "Basic base64(user:pass)"
            $expected = 'Basic ' . base64_encode('elastic:s3cret');
            return isset($auth[0]) && $auth[0] === $expected;
        });
    }
}

<?php

namespace Secursus\Firewall\Tests\Feature;

use Carbon\Carbon;
use Secursus\Firewall\Events\AttackDetected;
use Secursus\Firewall\Listeners\BlockIp;
use Secursus\Firewall\Models\Ip;
use Secursus\Firewall\Models\Log;
use Secursus\Firewall\Tests\TestCase;

class BlockIpListenerTest extends TestCase
{
    public function testShouldNotBlockWhenBelowAttemptThreshold()
    {
        config(['firewall.middleware.xss.auto_block.attempts' => 5]);
        config(['firewall.middleware.xss.auto_block.frequency' => 60]);

        $log = Log::create([
            'ip' => '10.0.0.1',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        (new BlockIp())->handle(new AttackDetected($log));

        $this->assertNull(Ip::where('ip', '10.0.0.1')->first());
    }

    public function testShouldBlockWhenAttemptThresholdReached()
    {
        config(['firewall.middleware.xss.auto_block.attempts' => 3]);
        config(['firewall.middleware.xss.auto_block.frequency' => 300]);

        // Create 2 prior logs + the triggering one = 3
        for ($i = 0; $i < 2; $i++) {
            Log::create([
                'ip' => '10.0.0.2',
                'level' => 'medium',
                'middleware' => 'xss',
                'user_id' => 0,
                'url' => 'http://example.com',
                'referrer' => 'NULL',
                'request' => 'test',
            ]);
        }

        $log = Log::create([
            'ip' => '10.0.0.2',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        (new BlockIp())->handle(new AttackDetected($log));

        $ip = Ip::where('ip', '10.0.0.2')->first();
        $this->assertNotNull($ip);
        $this->assertEquals($log->id, $ip->log_id);
    }

    public function testShouldBlockWhenAttemptThresholdIsExceeded()
    {
        config(['firewall.middleware.xss.auto_block.attempts' => 3]);
        config(['firewall.middleware.xss.auto_block.frequency' => 300]);

        // Concurrent requests may insert several logs before the listener counts them
        for ($i = 0; $i < 3; $i++) {
            Log::create([
                'ip' => '10.0.0.3',
                'level' => 'medium',
                'middleware' => 'xss',
                'user_id' => 0,
                'url' => 'http://example.com',
                'referrer' => 'NULL',
                'request' => 'test',
            ]);
        }

        $log = Log::create([
            'ip' => '10.0.0.3',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        (new BlockIp())->handle(new AttackDetected($log));

        $this->assertNotNull(Ip::where('ip', '10.0.0.3')->first());
    }

    public function testShouldNotBlockTheSameIpTwice()
    {
        config(['firewall.middleware.xss.auto_block.attempts' => 3]);
        config(['firewall.middleware.xss.auto_block.frequency' => 300]);

        for ($i = 0; $i < 4; $i++) {
            $log = Log::create([
                'ip' => '10.0.0.4',
                'level' => 'medium',
                'middleware' => 'xss',
                'user_id' => 0,
                'url' => 'http://example.com',
                'referrer' => 'NULL',
                'request' => 'test',
            ]);

            (new BlockIp())->handle(new AttackDetected($log));
        }

        $this->assertEquals(1, Ip::where('ip', '10.0.0.4')->count());
    }

    public function testShouldNotCountLogsFromAnotherMiddleware()
    {
        config(['firewall.middleware.xss.auto_block.attempts' => 3]);
        config(['firewall.middleware.xss.auto_block.frequency' => 300]);

        foreach (['sqli', 'rfi'] as $middleware) {
            Log::create([
                'ip' => '10.0.0.8',
                'level' => 'medium',
                'middleware' => $middleware,
                'user_id' => 0,
                'url' => 'http://example.com',
                'referrer' => 'NULL',
                'request' => 'test',
            ]);
        }

        $log = Log::create([
            'ip' => '10.0.0.8',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        (new BlockIp())->handle(new AttackDetected($log));

        $this->assertNull(Ip::where('ip', '10.0.0.8')->first());
    }

    public function testShouldNotCountLogsOlderThanTheFrequencyWindow()
    {
        config(['firewall.middleware.xss.auto_block.attempts' => 3]);
        config(['firewall.middleware.xss.auto_block.frequency' => 300]);

        for ($i = 0; $i < 2; $i++) {
            $old = Log::create([
                'ip' => '10.0.0.9',
                'level' => 'medium',
                'middleware' => 'xss',
                'user_id' => 0,
                'url' => 'http://example.com',
                'referrer' => 'NULL',
                'request' => 'test',
            ]);

            $old->created_at = Carbon::now()->subMinutes(30);
            $old->save();
        }

        $log = Log::create([
            'ip' => '10.0.0.9',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        (new BlockIp())->handle(new AttackDetected($log));

        $this->assertNull(Ip::where('ip', '10.0.0.9')->first());
    }
}

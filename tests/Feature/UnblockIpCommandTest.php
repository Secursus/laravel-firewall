<?php

namespace Secursus\Firewall\Tests\Feature;

use Carbon\Carbon;
use Secursus\Firewall\Models\Ip;
use Secursus\Firewall\Models\Log;
use Secursus\Firewall\Tests\TestCase;

class UnblockIpCommandTest extends TestCase
{
    public function testShouldUnblockExpiredIps()
    {
        config(['firewall.middleware.xss.auto_block.period' => 60]);

        $log = Log::create([
            'ip' => '10.0.0.5',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        $ip = Ip::create([
            'ip' => '10.0.0.5',
            'log_id' => $log->id,
        ]);

        // Simulate IP was created 2 minutes ago (past the 60s period)
        $ip->created_at = Carbon::now()->subSeconds(120);
        $ip->save();

        $this->artisan('firewall:unblockip')->assertSuccessful();

        $this->assertNull(Ip::withTrashed()->where('ip', '10.0.0.5')->whereNull('deleted_at')->first());
    }

    public function testShouldNotUnblockActiveIps()
    {
        config(['firewall.middleware.xss.auto_block.period' => 3600]);

        $log = Log::create([
            'ip' => '10.0.0.6',
            'level' => 'medium',
            'middleware' => 'xss',
            'user_id' => 0,
            'url' => 'http://example.com',
            'referrer' => 'NULL',
            'request' => 'test',
        ]);

        Ip::create([
            'ip' => '10.0.0.6',
            'log_id' => $log->id,
        ]);

        $this->artisan('firewall:unblockip')->assertSuccessful();

        $this->assertNotNull(Ip::where('ip', '10.0.0.6')->first());
    }
}

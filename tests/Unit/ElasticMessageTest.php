<?php

namespace Secursus\Firewall\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Secursus\Firewall\Notifications\Message\ElasticMessage;

class ElasticMessageTest extends TestCase
{
    public function testFluentSetters()
    {
        $msg = (new ElasticMessage())
            ->host('localhost')
            ->port(9200)
            ->scheme('https')
            ->user('elastic')
            ->pass('secret')
            ->index('firewall-logs')
            ->fields(['ip' => '127.0.0.1']);

        $this->assertSame('localhost', $msg->host);
        $this->assertSame(9200, $msg->port);
        $this->assertSame('https', $msg->scheme);
        $this->assertSame('elastic', $msg->user);
        $this->assertSame('secret', $msg->pass);
        $this->assertSame('firewall-logs', $msg->index);
        $this->assertSame(['ip' => '127.0.0.1'], $msg->fields);
    }

    public function testReturnsSelfForChaining()
    {
        $msg = new ElasticMessage();

        $this->assertSame($msg, $msg->host('h'));
        $this->assertSame($msg, $msg->port(9200));
        $this->assertSame($msg, $msg->scheme('https'));
        $this->assertSame($msg, $msg->user('u'));
        $this->assertSame($msg, $msg->pass('p'));
        $this->assertSame($msg, $msg->index('i'));
        $this->assertSame($msg, $msg->fields([]));
    }
}

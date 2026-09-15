<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Xss;
use Secursus\Firewall\Tests\TestCase;

class XssTest extends TestCase
{
    public function testShouldAllow()
    {
        $this->assertEquals('next', (new Xss())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlock()
    {
        $this->app->request->query->set('foo', '<script>alert(123)</script>');

        $this->assertEquals('403', (new Xss())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    /**
     * @return list<string>
     */
    private function payloads(): array
    {
        return [
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            'JaVaScRiPt:alert(1)',
            'livescript:alert(1)',
            'vbscript:msgbox(1)',
            'mocha:alert(1)',
            '<img src=x onerror=alert(1)>',
            '<iframe src=//evil.tld></iframe>',
            '<svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '<a xlink:href=javascript:alert(1)>',
            '<div style=x:expression(alert(1))>',
            '-moz-binding:url(evil.xml)',
            '<base href=//evil.tld>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:image/svg+xml;base64,PHN2Zy8+',
        ];
    }

    public function testShouldBlockKnownPayloads()
    {
        foreach ($this->payloads() as $payload) {
            $this->assertTrue($this->isBlocked(Xss::class, ['q' => $payload], 'POST'), "Not blocked: {$payload}");
        }
    }

    /**
     * The old '!((java|live|vb)script|mocha|feed|data):(\w)*!iUu' pattern flagged any
     * sentence containing "data:" or "feed:", 403ing real visitors.
     */
    public function testShouldNotBlockLegitimateMessages()
    {
        foreach ($this->legitimateMessages() as $message) {
            $this->assertFalse(
                $this->isBlocked(Xss::class, ['message' => $message], 'POST'),
                "Wrongly blocked: {$message}"
            );
        }
    }
}

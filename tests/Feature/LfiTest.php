<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Lfi;
use Secursus\Firewall\Tests\TestCase;

class LfiTest extends TestCase
{
    public function testShouldAllow()
    {
        $this->assertEquals('next', (new Lfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlock()
    {
        $this->app->request->query->set('foo', '../../../../etc/passwd');

        $this->assertEquals('403', (new Lfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    /**
     * @return list<string>
     */
    private function payloads(): array
    {
        return [
            '../../etc/passwd',
            '..\\..\\windows\\win.ini',
            '..%2f..%2fetc%2fpasswd',
            '..%5c..%5cwindows%5cwin.ini',
            '%2e%2e/%2e%2e/etc/shadow',
            '%252e%252e%252fetc%252fpasswd',
            '/proc/self/environ',
            '/etc/passwd%00',
            'php://filter/convert.base64-encode/resource=index',
            'php://input',
            'zip://shell.zip#shell.php',
            'phar://test.phar/x',
            'expect://id',
            'glob://*.php',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==',
        ];
    }

    public function testShouldBlockKnownPayloads()
    {
        foreach ($this->payloads() as $payload) {
            $this->assertTrue($this->isBlocked(Lfi::class, ['file' => $payload]), "Not blocked: {$payload}");
        }
    }

    public function testShouldNotBlockLegitimateMessages()
    {
        foreach ($this->legitimateMessages() as $message) {
            $this->assertFalse(
                $this->isBlocked(Lfi::class, ['message' => $message], 'POST'),
                "Wrongly blocked: {$message}"
            );
        }
    }
}

<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Exceptions\AccessDenied;
use Secursus\Firewall\Middleware\Xss;
use Secursus\Firewall\Tests\TestCase;
use Illuminate\Support\Facades\Response;

class RespondTest extends TestCase
{
    protected function getMiddleware(): Xss
    {
        $m = new Xss();
        $m->request = $this->app->request;
        $m->middleware = 'xss';

        return $m;
    }

    public function testRespondReturnsEmptyStringForCode200()
    {
        $m = $this->getMiddleware();

        $result = $m->respond(['code' => 200, 'view' => null, 'redirect' => null, 'abort' => false]);

        $this->assertSame('', $result);
    }

    public function testRespondReturns403ByDefault()
    {
        $m = $this->getMiddleware();

        $result = $m->respond(config('firewall.responses.block'));

        $this->assertEquals(403, $result->getStatusCode());
        $this->assertStringContainsString('Access Denied', $result->getContent());
    }

    public function testRespondWithRedirect()
    {
        $m = $this->getMiddleware();

        $result = $m->respond([
            'code' => 403,
            'view' => null,
            'redirect' => '/blocked',
            'abort' => false,
        ]);

        $this->assertTrue($result->isRedirection());
    }

    public function testRespondWithAbort()
    {
        $m = $this->getMiddleware();

        $this->expectException(\Symfony\Component\HttpKernel\Exception\HttpException::class);

        $m->respond([
            'code' => 403,
            'view' => null,
            'redirect' => null,
            'abort' => true,
        ]);
    }

    public function testRespondWithException()
    {
        $m = $this->getMiddleware();

        $this->expectException(AccessDenied::class);

        $m->respond([
            'code' => 403,
            'view' => null,
            'redirect' => null,
            'abort' => false,
            'exception' => AccessDenied::class,
        ]);
    }

    public function testRespondWithExceptionSetToNull()
    {
        $m = $this->getMiddleware();

        $result = $m->respond([
            'code' => 403,
            'view' => null,
            'redirect' => null,
            'abort' => false,
            'exception' => null,
        ]);

        $this->assertEquals(403, $result->getStatusCode());
    }
}

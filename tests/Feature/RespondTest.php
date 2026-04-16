<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Exceptions\AccessDenied;
use Secursus\Firewall\Middleware\Ip;
use Secursus\Firewall\Middleware\Xss;
use Secursus\Firewall\Tests\TestCase;

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

    public function testRespondWithView()
    {
        // Register an inline Blade view
        $this->app['view']->addNamespace('test', []);
        $this->app['view']->getFinder()->addLocation(resource_path('views'));

        // Create a temporary view file
        $viewDir = $this->app->resourcePath('views');
        if (! is_dir($viewDir)) {
            mkdir($viewDir, 0755, true);
        }
        file_put_contents($viewDir . '/firewall-blocked.blade.php', '<h1>Blocked</h1><p>Your IP has been blocked.</p>');

        $m = $this->getMiddleware();

        $result = $m->respond([
            'code' => 403,
            'view' => 'firewall-blocked',
            'redirect' => null,
            'abort' => false,
        ]);

        $this->assertEquals(403, $result->getStatusCode());
        $this->assertStringContainsString('Blocked', $result->getContent());
        $this->assertStringContainsString('Your IP has been blocked', $result->getContent());

        // Cleanup
        @unlink($viewDir . '/firewall-blocked.blade.php');
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
        $this->assertStringContainsString('/blocked', $result->headers->get('Location'));
    }

    public function testRespondWithRedirectAbortsForIpMiddlewareOnSameRoute()
    {
        // When ip middleware tries to redirect to the same URL it's on, it should abort
        $m = new Ip();
        $m->request = $this->app->request;
        $m->middleware = 'ip';

        $this->expectException(\Symfony\Component\HttpKernel\Exception\HttpException::class);

        $m->respond([
            'code' => 403,
            'view' => null,
            'redirect' => '/',
            'abort' => false,
        ]);
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

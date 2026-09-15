<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Rfi;
use Secursus\Firewall\Tests\TestCase;

class RfiTest extends TestCase
{
    public function testShouldAllow()
    {
        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlock()
    {
        $this->app->request->query->set('foo', 'https://attacker.example.com/evil.php');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockWhenPayloadIsNotTheLastInput()
    {
        $this->app->request->query->set('name', 'http://attacker.example.com/evil.txt?.jpg');
        $this->app->request->query->set('captcha', 'ABCD');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockWhenPayloadIsFollowedByAnEmptyInput()
    {
        $this->app->request->query->set('name', 'http://attacker.example.com/evil.txt?.jpg');
        $this->app->request->query->set('company', '');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldBlockWhenRemoteContentIsNotReachable()
    {
        $this->app->request->query->set('foo', 'http://127.0.0.1:1/unreachable.txt');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldAllowOwnDomain()
    {
        $this->app->request->query->set('url', 'http://' . $this->app->request->getHost() . '/contact-us');

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldNotScanExceptInputs()
    {
        config(['firewall.middleware.rfi.inputs.except' => ['password']]);

        $this->app->request->query->set('password', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlockPayloadNestedInAnArrayInput()
    {
        $this->app->request->query->set('parcels', [
            ['reference' => 'ABC'],
            ['reference' => 'http://attacker.example.com/evil.txt'],
        ]);
        $this->app->request->query->set('total', '3');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldOnlyScanInputsListedInOnly()
    {
        config(['firewall.middleware.rfi.inputs.only' => ['url']]);

        $this->app->request->query->set('comment', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));

        $this->app->request->query->set('url', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldSkipWhenMethodIsNotWatched()
    {
        config(['firewall.middleware.rfi.methods' => ['post']]);

        $this->app->request->query->set('foo', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldSkipWhitelistedIps()
    {
        config(['firewall.whitelist' => ['127.0.0.1']]);

        $this->app->request->query->set('foo', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldSkipWhenTheMiddlewareIsDisabled()
    {
        config(['firewall.middleware.rfi.enabled' => false]);

        $this->app->request->query->set('foo', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    /**
     * The per-middleware flag wins over the global one: firewall.enabled is only a
     * fallback for middleware that do not declare their own 'enabled' key.
     */
    public function testPerMiddlewareFlagOverridesTheGlobalSwitch()
    {
        config(['firewall.enabled' => false]);
        config(['firewall.middleware.rfi.enabled' => true]);

        $this->app->request->query->set('foo', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());

        config(['firewall.middleware.rfi' => array_diff_key(config('firewall.middleware.rfi'), ['enabled' => null])]);

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldNotFailWhenExceptionsConfigIsMissing()
    {
        config(['firewall.middleware.rfi.exceptions' => null]);

        $this->app->request->query->set('foo', 'http://attacker.example.com/evil.txt');

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldHonourConfiguredExceptions()
    {
        config(['firewall.middleware.rfi.exceptions' => ['https://cdn.partner.example.com']]);

        $this->app->request->query->set('asset', 'https://cdn.partner.example.com/logo.png');

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    /**
     * Array inputs (name="description[]") must honour inputs.except just like scalar ones.
     * The recursion used to happen before isInput() was consulted, so only the numeric
     * indices were checked against the exclusion list — never the field name.
     */
    public function testShouldHonourExceptedInputsInsideArrays()
    {
        config(['firewall.middleware.rfi.inputs.except' => ['description']]);

        $this->app->request->query->set('description', ['Suivi : https://carrier.example.com/track?id=1']);

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldStillScanNonExceptedArrays()
    {
        config(['firewall.middleware.rfi.inputs.except' => ['description']]);

        $this->app->request->query->set('shipper_name', ['http://attacker.example.com/evil.txt']);

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldHonourOnlyInputsInsideArrays()
    {
        config(['firewall.middleware.rfi.inputs.only' => ['url']]);

        $this->app->request->query->set('comment', ['http://attacker.example.com/evil.txt']);

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));

        $this->app->request->query->set('url', ['http://attacker.example.com/evil.txt']);

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldHonourExceptedInputsInsideNestedArrays()
    {
        config(['firewall.middleware.rfi.inputs.except' => ['description']]);

        $this->app->request->query->set('parcels', [
            ['description' => 'Suivi : https://carrier.example.com/track?id=1'],
        ]);

        $this->assertEquals('next', (new Rfi())->handle($this->app->request, $this->getNextClosure()));

        $this->app->request->query->set('parcels', [
            ['shipper_name' => 'http://attacker.example.com/evil.txt'],
        ]);

        $this->assertEquals('403', (new Rfi())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }
}

<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Geo;
use Secursus\Firewall\Tests\TestCase;

/**
 * Testable Geo subclass that overrides getResponse() to avoid real HTTP calls.
 */
class FakeGeo extends Geo
{
    public static $fakeResponse = null;

    public function prepare($request)
    {
        parent::prepare($request);

        // Force middleware name to 'geo' so config lookups work
        $this->middleware = 'geo';
    }

    protected function getResponse($url)
    {
        return static::$fakeResponse;
    }
}

class GeoMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.middleware.geo.enabled' => true]);
        config(['firewall.middleware.geo.methods' => ['all']]);
        config(['firewall.middleware.geo.service' => 'ipapi']);
    }

    protected function tearDown(): void
    {
        FakeGeo::$fakeResponse = null;
        parent::tearDown();
    }

    // -------------------------------------------------------------------------
    // isEmpty / no config → should allow
    // -------------------------------------------------------------------------

    public function testShouldAllowWhenAllPlacesEmpty()
    {
        // Default config has all allow/block lists empty
        $this->assertEquals('next', (new FakeGeo())->handle($this->app->request, $this->getNextClosure()));
    }

    // -------------------------------------------------------------------------
    // getLocation returns false → should allow
    // -------------------------------------------------------------------------

    public function testShouldAllowWhenLocationServiceFails()
    {
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['China'],
        ]]);

        FakeGeo::$fakeResponse = null; // service failure

        $this->assertEquals('next', (new FakeGeo())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldAllowWhenServiceReturnsInvalidResponse()
    {
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['China'],
        ]]);

        FakeGeo::$fakeResponse = (object) []; // empty object, no country/city

        $this->assertEquals('next', (new FakeGeo())->handle($this->app->request, $this->getNextClosure()));
    }

    // -------------------------------------------------------------------------
    // Block by country
    // -------------------------------------------------------------------------

    public function testShouldBlockWhenCountryInBlockList()
    {
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['China'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Asia',
            'country' => 'China',
            'regionName' => 'Beijing',
            'city' => 'Beijing',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldAllowWhenCountryNotInBlockList()
    {
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['China'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Europe',
            'country' => 'France',
            'regionName' => 'Ile-de-France',
            'city' => 'Paris',
        ];

        $this->assertEquals('next', (new FakeGeo())->handle($this->app->request, $this->getNextClosure()));
    }

    // -------------------------------------------------------------------------
    // Allow-list filtering
    // -------------------------------------------------------------------------

    public function testShouldBlockWhenCountryNotInAllowList()
    {
        config(['firewall.middleware.geo.countries' => [
            'allow' => ['France', 'Germany'],
            'block' => [],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Asia',
            'country' => 'China',
            'regionName' => 'Beijing',
            'city' => 'Beijing',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testShouldAllowWhenCountryInAllowList()
    {
        config(['firewall.middleware.geo.countries' => [
            'allow' => ['France', 'Germany'],
            'block' => [],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Europe',
            'country' => 'France',
            'regionName' => 'Ile-de-France',
            'city' => 'Paris',
        ];

        $this->assertEquals('next', (new FakeGeo())->handle($this->app->request, $this->getNextClosure()));
    }

    // -------------------------------------------------------------------------
    // Block by continent
    // -------------------------------------------------------------------------

    public function testShouldBlockByContinentBlockList()
    {
        config(['firewall.middleware.geo.continents' => [
            'allow' => [],
            'block' => ['Asia'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Asia',
            'country' => 'Japan',
            'regionName' => 'Tokyo',
            'city' => 'Tokyo',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    // -------------------------------------------------------------------------
    // Block by city
    // -------------------------------------------------------------------------

    public function testShouldBlockByCityBlockList()
    {
        config(['firewall.middleware.geo.cities' => [
            'allow' => [],
            'block' => ['Moscow'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Europe',
            'country' => 'Russia',
            'regionName' => 'Moscow',
            'city' => 'Moscow',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    // -------------------------------------------------------------------------
    // Block by region
    // -------------------------------------------------------------------------

    public function testShouldBlockByRegionBlockList()
    {
        config(['firewall.middleware.geo.regions' => [
            'allow' => [],
            'block' => ['Crimea'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Europe',
            'country' => 'Ukraine',
            'regionName' => 'Crimea',
            'city' => 'Sevastopol',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    // -------------------------------------------------------------------------
    // Different geo services
    // -------------------------------------------------------------------------

    public function testIpstackService()
    {
        config(['firewall.middleware.geo.service' => 'ipstack']);
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['China'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent_name' => 'Asia',
            'country_name' => 'China',
            'region_name' => 'Beijing',
            'city' => 'Beijing',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testExtremeIpLookupService()
    {
        config(['firewall.middleware.geo.service' => 'extremeiplookup']);
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['Russia'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Europe',
            'country' => 'Russia',
            'region' => 'Moscow',
            'city' => 'Moscow',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testIpdataService()
    {
        config(['firewall.middleware.geo.service' => 'ipdata']);
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['Iran'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent_name' => 'Asia',
            'country_name' => 'Iran',
            'region_name' => 'Tehran',
            'city' => 'Tehran',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testIpinfoService()
    {
        config(['firewall.middleware.geo.service' => 'ipinfo']);
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['KP'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'country' => 'KP',
            'region' => 'Pyongyang',
            'city' => 'Pyongyang',
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    public function testIpregistryService()
    {
        config(['firewall.middleware.geo.service' => 'ipregistry']);
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['North Korea'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'location' => (object) [
                'continent' => (object) ['name' => 'Asia'],
                'country' => (object) ['name' => 'North Korea', 'code' => 'KP'],
                'region' => (object) ['name' => 'Pyongyang'],
                'city' => 'Pyongyang',
                'in_eu' => false,
                'language' => (object) ['code' => 'ko'],
            ],
            'time_zone' => (object) ['id' => 'Asia/Pyongyang'],
            'currency' => (object) ['code' => 'KPW'],
        ];

        $this->assertEquals('403', (new FakeGeo())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    // -------------------------------------------------------------------------
    // Disabled
    // -------------------------------------------------------------------------

    public function testShouldSkipWhenDisabled()
    {
        config(['firewall.middleware.geo.enabled' => false]);
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['China'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Asia',
            'country' => 'China',
            'regionName' => 'Beijing',
            'city' => 'Beijing',
        ];

        $this->assertEquals('next', (new FakeGeo())->handle($this->app->request, $this->getNextClosure()));
    }

    // -------------------------------------------------------------------------
    // Multiple place filters combined
    // -------------------------------------------------------------------------

    public function testShouldAllowWhenNoPlaceMatches()
    {
        config(['firewall.middleware.geo.countries' => [
            'allow' => [],
            'block' => ['China'],
        ]]);
        config(['firewall.middleware.geo.cities' => [
            'allow' => [],
            'block' => ['Moscow'],
        ]]);

        FakeGeo::$fakeResponse = (object) [
            'continent' => 'Europe',
            'country' => 'France',
            'regionName' => 'Ile-de-France',
            'city' => 'Paris',
        ];

        $this->assertEquals('next', (new FakeGeo())->handle($this->app->request, $this->getNextClosure()));
    }
}

<?php

namespace Secursus\Firewall\Tests;

use Secursus\Firewall\Provider;
use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpDatabase();

        $this->setUpConfig();

        $this->artisan('vendor:publish', ['--tag' => 'firewall']);
        $this->artisan('migrate:refresh', ['--database' => 'testbench']);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }

    protected function getPackageProviders($app)
    {
        return [
            Provider::class,
        ];
    }

    protected function setUpDatabase()
    {
        config(['database.default' => 'testbench']);

        config(['database.connections.testbench' => [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ],
        ]);
    }

    protected function setUpConfig()
    {
        config(['firewall' => require __DIR__ . '/../src/Config/firewall.php']);

        config(['firewall.notifications.mail.enabled' => false]);
        config(['firewall.middleware.ip.methods' => ['all']]);
        config(['firewall.middleware.lfi.methods' => ['all']]);
        config(['firewall.middleware.rfi.methods' => ['all']]);
        config(['firewall.middleware.sqli.methods' => ['all']]);
        config(['firewall.middleware.xss.methods' => ['all']]);
    }

    public function getNextClosure()
    {
        return function () {
            return 'next';
        };
    }

    /**
     * Run one input set through a middleware and tell whether it was blocked.
     *
     * @param class-string $middleware
     * @param array<string, mixed> $input
     */
    public function isBlocked(string $middleware, array $input, string $method = 'GET'): bool
    {
        $request = Request::create('https://example.com/contact', $method, $input);

        return (new $middleware())->handle($request, $this->getNextClosure()) !== 'next';
    }

    /**
     * Messages a real visitor could legitimately send. None of them may ever be blocked.
     *
     * @return list<string>
     */
    public function legitimateMessages(): array
    {
        return [
            'Hello, I am writing from London about an insurance quote.',
            'Where can I find the terms and conditions?',
            'Please delete my account and all my data (GDPR).',
            'Could you insert my VAT number into the invoice?',
            'I want to select a higher coverage, from 500 to 2000 EUR.',
            'Select the option that suits you best and let me know.',
            'We ship from France to Spain, where are your offices?',
            'Cast iron parts, value 1200 EUR, shipped from Lyon.',
            'The box is 30x20x10 and weight = 2kg',
            'I will order by friday, 3 parcels, and insurance for each.',
            "O'Brien, Patrick - 12 Main Street, Dublin",
            'Our data: 300 parcels per month, invoice 2024-1188',
            'Please send the feed: RSS or Atom, either works.',
            'Reference ACME-2024/0042, price 1.500,00 EUR / 1.250,00 EUR',
            'See the file ./docs/guide.pdf attached to my previous email.',
            'Tracking link: https://www.laposte.fr/outils/suivre?code=6A1',
            'It is urgent -- can you answer today?',
            'Please delete from my account the old address.',
            'Could you insert into the invoice my VAT number?',
            'Please insert into the box a fragile sticker.',
            'We would like to delete from our contract the option B.',
        ];
    }
}

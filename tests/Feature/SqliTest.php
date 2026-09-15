<?php

namespace Secursus\Firewall\Tests\Feature;

use Secursus\Firewall\Middleware\Sqli;
use Secursus\Firewall\Tests\TestCase;

class SqliTest extends TestCase
{
    public function testShouldAllow()
    {
        $this->assertEquals('next', (new Sqli())->handle($this->app->request, $this->getNextClosure()));
    }

    public function testShouldBlock()
    {
        $this->app->request->query->set('foo', '-1+union+select+1,2,3,4,5,6,7,8,9,(SELECT+password+FROM+users+WHERE+ID=1)');

        $this->assertEquals('403', (new Sqli())->handle($this->app->request, $this->getNextClosure())->getStatusCode());
    }

    /**
     * @return list<string>
     */
    private function payloads(): array
    {
        return [
            "1' OR '1'='1",
            "admin'--",
            '1 UNION SELECT username, password FROM users',
            "' UNION ALL SELECT NULL,NULL,NULL--",
            '1; DROP TABLE users--',
            "' OR 1=1--",
            "1' AND SLEEP(5)--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            '1) OR (1=1',
            "'; INSERT INTO users VALUES('x','y');--",
            '1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)',
            "' OR 'x'='x",
            "' OR ''='",
            '-1 UNION SELECT 1,group_concat(password) FROM users',
            "1' ORDER BY 1-- ",
            "'; WAITFOR DELAY '0:0:5'--",
            "test' UNION SELECT LOAD_FILE('/etc/passwd')--",
            '1 AND 1=1',
            "1' AND BENCHMARK(1000000,MD5('a'))--",
            "' UNION SELECT @@version--",
            "1'; EXEC xp_cmdshell('dir')--",
            "' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
            "1 UNION SELECT 1,2,3 INTO OUTFILE '/tmp/x'--",
            "' OR 1=1 /*",
            "admin' #",
            "' UNION SELECT NULL FROM sysobjects--",
            "1' PROCEDURE ANALYSE()--",
            "'; DELETE FROM users WHERE 1=1--",
        ];
    }

    public function testShouldBlockKnownPayloads()
    {
        foreach ($this->payloads() as $payload) {
            $this->assertTrue($this->isBlocked(Sqli::class, ['q' => $payload]), "Not blocked: {$payload}");
        }
    }

    public function testShouldNotBlockLegitimateMessages()
    {
        foreach ($this->legitimateMessages() as $message) {
            $this->assertFalse(
                $this->isBlocked(Sqli::class, ['message' => $message], 'POST'),
                "Wrongly blocked: {$message}"
            );
        }
    }

    public function testShouldNotScanCredentialFields()
    {
        foreach ($this->credentialFields() as $field) {
            foreach ($this->credentialPayloads() as $password) {
                $this->assertFalse(
                    $this->isBlocked(Sqli::class, [$field => $password], 'POST'),
                    "Scans [{$field}] and would block the password: {$password}"
                );
            }
        }
    }
}

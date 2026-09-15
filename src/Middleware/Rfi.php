<?php

namespace Secursus\Firewall\Middleware;

use Secursus\Firewall\Abstracts\Middleware;

class Rfi extends Middleware
{
    /**
     * Strip the URLs that must not be considered as a remote file inclusion
     * before the pattern is applied to the input.
     *
     * @param string $value
     * @return string
     */
    public function prepareInput($value)
    {
        return $this->applyExceptions($value);
    }

    /**
     * @param string $string
     * @return string
     */
    protected function applyExceptions($string)
    {
        $exceptions = (array) config('firewall.middleware.' . $this->middleware . '.exceptions', []);

        $domain = $this->request->getHost();

        $exceptions[] = 'http://' . $domain;
        $exceptions[] = 'https://' . $domain;
        $exceptions[] = 'http://&';
        $exceptions[] = 'https://&';

        return str_replace($exceptions, '', $string);
    }
}

<?php

namespace Secursus\Firewall\Notifications\Message;

use Illuminate\Notifications\Notification;

class ElasticMessage
{
    /**
     * The host configurations.
     *
     * @var string
     */
    public $host;

    /**
     * The port configurations.
     *
     * @var string
     */
    public $port;

    /**
     * The scheme configurations.
     *
     * @var string
     */
    public $scheme;

    /**
     * The user for send the message.
     *
     * @var string
     */
    public $user;

    /**
     * The password for send the message.
     *
     * @var string
     */
    public $pass;

    /**
     * The index to send the message.
     *
     * @var string
     */
    public $index;

    /**
     * The array content of the message.
     *
     * @var array
     */
    public $fields;

    /**
     * Set a host for the Elastic message.
     *
     * @param  string  $host
     * @return $this
     */
    public function host($host)
    {
        $this->host = $host;

        return $this;
    }

    /**
     * Set a port for the Elastic message.
     *
     * @param  integer  $port
     * @return $this
     */
    public function port($port)
    {
        $this->port = $port;

        return $this;
    }

    /**
     * Set a scheme for the Elastic message.
     *
     * @param  string  $scheme
     * @return $this
     */
    public function scheme($scheme)
    {
        $this->scheme = $scheme;

        return $this;
    }

    /**
     * Set a user for the Elastic message.
     *
     * @param  string  $user
     * @return $this
     */
    public function user($user)
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Set a password for the Elastic message.
     *
     * @param  string  $pass
     * @return $this
     */
    public function pass($pass)
    {
        $this->pass = $pass;

        return $this;
    }

    /**
     * Set a index for the Elastic message.
     *
     * @param  string  $content
     * @return $this
     */
    public function index($index)
    {
        $this->index = $index;

        return $this;
    }

    /**
     * Set the fields of the Slack message.
     *
     * @param  array  $fields
     * @return $this
     */
    public function fields($fields)
    {
        $this->fields = $fields;

        return $this;
    }
}

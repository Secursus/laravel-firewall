<?php

return [

    'enabled' => env('FIREWALL_ENABLED', true),

    'whitelist' => explode(',', env('FIREWALL_WHITELIST', '')),

    'models' => [
        'user' => '\App\Models\User',
        // 'log' => '\App\Models\YourLogModel',
        // 'ip' => '\App\Models\YourIpModel',
    ],

    'log' => [
        'max_request_size' => 2048,
    ],

    'cron' => [
        'enabled' => env('FIREWALL_CRON_ENABLED', true),
        'expression' => env('FIREWALL_CRON_EXPRESSION', '*/15 * * * *'),
        'on_one_server' => env('FIREWALL_CRON_ON_ONE_SERVER', true),
        'without_overlapping' => env('FIREWALL_CRON_WITHOUT_OVERLAPPING', 10),
        'in_background' => env('FIREWALL_CRON_IN_BACKGROUND', true),
    ],

    'responses' => [
        'block' => [
            'view' => env('FIREWALL_BLOCK_VIEW', null),
            'redirect' => env('FIREWALL_BLOCK_REDIRECT', null),
            'abort' => env('FIREWALL_BLOCK_ABORT', false),
            'code' => env('FIREWALL_BLOCK_CODE', 403),
            //'exception' => \Secursus\Firewall\Exceptions\AccessDenied::class,
        ],
    ],

    'notifications' => [
        'mail' => [
            'enabled' => env('FIREWALL_EMAIL_ENABLED', false),
            'name' => env('FIREWALL_EMAIL_NAME', 'Laravel Firewall'),
            'from' => env('FIREWALL_EMAIL_FROM', 'firewall@mydomain.com'),
            'to' => env('FIREWALL_EMAIL_TO', 'admin@mydomain.com'),
            'queue' => env('FIREWALL_EMAIL_QUEUE', 'default'),
        ],

        'slack' => [
            'enabled' => env('FIREWALL_SLACK_ENABLED', false),
            'emoji' => env('FIREWALL_SLACK_EMOJI', ':fire:'),
            'from' => env('FIREWALL_SLACK_FROM', 'Laravel Firewall'),
            'to' => env('FIREWALL_SLACK_TO'), // webhook url
            'channel' => env('FIREWALL_SLACK_CHANNEL', null), // set null to use the default channel of webhook
            'queue' => env('FIREWALL_SLACK_QUEUE', 'default'),
        ],

        'elastic' => [
            'enabled' => env('FIREWALL_ELASTIC_ENABLED', false),
            'host' => env('FIREWALL_ELASTIC_HOST'), // Host ES
            'port' => env('FIREWALL_ELASTIC_PORT', 9200),
            'scheme' => env('FIREWALL_ELASTIC_SCHEME', 'https'),
            'user' => env('FIREWALL_ELASTIC_USER'), // User ES
            'pass' => env('FIREWALL_ELASTIC_PASS'), // Password ES
            'index' => env('FIREWALL_ELASTIC_INDEX', 'laravel-firewall'), // Index ES
            'queue' => env('FIREWALL_ELASTIC_QUEUE', 'default'),
        ],
    ],

    'all_middleware' => [
        'firewall.ip',
        'firewall.agent',
        'firewall.bot',
        'firewall.geo',
        'firewall.lfi',
        'firewall.php',
        'firewall.referrer',
        'firewall.rfi',
        'firewall.session',
        'firewall.sqli',
        'firewall.swear',
        'firewall.xss',
        //'App\Http\Middleware\YourCustomRule',
    ],

    'middleware' => [

        'ip' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_IP_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['all'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
        ],

        'agent' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_AGENT_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['all'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'browsers' => [
                'allow' => [], // i.e. 'Chrome', 'Firefox'
                'block' => [], // i.e. 'IE'
            ],
            'platforms' => [
                'allow' => [], // i.e. 'Ubuntu', 'Windows'
                'block' => [], // i.e. 'OS X'
            ],
            'devices' => [
                'allow' => [], // i.e. 'Desktop', 'Mobile'
                'block' => [], // i.e. 'Tablet'
            ],
            'properties' => [
                'allow' => [], // i.e. 'Gecko', 'Version/5.1.7'
                'block' => [], // i.e. 'AppleWebKit'
            ],
            'auto_block' => [
                'attempts' => 5,
                'frequency' => 1 * 60, // 1 minute
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'bot' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_BOT_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['all'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            // https://github.com/JayBizzle/Crawler-Detect/blob/master/raw/Crawlers.txt
            'crawlers' => [
                'allow' => [], // i.e. 'GoogleSites', 'GuzzleHttp'
                'block' => [], // i.e. 'Holmes'
            ],
            'auto_block' => [
                'attempts' => 5,
                'frequency' => 1 * 60, // 1 minute
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'geo' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_GEO_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['all'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'continents' => [
                'allow' => [], // i.e. 'Africa'
                'block' => [], // i.e. 'Europe'
            ],
            'regions' => [
                'allow' => [], // i.e. 'California'
                'block' => [], // i.e. 'Nevada'
            ],
            'countries' => [
                'allow' => [], // i.e. 'Albania'
                'block' => [], // i.e. 'Madagascar'
            ],
            'cities' => [
                'allow' => [], // i.e. 'Istanbul'
                'block' => [], // i.e. 'London'
            ],
            // ipapi, extremeiplookup, ipstack, ipdata, ipinfo, ipregistry, ip2locationio
            'service' => 'ipapi',
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'lfi' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_LFI_ENABLED', env('FIREWALL_ENABLED', true)),
            'level' => 'high',
            'methods' => ['get', 'post', 'put', 'patch', 'delete'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'inputs' => [
                'only' => [], // i.e. 'first_name'
                'except' => [], // i.e. 'password'
            ],
            // Real path traversal and stream wrappers. The previous '#\.\/#is' matched a bare
            // './', which is noisy on free text and misses every encoded variant.
            'patterns' => [
                '~\\.\\.[/\\\\]~',
                '~\\.\\.(%2f|%5c|%252f|%255c)~i',
                '~%252e%252e(%252f|%255c)~i',
                '~%2e%2e(%2f|%5c|%252f|/|\\\\)~i',
                '~[/\\\\](etc/passwd|etc/shadow|proc/self/environ|windows/win\\.ini)~i',
                '~\\b(php|zip|phar|expect|glob|bzip2|zlib|rar|ogg|ssh2|data|compress\\.(zlib|bzip2))://~i',
                '~%00~',
            ],
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'login' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_LOGIN_ENABLED', env('FIREWALL_ENABLED', true)),
            'auto_block' => [
                'attempts' => 5,
                'frequency' => 1 * 60, // 1 minute
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'php' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_PHP_ENABLED', env('FIREWALL_ENABLED', true)),
            'level' => 'high',
            'methods' => ['get', 'post', 'delete'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'inputs' => [
                'only' => [], // i.e. 'first_name'
                'except' => [], // i.e. 'password'
            ],
            // Plain strings on purpose: Php::match() uses stripos($value, $pattern) === 0,
            // so these are literal prefixes, not regexes. Converting them to regexes
            // silently disables the middleware. Wrappers appearing anywhere else in a
            // value are covered by the 'lfi' stream wrapper pattern.
            'patterns' => [
                'bzip2://',
                'expect://',
                'glob://',
                'phar://',
                'php://',
                'ogg://',
                'rar://',
                'ssh2://',
                'zip://',
                'zlib://',
            ],
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'referrer' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_REFERRER_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['all'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'blocked' => [],
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'rfi' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_RFI_ENABLED', env('FIREWALL_ENABLED', true)),
            'level' => 'high',
            'methods' => ['get', 'post', 'put', 'patch', 'delete'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            // The pattern below matches ANY external URL. List your free-text fields here
            // (message, description, comment...) or legitimate visitors pasting a tracking
            // link will be blocked, then auto-banned after a few submissions.
            'inputs' => [
                'only' => [], // i.e. 'first_name'
                'except' => [], // i.e. 'message'
            ],
            'patterns' => [
                '#(http|ftp){1,1}(s){0,1}://.*#i',
            ],
            'exceptions' => [],
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'session' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_SESSION_ENABLED', env('FIREWALL_ENABLED', true)),
            'level' => 'high',
            'methods' => ['get', 'post', 'delete'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'inputs' => [
                'only' => [], // i.e. 'first_name'
                'except' => [], // i.e. 'password'
            ],
            'patterns' => [
                '@[\|:]O:\d{1,}:"[\w_][\w\d_]{0,}":\d{1,}:{@i',
                '@[\|:]a:\d{1,}:{@i',
            ],
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'sqli' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_SQLI_ENABLED', env('FIREWALL_ENABLED', true)),
            'level' => 'high',
            'methods' => ['get', 'post', 'put', 'patch', 'delete'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'inputs' => [
                'only' => [], // i.e. 'first_name'
                'except' => [], // i.e. 'password'
            ],
            // Patterns require actual SQL syntax rather than a bare English keyword. The previous
            // '(union|insert|from|where|select|delete|having)' alternation matched ordinary
            // prose such as "I am writing from London", which made scanning POST bodies
            // impossible without blocking real users.
            'patterns' => [
                '~\\bunion\\b[\\s\\S]{0,60}?\\bselect\\b~i',
                '~[\'"(,]\\s*select\\b[\\s\\S]{0,120}?\\bfrom\\b~i',
                '~\\bselect\\b\\s+(\\*|count\\s*\\(|concat\\s*\\(|group_concat\\s*\\(|null\\b|@@|version\\s*\\()~i',
                '~\\binsert\\b\\s+\\binto\\b\\s+[\\w`\\[\\]".]+\\s*(\\(|\\bvalues\\b|\\bselect\\b|\\bset\\b)~i',
                '~\\bdelete\\b\\s+\\bfrom\\b\\s+[\\w`\\[\\]".]+\\s*(\\bwhere\\b|;|--|/\\*|\\)|$)~i',
                '~\\bdrop\\b\\s+\\b(table|database|schema)\\b~i',
                '~\\bupdate\\b[\\s\\S]{0,60}?\\bset\\b\\s*[\\w`\'"]+\\s*=~i',
                '~\\b(or|and)\\b\\s*\\(?\\s*([\'"`]?)([\\w]{1,12})\\2\\s*(?:=|<>|!=|\\blike\\b)\\s*\\(?\\s*[\'"`]?\\3\\b~i',
                '~[\'"`)]\\s*(--|\\#|/\\*)~',
                '~[\'"]\\s*(order\\s+by|group\\s+by|having\\b|procedure\\s+analyse)~i',
                '~[\'"]\\s*\\b(or|and)\\b\\s*[\'"]{2}\\s*(=|<>|!=|\\blike\\b)~i',
                '~\\b(sleep|benchmark|pg_sleep|dbms_pipe\\.receive_message)\\s*\\(~i',
                '~\\bwaitfor\\b\\s+\\bdelay\\b~i',
                '~\\b(information_schema|sysobjects|pg_catalog|mysql\\.user)\\b~i',
                '~\\b(load_file|outfile|dumpfile|xp_cmdshell|group_concat)\\s*\\(~i',
            ],
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'swear' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_SWEAR_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['post', 'put', 'patch'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
            'inputs' => [
                'only' => [], // i.e. 'first_name'
                'except' => [], // i.e. 'password'
            ],
            'words' => [],
            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'url' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_URL_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['all'],
            'inspections' => [], // i.e. 'admin'
            'auto_block' => [
                'attempts' => 5,
                'frequency' => 1 * 60, // 1 minute
                'period' => 30 * 60, // 30 minutes
            ],
        ],

        'whitelist' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_WHITELIST_ENABLED', env('FIREWALL_ENABLED', true)),
            'methods' => ['all'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],
        ],

        'xss' => [
            'enabled' => env('FIREWALL_MIDDLEWARE_XSS_ENABLED', env('FIREWALL_ENABLED', true)),
            'level' => 'high',
            'methods' => ['post', 'put', 'patch'],
            'routes' => [
                'only' => [], // i.e. 'contact'
                'except' => [], // i.e. 'admin/*'
            ],

            'inputs' => [
                'only' => [], // i.e. 'first_name'
                'except' => [], // i.e. 'password'
            ],

            'patterns' => [
                // Evil starting attributes
                '#(<[^>]+[\x00-\x20\"\'\/])(form|formaction|on\w*|style|xmlns|xlink:href)[^>]*>?#iUu',

                // javascript:, livescript:, vbscript:, mocha: protocols
                '~\\b(java|live|vb)script\\s*:~i',
                '~\\bmocha\\s*:~i',

                // data:/feed: only when followed by a real MIME type or a base64 payload,
                // so an ordinary sentence such as "our data: 300 parcels" is not flagged.
                '~\\b(data|feed)\\s*:\\s*(text|image|application|audio|video|font|model|multipart|message)/[\\w.+-]+~i',
                '~\\bdata\\s*:[^,\\s]{0,64};base64,~i',
                '#-moz-binding[\x00-\x20]*:#u',

                // Unneeded tags
                '#</*(applet|meta|xml|blink|link|style|script|embed|object|iframe|frame|frameset|ilayer|layer|bgsound|title|base|img)[^>]*>?#i'
            ],

            'auto_block' => [
                'attempts' => 3,
                'frequency' => 5 * 60, // 5 minutes
                'period' => 30 * 60, // 30 minutes
            ],
        ],
    ],
];

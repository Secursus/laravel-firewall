<?php

namespace Secursus\Firewall\Support;

use Detection\MobileDetect;
use Jaybizzle\CrawlerDetect\CrawlerDetect;

class AgentParser
{
    protected MobileDetect $detect;
    protected CrawlerDetect $crawlerDetect;
    protected string $userAgent;

    /**
     * List of additional browsers (same order as jenssegers/agent).
     */
    protected static array $browsers = [
        'Opera Mini' => 'Opera Mini',
        'Opera' => 'Opera|OPR',
        'Edge' => 'Edge|Edg',
        'Coc Coc' => 'coc_coc_browser',
        'UCBrowser' => 'UCBrowser',
        'Vivaldi' => 'Vivaldi',
        'Chrome' => 'Chrome',
        'Firefox' => 'Firefox',
        'Safari' => 'Safari',
        'IE' => 'MSIE|IEMobile|MSIEMobile|Trident/[.0-9]+',
        'Netscape' => 'Netscape',
        'Mozilla' => 'Mozilla',
    ];

    /**
     * List of operating systems (same as jenssegers/agent).
     */
    protected static array $platforms = [
        'AndroidOS' => 'Android',
        'BlackBerryOS' => 'blackberry|BB10',
        'PalmOS' => 'PalmOS|avantgo|blazer|elaine|hiptop|palm|plucker|xiino',
        'SymbianOS' => 'Symbian|SymbOS|Series60|Series40|SYB-[0-9]+|S60',
        'WindowsMobileOS' => 'Windows CE.*(PPC|Smartphone|Mobile|[0-9]{3}x[0-9]{3})|Windows Mobile|Windows Phone [0-9.]+|WCE;',
        'WindowsPhoneOS' => 'Windows Phone 10.0|Windows Phone 8.1|Windows Phone 8.0|Windows Phone OS|XBLWP7|ZuneWP7|Windows NT 6.[23]; ARM;',
        'iOS' => '\biPhone.*Mobile|\biPod|\biPad|AppleCoreMedia',
        'iPadOS' => 'iPad|Macintosh.*Safari',
        'MeeGoOS' => 'MeeGo',
        'MaemoOS' => 'Maemo',
        'JavaOS' => 'J2ME/|\bMIDP\b|\bCLDC\b',
        'webOS' => 'webOS|hpwOS',
        'badaOS' => '\bBada\b',
        'BREWOS' => 'BREW',
        'Windows' => 'Windows',
        'Windows NT' => 'Windows NT',
        'OS X' => 'Mac OS X',
        'Debian' => 'Debian',
        'Ubuntu' => 'Ubuntu',
        'Macintosh' => 'PPC',
        'OpenBSD' => 'OpenBSD',
        'Linux' => 'Linux',
        'ChromeOS' => 'CrOS',
    ];

    public function __construct(?string $userAgent = null)
    {
        $this->detect = new MobileDetect();
        $this->crawlerDetect = new CrawlerDetect();

        if ($userAgent !== null) {
            $this->detect->setUserAgent($userAgent);
        }

        $this->userAgent = $this->detect->getUserAgent() ?? '';
    }

    /**
     * Get the raw user agent string.
     */
    public function getUserAgent(): string
    {
        return $this->userAgent;
    }

    /**
     * Check if the device is a mobile.
     */
    public function isMobile(): bool
    {
        return $this->detect->isMobile();
    }

    /**
     * Check if the device is a tablet.
     */
    public function isTablet(): bool
    {
        return $this->detect->isTablet();
    }

    /**
     * Check if the device is a desktop (not mobile, not tablet, not robot).
     */
    public function isDesktop(): bool
    {
        return ! $this->isMobile() && ! $this->isTablet() && ! $this->isRobot();
    }

    /**
     * Get the browser name.
     *
     * @return string|false
     */
    public function browser()
    {
        foreach (static::$browsers as $name => $pattern) {
            if (preg_match('#' . $pattern . '#i', $this->userAgent)) {
                return $name;
            }
        }

        return false;
    }

    /**
     * Get the platform/OS name.
     *
     * @return string|false
     */
    public function platform()
    {
        foreach (static::$platforms as $name => $pattern) {
            if (preg_match('#' . $pattern . '#i', $this->userAgent)) {
                return $name;
            }
        }

        return false;
    }

    /**
     * Check if the user agent is a robot/crawler.
     */
    public function isRobot(): bool
    {
        return $this->crawlerDetect->isCrawler($this->userAgent);
    }

    /**
     * Get the robot/crawler name.
     *
     * @return string|false
     */
    public function robot()
    {
        if ($this->crawlerDetect->isCrawler($this->userAgent)) {
            return ucfirst($this->crawlerDetect->getMatches());
        }

        return false;
    }

    /**
     * Check a property against the user agent using MobileDetect rules
     * or a direct regex match (mirrors jenssegers/agent __call behavior).
     */
    public function is(string $property): bool
    {
        $method = 'is' . $property;

        if (method_exists($this->detect, $method)) {
            return (bool) $this->detect->$method();
        }

        // Check in browsers
        if (isset(static::$browsers[$property])) {
            return (bool) preg_match('#' . static::$browsers[$property] . '#i', $this->userAgent);
        }

        // Check in platforms
        if (isset(static::$platforms[$property])) {
            return (bool) preg_match('#' . static::$platforms[$property] . '#i', $this->userAgent);
        }

        // Fallback: direct match against user agent
        return (bool) preg_match('#' . preg_quote($property, '#') . '#i', $this->userAgent);
    }
}

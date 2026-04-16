<?php

namespace Secursus\Firewall\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Secursus\Firewall\Support\AgentParser;

class AgentParserTest extends TestCase
{
    // -------------------------------------------------------------------------
    // getUserAgent
    // -------------------------------------------------------------------------

    public function testGetUserAgentReturnsString()
    {
        $parser = new AgentParser('Mozilla/5.0');
        $this->assertSame('Mozilla/5.0', $parser->getUserAgent());
    }

    public function testGetUserAgentEmptyWhenNull()
    {
        $parser = new AgentParser('');
        $this->assertSame('', $parser->getUserAgent());
    }

    // -------------------------------------------------------------------------
    // browser() — must return string|false, same as jenssegers/agent
    // -------------------------------------------------------------------------

    public function testBrowserDetectsChrome()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        $this->assertSame('Chrome', $parser->browser());
    }

    public function testBrowserDetectsFirefox()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0');
        $this->assertSame('Firefox', $parser->browser());
    }

    public function testBrowserDetectsEdge()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0');
        $this->assertSame('Edge', $parser->browser());
    }

    public function testBrowserDetectsOpera()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0');
        $this->assertSame('Opera', $parser->browser());
    }

    public function testBrowserDetectsOperaMini()
    {
        $parser = new AgentParser('Opera/9.80 (J2ME/MIDP; Opera Mini/5.1.21214/28.2725; U; ru) Presto/2.8.119 Version/11.10');
        $this->assertSame('Opera Mini', $parser->browser());
    }

    public function testBrowserDetectsSafari()
    {
        $parser = new AgentParser('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15');
        $this->assertSame('Safari', $parser->browser());
    }

    public function testBrowserDetectsIE()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko');
        $this->assertSame('IE', $parser->browser());
    }

    public function testBrowserDetectsVivaldi()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5');
        $this->assertSame('Vivaldi', $parser->browser());
    }

    public function testBrowserDetectsUCBrowser()
    {
        $parser = new AgentParser('Mozilla/5.0 (Linux; U; Android 9; en-US; SM-G960F Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/78.0.3904.108 UCBrowser/13.4.0.1306 Mobile Safari/537.36');
        $this->assertSame('UCBrowser', $parser->browser());
    }

    public function testBrowserDetectsCocCoc()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) coc_coc_browser/99.0 Chrome/93.0.4577.82 Safari/537.36');
        $this->assertSame('Coc Coc', $parser->browser());
    }

    public function testBrowserReturnsFalseForUnknown()
    {
        $parser = new AgentParser('totally-unknown-agent');
        $this->assertFalse($parser->browser());
    }

    // -------------------------------------------------------------------------
    // platform() — must return string|false
    // -------------------------------------------------------------------------

    public function testPlatformDetectsWindows()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0');
        $this->assertSame('Windows', $parser->platform());
    }

    public function testPlatformDetectsOSX()
    {
        $parser = new AgentParser('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15');
        $this->assertSame('OS X', $parser->platform());
    }

    public function testPlatformDetectsLinux()
    {
        $parser = new AgentParser('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0');
        $this->assertSame('Linux', $parser->platform());
    }

    public function testPlatformDetectsAndroid()
    {
        $parser = new AgentParser('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36');
        $this->assertSame('AndroidOS', $parser->platform());
    }

    public function testPlatformDetectsIOS()
    {
        $parser = new AgentParser('Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1');
        $this->assertSame('iOS', $parser->platform());
    }

    public function testPlatformDetectsChromeOS()
    {
        $parser = new AgentParser('Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 Chrome/120.0.0.0');
        $this->assertSame('ChromeOS', $parser->platform());
    }

    public function testPlatformDetectsUbuntu()
    {
        $parser = new AgentParser('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0');
        $this->assertSame('Ubuntu', $parser->platform());
    }

    public function testPlatformReturnsFalseForUnknown()
    {
        $parser = new AgentParser('totally-unknown-agent');
        $this->assertFalse($parser->platform());
    }

    // -------------------------------------------------------------------------
    // robot() / isRobot() — uses jaybizzle/crawler-detect, returns string|false
    // -------------------------------------------------------------------------

    public function testIsRobotDetectsGooglebot()
    {
        $parser = new AgentParser('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        $this->assertTrue($parser->isRobot());
    }

    public function testRobotReturnsNameForGooglebot()
    {
        $parser = new AgentParser('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        $robot = $parser->robot();
        $this->assertIsString($robot);
        $this->assertNotEmpty($robot);
    }

    public function testIsRobotDetectsBingbot()
    {
        $parser = new AgentParser('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)');
        $this->assertTrue($parser->isRobot());
    }

    public function testIsRobotDetectsAhrefsBot()
    {
        $parser = new AgentParser('Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)');
        $this->assertTrue($parser->isRobot());
    }

    public function testIsRobotReturnsFalseForChrome()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        $this->assertFalse($parser->isRobot());
    }

    public function testRobotReturnsFalseForRealBrowser()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        $this->assertFalse($parser->robot());
    }

    public function testRobotReturnsUcfirstMatch()
    {
        $parser = new AgentParser('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        $robot = $parser->robot();
        $this->assertIsString($robot);
        // ucfirst is applied to the match, first char should be uppercase
        $this->assertSame(ucfirst($robot), $robot);
    }

    // -------------------------------------------------------------------------
    // isMobile() / isTablet() / isDesktop()
    // -------------------------------------------------------------------------

    public function testIsMobileForIPhone()
    {
        $parser = new AgentParser('Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1');
        $this->assertTrue($parser->isMobile());
    }

    public function testIsMobileFalseForDesktop()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        $this->assertFalse($parser->isMobile());
    }

    public function testIsTabletForIPad()
    {
        $parser = new AgentParser('Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1');
        $this->assertTrue($parser->isTablet());
    }

    public function testIsDesktopForWindowsChrome()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        $this->assertTrue($parser->isDesktop());
    }

    public function testIsDesktopFalseForMobile()
    {
        $parser = new AgentParser('Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15');
        $this->assertFalse($parser->isDesktop());
    }

    public function testIsDesktopFalseForRobot()
    {
        $parser = new AgentParser('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        $this->assertFalse($parser->isDesktop());
    }

    // -------------------------------------------------------------------------
    // is() — property matching
    // -------------------------------------------------------------------------

    public function testIsMatchesBrowserName()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36');
        $this->assertTrue($parser->is('Chrome'));
    }

    public function testIsMatchesPlatformName()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
        $this->assertTrue($parser->is('Windows'));
    }

    public function testIsReturnsFalseForNonMatch()
    {
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0');
        $this->assertFalse($parser->is('Firefox'));
    }

    public function testIsFallbackRegex()
    {
        $parser = new AgentParser('SomeCustomAgent/1.0 CustomProperty');
        $this->assertTrue($parser->is('CustomProperty'));
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    public function testEmptyUserAgent()
    {
        $parser = new AgentParser('');
        $this->assertSame('', $parser->getUserAgent());
        $this->assertFalse($parser->browser());
        $this->assertFalse($parser->platform());
        $this->assertFalse($parser->robot());
        $this->assertFalse($parser->isRobot());
        $this->assertFalse($parser->isMobile());
        $this->assertFalse($parser->isTablet());
    }

    public function testBrowserPriorityOperaBeforeChrome()
    {
        // Opera UA contains Chrome — Opera should be detected first
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0');
        $this->assertSame('Opera', $parser->browser());
    }

    public function testBrowserPriorityEdgeBeforeChrome()
    {
        // Edge UA contains Chrome — Edge should be detected first
        $parser = new AgentParser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0');
        $this->assertSame('Edge', $parser->browser());
    }

    public function testAndroidMobileDetection()
    {
        $parser = new AgentParser('Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36');
        $this->assertTrue($parser->isMobile());
        $this->assertFalse($parser->isDesktop());
        $this->assertSame('AndroidOS', $parser->platform());
    }

    public function testMultipleRobotsDetected()
    {
        $bots = [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
            'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
            'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
            'Twitterbot/1.0',
        ];

        foreach ($bots as $botUA) {
            $parser = new AgentParser($botUA);
            $this->assertTrue($parser->isRobot(), "Failed to detect robot: {$botUA}");
            $this->assertNotFalse($parser->robot(), "robot() returned false for: {$botUA}");
        }
    }

    public function testMaliciousUserAgentEmpty()
    {
        $parser = new AgentParser('-');
        $this->assertFalse($parser->browser());
        $this->assertFalse($parser->platform());
    }
}

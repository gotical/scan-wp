<?php
/**
 * RLS_Firewall
 * Модуль WAF. Версия 1.7.0
 * Обновлено: Интегрирована полная база плохих ботов из старого скрипта.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'RLS_Stats_Helper' ) ) {
    class RLS_Stats_Helper {
        public static function increment_stat( $counter_key, $value = 1 ) {
            $stats = get_option( 'rls_stats', [] );
            if ( ! is_array( $stats ) ) $stats = [];
            if ( ! isset( $stats[ $counter_key ] ) ) $stats[ $counter_key ] = 0;
            $stats[ $counter_key ] += $value;
            if ( ! isset( $stats['firewall_blocked'] ) ) $stats['firewall_blocked'] = 0;
            $stats['firewall_blocked'] += $value;
            update_option( 'rls_stats', $stats, false );
        }
    }
}

class RLS_Firewall {
    
    const BLOCK_DURATION       = 3600;
    const MAX_REQUESTS_PER_MIN = 150;
    
    const OPT_BLOCKED_IPS      = 'rls_blocked_ips';
    const OPT_MANUAL_BLACKLIST = 'rls_manual_blacklist';
    const OPT_GLOBAL_BLACKLIST = 'rls_global_blacklist';
    const OPT_WHITELIST        = 'rls_ip_whitelist';
    
    const PATTERNS = [
        'sql_injection' => [
            'patterns' => [ 'union\s+(all\s+)?select', 'information_schema', 'concat\s*\(', 'waitfor\s+delay', 'benchmark\s*\(', 'sleep\s*\(', 'into\s+outfile', ';\s*drop\s+table', 'updatexml\s*\(', 'extractvalue\s*\(', '0x[0-9a-f]{2,}' ],
            'reason' => 'SQL Injection'
        ],
        'code_execution' => [
            'patterns' => [ 'base64_decode\s*\(', 'eval\s*\(', 'system\s*\(', 'shell_exec', 'passthru\s*\(', 'proc_open', 'pcntl_exec', 'phpinfo\s*\(', '<\?php', 'input_file', 'mosConfig_' ],
            'reason' => 'RCE Attempt'
        ],
        'xss' => [
            'patterns' => [ '<script', 'javascript:', 'vbscript:', 'onload\s*=', 'onerror\s*=', '<iframe', '<object', 'alert\s*\(' ],
            'reason' => 'XSS Attack'
        ],
        'lfi' => [
            'patterns' => [ '\.\.\/', '\/etc\/passwd', 'win\.ini', '\.\.%2f', '\\x00', '%00' ],
            'reason' => 'Path Traversal'
        ]
    ];
    
    private $client_ip = '';
    private $user_agent = '';
    private $request_uri = '';
    
    public function init() {
        add_action( 'plugins_loaded', [ $this, 'run_firewall' ], 0 );
        add_action( 'send_headers', [ $this, 'send_security_headers' ] );
        add_action( 'template_redirect', [ $this, 'check_404_probing' ] );
        add_action( 'init', [ $this, 'check_xmlrpc' ], 1 );
    }
    
    public function send_security_headers() {
        if ( headers_sent() ) return;
        $settings = get_option( 'rls_settings', [] );
        if ( empty( $settings['enable_firewall'] ) ) return;

        @header( 'X-Frame-Options: SAMEORIGIN' );
        @header( 'X-Content-Type-Options: nosniff' );
        @header( 'X-XSS-Protection: 1; mode=block' );
        @header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        if ( is_ssl() ) @header( 'Strict-Transport-Security: max-age=31536000' );
        @header( 'X-Powered-By: Rybinsk Lab Security' );
    }

    public function run_firewall() {
        $this->client_ip   = $this->get_universal_ip();
        $this->user_agent  = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->request_uri = $_SERVER['REQUEST_URI'] ?? '';

        if ( $this->is_ip_whitelisted() ) return;

        $settings = get_option( 'rls_settings', [] );
        if ( empty( $settings['enable_firewall'] ) ) return;

        if ( current_user_can( 'manage_options' ) && ! $this->is_manually_banned() ) return;

        $block_reason = $this->check_blacklists();
        if ( $block_reason ) $this->trigger_block( $block_reason );

        if ( $this->check_rate_limit() ) $this->block_ip( "Превышен лимит запросов (Anti-DDoS)" );

        // 1. Сначала проверяем на хороших ботов (Whitelisting)
        $bot_status = $this->verify_search_bot();
        if ( $bot_status === 'fake' ) {
            $this->log_attack_type('bot');
            $this->block_ip( "Fake Googlebot/Yandexbot detected" );
        } elseif ( $bot_status === 'verified' ) {
            // Если бот подтвержден (настоящий Google), мы не проверяем его по списку плохих ботов
            return;
        }

        // 2. Если не подтвержденный хороший бот - проверяем по черному списку User-Agents
        $this->check_bad_user_agents();
        
        $this->perform_deep_scan();
    }

    private function check_blacklists() {
        if ( $this->is_manually_banned() ) return "IP находится в черном списке администратора";
        if ( $this->is_auto_blocked() ) return "IP временно заблокирован за подозрительную активность";
        $global_list = get_option( self::OPT_GLOBAL_BLACKLIST, [] );
        if ( is_array( $global_list ) && in_array( $this->client_ip, $global_list ) ) return "IP заблокирован в глобальной базе угроз";
        return false;
    }

    private function is_ip_whitelisted() {
        $whitelist = get_option( self::OPT_WHITELIST, [] );
        return is_array( $whitelist ) && in_array( $this->client_ip, $whitelist );
    }

    private function is_manually_banned() {
        $manual_list = get_option( self::OPT_MANUAL_BLACKLIST, [] );
        return is_array( $manual_list ) && in_array( $this->client_ip, $manual_list );
    }

    private function is_auto_blocked() {
        $blocked = get_option( self::OPT_BLOCKED_IPS, [] );
        if ( isset( $blocked[ $this->client_ip ] ) ) {
            if ( time() > $blocked[ $this->client_ip ]['expires'] ) {
                unset( $blocked[ $this->client_ip ] );
                update_option( self::OPT_BLOCKED_IPS, $blocked, false );
                return false;
            }
            return true;
        }
        return false;
    }

    public function get_universal_ip() {
        $settings = get_option( 'rls_settings', [] );
        $trust_cf = ! empty( $settings['trust_cloudflare'] );
        if ( $trust_cf && isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            if ( filter_var( $_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP ) ) return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    public function check_xmlrpc() {
        $settings = get_option( 'rls_settings', [] );
        if ( $this->is_ip_whitelisted() ) return;
        if ( ! empty( $settings['disable_xmlrpc'] ) ) {
            if ( stripos( $_SERVER['SCRIPT_NAME'] ?? '', 'xmlrpc.php' ) !== false ) {
                $this->log_attack_type( 'bot' );
                if ( ! headers_sent() ) { header( 'HTTP/1.1 403 Forbidden' ); header( 'Content-Type: text/plain' ); }
                if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $this->get_universal_ip(), 'bot', 'XML-RPC Access Denied' );
                die( 'XML-RPC Access Denied by Rybinsk Lab Security' );
            }
        }
    }
    
    public function check_404_probing() {
        if ( ! is_404() ) return;
        $uri = $_SERVER['REQUEST_URI'];
        $suspicious_exts = [ '.zip', '.tar.gz', '.tgz', '.sql', '.bak', '.env', '.log', '.ini', '.old', '.git', '.svn' ];
        $suspicious_files = [ 'wp-config.php', 'xmlrpc.php', 'adminer.php', 'db.php', 'shell.php', 'backup.php', 'install.php' ];
        
        $is_attack = false;
        foreach ( $suspicious_exts as $ext ) { if ( stripos( $uri, $ext ) !== false ) { $is_attack = true; break; } }
        if ( ! $is_attack ) { foreach ( $suspicious_files as $file ) { if ( stripos( $uri, $file ) !== false ) { $is_attack = true; break; } } }

        if ( $is_attack ) {
            $this->log_attack_type( 'bot' ); 
            $this->block_ip( "Probing Trap: " . esc_html( $uri ) );
        }
    }

    private function log_attack_type( $type ) {
        if ( class_exists( 'RLS_Stats_Helper' ) ) RLS_Stats_Helper::increment_stat( 'details_' . $type );
    }

    private function check_rate_limit() {
        if ( preg_match( '/\.(jpg|jpeg|png|gif|css|js|ico|svg|webp)$/i', $this->request_uri ) ) return false;
        $transient_key = 'rls_lim_' . md5( $this->client_ip );
        $count = get_transient( $transient_key );
        if ( false === $count ) set_transient( $transient_key, 1, 60 );
        else {
            if ( $count > self::MAX_REQUESTS_PER_MIN ) return true;
            set_transient( $transient_key, $count + 1, 60 );
        }
        return false;
    }

    private function verify_search_bot() {
        $ua = strtolower( $this->user_agent );
        $is_google = strpos( $ua, 'googlebot' ) !== false;
        $is_yandex = strpos( $ua, 'yandexbot' ) !== false;
        $is_bing   = strpos( $ua, 'bingbot' ) !== false;
        if ( ! $is_google && ! $is_yandex && ! $is_bing ) return 'unknown';

        $cache_key = 'rls_bot_' . md5( $this->client_ip );
        $status = get_transient( $cache_key );
        if ( $status ) return $status;

        $hostname = @gethostbyaddr( $this->client_ip );
        $status = 'fake';
        if ( $hostname ) {
            if ( $is_google && preg_match( '/\.google(bot)?\.com$/i', $hostname ) ) $status = 'verified';
            elseif ( $is_yandex && preg_match( '/(\.yandex\.(ru|com|net)|\.yandex\.net)$/i', $hostname ) ) $status = 'verified';
            elseif ( $is_bing && preg_match( '/\.search\.msn\.com$/i', $hostname ) ) $status = 'verified';
        }
        set_transient( $cache_key, $status, DAY_IN_SECONDS );
        return $status;
    }

    private function perform_deep_scan() {
        $this->scan_value( rawurldecode( $this->request_uri ), 'URI' );
        if ( ! empty( $_POST ) ) $this->scan_array( $_POST, 'POST' );
        if ( ! empty( $_COOKIE ) ) $this->scan_array( $_COOKIE, 'COOKIE' );
    }

    private function scan_array( $arr, $ctx, $depth = 0 ) {
        if ( $depth > 5 ) return;
        foreach ( $arr as $k => $v ) {
            $this->scan_value( (string)$k, "$ctx Key" );
            if ( is_array( $v ) ) $this->scan_array( $v, $ctx, $depth + 1 );
            else $this->scan_value( (string)$v, "$ctx Value" );
        }
    }

    private function scan_value( $val, $ctx ) {
        if ( empty( $val ) || ! is_string( $val ) ) return;
        $val_lower = strtolower( $val );
        foreach ( self::PATTERNS as $type => $cfg ) {
            foreach ( $cfg['patterns'] as $ptn ) {
                if ( @preg_match( '/' . $ptn . '/i', $val_lower ) ) {
                    $stat_type = 'unknown';
                    if ( $type === 'sql_injection' ) $stat_type = 'sqli';
                    elseif ( $type === 'xss' ) $stat_type = 'xss';
                    elseif ( $type === 'code_execution' ) $stat_type = 'rce';
                    elseif ( $type === 'lfi' ) $stat_type = 'lfi';
                    $this->log_attack_type( $stat_type );
                    $this->block_ip( "Обнаружено: {$cfg['reason']} в $ctx" );
                }
            }
        }
    }

    /**
     * Проверка User-Agent по базе из старого скрипта
     */
    private function check_bad_user_agents() {
        $ua = $this->user_agent;
        
        // Базовая проверка
        if ( empty( $ua ) ) { 
            $this->log_attack_type('bot'); 
            $this->block_ip( "Empty User-Agent" ); 
        }

        if ( $_SERVER['REQUEST_METHOD'] === 'POST' && empty( $_SERVER['HTTP_REFERER'] ) ) {
            if ( strpos( $this->request_uri, 'wp-login.php' ) !== false || strpos( $this->request_uri, 'xmlrpc.php' ) !== false ) {
                $this->log_attack_type('bot');
                $this->block_ip( "POST request without Referer" );
            }
        }

        // Загружаем полный список подписей плохих ботов
        $bad_bots = $this->get_bad_bot_signatures();

        // Проверяем вхождение
        // stripos - регистронезависимый поиск (аналог strtolower + strpos)
        foreach ( $bad_bots as $bot ) {
            if ( stripos( $ua, $bot ) !== false ) {
                $this->log_attack_type('bot');
                $this->block_ip( "Bad Bot Detected: " . esc_html( $bot ) );
                // IP блокируется, скрипт завершается внутри block_ip -> trigger_block
            }
        }
    }

    private function block_ip( $reason ) {
        $blocked = get_option( self::OPT_BLOCKED_IPS, [] );
        $blocked[ $this->client_ip ] = [ 'reason' => $reason, 'expires' => time() + self::BLOCK_DURATION ];
        update_option( self::OPT_BLOCKED_IPS, $blocked, false );
        
        $type = 'waf'; 
        if ( stripos($reason, 'bot') !== false ) $type = 'bot';
        
        if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $this->client_ip, $type, $reason );
        
        $this->trigger_block( $reason );
    }

    private function trigger_block( $reason ) {
        if ( ! headers_sent() ) { status_header( 403 ); header( 'Content-Type: text/html; charset=utf-8' ); }
        $html = "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>
        <body style='font-family:sans-serif; text-align:center; padding:50px;'>
        <h1 style='color:#d63638;'>403 Access Denied</h1>
        <p>Ваш IP адрес был заблокирован системой безопасности.</p>
        <p style='background:#f0f0f1; display:inline-block; padding:10px; border-radius:5px;'>Причина: <strong>" . esc_html( $reason ) . "</strong></p>
        <p>IP: " . esc_html( $this->client_ip ) . "</p>
        <p style='color:#666; font-size:12px;'>Protected by Rybinsk Lab Security</p>
        </body></html>";
        wp_die( $html, "Access Denied", [ 'response' => 403 ] );
    }

    /**
     * Полный список плохих ботов из Legacy версии
     * Вынесен вниз для чистоты кода.
     */
    private function get_bad_bot_signatures() {
        return [
            "Abonti", "aggregator", "almaden", "Anarchie", "ASPSeek", "asterias", "autoemailspider", "Bandit", "BDCbot", "BackWeb", "BatchFTP", "BlackWidow", "BLEXBot", "Bolt", "Buddy",
            "BuiltBotTough", "Bullseye", "bumblebee", "BunnySlippers", "ca-crawler", "CazoodleBot", "CCBot", "Cegbfeieh", "CheeseBot", "CherryPicker", "ChinaClaw", "CICC", "Collector",
            "Copier", "CopyRightCheck", "cosmos", "Crescent", "Custo", "DIIbot", "discobot", "DittoSpyder", "DOC", "Download Ninja", "Drip", "DSurf", "EasouSpider", "eCatch", "ecxi",
            "EmailCollector", "EmailSiphon", "EmailWolf", "EroCrawler", "EirGrabber", "ExtractorPro", "EyeNetIE", "Fasterfox", "FeedBooster", "FlashGet", "Foobot", "FrontPage", "Genieo",
            "GetRight", "GetSmart", "GetWeb!", "gigabaz", "Go!Zilla", "Go-Ahead-Got-It", "gotit", "Grabber", "GrabNet", "Grafula", "grub-client", "Harvest", "hloader", "httplib",
            "HMView", "HTTrack", "httpdown", "humanlinks", "IDBot", "id-search", "ieautodiscovery", "InfoNaviRobot", "InterGET", "InternetLinkagent", "IstellaBot", "InternetSeer",
            "Iria", "IRLbot", "JennyBot", "JetCar", "JustView", "k2spider", "Kenjin Spider", "Keyword Density", "larbin", "LeechFTP", "LexiBot", "lftp", "libWeb", "libwww-perl",
            "likse", "Link*Sleuth", "LinkextractorPro", "linko", "LinkScan", "LinkWalker", "LNSpiderguy", "lwp-trivial", "Mag-Net", "magpie", "Mata Hari", "MaxPointCrawler",
            "MegaIndex", "Memo", "MFC_Tear_Sample", "Microsoft URL Control", "MIDown", "MIIxpc", "Mippin", "Missigua Locator", "Mister PiX", "moget", "MSIECrawler", "Navroad",
            "NearSite", "NetAnts", "NetMechanic", "NetSpider", "NICErsPRO", "Niki-Bot", "Ninja", "NPBot", "Nutch", "Octopus", "Offline Explorer", "Openfind data gathere",
            "Openfind", "PageGrabber", "panscient.com", "pavuk", "pcBrowser", "PeoplePal", "PHP5.{", "PHPCrawl", "PingALink", "PleaseCrawl", "Pockey", "ProPowerBot", "ProWebWalker",
            "psbot", "Pump", "Python-urllib", "QueryN Metasearch", "QRVA", "Reaper", "Recorder", "ReGet", "RepoMonkey", "Rippers", "SBIder", "Scooter", "Seeker", "Siphon", "SISTRIX",
            "sitecheck.Internetseer.com", "SiteSnagger", "SlySearch", "SmartDownload", "Snake", "SnapPreviewBot", "SpaceBison", "SpankBot", "spanner", "spbot", "Spinn3r", "sproose",
            "Steeler", "Stripper", "Sucker", "SuperBot", "SuperHTTP", "suzuran", "Szukacz", "tAkeOut", "Teleport", "TeleportPro", "Telesoft", "The Intraformant", "TheNomad",
            "TightTwatBot", "Titan", "toCrawlUrlDispatcher", "True_Robot", "turingos", "TurnitinBot", "UbiCrawler", "UnisterBot", "URLSpiderPro", "URLy Warning", "Vacuum",
            "VCI WebViewer VCI WebViewer", "VoidEYE", "webalta", "WebAuto", "Win32", "VCI", "WBSearchBot", "Web Downloader", "Web Image Collector", "WebBandit", "WebCollage",
            "WebCopier", "WebEMailExtrac", "WebEnhancer", "WebFetch", "WebGo", "WebHook", "WebLeacher", "WebmasterWorldForumBot", "WebMiner", "WebMirror", "WebReaper", "WebSauger",
            "Website Quester", "Webster Pro", "WebStripper", "WebZip", "Whacker", "Widow", "Wotcard", "Wget", "wsr-agent", "WWW-Collector-E", "WWW-Mechanize", "WWWOFFLE", "x-Tractor",
            "Xaldon", "Xenu", "Zao", "zermelo", "Zeus", "ZyBORG", "coccoc", "Incutio", "lmspider", "memoryBot", "serf", "uptime files", "craftbot", "Download Demon",
            "Express WebPictures", "Indy Library", "NetZIP", "Vampire", "Offline", "RealDownload", "Download", "Surfbot", "WebWhacker", "eXtractor", "WebSpider", "archiverloader",
            "clshttp", "cmswor", "curl", "diavol", "email", "extract", "flicky", "grab", "kmccrew", "miner", "nikto", "planetwork", "pycurl", "scan", "skygrid", "winhttp", "Scanner",
            "DigExt", "80legs", "Ezooms", "%0A", "%0D", "%27", "%3C", "%3E", "%00", "!susie", "_irc", "_works", "+select+", "+union+", "&lt;?", "3gse", "4all", "4anything", "a1 site",
            "a_browser", "abac", "abach", "abby", "aberja", "abilon", "abont", "aboutoil", "accept", "accoo", "accoon", "aceftp", "acme", "active", "address", "adopt", "adress",
            "advisor", "ahead", "aihit", "aipbot", "alarm", "albert", "alek", "alexa toolbar", "alltop", "alma", "alpha", "america online browser", "amfi", "amfibi", "andit", "anon",
            "ansearch", "answerbus", "answerchase", "antivirx", "apollo", "appie", "arach", "arian", "asps", "atari", "atlocal", "atrax", "atrop", "attrib", "autoh", "autohot",
            "av fetch", "avsearch", "axod", "axon", "baboom", "baby", "back", "bali", "barry", "basichttp", "batch", "bdfetch", "beat", "beaut", "become", "bee", "beij", "betabot",
            "biglotron", "bilgi", "binlar", "bison", "bitacle", "bitly", "blaiz", "blitz", "blogl", "blogscope", "blogzice", "bloob", "bond", "bord", "boris", "bost", "bot.ara",
            "botje", "botw", "bpimage", "brok", "broth", "browseabit", "browsex", "bruin", "bsalsa", "bsdseek", "built", "bulls", "bumble", "bunny", "busca", "buy", "bwh3", "cafek",
            "cafi", "camel", "cand", "captu", "catch", "ccubee", "cd34", "ceg", "cgichk", "cha0s", "chang", "chaos", "char", "char(", "chase x", "check_http", "checker", "checkonly",
            "checkpriv", "chek", "chill", "chttpclient", "cipinet", "cisco", "cita", "citeseer", "clam", "claria", "claw", "cloak", "clush", "coast", "code.com", "cogent", "coldfusion",
            "coll", "collect", "comb", "combine", "commentreader", "common", "comodo", "compan", "conc", "conduc", "contact", "control", "contype", "conv", "copi", "copy", "coral",
            "corn", "costa", "cowbot", "cr4nk", "craft", "cralwer", "crank", "crap", "crawler0", "crazy", "cres", "cs-cz", "cshttp", "cuill", "curry", "cute", "cz3", "czx", "daily",
            "daobot", "dark", "daten", "dcbot", "dcs", "dds explorer", "deep", "deps", "diam", "dillo", "disp", "ditto", "dlc", "doco", "drec", "dsdl", "dsok", "dts", "dumb", "eag",
            "earn", "earthcom", "easydl", "ebin", "echo", "edco", "egoto", "elnsb5", "emer", "empas", "encyclo", "enfi", "enhan", "enterprise_search", "envolk", "erck", "erocr",
            "eventax", "evere", "evil", "ewh", "exploit", "expre", "extra", "eyen", "fang", "fastbug", "faxo", "fdse", "feed24", "feeddisc", "feedfinder", "feedhub", "filan",
            "fileboo", "fimap", "find", "firebat", "firedownload", "firefox0", "firs", "flam", "flash", "flexum", "fly", "fooky", "forum", "forv", "fost", "foto", "foun", "fount",
            "foxy1;", "friend", "fuck", "fuer", "futile", "fyber", "gais", "galbot", "gbpl", "geni", "geo", "geona", "geth", "getr", "getw", "ggl", "gira", "gluc", "gnome", "goforit",
            "goldfire", "gonzo", "gosearch", "got-it", "gozilla", "graf", "grub", "grup", "gsa-cra", "gsearch", "gt::www", "guidebot", "guruji", "gyps", "haha", "hailo", "harv", "hash",
            "hatena", "hax", "helm", "hgre", "hippo", "hmse", "holm", "holy", "hotbar", "hpprint", "httpconnect", "human", "huron", "hverify", "hybrid", "iaskspi", "ibm evv", "iccra",
            "ichiro", "icopy", "ics)", "ie5.0", "ieauto", "iempt", "iexplore.exe", "ilium", "ilse", "iltrov", "indexer", "indy", "ineturl", "infonav", "innerpr", "inspect", "insuran",
            "intellig", "internet_explorer", "internetx", "intraf", "ip2", "ipsel", "isc_sys", "isilo", "isrccrawler", "isspi", "jady", "jaka", "jam", "jenn", "jiro", "jobo", "joc",
            "jupit", "just", "jyx", "jyxo", "kash", "kazo", "kbee", "kenjin", "kernel", "keywo", "kfsw", "kkma", "kmc", "kosmix", "krae", "krug", "ksibot", "ktxn", "kum", "labs",
            "lanshan", "lapo", "leech", "lets", "lexi", "lexxe", "libby", "libcrawl", "libcurl", "libfetch", "linc", "lingue", "linkcheck", "linklint", "linkman", "lint", "list",
            "litefeeds", "livedoor", "livejournal", "liveup", "lmq", "loader", "locu", "london", "lone", "loop", "lork", "lth_", "lwp", "mac_f", "magi", "magp", "mail.ru", "majest",
            "mam", "mama", "marketwire", "masc", "mass", "mata", "mcbot", "mecha", "mechanize", "metadata", "metalogger", "metaspin", "metauri", "mete", "mib2.2", "microsoft.url",
            "microsoft_internet_explorer", "mido", "miggi", "miix", "mindjet", "mindman", "mips", "mira", "mire", "miss", "mist", "mizz", "mlbot", "mlm", "mnog", "moge", "moje", "mooz",
            "mouse", "mozdex", "mvi", "msie6xpv1", "msproxy", "msrbot", "musc", "mvac", "mwm", "my_age", "myapp", "mydog", "myeng", "myie2", "mysearch", "myurl", "name", "naver",
            "navr", "near", "netcach", "netcrawl", "netfront", "netinfo", "netmech", "netsp", "netx", "netz", "neural", "neut", "newsbreak", "newsgatorincard", "newsrob", "newt",
            "ng2", "nice", "nimb", "ninte", "nog", "noko", "nomad", "nuse", "nutex", "nwsp", "obje", "ocel", "octo", "odi3", "oegp", "offby", "omea", "omg", "omhttp", "onfo",
            "onyx", "openf", "openssl", "openu", "orac", "orbit", "oreg", "osis", "outf", "owl", "p3p_", "page2rss", "pagefet", "pansci", "patw", "pavu", "pb2pb", "pcbrow", "peer",
            "pepe", "perfect", "petit", "phoenix0.", "phras", "picalo", "piff", "pig", "pipe", "pirs", "plag", "planet", "plant", "platform", "plesk", "pluck", "plukkie", "poe-com",
            "poirot", "pomp", "postrank", "powerset", "privoxy", "probe", "program_shareware", "protect", "protocol", "prowl", "proxie", "pubsub", "pulse", "punit", "purebot", "purity",
            "pyq", "query", "qweer", "radian", "rambler", "ramp", "rapid", "rawdog", "rawgrunt", "reap", "reeder", "refresh", "relevare", "repo", "rese", "retrieve", "roboz", "rogue",
            "rpt-http", "rsscache", "ruby", "ruff", "rufus", "rv:0.9.7)", "salt", "sample", "sauger", "savvy", "sbcyds", "sblog", "sbp", "scagent", "scej_", "sched", "schizo", "schlong",
            "schmo", "scorp", "scott", "scout", "scrawl", "screen", "screenshot", "script", "search17", "searchbot", "searchme", "sega", "semto", "sensis", "seop", "seopro", "sept",
            "sharp", "shaz", "shell", "shelo", "sherl", "shim", "shopwiki", "silurian", "simple", "simplepie", "siph", "sitekiosk", "sitescan", "sitevigil", "sitex", "skam", "skimp",
            "sledink", "slide", "sly", "smag", "smurf", "snag", "snapbot", "snif", "snoop", "sock", "socsci", "sohu", "solr", "some", "soso", "spad", "span", "sphere", "spin", "spurl",
            "sputnik", "spyder", "squi", "sqwid", "sqworm", "ssm_ag", "stack", "stamp", "statbot", "state", "stilo", "strateg", "stress", "strip", "style", "subot", "such", "suck",
            "sume", "sunos 5.7", "sunrise", "superbro", "supervi", "surf4me", "survey", "susi", "suza", "suzu", "sweep", "swish", "sygol", "synapse", "sync2it", "systems", "tagger",
            "tagoo", "tagyu", "take", "talkro", "tamu", "tandem", "tarantula", "tcf", "tcs1", "teamsoft", "tecomi", "teesoft", "tencent", "terrawiz", "texnut", "thomas", "tiehttp",
            "timebot", "timely", "tipp", "tiscali", "tmcrawler", "tmhtload", "tocrawl", "todobr", "tongco", "toolbar; (r1", "topic", "topyx", "torrent", "track", "translate",
            "traveler", "treeview", "tricus", "trivia", "trivial", "true", "tunnel", "turing", "turnitin", "tutorgig", "twat", "tweak", "twice", "tygo", "ubee", "uchoo", "ultraseek",
            "unavail", "unf", "upg1", "urlbase", "urllib", "urly", "user-agent:", "useragent", "usyd", "vagabo", "valet", "vamp", "veri~li", "versus", "vikspi", "virtual", "visual",
            "void", "voyager", "vsyn", "w0000t", "w3search", "walhello", "walker", "wand", "waol", "watch", "wavefire", "wbdbot", "weather", "web2mal", "web.ima", "webbot", "webcat",
            "webcor", "webcorp", "webcrawl", "webdat", "webdup", "webind", "webis", "webitpr", "weblea", "webmin", "webmoney", "webp", "webql", "webrobot", "webster", "websurf",
            "webtre", "webvac", "card card-body bg-lights", "wep_s", "whiz", "win67", "windows-rss", "winht", "winodws", "wish", "wizz", "worio", "works", "worth", "wwwc", "wwwo",
            "wwwster", "xirq", "y!tunnel", "yacy", "yahoo-mmaudvid", "yahooseeker", "yahooysmcm", "yamm", "yang", "yoono", "yori", "yotta", "yplus ", "ytunnel", "zade", "zagre",
            "zeal", "zebot", "zerx", "zhuaxia", "zipcode", "zixy", "zmao", "zmeu", "zune", "backdoorbot", "black hole", "blowfish", "botalot", "cherrypicker",
            "crescent internet toolpak http ole control", "linkscan unix", "mozilla4.0 (compatible; bullseye; windows 95)", "repomonkey bait &amp; tacklev1",
            "vci webviewer vci webviewer win32", "xenu's", "xenu's link sleuth", "zeus webster pro", "8484_Boston_Project", "#[Ww]eb[Bb]andit", "Abacho", "acontbot", "AdoSpeaker",
            "ah-ha", "AIBOT", "#almaden", "Amfibibot", "Arachmo", "Arameda", "Arellis", "Argus", "attach", "BecomeBot", "BigCliqueBOT", "Bimbot", "boitho.com-dc",
            "Bot mailto:craftbot@yahoo.com", "BruinBot", "btbot", "CCGCrawl", "CipinetBot", "citenikbot", "ContextAd Bot", "contextadbot", "ConveraCrawler",
            "ConveraMultiMediaCrawler", "CostaCider", "CrawlConvera", "CrawlWave", "#Crescent", "CXL-FatAssANT", "DataCha0s", "DataFountains", "Deepindex",
            "devoll.roscard card-body bg-lightspringcatalog.info/spring-fashion-2003.html8/18/2006", "DiamondBot", "Digger", "DISCo Pump", "DM-Search", "Download Wonder",
            "Downloader", "Drecombot", "DTAagent", "EnfinBot", "Eule-Robot", "EuripBot", "fantomas", "Favcollector", "Faxobot", "FDM_2.x", "FileHound", "Firefox_1.0.6_kasparek",
            "Firefox_kastaneta", "First_Browse_of_COnn", "fluffy", "Franklin_Locator", "FyberSpider", "Gaisbot", "GalaxyBot", "gazz", "GenericBot-ax", "genevabot", "GeoBot",
            "Girafabot", "GOFORITBOT", "GornKer", "GroschoBot", "gsa-crawler", "HappyFunBot", "Healthbot", "holmes", "HooWWWer", "Hotzonu", "htdig", "Html_Link_Validator_",
            "http_sample", "HttpProxy", "httpunit", "IconSurf", "Iltrovatore-Setaccio", "Image Stripper", "Image Sucker", "#Indy Library", "InfociousBot", "INGRID", "InnerpriseBot",
            "Internet Ninja", "InternetSeer.com", "intraVnews", "IOneSearch.bot", "ISC_Systems_iRc_Search", "Jakarta_Commons-HttpClient", "Jayde Crawler", "JetBot", "JOC Web Spider",
            "KakleBot", "Kyluka", "lanshanbot", "LapozzBot", "Link_Valet_Online", "LinkAlarm", "LocalcomBot", "LWP::Simple", "Mac_Finder", "Mackster", "Magnet", "Mass Downloader",
            "Matrix", "Metaspinner", "Microsoft_URL_Control", "MIDown tool", "Mirago", "Missigua_Locator", "Mnogosearch", "MonkeyCrawl", "Mozilla.*NEWT", "Mozzilla", "MVAClient",
            "My_WinHTTP_Connection", "NaverBot", "NavissoBot", "Net Vampire", "NetMind-Minder", "NetMonitor", "Networking4all", "Newsgroupreporter_LinkCheck", "NextGenSearchBot",
            "nicebot", "NimbleCrawler", "NLCrawler", "noxtrumbot", "NuSearch Spider", "NutchCVS", "ObjectsSearch", "Ocelli", "Octora_Beta", "Offline Navigator", "OmniExplorer_Bot",
            "Omnipelagos", "online link validator", "Openbot", "Orbiter", "OutfoxBot", "page_verifier", "PageBitesHyperBot", "Pajaczek", "Papa Foto", "Patwebbot",
            "PEAR_HTTP_Request_class", "PEERbot", "PHP_version_tracker", "PhpDig", "pipeLiner", "POE-Component-Client-HTTP", "polybot", "Pompos", "Poodle_predictor",
            "Pooodle_predictor", "Popdexter", "Port_Huron_Labs", "psbot test for robots.txt", "psycheclone", "PyQuery", "QweeryBot", "RAMPyBot", "Random", "Ranking-Manager",
            "REL_Link_Checker_Lite", "robschecker", "RRG", "RufusBot", "SandCrawler", "SANSARN", "schibstedsokbot", "#scooter", "Screw-Ball", "Scrubby", "Search-10", "search.ch",
            "Searchmee!", "SearchSpider", "Seekbot", "Sensis Web Crawler", "Sensis.com.au Web Crawler", "Shim+Bot", "ShunixBot", "shybunnie-engine", "SideWinder", "SiteSpider",
            "#SlySearch test robots.txt", "sna-", "Snappy", "Snoopy", "sohu-search", "Speed-Meter", "SpeedySpider", "Spinne", "SpokeSpider", "Squid-Prefetch",
            "SquidClamAV_Redirector", "SquigglebotBot", "StackRambler", "sureseeker", "SurveyBot", "SygolBot", "SynoBot", "Teleport Pro", "TerrawizBot",
            "ThisIsOurYear_Linkchecker", "thumbshots-de-Bot", "Tkensaku", "topicblogs", "TridentSpider", "troovziBot", "TutorGigBot", "#ua", "unchaos_crawler", "Updated",
            "URL Spider Pro", "URL Spider SQL", "Vagabondo", "vBSEO_", "VoilaBot", "W3CRobot", "Web Sucker", "Web_Downloader", "webcrawl.net", "WebDataCentreBot", "WebEMailExtrac.*",
            "WebFindBot", "WebGather", "WebGo IS", "WebIndexer", "Webnavigator", "webPluck", "Website", "Website eXtractor", "card card-body bg-lights_Search_II", "WEP_Search",
            "WhizBang", "WISEbot", "WWWeasel", "Xaldon WebSpider", "Xenu_Link_Sleuth", "Xombot", "XunBot", "yacybot", "YadowsCrawler", "Yeti", "YodaoBot", "YottaShopping_Bot",
            "Zatka", "Zealbot", "Zeus.*Webster", "#Zeus_", "ZipppBot", "Alexibot", "Aqua_Products", "b2w", "Bookmark search tool", "Copernic", "dumbot", "FairAd Client",
            "Flaming AttackBot", "Hatena Antenna", "Iron33", "LinkScan/8.1a Unix", "LinkScan/8.1a Unix User-agent: Kenjin Spider", "Morfeus",
            "Mozilla/4.0 (compatible; BullsEye; Windows 95)", "Oracle Ultra Search", "PerMan", "Radiation Retriever", "RepoMonkey Bait & Tackle", "searchpreview", "sootle",
            "toCrawl/UrlDispatcher", "URL Control", "URL_Spider_Pro", "WebmasterWorld Extractor", "Zeus 32297 Webster Pro V2.9 Win32", "Zeus Link Scout", "<?", "1,1,1,",
            "2icommerce", "ActiveTouristBot", "adressendeutschland", "ADSARobot", "AESOP_com_SpiderMan", "Alligator", "AllSubmitter", "aktuelles", "Akregat", "amzn_assoc",
            "AnotherBot", "Apexoo", "ASPSe", "ASSORT", "ATHENS", "AtHome", "Atomic_Email_Hunter", "Atomz", "^attach", "autohttp", "BackStreet", "Badass", "BenchMark", "berts",
            "bew", "big.brother", "Bigfoot", "Biz360", "Black.Hole", "bladder.fusion", "Blog.Checker", "BlogPeople", "Blogshares.Spiders", "Bloodhound", "bmclient", "BOI",
            "boitho", "Bookmark.search.tool", "Boston.Project", "BotRightHere", "Bot.mailto:craftbot@yahoo.com", "botpaidtoclick", "brandwatch", "BravoBrian", "Bropwers",
            "Browsezilla", "c-spider", "char(32,35)", "charlotte", "Click.Bot", "clipping", "core-project", "cyberalert", "^DA$", "Daum", "Deweb", "Digimarc", "digout4uagent",
            "DnloadMage", "Doubanbot", "Download.Demon", "Download.Devil", "Download.Wonder", "DreamPassport", "DynaWeb", "e-collector", "EBM-APPLE", "ecollector", "edgeio",
            "efp@gmx.net", "Email.Extractor", "EmailSearch", "ESurf", "Eval", "Exact", "EXPLOITER", "FairAd", "Fake", "fastlwspider", "FavOrg", "Favorites.Sweeper", "FDM_1",
            "FEZhead", "Firefox.2.0", "FlickBot", "flunky", "Foob", "Forex", "Franklin.Locator", "freefind", "FreshDownload", "FSurf", "Gamespy_Arcade", "Get", "Ginxbot",
            "glx.?v", "Go.Zilla", "^gotit$", "Green.Research", "gvfs", "hack", "hhjhj@yahoo", "HomePageSearch", "HouxouCrawler", "http.generic", "HTTPGet", "HTTPRetriever",
            "IBM_Planetwide", "iGetter", "Image.Stripper", "Image.Sucker", "imagefetch", "iimds_monitor", "IncyWincy", "Industry.Program", "informant", "InfoTekies", "Ingelin",
            "InstallShield.DigitalWizard", "Insuran.", "Intelliseek", "Internet.Ninja", "Internet.x", "Irvine", "IUPUI.Research.Bot", "^Java", "java/", "Java(tm)", "JBH.agent",
            "Jenny", "JetB", "JetC", "jeteye", "Kapere", "KRetrieve", "ksoap", "KWebGet", "Lachesis", "leacher", "LeechGet", "leipzig.de", "libghttp", "libwhisker", "libwww-FM",
            "LightningDownload", "Link.Sleuth", "Linkie", "LINKS.ARoMATIZED", "linktiger", "lmcrawler", "looksmart", "lwp-request", "Mac.Finder", "Macintosh;.I;.PPC",
            "Mail.Sweeper", "MarcoPolo", "mark.blonin", "MarkWatch", "MaSagool", "Mass.Downloader", "mavi", "MCspider", "^Memo", "MEGAUPLOAD", "MetaProducts.Download.Express",
            "Missauga", "Missigua.Locator", "Missouri.College.Browse", "mkdb", "MMMoCrawl", "Monster", "Monza.Browser", "MOT-MPx220", "mothra/netscan", "MovableType", "Mozi!",
            "^Mozilla.*Indy", "^Mozilla.*NEWT", "^Mozilla*MSIECrawler", "Mp3Bot", "MS.FrontPage", "MS.?Search", "MSFrontPage", "multithreaddb", "MyFamilyBot", "MyGetRight",
            "NAMEPROTECT", "NASA.Search", "nationaldirectory", "netattache", "NetCarta", "Netcraft", "netprospector", "NetResearchServer", "Net.Vampire", "newLISP", "NEWT.ActiveX",
            "^NG", "NIPGCrawler", "Noga", "nogo", "Offline.Explorer", "Offline.Navigator", "OK.Mozilla", "Omni", "OpaL", "OpenTextSiteCrawler", "OrangeBot", "P3P", "PackRat",
            "PagmIEDownload", "Papa", "Pars", "PECL", "PersonaPilot", "Persuader", "PHP.vers", "PHPot", "Pige", "pigs", "^Ping", "playstarmusic", "Port.Huron",
            "Program.Shareware", "Progressive.Download", "prospector", "Provider.Protocol.Discover", "Prozilla", "PSurf", "^puf$", "PushSite", "PussyCat", "PuxaRapido",
            "QuepasaCreep", "Radiation", "RedCarpet", "RedKernel", "relevantnoise", "replacer", "Rover", "Rsync", "RTG30", ".ru)", "SAPO", "ScoutOut", "SearchExpress",
            "searchhippo", "searchterms", "Second.Street.Research", "Security.Kol", "Serious", "Shai", "Shiretoko", "SickleBot", "sitecheck", "SiteCrawler", "Site.Sniper",
            "SiteSucker", "Slurpy.Verifier", "So-net", "Spegla", "Sphider", "SpiderBot", "SpiderEngine", "SpiderView", "SQ.Webscanner", "Stamina", "Stanford", "studybot",
            "sun4m", "SurfWalker", "syncrisis", "TALWinHttpClient", "tarspider", "Tcs/1", "Templeton", "The.Intraformant", "TV33_Mercator", "Twisted.PageGetter", "UCmore",
            "UdmSearch", "UIowaCrawler", "UMBC", "UniversalFeedParser", "UtilMind", "URL.Control", "urldispatcher", "URLGetFile", "User-Agent", "vayala", "VB_", "visibilitygap",
            "vobsub", "vspider", "w:PACBHO60", "w3m", "WAPT", "web.by.mail", "Web.Data.Extractor", "Web.Downloader", "Web.Mole", "Web.Sucker", "Web2WAP", "WebaltBot",
            "WebCapture", "webcraft@bea", "Webclip", "WebCollector", "WebCopy", "WebDav", "webdevil", "webdownloader", "WebEMail", "Webinator", "WebFilter", "WebFountain",
            "webmole", "webpic", "WebPin", "WebPix", "WebRipper", "Website.eXtractor", "Website.Quester", "WebSnake", "websucker", "webwalk", "WebWasher", "WebWeasel",
            "WEP.Search.00", "WeRelateBot", "Whack", "WhosTalking", "window.location", "Wildsoft.Surfer", "WinHttpRequest", "WinHTTrack", "Winnie.Poh", "wisenutbot", "WUMPUS",
            "Wweb", "WWW-Collector", "WWW.Mechanize", "www.ranks.nl", "^x$", "X12R1", "XGET", "Y!OASIS", "YaDirectBot", "ZBot", "Zyborg", "choppy", "g00g1e", "seekerspider",
            "siclab", "sqlmap", "turnit", "xxxyy", "youda", "finder", "acapbot", "semalt", "AITCSRobot", "Arachnophilia", "aspider", "AURESYS", "BackRub", "Big Brother",
            "BizBot", "BSpider", "linklooker", "SafetyNet Robot", "CACTVS Chemistry Spider", "EnigmaBot", "Checkbot"
        ];
    }
}
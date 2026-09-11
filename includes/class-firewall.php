<?php
/**
 * RLS_Firewall
 * Модуль WAF. Версия 1.7.0
 * Обновлено: Интегрирована полная Р±Р°Р·Р° плохих ботов РёР· старого скрипта.
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
    const OPT_WAF_BLACKLIST    = 'rls_waf_blacklist';
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
    private $search_bot_status = null;

    const CLOUDFLARE_IPV4_CIDRS = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ];

    const CLOUDFLARE_IPV6_CIDRS = [
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];
    
    public function init() {
        // Вешаем на init, так как добавление callbacks на plugins_loaded изнутри
        // plugins_loaded может не выполниться в текущем запросе.
        add_action( 'init', [ $this, 'run_firewall' ], 0 );
        add_action( 'send_headers', [ $this, 'send_security_headers' ] );
        add_action( 'template_redirect', [ $this, 'check_404_probing' ] );
        add_action( 'init', [ $this, 'check_xmlrpc' ], 1 );
        add_action( 'init', [ $this, 'check_hotlink' ], 2 );
    }

    /**
     * Hotlink protection: prevent third-party sites from embedding wp-content/uploads
     * images directly. Always allow:
     *  - empty referrer (typing URL, bookmarks)
     *  - same-origin
     *  - hosts explicitly listed in hotlink_allowed_hosts (newline- or comma-separated)
     */
    public function check_hotlink() {
        $settings = get_option( 'rls_settings', [] );
        if ( empty( $settings['hotlink_protection'] ) ) return;
        if ( is_admin() || is_user_logged_in() ) return;

        $uri = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
        if ( ! is_string( $uri ) ) return;
        // Only guard the uploads directory.
        $uploads = wp_upload_dir();
        if ( empty( $uploads['basedir'] ) || empty( $uploads['baseurl'] ) ) return;
        $uploads_path = wp_parse_url( $uploads['baseurl'], PHP_URL_PATH );
        if ( ! is_string( $uploads_path ) || strpos( $uri, $uploads_path ) !== 0 ) return;

        $ref = $_SERVER['HTTP_REFERER'] ?? '';
        if ( $ref === '' ) return; // Direct load: allow.

        $host = wp_parse_url( $ref, PHP_URL_HOST );
        if ( ! is_string( $host ) || $host === '' ) return;
        $site_host = wp_parse_url( home_url(), PHP_URL_HOST );

        if ( $site_host && strcasecmp( $host, $site_host ) === 0 ) return;

        // Custom allowlist (comma/newline separated).
        $allowed = preg_split( '/[\s,]+/', (string) ( $settings['hotlink_allowed_hosts'] ?? '' ), -1, PREG_SPLIT_NO_EMPTY );
        foreach ( (array) $allowed as $h ) {
            if ( strcasecmp( $h, $host ) === 0 ) return;
        }

        // Block.
        if ( ! headers_sent() ) {
            status_header( 403 );
            header( 'Content-Type: image/png' );
        }
        // 1x1 transparent PNG.
        echo base64_decode( 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=' );
        exit;
    }
    
    public function send_security_headers() {
        if ( headers_sent() ) return;
        $settings = get_option( 'rls_settings', [] );
        if ( function_exists( 'rls_is_firewall_runtime_enabled' ) ) {
            if ( ! rls_is_firewall_runtime_enabled( $settings ) ) return;
        } elseif ( empty( $settings['enable_firewall'] ) ) {
            return;
        }

        @header( 'X-Frame-Options: SAMEORIGIN' );
        @header( 'X-Content-Type-Options: nosniff' );
        @header( 'X-XSS-Protection: 1; mode=block' );
        @header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        if ( is_ssl() ) @header( 'Strict-Transport-Security: max-age=31536000' );
        @header( 'X-Powered-By: Rybinsk Lab Security' );
    }

    public function run_firewall() {
        // Не фильтруем wp-admin/admin-ajax, чтобы не ломать админские операции
        // (сканер, настройки, импорт/экспорт и т.д.).
        if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
            return;
        }

        $this->client_ip   = $this->get_universal_ip();
        $this->user_agent  = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->request_uri = $_SERVER['REQUEST_URI'] ?? '';

        $this->handle_frontend_diagnostics();

        // Emergency mode: Panic / Lockdown short-circuit normal flow.
        if ( class_exists( 'RLS_Mode_Manager' ) ) {
            $emergency = RLS_Mode_Manager::get_active_emergency();
            if ( $emergency ) {
                $this->handle_emergency_mode( $emergency );
                return;
            }
        }

        if ( $this->is_ip_whitelisted() ) return;

        $settings = get_option( 'rls_settings', [] );
        if ( function_exists( 'rls_is_firewall_runtime_enabled' ) ) {
            if ( ! rls_is_firewall_runtime_enabled( $settings ) ) return;
        } elseif ( empty( $settings['enable_firewall'] ) ) {
            return;
        }

        $is_full_protection = ! function_exists( 'rls_is_full_protection_mode' ) || rls_is_full_protection_mode();
        $should_run_strict_bot_protection = function_exists( 'rls_should_run_strict_bot_protection' )
            ? rls_should_run_strict_bot_protection()
            : $is_full_protection;

        $is_privileged_admin = current_user_can( 'manage_options' ) && ! $this->is_manually_banned();

        if ( $is_full_protection ) {
            $lang_reason = $this->check_language_rules();
            if ( $lang_reason ) {
                $this->record_access_denied( 'language', $lang_reason, 'pending', 'language' );
                $this->trigger_block( $lang_reason );
            }
        }

        $manual_list_reason = $this->check_manual_blacklist_rules();
        if ( $manual_list_reason ) {
            $this->record_access_denied( 'blacklist', $manual_list_reason, 'pending', 'manual' );
            $this->trigger_block( $manual_list_reason );
        }

        if ( $is_full_protection ) {
            $geo_reason = $this->check_country_rules();
            if ( $geo_reason ) {
                $this->record_access_denied( 'geo', $geo_reason, 'pending', 'geo' );
                $this->trigger_block( $geo_reason );
            }
        }

        $search_bot_status = 'unknown';
        $global_list_reason = $this->check_global_blacklist_rule();
        if ( $global_list_reason ) {
            $search_bot_status = $this->get_search_bot_status();
        }
        if ( $global_list_reason && ! $this->should_bypass_global_blacklist_for_bot( $search_bot_status ) ) {
            $this->record_access_denied( 'blacklist', $global_list_reason, 'global', 'blacklist' );
            $this->trigger_block( $global_list_reason );
        }

        // Администратор не освобождается от GeoIP и blacklist проверок,
        // но может быть освобожден от "шумных" эвристик ниже.
        if ( $is_privileged_admin ) return;

        if ( $this->check_rate_limit() ) $this->block_ip( "Превышен лимит запросов (Anti-DDoS)" );

        // 1. Сначала проверяем РЅР° хороших ботов (Whitelisting)
        if ( $should_run_strict_bot_protection ) {
            if ( $search_bot_status === 'unknown' ) {
                $search_bot_status = $this->get_search_bot_status();
            }
            $bot_status = $search_bot_status;
            if ( $bot_status === 'fake' ) {
                if ( $this->is_allowed_yandex_dzen_feed_request() ) {
                    return;
                }
                if ( ! empty( $settings['soft_search_bot_mode'] ) || ! isset( $settings['soft_search_bot_mode'] ) ) {
                    $this->log_attack_type( 'bot' );
                    if ( class_exists( 'RLS_Logger' ) ) {
                        RLS_Logger::log_attack( $this->client_ip, 'bot', 'Soft mode: suspicious search bot allowed (DNS verification mismatch)' );
                    }
                    return;
                }
                $this->log_attack_type( 'bot' );
                $this->block_ip( 'Fake Googlebot/Yandexbot detected', 'bot' );
            } elseif ( $bot_status === 'verified' ) {
                return;
            }

            $this->check_bad_user_agents();
        }

        $this->perform_deep_scan();
        return;

    }

    private function are_local_blacklists_enabled() {
        $settings = get_option( 'rls_settings', [] );
        if ( isset( $settings['blacklists_enabled'] ) && (int) $settings['blacklists_enabled'] !== 1 ) {
            return false;
        }
        return true;
    }

    private function check_manual_blacklist_rules() {
        if ( ! $this->are_local_blacklists_enabled() ) {
            return false;
        }
        if ( $this->is_waf_blacklisted() ) return "IP находится в WAF черном списке";
        if ( $this->is_manual_blacklisted() ) return "IP находится в черном списке администратора";
        if ( $this->is_auto_blocked() ) return "IP временно заблокирован за подозрительную активность";
        return false;
    }

    private function check_global_blacklist_rule() {
        $settings = get_option( 'rls_settings', [] );
        if ( ! function_exists( 'rls_is_global_blacklist_runtime_enabled' ) || ! rls_is_global_blacklist_runtime_enabled( $settings ) ) {
            return false;
        }
        $global_list = get_option( self::OPT_GLOBAL_BLACKLIST, [] );
        if ( is_array( $global_list ) && in_array( $this->client_ip, $global_list ) ) return "IP заблокирован в глобальной базе угроз";
        return false;
    }

    private function check_language_rules() {
        $settings = get_option( 'rls_settings', [] );
        if ( empty( $settings['language_filter_enabled'] ) ) {
            return false;
        }

        $raw_codes = $settings['language_codes'] ?? [];
        if ( ! is_array( $raw_codes ) ) {
            $raw_codes = explode( ',', (string) $raw_codes );
        }
        $codes = [];
        foreach ( $raw_codes as $code ) {
            $lang = strtolower( preg_replace( '/[^a-z]/i', '', (string) $code ) );
            if ( preg_match( '/^[a-z]{2,3}$/', $lang ) ) {
                $codes[] = $lang;
            }
        }
        $codes = array_values( array_unique( $codes ) );
        if ( empty( $codes ) ) {
            return false;
        }

        $accept_language = isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ? strtolower( (string) $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) : '';
        if ( $accept_language === '' ) {
            return 'Языковой фильтр: отсутствует заголовок Accept-Language';
        }

        $browser_langs = [];
        foreach ( explode( ',', $accept_language ) as $part ) {
            $token = trim( explode( ';', $part )[0] ?? '' );
            if ( preg_match( '/^([a-z]{2,3})(-[a-z]{2,4})?$/', $token, $m ) ) {
                $browser_langs[] = $m[1];
            }
        }
        $browser_langs = array_values( array_unique( $browser_langs ) );
        if ( empty( $browser_langs ) ) {
            return 'Языковой фильтр: язык браузера не определен';
        }

        $mode = $settings['language_mode'] ?? 'allow';
        $mode = in_array( $mode, [ 'allow', 'block' ], true ) ? $mode : 'allow';

        $intersection = array_intersect( $browser_langs, $codes );
        if ( $mode === 'allow' && empty( $intersection ) ) {
            return 'Языковой фильтр: язык браузера не разрешен (' . implode( ',', $browser_langs ) . ')';
        }
        if ( $mode === 'block' && ! empty( $intersection ) ) {
            return 'Языковой фильтр: язык браузера в списке блокировки (' . implode( ',', $browser_langs ) . ')';
        }

        return false;
    }

    private function check_country_rules() {
        if ( ! class_exists( 'RLS_GeoIP' ) ) {
            return false;
        }
        $settings = get_option( 'rls_settings', [] );
        if ( empty( $settings['geo_blocking_enabled'] ) ) {
            return false;
        }

        $allow_list = $settings['geo_countries_allow'] ?? [];
        $block_list = $settings['geo_countries_block'] ?? [];
        $countries = $settings['geo_countries'] ?? [];
        if ( ! is_array( $allow_list ) ) $allow_list = [];
        if ( ! is_array( $block_list ) ) $block_list = [];
        if ( ! is_array( $countries ) ) $countries = [];
        if ( empty( $allow_list ) && empty( $block_list ) && empty( $countries ) ) {
            return false;
        }

        $mode = $settings['geo_mode'] ?? 'block';
        $mode = in_array( $mode, [ 'allow', 'block' ], true ) ? $mode : 'block';

        $country = RLS_GeoIP::lookup_country_code( $this->client_ip );
        if ( empty( $country ) ) {
            // Fail-open: на некоторых хостингах/прокси GeoIP может временно не определяться.
            // Чтобы не ломать доступ легитимным пользователям, не блокируем при unknown country.
            return false;
        }

        $country_uc = strtoupper( $country );
        $allow_list = array_map( 'strtoupper', (array) $allow_list );
        $block_list = array_map( 'strtoupper', (array) $block_list );

        // Backward compatibility with old single list.
        if ( empty( $allow_list ) && empty( $block_list ) && ! empty( $countries ) ) {
            if ( $mode === 'allow' ) {
                $allow_list = array_map( 'strtoupper', (array) $countries );
            } else {
                $block_list = array_map( 'strtoupper', (array) $countries );
            }
        }

        if ( $mode === 'block' && in_array( $country_uc, $block_list, true ) ) {
            return 'GeoIP: страна заблокирована (' . $country . ')';
        }
        if ( $mode === 'allow' && ! in_array( $country_uc, $allow_list, true ) ) {
            return 'GeoIP: страна не в списке разрешенных (' . $country . ')';
        }

        return false;
    }

    private function is_ip_whitelisted() {
        $whitelist = get_option( self::OPT_WHITELIST, [] );
        return is_array( $whitelist ) && in_array( $this->client_ip, $whitelist );
    }

    private function is_manual_blacklisted() {
        $manual_list = get_option( self::OPT_MANUAL_BLACKLIST, [] );
        return is_array( $manual_list ) && in_array( $this->client_ip, $manual_list, true );
    }

    private function is_waf_blacklisted() {
        $waf_list = get_option( self::OPT_WAF_BLACKLIST, [] );
        return is_array( $waf_list ) && in_array( $this->client_ip, $waf_list, true );
    }

    private function is_manually_banned() {
        return $this->is_manual_blacklisted() || $this->is_waf_blacklisted();
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
        $remote_addr = (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
        $remote_is_valid = filter_var( $remote_addr, FILTER_VALIDATE_IP ) !== false;
        $remote_is_private = $remote_is_valid
            && ! filter_var( $remote_addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );

        if ( $trust_cf && $remote_is_valid && $this->ip_in_cidrs( $remote_addr, array_merge( self::CLOUDFLARE_IPV4_CIDRS, self::CLOUDFLARE_IPV6_CIDRS ) ) ) {
            $cf_ip = (string) ( $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '' );
            if ( filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
                return $cf_ip;
            }
        }

        // За proxy-заголовки отвечают только доверенные промежуточные прокси
        // (обычно private REMOTE_ADDR от nginx/apache/haproxy).
        if ( $remote_is_private ) {
            $x_forwarded_for = (string) ( $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '' );
            if ( $x_forwarded_for !== '' ) {
                $parts = array_map( 'trim', explode( ',', $x_forwarded_for ) );
                foreach ( $parts as $candidate ) {
                    if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
                        return $candidate;
                    }
                }
            }

            $x_real_ip = (string) ( $_SERVER['HTTP_X_REAL_IP'] ?? '' );
            if ( filter_var( $x_real_ip, FILTER_VALIDATE_IP ) ) {
                return $x_real_ip;
            }
        }

        if ( $remote_is_valid ) {
            return $remote_addr;
        }

        return '0.0.0.0';
    }

    private function ip_in_cidrs( $ip, $cidrs ) {
        foreach ( $cidrs as $cidr ) {
            if ( $this->ip_in_cidr( $ip, $cidr ) ) {
                return true;
            }
        }
        return false;
    }

    private function ip_in_cidr( $ip, $cidr ) {
        $parts = explode( '/', $cidr, 2 );
        if ( count( $parts ) !== 2 ) {
            return false;
        }

        $range_ip = $parts[0];
        $prefix = (int) $parts[1];

        $bin_ip = @inet_pton( $ip );
        $bin_range = @inet_pton( $range_ip );
        if ( $bin_ip === false || $bin_range === false || strlen( $bin_ip ) !== strlen( $bin_range ) ) {
            return false;
        }

        $max_bits = strlen( $bin_ip ) * 8;
        if ( $prefix < 0 || $prefix > $max_bits ) {
            return false;
        }

        $bytes = (int) floor( $prefix / 8 );
        $bits = $prefix % 8;

        if ( $bytes > 0 && substr( $bin_ip, 0, $bytes ) !== substr( $bin_range, 0, $bytes ) ) {
            return false;
        }

        if ( $bits === 0 ) {
            return true;
        }

        $mask = 0xFF << ( 8 - $bits );
        $ip_byte = ord( $bin_ip[ $bytes ] );
        $range_byte = ord( $bin_range[ $bytes ] );

        return ( $ip_byte & $mask ) === ( $range_byte & $mask );
    }

    public function check_xmlrpc() {
        $settings = get_option( 'rls_settings', [] );
        if ( $this->is_ip_whitelisted() ) return;
        if ( function_exists( 'rls_is_scanner_only_mode' ) && rls_is_scanner_only_mode() ) return;
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
            $this->block_ip( "Probing Trap: " . esc_html( $uri ), 'bot' );
        }
    }

    private function log_attack_type( $type ) {
        if ( class_exists( 'RLS_Stats_Helper' ) ) RLS_Stats_Helper::increment_stat( 'details_' . $type );
    }

    private function record_access_denied( $type, $reason, $status = 'pending', $source_kind = null ) {
        if ( class_exists( 'RLS_Logger' ) ) {
            RLS_Logger::log_attack( $this->client_ip, $type, $reason );
        }

        if ( class_exists( 'RLS_API_Client' ) ) {
            $source_kind = is_string( $source_kind ) && $source_kind !== '' ? $source_kind : $type;
            if ( ! in_array( $source_kind, [ 'waf', 'brute', 'manual', 'geo', 'language', 'blacklist', 'bot' ], true ) ) {
                $source_kind = $type;
            }

            RLS_API_Client::submit_banned_ip( $this->client_ip, $reason, [
                'status' => $status,
                'source_kind' => $source_kind,
                'type' => $type,
            ] );
        }
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
        $is_yandex = preg_match( '/yandex(bot|images|image|video|media|news|blogs|favicons|metrika|direct|webmaster|mirrordetector)/i', $ua ) === 1;
        $is_mailru = preg_match( '/(mail\\.ru|mailru|go\\-mail\\.ru|mail\\.ru_bot)/i', $ua ) === 1;
        $is_bing   = strpos( $ua, 'bingbot' ) !== false;
        if ( ! $is_google && ! $is_yandex && ! $is_mailru && ! $is_bing ) return 'unknown';

        $settings = get_option( 'rls_settings', [] );
        if ( ( $is_google && empty( $settings['allow_googlebot'] ) ) ||
             ( $is_yandex && empty( $settings['allow_yandexbot'] ) ) ||
             ( $is_mailru && empty( $settings['allow_mailru_bot'] ) ) ||
             ( $is_bing && empty( $settings['allow_bingbot'] ) ) ) {
            return 'unknown';
        }

        $cache_key = 'rls_bot_' . md5( $this->client_ip );
        $status = get_transient( $cache_key );
        if ( $status ) return $status;

        $hostname = @gethostbyaddr( $this->client_ip );
        $status = 'unknown';
        if ( $hostname && $hostname !== $this->client_ip ) {
            if ( $is_google && preg_match( '/\.google(bot)?\.com$/i', $hostname ) ) $status = $this->hostname_resolves_to_client_ip( $hostname ) ? 'verified' : 'fake';
            elseif ( $is_yandex && preg_match( '/(\.yandex\.(ru|com|net)|\.yandex\.net)$/i', $hostname ) ) $status = $this->hostname_resolves_to_client_ip( $hostname ) ? 'verified' : 'fake';
            elseif ( $is_mailru && preg_match( '/(\.mail\.ru|\.go-mail\.ru)$/i', $hostname ) ) $status = $this->hostname_resolves_to_client_ip( $hostname ) ? 'verified' : 'fake';
            elseif ( $is_bing && preg_match( '/\.search\.msn\.com$/i', $hostname ) ) $status = $this->hostname_resolves_to_client_ip( $hostname ) ? 'verified' : 'fake';
        }
        set_transient( $cache_key, $status, DAY_IN_SECONDS );
        return $status;
    }

    private function get_search_bot_status() {
        if ( $this->search_bot_status !== null ) {
            return $this->search_bot_status;
        }

        $this->search_bot_status = $this->verify_search_bot();
        return $this->search_bot_status;
    }

    private function should_bypass_global_blacklist_for_bot( $bot_status ) {
        return $bot_status === 'verified';
    }

    private function hostname_resolves_to_client_ip( $hostname ) {
        if ( empty( $hostname ) || empty( $this->client_ip ) ) return false;
        $records = @gethostbynamel( $hostname );
        if ( is_array( $records ) && in_array( $this->client_ip, $records, true ) ) return true;
        $resolved_ip = @gethostbyname( $hostname );
        return is_string( $resolved_ip ) && $resolved_ip === $this->client_ip;
    }

    private function is_allowed_yandex_dzen_feed_request() {
        $ua = strtolower( $this->user_agent );
        $uri = strtolower( (string) $this->request_uri );

        if ( strpos( $uri, '/feed/dzen-posts/' ) === false ) {
            return false;
        }

        if ( strpos( $ua, 'yandex' ) === false ) {
            return false;
        }

        $method = strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) );
        return $method === 'GET' || $method === 'HEAD';
    }

    private function perform_deep_scan() {
        // На wp-login.php работает отдельный модуль защиты входа (RLS_Login_Security),
        // а WAF-проверка POST здесь может давать ложные SQLi/XSS срабатывания на паролях.
        if ( strpos( $this->request_uri, 'wp-login.php' ) !== false && ! empty( $_POST ) ) {
            return;
        }

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
                    $permanent_blacklist = in_array( $type, [ 'sql_injection', 'code_execution', 'xss', 'lfi' ], true );
                    $this->block_ip( "Обнаружено: {$cfg['reason']} в $ctx", 'waf', $permanent_blacklist );
                }
            }
        }
    }

    /**
     * Проверка User-Agent РїРѕ Р±Р°Р·Рµ РёР· старого скрипта
     */
    private function check_bad_user_agents() {
        if ( function_exists( 'rls_should_run_strict_bot_protection' ) && ! rls_should_run_strict_bot_protection() ) {
            return;
        }

        $ua = $this->user_agent;

        if ( $this->is_allowed_configured_bot() ) {
            return;
        }
        
        // Базовая проверка
        if ( empty( $ua ) ) { 
            if ( ! $this->is_api_or_service_endpoint_request() ) {
                $this->log_attack_type('bot'); 
                $this->block_ip( "Empty User-Agent", 'bot' ); 
            }
            return;
        }

        if ( $_SERVER['REQUEST_METHOD'] === 'POST' && empty( $_SERVER['HTTP_REFERER'] ) ) {
            if ( strpos( $this->request_uri, 'wp-login.php' ) !== false || strpos( $this->request_uri, 'xmlrpc.php' ) !== false ) {
                $this->log_attack_type('bot');
                $this->block_ip( "POST request without Referer", 'bot' );
            }
        }

        // Загружаем полный список подписей плохих ботов
        $bad_bots = $this->get_bad_bot_signatures();

        // Проверяем вхождение
        // stripos - регистронезависимый поиск (Р°РЅР°Р»РѕРі strtolower + strpos)
        foreach ( $bad_bots as $bot ) {
            if ( stripos( $ua, $bot ) !== false ) {
                $this->log_attack_type('bot');
                $this->block_ip( "Bad Bot Detected: " . esc_html( $bot ), 'bot' );
                // IP блокируется, скрипт завершается внутри block_ip -> trigger_block
            }
        }
    }

    private function is_allowed_configured_bot() {
        $settings = get_option( 'rls_settings', [] );
        $ua = strtolower( $this->user_agent );

        $map = [
            'allow_googlebot'      => 'googlebot',
            'allow_yandexbot'      => 'yandex',
            'allow_mailru_bot'     => 'mail.ru',
            'allow_bingbot'        => 'bingbot',
            'allow_duckduckbot'   => 'duckduckbot',
            'allow_baiduspider'   => 'baiduspider',
            'allow_applebot'      => 'applebot',
            'allow_slurp'         => 'slurp',
            'allow_seznambot'     => 'seznambot',
            'allow_naverbot'      => 'naverbot',
            'allow_petalbot'      => 'petalbot',
            'allow_sogou'         => 'sogou',
            'allow_exabot'        => 'exabot',
            'allow_qwantbot'      => 'qwantify',
            'allow_mojeekbot'     => 'mojeekbot',
            'allow_gptbot'        => 'gptbot',
            'allow_chatgpt_user'  => 'chatgpt-user',
            'allow_oai_searchbot' => 'oai-searchbot',
            'allow_claudebot'     => 'claudebot',
            'allow_perplexitybot' => 'perplexitybot',
            'allow_cohere_ai'     => 'cohere-ai',
            'allow_amazonbot'     => 'amazonbot',
            'allow_ccbot'         => 'ccbot',
            'allow_bytespider'    => 'bytespider',
        ];

        foreach ( $map as $setting_key => $needle ) {
            if ( ! empty( $settings[ $setting_key ] ) && strpos( $ua, $needle ) !== false ) {
                return true;
            }
        }

        return false;
    }

    private function is_api_or_service_endpoint_request() {
        $uri = strtolower( (string) $this->request_uri );
        $method = strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) );

        if ( $method === 'HEAD' ) return true;
        if ( strpos( $uri, '/wp-json/' ) !== false ) return true;
        if ( strpos( $uri, 'rest_route=' ) !== false ) return true;
        if ( strpos( $uri, '/feed/' ) !== false ) return true;

        return false;
    }

    /**
     * Handle active emergency mode (Panic / Lockdown).
     * Always allows wp-admin for whitelisted admin IPs and login attempts.
     */
    private function handle_emergency_mode( $emergency ) {
        $ip = $this->client_ip;

        // Allow whitelisted IPs to bypass emergency mode.
        if ( $this->is_ip_whitelisted() ) return;

        $whitelist = (array) get_option( 'rls_settings', [] );
        $whitelist_ips = (array) ( $whitelist['emergency_panic_whitelist'] ?? [] );
        if ( in_array( $ip, $whitelist_ips, true ) ) return;

        if ( $emergency['mode'] === 'panic' ) {
            // Panic: block all non-admin requests.
            $uri = $this->request_uri;
            $is_admin_path = ( strpos( $uri, '/wp-admin' ) !== false || strpos( $uri, '/wp-login.php' ) !== false );
            if ( ! $is_admin_path ) {
                status_header( 503 );
                header( 'X-RLS-Emergency: panic' );
                header( 'Retry-After: 3600' );
                nocache_headers();
                exit;
            }
            return;
        }

        if ( $emergency['mode'] === 'lockdown' ) {
            // Lockdown: only allow wp-admin, block everything else.
            $uri = $this->request_uri;
            $is_admin_path = ( strpos( $uri, '/wp-admin' ) !== false || strpos( $uri, '/wp-login.php' ) !== false );
            if ( ! $is_admin_path ) {
                status_header( 503 );
                header( 'X-RLS-Emergency: lockdown' );
                header( 'Retry-After: 7200' );
                nocache_headers();
                exit;
            }
            return;
        }
    }

    private function block_ip( $reason, $type = null, $permanent = false ) {
        $blocked = get_option( self::OPT_BLOCKED_IPS, [] );
        $blocked[ $this->client_ip ] = [ 'reason' => $reason, 'expires' => time() + self::BLOCK_DURATION ];
        update_option( self::OPT_BLOCKED_IPS, $blocked, false );
        
        if ( ! is_string( $type ) || $type === '' ) {
            $type = stripos( $reason, 'bot' ) !== false ? 'bot' : 'waf';
        }

        if ( $permanent ) {
            $waf_blacklist = get_option( self::OPT_WAF_BLACKLIST, [] );
            if ( ! is_array( $waf_blacklist ) ) {
                $waf_blacklist = [];
            }

            if ( ! in_array( $this->client_ip, $waf_blacklist, true ) ) {
                $waf_blacklist[] = $this->client_ip;
                update_option( self::OPT_WAF_BLACKLIST, $waf_blacklist, false );
            }
        }
        
        if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $this->client_ip, $type, $reason );
        if ( class_exists( 'RLS_API_Client' ) ) {
            $source_kind = 'waf';
            if ( $type === 'brute' ) {
                $source_kind = 'brute';
            } elseif ( $type === 'manual' ) {
                $source_kind = 'manual';
            }

            RLS_API_Client::submit_banned_ip( $this->client_ip, $reason, [
                'status' => $permanent ? 'global' : 'pending',
                'source_kind' => $source_kind,
                'type' => $type,
            ] );
        }
        
        $this->trigger_block( $reason );
    }

    private function trigger_block( $reason ) {
        if ( ! headers_sent() ) { status_header( 403 ); header( 'Content-Type: text/html; charset=utf-8' ); }
        $html = "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>
        <body style='font-family:sans-serif; text-align:center; padding:50px;'>
        <h1 style='color:#d63638;'>403 Access Denied</h1>
        <p>Ваш IP-адрес был заблокирован системой безопасности.</p>
        <p style='background:#f0f0f1; display:inline-block; padding:10px; border-radius:5px;'>Причина: <strong>" . esc_html( $reason ) . "</strong></p>
        <p>IP: " . esc_html( $this->client_ip ) . "</p>
        <p style='color:#666; font-size:12px;'>Protected by Rybinsk Lab Security</p>
        </body></html>";
        wp_die( $html, "Access Denied", [ 'response' => 403 ] );
    }

    private function handle_frontend_diagnostics() {
        $is_admin_debug  = isset( $_GET['rls_geo_test'] ) && current_user_can( 'manage_options' );
        $is_public_debug = isset( $_GET['rls_fw_test'] );

        if ( ! $is_admin_debug && ! $is_public_debug ) {
            return;
        }

        // SECURITY: rate-limit the public debug endpoint to prevent IP/GeoIP fingerprinting.
        if ( $is_public_debug ) {
            $key = 'rls_pub_dbg_' . md5( $this->client_ip );
            if ( get_transient( $key ) ) {
                status_header( 429 );
                exit;
            }
            set_transient( $key, 1, MINUTE_IN_SECONDS );
        }

        $settings = get_option( 'rls_settings', [] );
        $country = class_exists( 'RLS_GeoIP' ) ? RLS_GeoIP::lookup_country_code( $this->client_ip ) : '';
        $geo_db_path = class_exists( 'RLS_GeoIP' ) ? RLS_GeoIP::get_database_path() : '';
        $is_whitelisted = $this->is_ip_whitelisted();
        $firewall_enabled = ! empty( $settings['enable_firewall'] );
        $is_full_protection = ! function_exists( 'rls_is_full_protection_mode' ) || rls_is_full_protection_mode();
        $should_run_strict_bot_protection = function_exists( 'rls_should_run_strict_bot_protection' )
            ? rls_should_run_strict_bot_protection()
            : $is_full_protection;
        $global_blacklist_bypassed = false;

        $lang_reason = $this->check_language_rules();
        $manual_list_reason = $this->check_manual_blacklist_rules();
        $geo_reason = $this->check_country_rules();
        $global_list_reason = $this->check_global_blacklist_rule();
        $search_bot_status = ( $global_list_reason || $should_run_strict_bot_protection ) ? $this->get_search_bot_status() : 'unknown';

        $would_block_reason = '';
        if ( $is_whitelisted ) {
            $would_block_reason = '';
        } elseif ( ! $firewall_enabled ) {
            $would_block_reason = '';
        } elseif ( ! empty( $lang_reason ) ) {
            $would_block_reason = $lang_reason;
        } elseif ( ! empty( $manual_list_reason ) ) {
            $would_block_reason = $manual_list_reason;
        } elseif ( ! empty( $geo_reason ) ) {
            $would_block_reason = $geo_reason;
        } elseif ( ! empty( $global_list_reason ) ) {
            if ( $this->should_bypass_global_blacklist_for_bot( $search_bot_status ) ) {
                $global_blacklist_bypassed = true;
            } else {
                $would_block_reason = $global_list_reason;
            }
        }

        $base_payload = [
            'time' => gmdate( 'c' ),
            'resolved_ip' => $this->client_ip,
            'country' => $country,
            'geo_db_path' => $geo_db_path,
            'geo_db_exists' => ( $geo_db_path && is_file( $geo_db_path ) ),
            'firewall_enabled' => $firewall_enabled,
            'is_whitelisted' => $is_whitelisted,
            'would_block' => ( $would_block_reason !== '' ),
            'would_block_reason' => $would_block_reason,
            'search_bot_status' => $search_bot_status,
            'global_blacklist_bypassed' => $global_blacklist_bypassed,
            'checks' => [
                'language' => $lang_reason ?: false,
                'manual_blacklist' => $manual_list_reason ?: false,
                'geo' => $geo_reason ?: false,
                'global_blacklist' => $global_list_reason ?: false,
            ],
            'proxy' => [
                'trust_cloudflare' => ! empty( $settings['trust_cloudflare'] ),
                'remote_addr' => (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ),
                'cf_connecting_ip' => (string) ( $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '' ),
                'x_real_ip' => (string) ( $_SERVER['HTTP_X_REAL_IP'] ?? '' ),
                'x_forwarded_for' => (string) ( $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '' ),
            ],
        ];

        if ( $is_admin_debug ) {
            $payload = array_merge(
                $base_payload,
                [
                    'mode' => 'admin_debug',
                    'user_agent' => $this->user_agent,
                    'accept_language' => (string) ( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '' ),
                    'geo_blocking_enabled' => ! empty( $settings['geo_blocking_enabled'] ),
                    'geo_mode' => (string) ( $settings['geo_mode'] ?? 'block' ),
                    'geo_allow' => array_values( (array) ( $settings['geo_countries_allow'] ?? [] ) ),
                    'geo_block' => array_values( (array) ( $settings['geo_countries_block'] ?? [] ) ),
                    'manual_blacklists_enabled' => ! ( isset( $settings['blacklists_enabled'] ) && (int) $settings['blacklists_enabled'] !== 1 ),
                    'global_blacklist_enabled' => function_exists( 'rls_is_global_blacklist_runtime_enabled' ) ? rls_is_global_blacklist_runtime_enabled( $settings ) : ! ( isset( $settings['global_blacklist_enabled'] ) && (int) $settings['global_blacklist_enabled'] !== 1 ),
                    'language_filter_enabled' => ! empty( $settings['language_filter_enabled'] ),
                    'language_mode' => (string) ( $settings['language_mode'] ?? 'allow' ),
                    'language_codes' => array_values( (array) ( $settings['language_codes'] ?? [] ) ),
                ]
            );
        } else {
            $payload = array_merge(
                $base_payload,
                [
                    'mode' => 'public_test',
                    'geo_mode' => (string) ( $settings['geo_mode'] ?? 'block' ),
                    'geo_allow_count' => count( (array) ( $settings['geo_countries_allow'] ?? [] ) ),
                    'geo_block_count' => count( (array) ( $settings['geo_countries_block'] ?? [] ) ),
                    'language_filter_enabled' => ! empty( $settings['language_filter_enabled'] ),
                    'language_mode' => (string) ( $settings['language_mode'] ?? 'allow' ),
                ]
            );
        }

        if ( ! headers_sent() ) {
            header( 'Content-Type: application/json; charset=utf-8' );
            header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
            header( 'Pragma: no-cache' );
        }
        echo wp_json_encode( $payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT );
        exit;
    }

    /**
     * Полный список плохих ботов РёР· Legacy версии
     * Вынесен РІРЅРёР· для чистоты РєРѕРґР°.
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

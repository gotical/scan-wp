<?php
/**
 * Класс RLS_Activator
 * Создает таблицы и загружает настройки по умолчанию.
 * Версия 1.6.2: Очищенная база сигнатур (Fix False Positives).
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Activator {

    /**
     * Базовые сигнатуры (Вшитая база).
     * Очищена от $GLOBALS и слишком общих строк.
     */
    const BASE_SIGNATURES = [
        // Критические сигнатуры
        'FilesMan', 'r57shell', 'c99shell', 'IndoXploit', 
        'shell_exec("uname -a")', 'eval(gzinflate(base64_decode', 
        'eval(base64_decode($_POST', 'eval(base64_decode($_GET',
        'preg_replace("/.*/e"', 'Wp-Vcd', 'scanRootPaths(); die(\'!ended!\');', 
        '<?php $upgrading =', 'eval($_HEADERS', 'file_put_contents("wp-content/uploads/\'.md5', 
        "md5(\$_GET['pass'])", 'wso_login', '$auth_pass', 
        'function_exists(\'opcache_reset\')', 
        'hacked by', 'Hacked By', 'Net Sparker', 'masscan',
        'str_rot13(base64_decode',
        
        // Сигнатуры из старого кода (ОЧИЩЕННЫЕ)
        'r0nin', 'm0rtix', 'iskorpitx', 'upl0ad', 'shellbot', 'phpshell', 
        'phpremoteview', 'directmail', 'bash_history', 'cwings', 'vandal', 'bitchx', 
        'eggdrop', 'guardservices', 'psybnc', 'dalnet', 'undernet', 'vulnscan', 
        'spymeta', 'raslan58', 'Webshell', 'FilesTools', 'Web Shell', 
        'bckdrprm', 'hackmeplz', 'wrgggthhd', 'WSOsetcookie', 'Hmei7', 
        'Inbox Mass Mailer', 'HackTeam', 'Hackeado', 'Janissaries', 'Miyachung', 
        'ccteam', 'Adminer', 'OOO000000', 'findsysfolder', 'makeret.ru', 
        'c0d3d by', 'C0de For', 'Perl Auto Rooter', 'b374k', 
        'devilzShell', 'N3tshell', 'Storm7Shell', 'Locus7Shell', 'private Shell', 
        'w4ck1ng', 'blackhat Shell', 'FaTaLisTiCz_Fx', 'th3w1tch Shell', 
        'Goog1e_analist', 'Antihutan', 'Attijari', 'ByroeNet', 'cpftpcrack', 
        'KAdot', 'MulCiShell', 'PHPJackal', 'POSTpe80', 'SRCrew', 'Safe0ver', 
        'SimShell', 'Storm7', 'Surrogafier', 'TuR334Vl', 'UberCracker', 'Vrs-hCk', 
        'Cyb3rDevils', 'DxShell', 'DataCha0s', 'Forever2008', 'InsideTeam', 
        'ItsmYarD', 'aKpuMPiN', 'Xnuxer', 'cgitelnet', 'ShellHook', 'Perlovga', 
        'Mirccrack', 'CookStealer', 'Bypassshell', 'r00t3r', 'zerocnbct', 'Ylyshell', 
        'egyspider', 'evilc0der', 'violaoeucc0101', 'iTSecTeam', 'putr4XtReme', 
        'aZRaiL', 'cbLorD', '_YM82iAN', 'XXRANDOMXX', '_POST..n13e558', 
        'envir0nn@yahoo.com', '$bogel', 'c999sh_surl', 'xVebaPURjEzLc', 'AQSP', 
        'ANTIPIDERSIA', 'uzanc', 'xadpritox', 'blackboy007', 'nacomb13', 
        'Devilzc0de', 'k2ll33d', 'tsxpwkpqbk', 'HackerBooty', 'Rawckerhead', 
        'UnixCrew', 'HolaKo', 'xunzhaocangjingkong', 'WwW.7jyewu.Cn', 
        'zbazszez64z_zdeczodze', 'HaniXavi', 'IRCBot', 'Locus7s', 'c100 Shell', 
        'Project x2300', 'Captain Crunch Team', 'Shadow & Preddy', 'milw0rm', 
        'Rootshell.c', 'ASPXSpy', 'Iranian Hackers', 'SimAttacker', 'simorgh-ev', 
        'GrayHatz Hacking', 'Kacak FSO', 'grayhatz.org', 'TurkGuvenligi', 'r57.biz', 
        'evalinfect', '1dt.w0lf'
    ];

    public static function activate() {
        self::create_database_tables();
        self::setup_options();
        self::schedule_cron_jobs();
        if ( class_exists( 'RLS_GeoIP' ) ) {
            RLS_GeoIP::ensure_seed_database();
        }
        
        // Принудительное обновление сигнатур при активации
        update_option( 'rls_base_signatures', self::BASE_SIGNATURES );
        
        if ( get_option( 'rls_activation_report_sent' ) !== 'yes' ) {
            update_option( 'rls_activation_report_sent', 'no' );
            if ( class_exists( 'RLS_API_Client' ) ) {
                RLS_API_Client::report_activation();
            }
        }

        set_transient( 'rls_activation_redirect', 1, 120 );
        
        flush_rewrite_rules();
    }

    public static function deactivate() {
        if ( class_exists( 'RLS_API_Client' ) ) {
            RLS_API_Client::report_deactivation();
        }
        self::clear_cron_jobs();

        if ( get_option( 'rls_wipe_data_on_uninstall', false ) ) {
            self::purge_plugin_data();
        }
    }

    private static function create_database_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

        // 1. Таблица истории сканирований
        $table_scan = $wpdb->prefix . 'rls_scan_history';
        $sql_scan = "CREATE TABLE $table_scan (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            scan_date datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
            scan_type varchar(20) DEFAULT 'manual' NOT NULL,
            scan_status varchar(20) DEFAULT 'clean' NOT NULL,
            threats_count int(5) DEFAULT 0 NOT NULL,
            scan_details longtext NOT NULL,
            duration int(5) DEFAULT 0,
            PRIMARY KEY  (id)
        ) $charset_collate;";
        dbDelta( $sql_scan );

        // 2. Таблица журнала атак (Live Logs)
        $table_log = $wpdb->prefix . 'rls_attack_log';
        $sql_log = "CREATE TABLE $table_log (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            event_date datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
            ip varchar(45) NOT NULL,
            type varchar(50) NOT NULL,
            reason varchar(255) NOT NULL,
            request_uri varchar(255) DEFAULT '' NOT NULL,
            user_agent varchar(255) DEFAULT '' NOT NULL,
            PRIMARY KEY  (id),
            KEY event_date (event_date)
        ) $charset_collate;";
        dbDelta( $sql_log );
    }
    
    private static function setup_options() {
        // 1. Основные настройки
        if ( get_option( 'rls_settings' ) === false ) {
            add_option( 'rls_settings', [
                'enable_firewall'       => 0,
                'protection_mode'       => 'full',
                'disable_xmlrpc'        => 0, 
                'trust_cloudflare'      => 0, 
                'enable_login_security' => 0,
                'login_questions_count' => 1,
                'license_key'           => '',
                'allow_googlebot'       => 1,
                'allow_yandexbot'       => 1,
                'soft_search_bot_mode'  => 1,
                'allow_mailru_bot'      => 0,
                'allow_bingbot'         => 0,
                'allow_duckduckbot'     => 0,
                'allow_baiduspider'     => 0,
                'allow_applebot'        => 0,
                'allow_slurp'           => 0,
                'allow_seznambot'       => 0,
                'allow_naverbot'        => 0,
                'allow_petalbot'        => 0,
                'allow_sogou'           => 0,
                'allow_exabot'          => 0,
                'allow_qwantbot'        => 0,
                'allow_mojeekbot'       => 0,
                'allow_gptbot'          => 0,
                'allow_chatgpt_user'    => 0,
                'allow_oai_searchbot'   => 0,
                'allow_claudebot'       => 0,
                'allow_perplexitybot'   => 0,
                'allow_cohere_ai'       => 0,
                'allow_amazonbot'       => 0,
                'allow_ccbot'           => 0,
                'allow_bytespider'      => 0,
                'ssl_verify_api'        => 0,
                'geo_blocking_enabled'  => 0,
                'geo_mode'              => 'block',
                'geo_countries'         => [],
                'geo_countries_allow'   => [],
                'geo_countries_block'   => [],
                'language_filter_enabled' => 0,
                'language_mode'           => 'allow',
                'language_codes'          => [ 'ru', 'uk', 'kk' ],
                'blacklists_enabled'      => 1,
                'global_blacklist_enabled'=> 0,
                'captcha_enabled_admin' => 0,
                'captcha_enabled_users' => 0,
                'captcha_client_key'    => '',
                'captcha_server_key'    => '',
            ]);
        }
        if ( get_option( 'rls_setup_completed' ) === false ) {
            add_option( 'rls_setup_completed', 0 );
        }
        
        // 2. Списки IP
        add_option( 'rls_ip_whitelist', [] );     
        add_option( 'rls_manual_blacklist', [] ); 
        add_option( 'rls_global_blacklist', [] ); 
        
        // 3. Сканер и Статистика
        if ( get_option( 'rls_auto_scan_frequency' ) === false ) {
            add_option( 'rls_auto_scan_frequency', 'disabled' );
        }

        add_option( 'rls_license_status', '' );
        add_option( 'rls_license_expires_at', '' );
        add_option( 'rls_license_max_domains', 0 );
        add_option( 'rls_premium_signatures', [] );
        add_option( 'rls_custom_signatures', [] );
        
        if ( get_option( 'rls_stats' ) === false ) {
            add_option( 'rls_stats', [
                'firewall_blocked' => 0, 
                'login_attempts_blocked' => 0,
                'bad_bots_blocked' => 0,
                'viruses_found' => 0, 
                'details_sqli' => 0, 'details_xss' => 0, 'details_rce' => 0
            ]);
        }
    }
    
    private static function schedule_cron_jobs() {
        if ( ! wp_next_scheduled( 'rls_hourly_event' ) ) wp_schedule_event( time(), 'hourly', 'rls_hourly_event' );
        if ( ! wp_next_scheduled( 'rls_daily_event' ) ) wp_schedule_event( time(), 'daily', 'rls_daily_event' );
    }
    
    private static function clear_cron_jobs() {
        wp_clear_scheduled_hook( 'rls_hourly_event' );
        wp_clear_scheduled_hook( 'rls_daily_event' );
    }

    public static function purge_plugin_data() {
        global $wpdb;

        $table_scan = $wpdb->prefix . 'rls_scan_history';
        $table_log  = $wpdb->prefix . 'rls_attack_log';

        $wpdb->query( "DROP TABLE IF EXISTS $table_scan" );
        $wpdb->query( "DROP TABLE IF EXISTS $table_log" );

        $options_to_delete = [
            'rls_settings',
            'rls_setup_completed',
            'rls_base_signatures',
            'rls_premium_signatures',
            'rls_custom_signatures',
            'rls_license_status',
            'rls_license_expires_at',
            'rls_license_max_domains',
            'rls_ip2location_db_path',
            'rls_geo_db_last_update',
            'rls_stats',
            'rls_stats_last_sync_snapshot',
            'rls_ip_whitelist',
            'rls_manual_blacklist',
            'rls_global_blacklist',
            'rls_auto_scan_frequency',
            'rls_last_auto_scan_timestamp',
            'rls_activation_report_sent',
            'rls_activation_redirect',
            'rls_login_questions',
            'rls_locked_ips',
            'rls_bruteforce_lockouts',
            'rls_blocked_ips',
            'rls_snapshot_data',
            'rls_snapshot_time',
            'rls_comparison_results',
            'rls_comparison_time',
            'rls_last_scan_results',
            'rls_last_scan_time',
            'rls_whitelist',
            'rls_firewall_log',
            'rls_scan_in_progress',
            'rls_wipe_data_on_uninstall',
        ];

        foreach ( $options_to_delete as $option ) {
            delete_option( $option );
        }

        delete_transient( 'rls_scan_file_list' );
        delete_transient( 'rls_dirs_to_scan' );
        delete_transient( 'rls_failed_log' );
        delete_transient( 'rls_last_pulse_sent' );
        delete_transient( 'rls_admin_heartbeat_sent' );
        delete_transient( 'rls_activation_redirect' );

        $wpdb->query(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_rls_%' OR option_name LIKE '_transient_timeout_rls_%'"
        );

        self::delete_geoip_database_file();
        self::delete_quarantine_directory();
    }

    private static function delete_geoip_database_file() {
        $db_path = (string) get_option( 'rls_ip2location_db_path', '' );
        if ( $db_path === '' || ! file_exists( $db_path ) ) {
            return;
        }

        $uploads = wp_upload_dir();
        $uploads_dir = wp_normalize_path( $uploads['basedir'] ?? '' );
        $normalized_db_path = wp_normalize_path( $db_path );

        if ( $uploads_dir !== '' && strpos( $normalized_db_path, $uploads_dir ) === 0 ) {
            @unlink( $normalized_db_path );
        }
    }

    private static function delete_quarantine_directory() {
        $uploads = wp_upload_dir();
        $base_dir = wp_normalize_path( $uploads['basedir'] ?? '' );
        if ( $base_dir === '' ) {
            return;
        }

        $quarantine_dir = $base_dir . '/rls-quarantine';
        if ( ! is_dir( $quarantine_dir ) ) {
            return;
        }

        self::delete_directory_recursive( $quarantine_dir );
    }

    private static function delete_directory_recursive( $path ) {
        $path = wp_normalize_path( $path );
        if ( ! file_exists( $path ) ) {
            return;
        }

        if ( is_file( $path ) || is_link( $path ) ) {
            @unlink( $path );
            return;
        }

        $items = scandir( $path );
        if ( ! is_array( $items ) ) {
            return;
        }

        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) {
                continue;
            }

            self::delete_directory_recursive( $path . '/' . $item );
        }

        @rmdir( $path );
    }
}

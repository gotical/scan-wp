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
        
        // Принудительное обновление сигнатур при активации
        update_option( 'rls_base_signatures', self::BASE_SIGNATURES );
        
        if ( get_option( 'rls_activation_report_sent' ) !== 'yes' ) {
            update_option( 'rls_activation_report_sent', 'no' );
            if ( class_exists( 'RLS_API_Client' ) ) {
                RLS_API_Client::report_activation();
            }
        }
        
        flush_rewrite_rules();
    }

    public static function deactivate() {
        if ( class_exists( 'RLS_API_Client' ) ) {
            RLS_API_Client::report_deactivation();
        }
        self::clear_cron_jobs();
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
                'disable_xmlrpc'        => 0, 
                'trust_cloudflare'      => 0, 
                'enable_login_security' => 0,
                'login_questions_count' => 1,
                'license_key'           => '',
                'allow_googlebot'       => 1,
                'allow_yandexbot'       => 1,
                'allow_bingbot'         => 0,
                'ssl_verify_api'        => 0,
            ]);
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
}
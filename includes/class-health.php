<?php
/**
 * Health check & system diagnostics.
 * - Environment sanity (PHP / WP / MySQL)
 * - Module self-test (each module reports OK/WARN/ERR)
 * - Plugin conflict detection
 * - System report export (JSON / text)
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Health {

    public function init() {
        add_action( 'wp_ajax_rls_health_check', [ $this, 'ajax_check' ] );
        add_action( 'wp_ajax_rls_health_export', [ $this, 'ajax_export' ] );
    }

    /**
     * Returns a structured array of health-check entries.
     */
    public function run_checks() {
        global $wp_version, $wpdb;
        $checks = [];

        // 1. PHP version
        $php = PHP_VERSION;
        $checks[] = [
            'id'    => 'php_version',
            'label' => 'PHP version',
            'value' => $php,
            'status'=> version_compare( $php, '7.4', '>=' ) ? 'ok' : ( version_compare( $php, '7.2', '>=' ) ? 'warn' : 'err' ),
            'hint'  => 'Требуется PHP 7.4 или выше.',
        ];

        // 2. WP version
        $checks[] = [
            'id'    => 'wp_version',
            'label' => 'WordPress version',
            'value' => $wp_version,
            'status'=> version_compare( $wp_version, '6.0', '>=' ) ? 'ok' : 'warn',
            'hint'  => 'Рекомендуется WP 6.0+.',
        ];

        // 3. MySQL version
        $mysql = $wpdb->db_version();
        $checks[] = [
            'id'    => 'mysql_version',
            'label' => 'MySQL version',
            'value' => $mysql,
            'status'=> version_compare( $mysql, '5.7', '>=' ) ? 'ok' : 'warn',
            'hint'  => 'Рекомендуется MySQL 5.7+ / MariaDB 10.3+.',
        ];

        // 4. SSL verify API setting
        $settings = get_option( 'rls_settings', [] );
        $ssl_verify = ! empty( $settings['ssl_verify_api'] );
        $checks[] = [
            'id'    => 'ssl_verify_api',
            'label' => 'API SSL verify',
            'value' => $ssl_verify ? 'enabled' : 'disabled',
            'status'=> $ssl_verify ? 'ok' : 'warn',
            'hint'  => 'Включите ssl_verify_api для безопасной связи с облаком.',
        ];

        // 5. File integrity
        $integrity_ok = class_exists( 'RLS_Cron' ) ? RLS_Cron::plugin_integrity_ok() : true;
        $checks[] = [
            'id'    => 'file_integrity',
            'label' => 'File integrity',
            'value' => $integrity_ok ? 'clean' : 'tampered',
            'status'=> $integrity_ok ? 'ok' : 'err',
            'hint'  => $integrity_ok ? 'Все файлы плагина прошли проверку.' : 'Обнаружены изменения файлов.',
        ];

        // 6. .htaccess writable (for hardening)
        $htaccess = class_exists( 'RLS_Hardening' ) ? RLS_Hardening::is_htaccess_writable() : true;
        $checks[] = [
            'id'    => 'htaccess_writable',
            'label' => '.htaccess writable',
            'value' => $htaccess ? 'yes' : 'no',
            'status'=> $htaccess ? 'ok' : 'warn',
            'hint'  => 'Если "no" — Hardening не может применять правила.',
        ];

        // 7. Quarantine writable
        $quarantine_dir = wp_normalize_path( wp_upload_dir()['basedir'] . '/rls-quarantine' );
        $checks[] = [
            'id'    => 'quarantine_writable',
            'label' => 'Quarantine directory',
            'value' => is_writable( $quarantine_dir ) ? 'writable' : 'readonly',
            'status'=> is_writable( $quarantine_dir ) ? 'ok' : 'err',
            'hint'  => 'Без доступа на запись карантин не работает.',
        ];

        // 8. Cron schedules
        $next = wp_next_scheduled( 'rls_cron_hourly' );
        $checks[] = [
            'id'    => 'cron_hourly',
            'label' => 'Cron: hourly',
            'value' => $next ? sprintf( 'next: %s', wp_date( 'Y-m-d H:i', $next ) ) : 'not scheduled',
            'status'=> $next ? 'ok' : 'err',
            'hint'  => 'WP-Cron не активирован — фоновые задачи не выполняются.',
        ];

        // 9. DB tables
        $tables = [
            $wpdb->prefix . 'rls_attack_log',
            $wpdb->prefix . 'rls_scan_history',
        ];
        $missing = [];
        foreach ( $tables as $t ) {
            if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $t ) ) !== $t ) {
                $missing[] = $t;
            }
        }
        $checks[] = [
            'id'    => 'db_tables',
            'label' => 'DB tables',
            'value' => empty( $missing ) ? 'present' : 'missing: ' . implode( ', ', $missing ),
            'status'=> empty( $missing ) ? 'ok' : 'err',
            'hint'  => 'Переактивируйте плагин для восстановления таблиц.',
        ];

        // 10. Known plugin conflicts (heuristic).
        $active = (array) get_option( 'active_plugins', [] );
        $known_conflicts = [
            'wordfence/wordfence.php'      => 'Wordfence уже имеет WAF — возможны конфликты правил.',
            'sucuri-scanner/sucuri.php'    => 'Sucuri имеет собственный WAF.',
            'all-in-one-wp-security-and-firewall/wp-security.php' => 'AIOS может конфликтовать по IP-спискам.',
        ];
        $conflicts = [];
        foreach ( $known_conflicts as $path => $msg ) {
            if ( in_array( $path, $active, true ) ) $conflicts[] = $msg;
        }
        $checks[] = [
            'id'    => 'plugin_conflicts',
            'label' => 'Plugin conflicts',
            'value' => empty( $conflicts ) ? 'none detected' : implode( '; ', $conflicts ),
            'status'=> empty( $conflicts ) ? 'ok' : 'warn',
            'hint'  => 'Конфликтующие плагины рекомендуется отключить для стабильной работы.',
        ];

        return $checks;
    }

    public function ajax_check() {
        check_ajax_referer( 'rls_health_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        $checks = $this->run_checks();
        wp_send_json_success( [ 'checks' => $checks ] );
    }

    public function ajax_export() {
        check_ajax_referer( 'rls_health_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Access denied' );

        $report = [
            'plugin'      => 'Rybinsk Lab Security',
            'version'     => defined( 'RLS_VERSION' ) ? RLS_VERSION : 'unknown',
            'site'        => home_url(),
            'php'         => PHP_VERSION,
            'wp'          => get_bloginfo( 'version' ),
            'db'          => 'unknown',
            'server'      => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'timestamp'   => gmdate( 'c' ),
            'user'        => wp_get_current_user()->user_login ?? 'unknown',
            'checks'      => $this->run_checks(),
            'options'     => [
                'rls_settings'         => get_option( 'rls_settings', [] ),
                'rls_license_status'   => get_option( 'rls_license_status', '' ),
                'rls_gdpr_settings'    => get_option( 'rls_gdpr_settings', [] ),
                'rls_session_settings' => get_option( 'rls_session_settings', [] ),
            ],
            'active_plugins' => (array) get_option( 'active_plugins', [] ),
            'theme'        => (string) get_option( 'stylesheet' ),
        ];

        global $wpdb;
        $report['db'] = $wpdb->db_version();

        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="rls-health-report-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
        exit;
    }
}

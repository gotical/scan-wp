<?php
/**
 * Login Attempts Tracker.
 * Logs every login success/failure with detailed metadata.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Login_Attempts {

    const TABLE_NAME = 'rls_login_attempts';
    const MAX_ROWS   = 50000;

    public function init() {
        add_action( 'wp_login', [ $this, 'on_success' ], 10, 2 );
        add_action( 'wp_login_failed', [ $this, 'on_failure' ], 10, 1 );
        add_action( 'rls_cron_daily', [ $this, 'cleanup' ] );
    }

    /**
     * Get the table name with prefix.
     */
    public static function table() {
        global $wpdb;
        return $wpdb->prefix . self::TABLE_NAME;
    }

    /**
     * Ensure DB schema is installed.
     */
    public static function install_schema() {
        global $wpdb;
        $table = self::table();
        $charset_collate = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( "CREATE TABLE IF NOT EXISTS {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            event_date DATETIME NOT NULL,
            user_login VARCHAR(255) NOT NULL DEFAULT '',
            user_id BIGINT UNSIGNED NULL,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            country_code VARCHAR(2) DEFAULT '',
            user_agent VARCHAR(512) DEFAULT '',
            referer VARCHAR(512) DEFAULT '',
            success TINYINT(1) NOT NULL DEFAULT 0,
            reason VARCHAR(64) DEFAULT '',
            captcha_status VARCHAR(32) DEFAULT '',
            PRIMARY KEY (id),
            KEY event_date (event_date),
            KEY ip (ip),
            KEY user_login (user_login),
            KEY success (success)
        ) {$charset_collate};" );
    }

    /**
     * Record a failed login attempt.
     */
    public function on_failure( $username ) {
        $ip = $this->client_ip();
        $ua = (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' );
        $ref = (string) ( $_SERVER['HTTP_REFERER'] ?? '' );
        $reason = $this->detect_failure_reason( $username );

        self::log_attempt( [
            'event_date'     => current_time( 'mysql' ),
            'user_login'     => (string) $username,
            'user_id'        => null,
            'ip'             => $ip,
            'country_code'   => self::lookup_country( $ip ),
            'user_agent'     => substr( $ua, 0, 500 ),
            'referer'        => substr( $ref, 0, 500 ),
            'success'        => 0,
            'reason'         => $reason,
            'captcha_status' => self::detect_captcha_status(),
        ] );
    }

    /**
     * Record a successful login.
     */
    public function on_success( $user_login, $user ) {
        if ( ! ( $user instanceof WP_User ) ) return;
        $ip = $this->client_ip();
        $ua = (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' );

        self::log_attempt( [
            'event_date'     => current_time( 'mysql' ),
            'user_login'     => (string) $user_login,
            'user_id'        => (int) $user->ID,
            'ip'             => $ip,
            'country_code'   => self::lookup_country( $ip ),
            'user_agent'     => substr( $ua, 0, 500 ),
            'referer'        => '',
            'success'        => 1,
            'reason'         => 'success',
            'captcha_status' => self::detect_captcha_status(),
        ] );
    }

    private function detect_failure_reason( $username ) {
        if ( empty( $username ) ) return 'empty_username';
        $user = get_user_by( 'login', $username );
        if ( ! $user ) return 'unknown_user';
        if ( is_multisite() && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) return 'not_member';
        return 'wrong_password';
    }

    private function detect_captcha_status() {
        $key = ( $_POST['g-recaptcha-response'] ?? '' ) ? 'google' : ( ( $_POST['smart-captcha-token'] ?? '' ) ? 'yandex' : 'none' );
        return $key;
    }

    private function client_ip() {
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private static function lookup_country( $ip ) {
        if ( ! class_exists( 'RLS_GeoIP' ) ) return '';
        if ( method_exists( 'RLS_GeoIP', 'lookup_country_code' ) ) {
            return (string) RLS_GeoIP::lookup_country_code( $ip );
        }
        return '';
    }

    public static function log_attempt( $data ) {
        global $wpdb;
        $table = self::table();
        $wpdb->insert( $table, $data, [
            '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s',
        ] );

        // Cap rows.
        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
        if ( $count > self::MAX_ROWS ) {
            $wpdb->query( $wpdb->prepare(
                "DELETE FROM {$table} ORDER BY id ASC LIMIT %d",
                $count - self::MAX_ROWS
            ) );
        }
    }

    public static function cleanup() {
        global $wpdb;
        $table = self::table();
        $days = (int) get_option( 'rls_login_attempts_retention', 90 );
        if ( $days <= 0 ) return;
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$table} WHERE event_date < DATE_SUB(%s, INTERVAL %d DAY)",
            current_time( 'mysql' ),
            $days
        ) );
    }

    /* === Analytics helpers === */

    public static function get_top_failing_ips( $days = 7, $limit = 20 ) {
        global $wpdb;
        $table = self::table();
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT ip, country_code, COUNT(*) AS failures, COUNT(DISTINCT user_login) AS users
             FROM {$table}
             WHERE success = 0 AND event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY ip, country_code
             ORDER BY failures DESC
             LIMIT %d",
            current_time( 'mysql' ),
            $days,
            $limit
        ), ARRAY_A );
    }

    public static function get_top_failing_usernames( $days = 7, $limit = 20 ) {
        global $wpdb;
        $table = self::table();
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT user_login, COUNT(*) AS failures, COUNT(DISTINCT ip) AS unique_ips
             FROM {$table}
             WHERE success = 0 AND event_date >= DATE_SUB(%s, INTERVAL %d DAY)
               AND user_login <> ''
             GROUP BY user_login
             ORDER BY failures DESC
             LIMIT %d",
            current_time( 'mysql' ),
            $days,
            $limit
        ), ARRAY_A );
    }

    public static function get_attempts_timeline( $days = 7 ) {
        global $wpdb;
        $table = self::table();
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT DATE(event_date) AS day,
                    SUM(success = 1) AS successes,
                    SUM(success = 0) AS failures
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY DATE(event_date)
             ORDER BY day ASC",
            current_time( 'mysql' ),
            $days
        ), ARRAY_A );
    }

    public static function get_hour_distribution( $days = 7 ) {
        global $wpdb;
        $table = self::table();
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT HOUR(event_date) AS hour, COUNT(*) AS total
             FROM {$table}
             WHERE success = 0 AND event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY HOUR(event_date)
             ORDER BY hour ASC",
            current_time( 'mysql' ),
            $days
        ), ARRAY_A );
    }

    public static function get_country_distribution( $days = 7, $limit = 20 ) {
        global $wpdb;
        $table = self::table();
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT country_code, COUNT(*) AS failures
             FROM {$table}
             WHERE success = 0 AND event_date >= DATE_SUB(%s, INTERVAL %d DAY)
               AND country_code <> ''
             GROUP BY country_code
             ORDER BY failures DESC
             LIMIT %d",
            current_time( 'mysql' ),
            $days,
            $limit
        ), ARRAY_A );
    }

    public static function get_recent_attempts( $limit = 100, $only_failures = false ) {
        global $wpdb;
        $table = self::table();
        $where = $only_failures ? 'WHERE success = 0' : '';
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$table} {$where} ORDER BY id DESC LIMIT %d",
            $limit
        ), ARRAY_A );
    }

    public static function get_summary( $days = 7 ) {
        global $wpdb;
        $table = self::table();
        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT
                COUNT(*) AS total,
                SUM(success = 1) AS successes,
                SUM(success = 0) AS failures,
                COUNT(DISTINCT ip) AS unique_ips,
                COUNT(DISTINCT user_login) AS unique_users
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)",
            current_time( 'mysql' ),
            $days
        ), ARRAY_A );
        return $row ?: [ 'total' => 0, 'successes' => 0, 'failures' => 0, 'unique_ips' => 0, 'unique_users' => 0 ];
    }
}

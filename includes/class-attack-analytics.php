<?php
/**
 * Attack analytics: aggregated stats from rls_attack_log + rls_login_attempts.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Attack_Analytics {

    const ATTACK_LOG = 'rls_attack_log';

    /**
     * Top attacking IPs in the attack_log table.
     */
    public static function get_top_attackers( $days = 7, $limit = 20 ) {
        global $wpdb;
        $table = $wpdb->prefix . self::ATTACK_LOG;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT ip, country_code, COUNT(*) AS attacks,
                   COUNT(DISTINCT type) AS types,
                   MIN(event_date) AS first_seen,
                   MAX(event_date) AS last_seen
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY ip, country_code
             ORDER BY attacks DESC
             LIMIT %d",
            current_time( 'mysql' ), $days, $limit
        ), ARRAY_A );
    }

    /**
     * Top attacked URIs.
     */
    public static function get_top_targeted_urls( $days = 7, $limit = 20 ) {
        global $wpdb;
        $table = $wpdb->prefix . self::ATTACK_LOG;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT request_uri, COUNT(*) AS attacks,
                   COUNT(DISTINCT ip) AS unique_ips
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
               AND request_uri <> ''
             GROUP BY request_uri
             ORDER BY attacks DESC
             LIMIT %d",
            current_time( 'mysql' ), $days, $limit
        ), ARRAY_A );
    }

    /**
     * Attack type breakdown.
     */
    public static function get_type_breakdown( $days = 7 ) {
        global $wpdb;
        $table = $wpdb->prefix . self::ATTACK_LOG;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT LOWER(type) AS type, COUNT(*) AS attacks
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY LOWER(type)
             ORDER BY attacks DESC",
            current_time( 'mysql' ), $days
        ), ARRAY_A );
    }

    /**
     * Hour-of-day distribution of attacks (for heatmap).
     */
    public static function get_hour_heatmap( $days = 7 ) {
        global $wpdb;
        $table = $wpdb->prefix . self::ATTACK_LOG;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT DAYOFWEEK(event_date) AS dow, HOUR(event_date) AS hour, COUNT(*) AS attacks
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY DAYOFWEEK(event_date), HOUR(event_date)
             ORDER BY dow, hour",
            current_time( 'mysql' ), $days
        ), ARRAY_A );
    }

    /**
     * Daily timeline (combined attacks + login failures).
     */
    public static function get_combined_timeline( $days = 14 ) {
        global $wpdb;
        $attack_table = $wpdb->prefix . self::ATTACK_LOG;
        $login_table = class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::table() : null;

        $attack_rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT DATE(event_date) AS day, COUNT(*) AS total
             FROM {$attack_table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY DATE(event_date)",
            current_time( 'mysql' ), $days
        ), ARRAY_A );

        $login_rows = [];
        if ( $login_table ) {
            $login_rows = $wpdb->get_results( $wpdb->prepare(
                "SELECT DATE(event_date) AS day, SUM(success = 0) AS failures
                 FROM {$login_table}
                 WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
                 GROUP BY DATE(event_date)",
                current_time( 'mysql' ), $days
            ), ARRAY_A );
        }

        // Merge by day.
        $merged = [];
        foreach ( $attack_rows as $r ) {
            $day = $r['day'];
            if ( ! isset( $merged[ $day ] ) ) $merged[ $day ] = [ 'day' => $day, 'attacks' => 0, 'login_failures' => 0 ];
            $merged[ $day ]['attacks'] = (int) $r['total'];
        }
        foreach ( $login_rows as $r ) {
            $day = $r['day'];
            if ( ! isset( $merged[ $day ] ) ) $merged[ $day ] = [ 'day' => $day, 'attacks' => 0, 'login_failures' => 0 ];
            $merged[ $day ]['login_failures'] = (int) $r['failures'];
        }
        ksort( $merged );
        return array_values( $merged );
    }

    /**
     * Geographic distribution of attacks.
     */
    public static function get_country_breakdown( $days = 7, $limit = 30 ) {
        global $wpdb;
        $table = $wpdb->prefix . self::ATTACK_LOG;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT country_code, COUNT(*) AS attacks,
                   COUNT(DISTINCT ip) AS unique_ips
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
               AND country_code <> ''
             GROUP BY country_code
             ORDER BY attacks DESC
             LIMIT %d",
            current_time( 'mysql' ), $days, $limit
        ), ARRAY_A );
    }

    /**
     * Time-to-block analysis: how long do attackers try before giving up?
     * Returns average # of attempts per IP per session.
     */
    public static function get_attempts_per_ip( $days = 7 ) {
        global $wpdb;
        $table = $wpdb->prefix . self::ATTACK_LOG;
        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT
                COUNT(*) AS total_attacks,
                COUNT(DISTINCT ip) AS unique_ips,
                ROUND(COUNT(*) / NULLIF(COUNT(DISTINCT ip), 0), 1) AS avg_per_ip
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)",
            current_time( 'mysql' ), $days
        ), ARRAY_A );
        return $row ?: [ 'total_attacks' => 0, 'unique_ips' => 0, 'avg_per_ip' => 0 ];
    }

    /**
     * Recent attack log with pagination.
     */
    public static function get_recent_attacks( $limit = 100, $filters = [] ) {
        global $wpdb;
        $table = $wpdb->prefix . self::ATTACK_LOG;
        $where = [ '1=1' ];
        $args  = [];

        if ( ! empty( $filters['type'] ) ) {
            $where[] = 'LOWER(type) = %s';
            $args[]  = strtolower( $filters['type'] );
        }
        if ( ! empty( $filters['ip'] ) ) {
            $where[] = 'ip = %s';
            $args[]  = $filters['ip'];
        }
        if ( ! empty( $filters['days'] ) ) {
            $where[] = 'event_date >= DATE_SUB(%s, INTERVAL %d DAY)';
            array_unshift( $args, current_time( 'mysql' ), (int) $filters['days'] );
        }
        $where_str = implode( ' AND ', $where );
        $args[] = (int) $limit;
        $sql = "SELECT * FROM {$table} WHERE {$where_str} ORDER BY id DESC LIMIT %d";
        return $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );
    }
}

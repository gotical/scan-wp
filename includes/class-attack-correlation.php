<?php
/**
 * Attack Correlation.
 * Groups related attacks into "campaigns" based on shared IP, UA, or time window.
 *
 * A campaign is a sequence of related events (same IP within X minutes, or
 * multiple IPs sharing the same user-agent / targeting the same path).
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Attack_Correlation {

    const TIME_WINDOW = 1800; // 30 minutes between events in same campaign
    const MIN_CAMPAIGN_SIZE = 3; // at least N attacks to form a campaign

    /**
     * Detect campaigns by IP within time windows.
     */
    public static function detect_ip_campaigns( $days = 7, $limit = 30 ) {
        global $wpdb;
        $attack_table = $wpdb->prefix . 'rls_attack_log';
        $login_table  = class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::table() : null;

        // Aggregate events by IP + time bucket.
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT ip, country_code, type, reason, request_uri, event_date
             FROM {$attack_table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             ORDER BY event_date ASC",
            current_time( 'mysql' ), $days
        ), ARRAY_A );

        $login_failures = [];
        if ( $login_table ) {
            $login_failures = $wpdb->get_results( $wpdb->prepare(
                "SELECT ip, country_code, reason, event_date
                 FROM {$login_table}
                 WHERE success = 0 AND event_date >= DATE_SUB(%s, INTERVAL %d DAY)
                 ORDER BY event_date ASC",
                current_time( 'mysql' ), $days
            ), ARRAY_A );
        }

        // Group by IP, then split by time gap.
        $by_ip = [];
        foreach ( $rows as $r ) {
            $ip = $r['ip'];
            if ( ! isset( $by_ip[ $ip ] ) ) $by_ip[ $ip ] = [];
            $by_ip[ $ip ][] = $r;
        }
        foreach ( $login_failures as $r ) {
            $ip = $r['ip'];
            if ( ! isset( $by_ip[ $ip ] ) ) $by_ip[ $ip ] = [];
            $r['type'] = 'login_failure';
            $r['request_uri'] = '';
            $by_ip[ $ip ][] = $r;
        }

        $campaigns = [];
        foreach ( $by_ip as $ip => $events ) {
            if ( count( $events ) < self::MIN_CAMPAIGN_SIZE ) continue;
            // Split into sub-campaigns by time gap.
            $current = [ $events[0] ];
            $types = [ $events[0]['type'] ];
            for ( $i = 1; $i < count( $events ); $i++ ) {
                $prev_ts = strtotime( $events[ $i - 1 ]['event_date'] );
                $cur_ts  = strtotime( $events[ $i ]['event_date'] );
                if ( ( $cur_ts - $prev_ts ) <= self::TIME_WINDOW ) {
                    $current[] = $events[ $i ];
                    if ( ! in_array( $events[ $i ]['type'], $types, true ) ) {
                        $types[] = $events[ $i ]['type'];
                    }
                } else {
                    if ( count( $current ) >= self::MIN_CAMPAIGN_SIZE ) {
                        $campaigns[] = self::build_campaign( $ip, $current, $types );
                    }
                    $current   = [ $events[ $i ] ];
                    $types     = [ $events[ $i ]['type'] ];
                }
            }
            // Last batch.
            if ( count( $current ) >= self::MIN_CAMPAIGN_SIZE ) {
                $campaigns[] = self::build_campaign( $ip, $current, $types );
            }
        }

        // Sort by severity (size + recency).
        usort( $campaigns, function( $a, $b ) {
            return $b['severity'] - $a['severity'];
        } );

        return array_slice( $campaigns, 0, $limit );
    }

    /**
     * Detect botnet-like activity: multiple IPs sharing same user-agent.
     */
    public static function detect_ua_clusters( $days = 7, $limit = 20 ) {
        global $wpdb;
        $table = $wpdb->prefix . 'rls_attack_log';
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT user_agent, COUNT(DISTINCT ip) AS unique_ips, COUNT(*) AS attacks,
                   GROUP_CONCAT(DISTINCT ip SEPARATOR ',') AS ips,
                   GROUP_CONCAT(DISTINCT type SEPARATOR ',') AS types
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
               AND user_agent <> ''
             GROUP BY user_agent
             HAVING unique_ips >= 3 AND attacks >= 5
             ORDER BY unique_ips DESC
             LIMIT %d",
            current_time( 'mysql' ), $days, $limit
        ), ARRAY_A );
        return $rows;
    }

    /**
     * Detect attacks on same URI by multiple IPs in time window (DDoS / scan pattern).
     */
    public static function detect_targeted_uri_campaigns( $days = 7, $limit = 20 ) {
        global $wpdb;
        $table = $wpdb->prefix . 'rls_attack_log';
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT request_uri, COUNT(DISTINCT ip) AS unique_ips, COUNT(*) AS attacks,
                   MIN(event_date) AS first_seen, MAX(event_date) AS last_seen,
                   GROUP_CONCAT(DISTINCT type SEPARATOR ',') AS types
             FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)
               AND request_uri <> ''
             GROUP BY request_uri
             HAVING unique_ips >= 3 AND attacks >= 5
             ORDER BY attacks DESC
             LIMIT %d",
            current_time( 'mysql' ), $days, $limit
        ), ARRAY_A );
        return $rows;
    }

    private static function build_campaign( $ip, $events, $types ) {
        $first = $events[0];
        $last  = end( $events );
        $first_ts = strtotime( $first['event_date'] );
        $last_ts  = strtotime( $last['event_date'] );
        $duration  = max( 1, $last_ts - $first_ts );

        $severity = 0;
        // Base: event count.
        $severity += min( 50, count( $events ) * 2 );
        // Bonus: diverse types.
        $severity += min( 20, count( array_unique( $types ) ) * 5 );
        // Bonus: short duration (more aggressive = more dangerous).
        if ( $duration < 60 )        $severity += 20;
        elseif ( $duration < 300 )  $severity += 10;
        elseif ( $duration < 1800 ) $severity += 5;
        $severity = min( 100, $severity );

        $level = $severity >= 75 ? 'critical' : ( $severity >= 50 ? 'high' : ( $severity >= 25 ? 'medium' : 'low' ) );

        return [
            'ip'           => $ip,
            'country'      => $first['country_code'] ?? '',
            'type'         => 'ip_campaign',
            'label'        => sprintf( 'IP-кампания: %s', $ip ),
            'events_count' => count( $events ),
            'unique_ips'   => 1,
            'types'        => array_values( array_unique( $types ) ),
            'first_seen'   => $first['event_date'],
            'last_seen'    => $last['event_date'],
            'duration_sec' => $duration,
            'severity'     => $severity,
            'severity_level' => $level,
            'sample'       => array_slice( $events, 0, 3 ),
        ];
    }

    public static function get_correlation_summary( $days = 7 ) {
        $ip_campaigns   = self::detect_ip_campaigns( $days, 1000 );
        $ua_clusters    = self::detect_ua_clusters( $days, 1000 );
        $uri_campaigns  = self::detect_targeted_uri_campaigns( $days, 1000 );

        return [
            'ip_campaigns'    => count( $ip_campaigns ),
            'ua_clusters'     => count( $ua_clusters ),
            'uri_campaigns'   => count( $uri_campaigns ),
            'top_ip'          => array_slice( $ip_campaigns, 0, 10 ),
            'top_ua'          => array_slice( $ua_clusters, 0, 10 ),
            'top_uri'         => array_slice( $uri_campaigns, 0, 10 ),
        ];
    }
}

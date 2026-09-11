<?php
/**
 * Scanner: database content scanner.
 * Checks wp_options, wp_posts, wp_users for malicious patterns.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Scanner_Database {

    const SCAN_TYPE = 'database';
    const LAST_SCAN_OPT = 'rls_db_scan_last';

    /**
     * Scan the database for suspicious content.
     */
    public static function scan() {
        global $wpdb;
        $findings = [];

        // 1. wp_options scan.
        $findings = array_merge( $findings, self::scan_options() );

        // 2. wp_users scan.
        $findings = array_merge( $findings, self::scan_users() );

        // 3. wp_posts scan (post_content for malware).
        $findings = array_merge( $findings, self::scan_posts() );

        // 4. wp_options cron scan.
        $findings = array_merge( $findings, self::scan_cron() );

        update_option( self::LAST_SCAN_OPT, time() );

        return $findings;
    }

    /**
     * Scan wp_options for suspicious values.
     */
    private static function scan_options() {
        global $wpdb;
        $findings = [];
        $table = $wpdb->options;

        // Find options with potential code execution patterns.
        $patterns = [
            'eval-base64' => [
                'pattern' => '/(eval|assert|exec|system|passthru|shell_exec)\s*\([^)]*\$/',
                'severity' => 95,
            ],
            'obfuscation-long-base64' => [
                'pattern' => '/["\']([A-Za-z0-9+\/=]{300,})["\']/',
                'severity' => 60,
            ],
            'php-serialized-payload' => [
                'pattern' => '/O:\d+:"(eval|exec|system|assert)/',
                'severity' => 75,
            ],
            'iframe-injection' => [
                'pattern' => '/<iframe[^>]*src=["\']?https?:\/\/(?!' . preg_quote( wp_parse_url( home_url(), PHP_URL_HOST ), '/' ) . ')/',
                'severity' => 50,
            ],
            'malicious-url' => [
                'pattern' => '/https?:\/\/(?:[a-z0-9-]+\.)*(?:pharma|viagra|casino|porn|malware)\./i',
                'severity' => 70,
            ],
        ];

        // Scan in batches to avoid memory issues.
        $offset = 0;
        $batch = 200;
        do {
            $rows = $wpdb->get_results( $wpdb->prepare(
                "SELECT option_id, option_name, option_value FROM $table LIMIT %d OFFSET %d",
                $batch,
                $offset
            ), ARRAY_A );
            if ( ! $rows ) break;

            foreach ( $rows as $row ) {
                $value = $row['option_value'];
                if ( ! is_string( $value ) || strlen( $value ) < 20 ) continue;
                // Skip known safe options.
                if ( in_array( $row['option_name'], [ 'siteurl', 'home', 'blogname', 'blogdescription' ], true ) ) continue;

                foreach ( $patterns as $id => $p ) {
                    if ( preg_match( $p['pattern'], $value ) ) {
                        $findings[] = [
                            'type'     => 'wp_options',
                            'location' => 'option:' . $row['option_name'],
                            'severity' => $p['severity'],
                            'rule_id'  => $id,
                            'snippet'  => mb_substr( $value, 0, 200 ),
                        ];
                    }
                }
            }
            $offset += $batch;
        } while ( count( $rows ) === $batch );

        return $findings;
    }

    /**
     * Scan wp_users for backdoor admin accounts.
     */
    private static function scan_users() {
        global $wpdb;
        $findings = [];
        $table = $wpdb->users;
        $meta_table = $wpdb->usermeta;

        // Find users with admin capabilities but suspicious patterns.
        $suspicious_logins = $wpdb->get_results(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered
             FROM $table u
             INNER JOIN $meta_table um ON u.ID = um.user_id
             WHERE um.meta_key = '{$wpdb->prefix}capabilities'
               AND (
                 um.meta_value LIKE '%administrator%'
                 OR um.meta_value LIKE '%editor%'
               )
               AND (
                 u.user_login REGEXP 'admin[0-9]{3,}'
                 OR u.user_email LIKE '%@mail.ru'
                 OR LENGTH(u.user_login) < 4
               )
             LIMIT 50",
            ARRAY_A
        );

        foreach ( (array) $suspicious_logins as $u ) {
            $findings[] = [
                'type'     => 'wp_users',
                'location' => sprintf( 'user:%d (%s)', $u['ID'], $u['user_login'] ),
                'severity' => 50,
                'rule_id'  => 'user-suspicious-pattern',
                'snippet'  => sprintf( 'login: %s, email: %s, registered: %s', $u['user_login'], $u['user_email'], $u['user_registered'] ),
            ];
        }
        return $findings;
    }

    /**
     * Scan wp_posts content for malicious code injections.
     */
    private static function scan_posts() {
        global $wpdb;
        $findings = [];
        $table = $wpdb->posts;

        $patterns = [
            'eval-in-content' => [
                'pattern' => '/<\?php[^<]*eval\s*\(/',
                'severity' => 90,
            ],
            'base64-in-content' => [
                'pattern' => '/<\?php[^<]*base64_decode\s*\(\s*["\'][A-Za-z0-9+\/=]{50,}/',
                'severity' => 85,
            ],
            'iframe-injection' => [
                'pattern' => '/<iframe[^>]*src=["\']?(https?:)?\/\/(?!' . preg_quote( wp_parse_url( home_url(), PHP_URL_HOST ), '/' ) . ')/i',
                'severity' => 60,
            ],
            'crypto-miner-script' => [
                'pattern' => '/cryptonight|stratum\+tcp|coinhive|minero\.com/i',
                'severity' => 95,
            ],
            'pharma-spam' => [
                'pattern' => '/\b(viagra|cialis|pharma|kamagra)\b.*\b(online|buy|cheap|price)\b/i',
                'severity' => 50,
            ],
        ];

        $rows = $wpdb->get_results(
            "SELECT ID, post_title, post_type, post_content
             FROM $table
             WHERE post_content REGEXP 'eval\\s*\\(|base64_decode\\s*\\(|<iframe|cryptonight|stratum\\+tcp'
               AND post_status IN ('publish', 'draft', 'pending', 'private')
             LIMIT 100",
            ARRAY_A
        );

        foreach ( (array) $rows as $row ) {
            foreach ( $patterns as $id => $p ) {
                if ( preg_match( $p['pattern'], $row['post_content'] ) ) {
                    $findings[] = [
                        'type'     => 'wp_posts',
                        'location' => sprintf( 'post:%d "%s" (%s)', $row['ID'], mb_substr( $row['post_title'], 0, 50 ), $row['post_type'] ),
                        'severity' => $p['severity'],
                        'rule_id'  => $id,
                        'snippet'  => mb_substr( preg_replace( '/\s+/', ' ', $row['post_content'] ), 0, 200 ),
                    ];
                    break;
                }
            }
        }
        return $findings;
    }

    /**
     * Scan WP-Cron entries for malicious scheduled tasks.
     */
    private static function scan_cron() {
        $findings = [];
        $crons = get_option( 'cron', [] );
        if ( ! is_array( $crons ) ) return $findings;

        foreach ( $crons as $timestamp => $hooks ) {
            if ( ! is_array( $hooks ) ) continue;
            foreach ( $hooks as $hook => $args_group ) {
                if ( ! is_array( $args_group ) ) continue;
                foreach ( $args_group as $args ) {
                    $args_str = serialize( $args );
                    // Check for suspicious patterns in serialized cron args.
                    if ( preg_match( '/(eval|exec|system|assert)\s*\(/', $args_str ) ) {
                        $findings[] = [
                            'type'     => 'wp_cron',
                            'location' => sprintf( 'cron:%s@%d', $hook, $timestamp ),
                            'severity' => 85,
                            'rule_id'  => 'cron-malicious-args',
                            'snippet'  => mb_substr( $args_str, 0, 200 ),
                        ];
                    }
                    // Suspicious hook names (random string, no plugin prefix).
                    if ( preg_match( '/^[a-z0-9]{20,}$/i', $hook ) ) {
                        $findings[] = [
                            'type'     => 'wp_cron',
                            'location' => sprintf( 'cron:%s@%d', $hook, $timestamp ),
                            'severity' => 50,
                            'rule_id'  => 'cron-random-hook',
                            'snippet'  => 'Suspicious random hook name',
                        ];
                    }
                }
            }
        }
        return $findings;
    }
}

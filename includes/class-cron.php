<?php
/**
 * пїЅпїЅпїЅпїЅпїЅ RLS_Cron
 * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ.
 * пїЅпїЅпїЅпїЅпїЅпїЅ 1.5.4 (Optimized)
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Cron {

    public function init() {
        add_action( 'rls_hourly_event', [ $this, 'run_hourly_tasks' ] );
        add_action( 'rls_daily_event', [ $this, 'run_daily_tasks' ] );
        add_action( 'init', [ $this, 'ensure_schedules' ] );
    }

    public function ensure_schedules() {
        if ( ! wp_next_scheduled( 'rls_hourly_event' ) ) {
            wp_schedule_event( time(), 'hourly', 'rls_hourly_event' );
        }
        if ( ! wp_next_scheduled( 'rls_daily_event' ) ) {
            wp_schedule_event( time(), 'daily', 'rls_daily_event' );
        }
    }

    public function run_hourly_tasks() {
        // 1. пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        if ( get_option( 'rls_activation_report_sent' ) !== 'yes' ) {
            $response = RLS_API_Client::report_activation();
            if ( ! is_wp_error( $response ) && isset( $response['status'] ) && $response['status'] === 'success' ) {
                update_option( 'rls_activation_report_sent', 'yes' );
            }
        }

        // 2. пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        self::sync_detailed_stats();
        self::sync_local_blacklists();

        // 3. пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        $this->update_premium_signatures();

        // 4. пїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅ
        $this->sync_global_blacklist();
        
        // 5. пїЅпїЅпїЅпїЅ
        RLS_API_Client::send_heartbeat();

        // 6. пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        $this->check_and_run_auto_scan();
    }

    public function run_daily_tasks() {
        // Резерв для тяжелых задач раз в сутки (например, очистка старых логов)
        $this->update_geo_database_weekly();
    }
    private function sync_global_blacklist() {
        if ( ! function_exists( 'rls_is_premium_license_active' ) || ! rls_is_premium_license_active() ) {
            return;
        }

        $response = RLS_API_Client::get_global_blacklist();
        if ( ! is_wp_error( $response ) && isset( $response['status'] ) && $response['status'] === 'success' ) {
            if ( ! empty( $response['data']['ips'] ) && is_array( $response['data']['ips'] ) ) {
                // Autoload = false (пїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ)
                update_option( 'rls_global_blacklist', $response['data']['ips'], false );
            }
        }
    }

    public static function sync_local_blacklists( $blocking = false ) {
        if ( ! class_exists( 'RLS_API_Client' ) ) {
            return false;
        }

        $records = self::build_local_blacklist_records();
        if ( empty( $records ) ) {
            return [ 'status' => 'skipped', 'data' => [ 'processed' => 0, 'skipped' => 0 ] ];
        }

        $snapshot = self::get_blacklist_sync_snapshot();
        $payload = self::build_blacklist_sync_payload( $records, $snapshot );

        if ( empty( $payload['delta']['upserts'] ) && empty( $payload['delta']['deletes'] ) ) {
            return [ 'status' => 'skipped', 'data' => [ 'processed' => 0, 'skipped' => 0 ] ];
        }

        $response = RLS_API_Client::sync_blacklist_inventory( $payload, $blocking );
        if ( is_wp_error( $response ) ) {
            return $response;
        }

        if ( ! $blocking || ( is_array( $response ) && ( ( $response['status'] ?? '' ) === 'success' || ( $response['status'] ?? '' ) === 'queued' ) ) ) {
            self::save_blacklist_sync_snapshot( $payload['snapshot'] );
        }

        return $response;
    }

    private static function build_local_blacklist_records() {
        $site_url = home_url();
        $records = [];

        $blocked_ips = get_option( 'rls_blocked_ips', [] );
        if ( is_array( $blocked_ips ) ) {
            foreach ( $blocked_ips as $ip => $row ) {
                $expires = is_array( $row ) ? (int) ( $row['expires'] ?? 0 ) : (int) $row;
                $reason  = is_array( $row ) ? (string) ( $row['reason'] ?? 'WAF block' ) : 'WAF block';
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) && $expires > time() ) {
                    $records[] = [
                        'ip' => $ip,
                        'type' => 'waf',
                        'status' => 'pending',
                        'reason' => $reason,
                        'source_site' => $site_url,
                        'expires' => $expires,
                        'source_kind' => 'waf',
                    ];
                }
            }
        }

        $locked_ips = get_option( 'rls_locked_ips', [] );
        if ( is_array( $locked_ips ) ) {
            foreach ( $locked_ips as $ip => $row ) {
                $expires = is_array( $row ) ? (int) ( $row['expires'] ?? 0 ) : (int) $row;
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) && $expires > time() ) {
                    $records[] = [
                        'ip' => $ip,
                        'type' => 'brute',
                        'status' => 'pending',
                        'reason' => 'BruteForce lockout',
                        'source_site' => $site_url,
                        'expires' => $expires,
                        'source_kind' => 'brute',
                    ];
                }
            }
        }

        $manual_blacklist = get_option( 'rls_manual_blacklist', [] );
        if ( is_array( $manual_blacklist ) ) {
            $manual_blacklist = array_values( array_unique( array_filter( array_map( 'trim', $manual_blacklist ) ) ) );
            foreach ( $manual_blacklist as $ip ) {
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    $records[] = [
                        'ip' => $ip,
                        'type' => 'manual',
                        'status' => 'global',
                        'reason' => 'Manual blacklist',
                        'source_site' => $site_url,
                        'source_kind' => 'manual',
                    ];
                }
            }
        }

        $waf_blacklist = get_option( 'rls_waf_blacklist', [] );
        if ( is_array( $waf_blacklist ) ) {
            $waf_blacklist = array_values( array_unique( array_filter( array_map( 'trim', $waf_blacklist ) ) ) );
            foreach ( $waf_blacklist as $ip ) {
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    $records[] = [
                        'ip' => $ip,
                        'type' => 'waf',
                        'status' => 'global',
                        'reason' => 'WAF injection blacklist',
                        'source_site' => $site_url,
                        'source_kind' => 'waf',
                    ];
                }
            }
        }

        return $records;
    }

    private static function build_blacklist_sync_payload( array $records, array $snapshot ) {
        $current_items = [];
        foreach ( $records as $record ) {
            $normalized = self::normalize_blacklist_sync_record( $record );
            if ( empty( $normalized ) ) {
                continue;
            }

            $key = self::get_blacklist_sync_record_key( $normalized );
            if ( $key === '' ) {
                continue;
            }

            $current_items[ $key ] = [
                'hash' => self::hash_blacklist_sync_record( $normalized ),
                'record' => $normalized,
            ];
        }

        $snapshot_items = [];
        if ( isset( $snapshot['items'] ) && is_array( $snapshot['items'] ) ) {
            $snapshot_items = $snapshot['items'];
        }

        $upserts = [];
        $deletes = [];

        foreach ( $current_items as $key => $entry ) {
            if ( ! isset( $snapshot_items[ $key ] ) || (string) $snapshot_items[ $key ] !== (string) $entry['hash'] ) {
                $upserts[] = $entry['record'];
            }
        }

        foreach ( $snapshot_items as $key => $hash ) {
            if ( isset( $current_items[ $key ] ) ) {
                continue;
            }

            list( $source_kind, $ip ) = array_pad( explode( '|', (string) $key, 2 ), 2, '' );
            if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                continue;
            }

            $deletes[] = [
                'ip' => $ip,
                'source_kind' => $source_kind ?: 'manual',
                'bucket' => $source_kind ?: 'manual',
                'status' => 'pending',
                'source_site' => home_url(),
            ];
        }

        return [
            'site_url' => home_url(),
            'delta' => [
                'upserts' => $upserts,
                'deletes' => $deletes,
            ],
            'snapshot' => [
                'items' => array_map( static function( $entry ) {
                    return $entry['hash'];
                }, $current_items ),
                'updated_at' => time(),
            ],
        ];
    }

    private static function normalize_blacklist_sync_record( array $record ) {
        $ip = trim( (string) ( $record['ip'] ?? '' ) );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return [];
        }

        $source_kind = strtolower( trim( (string) ( $record['source_kind'] ?? '' ) ) );
        if ( ! in_array( $source_kind, [ 'waf', 'brute', 'manual' ], true ) ) {
            $source_kind = 'manual';
        }

        $type = strtolower( trim( (string) ( $record['type'] ?? $source_kind ) ) );
        if ( $type === '' ) {
            $type = $source_kind;
        }

        $status = strtolower( trim( (string) ( $record['status'] ?? 'pending' ) ) );
        if ( $status === '' ) {
            $status = 'pending';
        }

        return [
            'ip' => $ip,
            'type' => $type,
            'status' => $status,
            'reason' => trim( (string) ( $record['reason'] ?? '' ) ),
            'source_site' => trim( (string) ( $record['source_site'] ?? home_url() ) ),
            'source_kind' => $source_kind,
            'expires' => (int) ( $record['expires'] ?? 0 ),
        ];
    }

    private static function get_blacklist_sync_record_key( array $record ) {
        $source_kind = trim( (string) ( $record['source_kind'] ?? '' ) );
        $ip = trim( (string) ( $record['ip'] ?? '' ) );
        if ( $source_kind === '' || $ip === '' ) {
            return '';
        }

        return $source_kind . '|' . $ip;
    }

    private static function hash_blacklist_sync_record( array $record ) {
        return md5( wp_json_encode( [
            'ip' => (string) ( $record['ip'] ?? '' ),
            'type' => (string) ( $record['type'] ?? '' ),
            'status' => (string) ( $record['status'] ?? '' ),
            'reason' => (string) ( $record['reason'] ?? '' ),
            'source_site' => (string) ( $record['source_site'] ?? '' ),
            'source_kind' => (string) ( $record['source_kind'] ?? '' ),
            'expires' => (int) ( $record['expires'] ?? 0 ),
        ] ) );
    }

    private static function get_blacklist_sync_snapshot() {
        $snapshot = get_option( 'rls_blacklist_sync_snapshot', [] );
        if ( ! is_array( $snapshot ) ) {
            return [ 'items' => [] ];
        }

        if ( ! isset( $snapshot['items'] ) || ! is_array( $snapshot['items'] ) ) {
            $snapshot['items'] = [];
        }

        return $snapshot;
    }

    private static function save_blacklist_sync_snapshot( array $snapshot ) {
        if ( ! isset( $snapshot['items'] ) || ! is_array( $snapshot['items'] ) ) {
            $snapshot['items'] = [];
        }

        $snapshot['updated_at'] = time();
        update_option( 'rls_blacklist_sync_snapshot', $snapshot, false );
    }

    private function check_and_run_auto_scan() {
        $frequency = get_option( 'rls_auto_scan_frequency', 'disabled' );
        
        if ( $frequency === 'disabled' ) {
            return;
        }
        
        if ( get_transient( 'rls_scan_in_progress' ) ) {
            return;
        }
        
        $last_scan = (int) get_option( 'rls_last_auto_scan_timestamp', 0 );
        $interval = ( $frequency === 'weekly' ) ? WEEK_IN_SECONDS : DAY_IN_SECONDS;
        
        if ( ( time() - $last_scan ) >= $interval ) {
            update_option( 'rls_last_auto_scan_timestamp', time() );
            set_transient( 'rls_scan_in_progress', true, 600 );
            $this->perform_background_scan();
            delete_transient( 'rls_scan_in_progress' );
        }
    }

    private function perform_background_scan() {
        if ( function_exists( 'set_time_limit' ) ) {
            @set_time_limit( 0 );
        }
        if ( function_exists( 'ini_set' ) ) {
            @ini_set( 'memory_limit', '512M' );
        }

        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ, пїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ Fatal Error
        if ( file_exists( RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-engine.php' ) ) {
            require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-engine.php';
        } else {
            error_log('RLS Error: Scanner engine file missing.');
            return;
        }
        
        if ( ! class_exists( 'RLS_Scan_History' ) && file_exists( RLS_PLUGIN_PATH . 'includes/scanner/class-scan-history.php' ) ) {
            require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scan-history.php';
        }
        
        try {
            if ( class_exists( 'RLS_Scanner_Engine' ) ) {
                $engine = new RLS_Scanner_Engine();
                $files_to_scan = $engine->get_critical_files_list();
                
                if ( ! empty( $files_to_scan ) ) {
                    $start_time = time();
                    $threats = $engine->scan_files_direct( $files_to_scan );
                    $duration = time() - $start_time;
                    
                    if ( class_exists( 'RLS_Scan_History' ) ) {
                        RLS_Scan_History::add_entry( 'auto', $threats, $duration );
                    }
                    
                    if ( count( $threats ) > 0 ) {
                        $stats = get_option( 'rls_stats', [] );
                        $stats['viruses_found'] = ( $stats['viruses_found'] ?? 0 ) + count( $threats );
                        update_option( 'rls_stats', $stats );
                    }
                }
            }
        } catch ( Exception $e ) {
            error_log( 'RLS Auto Scan Error: ' . $e->getMessage() );
        }
    }

    public static function sync_detailed_stats() {
        $current_stats = get_option( 'rls_stats', [] );
        if ( empty( $current_stats ) ) return;

        $last_synced = get_option( 'rls_stats_last_sync_snapshot', [] );
        $stats_to_send = [];
        $has_new_data = false;

        $keys_to_track = [
            'firewall_blocked', 'login_attempts_blocked', 'bad_bots_blocked',
            'viruses_found', 'ai_requests', 'ai_tokens',
            'details_sqli', 'details_xss', 'details_rce', 'details_lfi', 'details_bot',
            'details_geo', 'details_language', 'details_blacklist', 'details_manual', 'details_brute', 'details_waf'
        ];

        foreach ( $keys_to_track as $key ) {
            $curr_val = intval( $current_stats[ $key ] ?? 0 );
            $last_val = intval( $last_synced[ $key ] ?? 0 );

            if ( $curr_val > $last_val ) {
                $stats_to_send[ $key ] = $curr_val - $last_val;
                $has_new_data = true;
            }
        }

        if ( $has_new_data ) {
            $stats_to_send['total_attacks'] = 
                ($stats_to_send['firewall_blocked'] ?? 0) + 
                ($stats_to_send['login_attempts_blocked'] ?? 0) + 
                ($stats_to_send['bad_bots_blocked'] ?? 0);

            $summary_types = [];
            foreach ( $stats_to_send as $key => $value ) {
                if ( strpos( (string) $key, 'details_' ) !== 0 ) {
                    continue;
                }
                $summary_types[ substr( $key, 8 ) ] = (int) $value;
            }

            if ( ! empty( $summary_types ) ) {
                $stats_to_send['attack_log_summary'] = $summary_types;
            }

            $response = RLS_API_Client::report_stats( $stats_to_send );
            if ( is_array( $response ) && isset( $response['status'] ) && $response['status'] === 'success' ) {
                update_option( 'rls_stats_last_sync_snapshot', $current_stats );
            }
        }
    }

    private function update_premium_signatures() {
        $settings = get_option( 'rls_settings', [] );
        $license_key = $settings['license_key'] ?? '';

        if ( ! empty( $license_key ) ) {
            $license_validation = RLS_API_Client::validate_license_key( $license_key );

            if ( is_wp_error( $license_validation ) ) {
                return;
            }

            if ( ! is_array( $license_validation ) || ( $license_validation['status'] ?? '' ) !== 'success' ) {
                rls_store_license_meta( 'invalid' );
                update_option( 'rls_premium_signatures', [] );
                return;
            }

            rls_store_license_meta( 'valid', (array) ( $license_validation['data'] ?? [] ) );

            $response = RLS_API_Client::get_signatures( $license_key );

            if ( is_array( $response ) && isset( $response['status'] ) ) {
                if ( $response['status'] === 'success' && ! empty( $response['data']['signatures'] ) ) {
                    // Autoload = false (пїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ, пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ)
                    update_option( 'rls_premium_signatures', $response['data']['signatures'], false );
                    rls_store_license_meta( 'valid', (array) ( $license_validation['data'] ?? [] ) );
                }
            }
        }
    }

    private function update_geo_database_weekly() {
        if ( ! class_exists( 'RLS_GeoIP' ) ) {
            return;
        }
        if ( ! RLS_GeoIP::is_premium_enabled() ) {
            return;
        }

        $last_update = (int) get_option( 'rls_geo_db_last_update', 0 );
        if ( $last_update > 0 && ( time() - $last_update ) < WEEK_IN_SECONDS ) {
            return;
        }

        $result = RLS_GeoIP::download_lite_database();
        if ( is_wp_error( $result ) ) {
            error_log( 'RLS Geo DB Update Error: ' . $result->get_error_message() );
        }
    }
}

<?php
/**
 * Класс RLS_Cron
 * Управляет фоновыми задачами.
 * Версия 1.5.4 (Optimized)
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
        // 1. Активация
        if ( get_option( 'rls_activation_report_sent' ) !== 'yes' ) {
            $response = RLS_API_Client::report_activation();
            if ( ! is_wp_error( $response ) && isset( $response['status'] ) && $response['status'] === 'success' ) {
                update_option( 'rls_activation_report_sent', 'yes' );
            }
        }

        // 2. Статистика
        self::sync_detailed_stats();

        // 3. Сигнатуры
        $this->update_premium_signatures();

        // 4. Черный список
        $this->sync_global_blacklist();
        
        // 5. Пинг
        RLS_API_Client::send_heartbeat();

        // 6. Автоскан
        $this->check_and_run_auto_scan();
    }

    public function run_daily_tasks() {
        // Резерв для тяжелых задач раз в сутки (например, очистка старых логов)
    }
    
    private function sync_global_blacklist() {
        $response = RLS_API_Client::get_global_blacklist();
        if ( ! is_wp_error( $response ) && isset( $response['status'] ) && $response['status'] === 'success' ) {
            if ( ! empty( $response['data']['ips'] ) && is_array( $response['data']['ips'] ) ) {
                // Autoload = false (ВАЖНО для производительности)
                update_option( 'rls_global_blacklist', $response['data']['ips'], false );
            }
        }
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

        // Проверка наличия файла перед подключением, чтобы избежать Fatal Error
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
            'details_sqli', 'details_xss', 'details_rce', 'details_lfi', 'details_bot'
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
            
            // Если массив не пустой, отправляем
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
            $response = RLS_API_Client::get_signatures( $license_key );

            if ( is_array( $response ) && isset( $response['status'] ) ) {
                if ( $response['status'] === 'success' && ! empty( $response['data']['signatures'] ) ) {
                    // Autoload = false (ВАЖНО для производительности, сигнатуры тяжелые)
                    update_option( 'rls_premium_signatures', $response['data']['signatures'], false );
                    update_option( 'rls_license_status', 'valid' );
                } elseif ( $response['status'] === 'error' && isset( $response['code'] ) && $response['code'] === 'invalid_license' ) {
                    update_option( 'rls_license_status', 'invalid' );
                }
            }
        }
    }
}
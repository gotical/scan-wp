<?php
/**
 * Класс RLS_Cron
 * Управляет выполнением запланированных событий и принудительной синхронизацией статистики.
 * Финальная версия: включает отправку статистики по заблокированным ботам.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) {
    die;
}

class RLS_Cron {

    public function init() {
        add_action('rls_daily_event', [$this, 'run_daily_tasks']);
        add_action('rls_hourly_signature_update_event', [$this, 'run_hourly_signature_update']);
    }

    public function run_daily_tasks() {
        RLS_API_Client::send_heartbeat();
        self::sync_stats_with_server();
    }
    
    /**
     * Статический метод для принудительной синхронизации статистики с сервером.
     * @return bool
     */
    public static function sync_stats_with_server() {
        $stats = get_option('rls_stats', []);
        if (empty($stats) || array_sum($stats) == 0) {
            return true;
        }

        $stats_to_send = [];
        
        // Собираем все типы атак в один счетчик
        $total_attacks = ($stats['firewall_blocked'] ?? 0) + ($stats['login_attempts_blocked'] ?? 0) + ($stats['bad_bots_blocked'] ?? 0);
        if ($total_attacks > 0) {
            $stats_to_send['attacks_prevented'] = $total_attacks;
        }

        // Отдельно собираем найденные файлы
        if (!empty($stats['viruses_found'])) {
            $stats_to_send['infected_files_found'] = $stats['viruses_found'];
        }

        if (!empty($stats_to_send)) {
            $response = RLS_API_Client::report_stats($stats_to_send);
            if (is_array($response) && $response['status'] === 'success') {
                // Сбрасываем все счетчики после успешной отправки
                update_option('rls_stats', [
                    'firewall_blocked' => 0,
                    'viruses_found' => 0,
                    'login_attempts_blocked' => 0,
                    'bad_bots_blocked' => 0,
                ]);
                return true;
            }
        }
        
        return false;
    }
    
    public function run_hourly_signature_update() {
        $settings = get_option('rls_settings', []);
        $license_key = $settings['license_key'] ?? '';
        $license_status = get_option('rls_license_status');

        if (empty($license_key) || $license_status !== 'valid') {
            return;
        }

        $response = RLS_API_Client::get_signatures($license_key);

        if (is_array($response) && $response['status'] === 'success' && !empty($response['data']['signatures'])) {
            update_option('rls_premium_signatures', $response['data']['signatures']);
        } elseif (is_array($response) && $response['status'] === 'error') {
            update_option('rls_license_status', 'invalid');
        }
    }
}
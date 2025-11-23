<?php
/**
 * Класс RLS_Cron
 * Управляет синхронизацией данных.
 * ФИНАЛЬНАЯ ВЕРСИЯ: 
 * 1. Сохраняет полную статистику в админке (не сбрасывает в ноль).
 * 2. Отправляет на сервер только новые события (разницу).
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) {
    die;
}

class RLS_Cron {

    public function init() {
        // Ежедневная задача (сердцебиение + статистика)
        add_action('rls_daily_event', [$this, 'run_daily_tasks']);
        // Ежечасная задача (обновление баз для премиум)
        add_action('rls_hourly_signature_update_event', [$this, 'run_hourly_signature_update']);
    }

    public function run_daily_tasks() {
        RLS_API_Client::send_heartbeat();
        self::sync_stats_with_server();
    }
    
    /**
     * Главная функция синхронизации.
     * Вычисляет разницу между "сейчас" и "прошлый раз", отправляет её вам,
     * но НЕ трогает локальные счетчики, чтобы в виджете были красивые большие цифры.
     * 
     * @return bool
     */
    public static function sync_stats_with_server() {
        // 1. Берем текущие полные цифры (например: 105 атак)
        $current_stats = get_option('rls_stats', []);
        
        if (empty($current_stats) || array_sum($current_stats) == 0) {
            return true; // Нечего отправлять
        }

        // 2. Берем цифры, которые были на момент прошлой отправки (например: 100 атак)
        $last_synced_stats = get_option('rls_stats_last_sync_snapshot', []);

        $stats_to_send = [];
        $has_new_data = false;

        // --- ЛОГИКА ПОДСЧЕТА РАЗНИЦЫ (ДЕЛЬТЫ) ---

        // А. Атаки (WAF + Боты + Вход)
        $current_attacks = 
            intval($current_stats['firewall_blocked'] ?? 0) + 
            intval($current_stats['login_attempts_blocked'] ?? 0) + 
            intval($current_stats['bad_bots_blocked'] ?? 0);
            
        $last_attacks = 
            intval($last_synced_stats['firewall_blocked'] ?? 0) + 
            intval($last_synced_stats['login_attempts_blocked'] ?? 0) + 
            intval($last_synced_stats['bad_bots_blocked'] ?? 0);

        // Если стало больше (105 > 100), отправляем разницу (5)
        if ($current_attacks > $last_attacks) {
            $stats_to_send['attacks_prevented'] = $current_attacks - $last_attacks;
            $has_new_data = true;
        }

        // Б. Вирусы
        $cur_viruses = intval($current_stats['viruses_found'] ?? 0);
        $last_viruses = intval($last_synced_stats['viruses_found'] ?? 0);
        
        if ($cur_viruses > $last_viruses) {
            $stats_to_send['infected_files_found'] = $cur_viruses - $last_viruses;
            $has_new_data = true;
        }

        // В. AI Запросы
        $cur_ai_req = intval($current_stats['ai_requests'] ?? 0);
        $last_ai_req = intval($last_synced_stats['ai_requests'] ?? 0);
        
        if ($cur_ai_req > $last_ai_req) {
            $stats_to_send['ai_requests'] = $cur_ai_req - $last_ai_req;
            $has_new_data = true;
        }

        // Г. AI Токены
        $cur_ai_tok = intval($current_stats['ai_tokens'] ?? 0);
        $last_ai_tok = intval($last_synced_stats['ai_tokens'] ?? 0);
        
        if ($cur_ai_tok > $last_ai_tok) {
            $stats_to_send['ai_tokens'] = $cur_ai_tok - $last_ai_tok;
            $has_new_data = true;
        }

        // 3. Отправка на сервер
        if ($has_new_data && !empty($stats_to_send)) {
            $response = RLS_API_Client::report_stats($stats_to_send);
            
            if (is_array($response) && $response['status'] === 'success') {
                // 4. ВАЖНО: Мы НЕ обнуляем rls_stats. 
                // Мы просто запоминаем, что на этот момент мы всё синхронизировали.
                update_option('rls_stats_last_sync_snapshot', $current_stats);
                return true;
            }
        } elseif (!$has_new_data) {
            // Данных новых нет, всё ок
            return true;
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
<?php
/**
 * Класс RLS_API_Client
 * Отвечает за все коммуникации с удаленным API-сервером.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) {
    die;
}

class RLS_API_Client {

    private static function send_request($body_data) {
        $args = ['timeout' => 25, 'body' => $body_data];
        $response = wp_remote_post(RLS_API_URL, $args);
        if (is_wp_error($response)) return $response;
        return json_decode(wp_remote_retrieve_body($response), true);
    }

    public static function report_activation() {
        global $wp_version;
        self::send_request(['action' => 'activate_plugin', 'site_url' => home_url(), 'plugin_version' => RLS_VERSION, 'wp_version' => $wp_version]);
    }

    public static function report_deactivation() {
        self::send_request(['action' => 'deactivate_plugin', 'site_url' => home_url()]);
    }
    
    public static function send_heartbeat() {
        self::send_request(['action' => 'heartbeat', 'site_url' => home_url()]);
    }

    public static function validate_license_key($license_key) {
        return self::send_request(['action' => 'validate_key', 'license_key' => $license_key, 'site_url' => home_url()]);
    }

    public static function get_signatures($license_key) {
        return self::send_request(['action' => 'get_signatures', 'license_key' => $license_key]);
    }

    public static function submit_suggestion($signature) {
        try {
            self::send_request(['action' => 'submit_suggestion', 'signature' => $signature, 'site_url' => home_url()]);
        } catch (Exception $e) { /* Игнорируем ошибку */ }
    }
    
    public static function report_stats($stats_data) {
        return self::send_request(['action' => 'report_stats', 'stats_data' => json_encode($stats_data), 'site_url' => home_url()]);
    }

    /**
     * Отправляет фрагмент кода на сервер для AI-анализа.
     * Считает использование токенов и запросов.
     */
    public static function analyze_code_snippet($snippet) {
        $response = self::send_request([
            'action' => 'analyze_code_snippet',
            'snippet' => $snippet,
            'site_url' => home_url()
        ]);

        // Учет статистики AI, если запрос прошел успешно
        if (!is_wp_error($response) && is_array($response) && isset($response['status']) && $response['status'] === 'success') {
            // Увеличиваем счетчик запросов
            RLS_Stats_Helper::increment_stat('ai_requests');

            // Пытаемся найти данные о токенах. 
            // Проверяем стандартные форматы ответа OpenAI или RybinskLab
            $tokens = 0;
            if (isset($response['data']['tokens_used'])) {
                $tokens = (int)$response['data']['tokens_used'];
            } elseif (isset($response['data']['usage']['total_tokens'])) {
                $tokens = (int)$response['data']['usage']['total_tokens'];
            }
            
            if ($tokens > 0) {
                RLS_Stats_Helper::increment_stat('ai_tokens', $tokens);
            }
        }

        return $response;
    }
}
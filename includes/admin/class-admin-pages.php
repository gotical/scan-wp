<?php
/**
 * Класс RLS_Admin_Pages
 * Финальная версия: включает "очистку" настроек для фильтра ботов.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) {
    die;
}

class RLS_Admin_Pages {

    public function init() {
        add_action('admin_menu', [$this, 'setup_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
        add_action('admin_init', [$this, 'initialize_settings']);
        add_action('wp_ajax_rls_add_signature', [$this, 'ajax_add_signature']);
        add_action('wp_ajax_rls_delete_signature', [$this, 'ajax_delete_signature']);
        add_action('wp_ajax_rls_sync_stats', [$this, 'ajax_sync_stats']);
        add_action('wp_ajax_rls_add_login_question', [$this, 'ajax_add_login_question']);
        add_action('wp_ajax_rls_delete_login_question', [$this, 'ajax_delete_login_question']);
        add_action('wp_ajax_rls_neutralize_file', [$this, 'ajax_neutralize_file']);
    }

    public function setup_admin_menu() {
        add_menu_page('Rybinsk Lab Security - Сканер', 'RL Security', 'manage_options', 'rls-scanner', [$this, 'render_scanner_page'], 'dashicons-shield-alt', 26);
        add_submenu_page('rls-scanner', 'Сканер вирусов и файлов', 'Сканер', 'manage_options', 'rls-scanner', [$this, 'render_scanner_page']);
        add_submenu_page('rls-scanner', 'Настройки', 'Настройки', 'manage_options', 'rls-settings', [$this, 'render_settings_page']);
    }
    
    public function enqueue_admin_assets($hook_suffix) {
        if (strpos($hook_suffix, 'rls-') === false) return;
        wp_enqueue_script('rls-admin-script', plugin_dir_url(RLS_PLUGIN_FILE) . 'assets/js/admin.js', ['jquery'], RLS_VERSION, true);
        wp_localize_script('rls-admin-script', 'rls_admin_data', ['ajax_url' => admin_url('admin-ajax.php'), 'sync_nonce' => wp_create_nonce('rls_sync_nonce')]);
        wp_enqueue_style('rls-admin-styles', plugin_dir_url(RLS_PLUGIN_FILE) . 'assets/css/admin.css', [], RLS_VERSION);
        if ($hook_suffix === 'toplevel_page_rls-scanner' || $hook_suffix === 'rl-security_page_rls-scanner') {
            wp_enqueue_script('rls-scanner-script', plugin_dir_url(RLS_PLUGIN_FILE) . 'assets/js/scanner.js', ['jquery'], RLS_VERSION, true);
            wp_localize_script('rls-scanner-script', 'rls_scanner_data', ['ajax_url' => admin_url('admin-ajax.php'),'nonce' => wp_create_nonce('rls_scanner_nonce'),'snapshot_exists' => (get_option('rls_snapshot_time', 0) > 0)]);
        }
    }
    
    public function render_scanner_page() { require_once RLS_PLUGIN_PATH . 'includes/admin/views/scanner-page.php'; }
    public function render_settings_page() { require_once RLS_PLUGIN_PATH . 'includes/admin/views/settings-page.php'; }
    public function initialize_settings() { register_setting('rls_settings_group', 'rls_settings', [$this, 'sanitize_settings_array']); }
    
    public function sanitize_settings_array($input) {
        $old_settings = get_option('rls_settings', []);
        $sanitized_input = $old_settings;
        $sanitized_input['enable_firewall'] = (isset($input['enable_firewall']) && $input['enable_firewall'] == 1) ? 1 : 0;
        $sanitized_input['enable_login_security'] = (isset($input['enable_login_security']) && $input['enable_login_security'] == 1) ? 1 : 0;
        if (isset($input['login_questions_count'])) { $sanitized_input['login_questions_count'] = in_array($input['login_questions_count'], [1, 2, 3]) ? (int)$input['login_questions_count'] : 1; }
        if (isset($input['license_key'])) { $sanitized_input['license_key'] = sanitize_text_field(strtoupper(trim($input['license_key']))); }
        
        // --- НОВЫЙ БЛОК: Сохранение настроек для ботов ---
        // Если чекбокс отмечен, сохраняем 1, если не отмечен - 0.
        $sanitized_input['allow_googlebot'] = (isset($input['allow_googlebot']) && $input['allow_googlebot'] == 1) ? 1 : 0;
        $sanitized_input['allow_yandexbot'] = (isset($input['allow_yandexbot']) && $input['allow_yandexbot'] == 1) ? 1 : 0;
        $sanitized_input['allow_bingbot'] = (isset($input['allow_bingbot']) && $input['allow_bingbot'] == 1) ? 1 : 0;

        return $sanitized_input;
    }

    public function ajax_neutralize_file() {
        check_ajax_referer('rls_scanner_nonce', 'nonce'); if (!current_user_can('manage_options')) wp_send_json_error('Нет прав.');
        $filepath = trim(stripslashes($_POST['filepath'] ?? '')); $signature = trim(stripslashes($_POST['signature'] ?? ''));
        if (empty($filepath) || !is_readable($filepath)) wp_send_json_error('Файл не найден или недоступен для чтения.');
        global $wp_version; $checksums = get_transient('wp_core_checksums_' . $wp_version);
        if (false === $checksums) {
            $response = wp_remote_get("https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale=ru_RU");
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) { $checksums = json_decode(wp_remote_retrieve_body($response), true)['checksums'] ?? []; set_transient('wp_core_checksums_' . $wp_version, $checksums, DAY_IN_SECONDS); } else { $checksums = []; }
        }
        $relative_path = str_replace(ABSPATH, '', $filepath);
        if (isset($checksums[$relative_path])) {
            if (md5_file($filepath) === $checksums[$relative_path]) { $this->add_to_whitelist($filepath, $checksums[$relative_path]); wp_send_json_success(['result' => 'whitelisted', 'message' => 'Файл ядра WordPress.']); }
        }
        $code_snippet = $this->get_code_snippet($filepath, $signature); if (!$code_snippet) wp_send_json_error('Не удалось найти сигнатуру в файле.');
        $ai_response = RLS_API_Client::analyze_code_snippet($code_snippet);
        if (is_wp_error($ai_response) || !is_array($ai_response) || $ai_response['status'] !== 'success') wp_send_json_error($ai_response['message'] ?? 'Ошибка сервера анализа.');
        $verdict = $ai_response['data']['verdict'] ?? 'Error';
        if ($verdict === 'Legitimate') { $this->add_to_whitelist($filepath, md5_file($filepath)); wp_send_json_success(['result' => 'ai_legitimate', 'message' => 'AI счел код безопасным.']); } 
        else { RLS_Stats_Helper::increment_stat('firewall_blocked'); wp_send_json_success(['result' => 'ai_virus', 'message' => 'AI подтвердил вредоносный код.', 'snippet' => esc_html($code_snippet)]); }
    }
    private function add_to_whitelist($filepath, $hash) { $whitelist = get_option('rls_whitelist', []); $whitelist[$filepath] = $hash; update_option('rls_whitelist', $whitelist); }
    private function get_code_snippet($filepath, $signature) { $lines = file($filepath, FILE_IGNORE_NEW_LINES); if (!$lines) return false; $line_number = -1; foreach ($lines as $key => $line) { if (strpos($line, $signature) !== false) { $line_number = $key; break; } } if ($line_number === -1) return false; $start = max(0, $line_number - 3); $end = min(count($lines) - 1, $line_number + 3); $snippet_lines = []; for ($i = $start; $i <= $end; $i++) { $snippet_lines[] = "Line " . ($i + 1) . ": " . $lines[$i]; } return implode("\n", $snippet_lines); }
    public function ajax_add_signature() { check_ajax_referer('rls_signatures_nonce', 'nonce'); if (!current_user_can('manage_options')) wp_send_json_error('Нет прав.'); $signature = trim(stripslashes($_POST['signature'] ?? '')); if (empty($signature)) wp_send_json_error('Сигнатура пуста.'); $custom_signatures = get_option('rls_custom_signatures', []); if (!in_array($signature, $custom_signatures)) { $custom_signatures[] = $signature; update_option('rls_custom_signatures', $custom_signatures); try { RLS_API_Client::submit_suggestion($signature); } catch (Exception $e) {} } wp_send_json_success(['signature' => esc_html($signature)]); }
    public function ajax_delete_signature() { check_ajax_referer('rls_signatures_nonce', 'nonce'); if (!current_user_can('manage_options')) wp_send_json_error('Нет прав.'); $signature_to_delete = trim(stripslashes($_POST['signature'] ?? '')); if (empty($signature_to_delete)) wp_send_json_error('Сигнатура не указана.'); $custom_signatures = get_option('rls_custom_signatures', []); $key = array_search($signature_to_delete, $custom_signatures); if ($key !== false) { unset($custom_signatures[$key]); update_option('rls_custom_signatures', array_values($custom_signatures)); } wp_send_json_success(['signature' => esc_html($signature_to_delete)]); }
    public function ajax_sync_stats() { check_ajax_referer('rls_sync_nonce', 'nonce'); if (!current_user_can('manage_options')) wp_send_json_error('Нет прав.'); $success = RLS_Cron::sync_stats_with_server(); if ($success) wp_send_json_success('Статистика синхронизирована.'); else wp_send_json_error('Не удалось синхронизировать.'); }
    public function ajax_add_login_question() { check_ajax_referer('rls_login_questions_nonce', 'nonce'); if (!current_user_can('manage_options')) wp_send_json_error('Нет прав.'); $question = trim(stripslashes($_POST['question'] ?? '')); $answer = trim(stripslashes($_POST['answer'] ?? '')); if (empty($question) || empty($answer)) wp_send_json_error('Вопрос и ответ не могут быть пустыми.'); $all_questions = get_option('rls_login_questions', []); if (count($all_questions) >= 10) wp_send_json_error('Можно добавить не более 10 вопросов.'); $all_questions[] = ['q' => $question, 'a_hash' => wp_hash_password($answer)]; update_option('rls_login_questions', $all_questions); wp_send_json_success(['key' => array_key_last($all_questions), 'question' => esc_html($question)]); }
    public function ajax_delete_login_question() { check_ajax_referer('rls_login_questions_nonce', 'nonce'); if (!current_user_can('manage_options')) wp_send_json_error('Нет прав.'); $key = isset($_POST['key']) ? (int)$_POST['key'] : -1; if ($key < 0) wp_send_json_error('Неверный ключ вопроса.'); $all_questions = get_option('rls_login_questions', []); if (isset($all_questions[$key])) { unset($all_questions[$key]); update_option('rls_login_questions', $all_questions); } wp_send_json_success(['key' => $key]); }
}
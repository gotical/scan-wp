<?php
/**
 * Класс RLS_Firewall
 * Базовый Web Application Firewall с "умным" фильтром ботов.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Вспомогательный класс для работы со статистикой.
 */
class RLS_Stats_Helper {
    public static function increment_stat($counter_key, $value = 1) {
        $stats = get_option('rls_stats', []);
        $stats[$counter_key] = ($stats[$counter_key] ?? 0) + $value;
        update_option('rls_stats', $stats);
    }
}

class RLS_Firewall {
    
    const FIREWALL_LOG_OPTION = 'rls_firewall_log';
    const MAX_LOG_ENTRIES = 500;
    const BLOCK_DURATION = 3600;
    
    const PATTERNS = [
        'sql_injection' => ['patterns' => [ 'union\s+select', 'concat\s*\(', 'group_concat\s*\(', 'information_schema', '--\s+', '\/\*\!', '\*\/', ';\s?--', 'waitfor\s+delay', 'benchmark\s*\(', 'sleep\s*\(', 'drop\s+table', 'insert\s+into', 'update\s+\w+\s+set', 'delete\s+from' ], 'reason' => 'SQL-инъекция'],
        'code_execution' => ['patterns' => [ 'base64_decode\s*\(', 'eval\s*\(', 'assert\s*\(', 'create_function\s*\(', 'preg_replace\s*\(.*\/e', 'system\s*\(', 'exec\s*\(', 'passthru\s*\(', 'shell_exec\s*\(', 'proc_open\s*\(', 'popen\s*\(', '`.*`', 'phpinfo\s*\(' ], 'reason' => 'Выполнение кода'],
        'directory_traversal' => ['patterns' => [ '\.\.\/', '\.\.\\', '\.\/\.\/', '\/etc\/passwd', '\/etc\/hosts', '\/proc\/self', '\.\.%2f', '\.\.%5c' ], 'reason' => 'Обход директории'],
        'xss' => ['patterns' => [ '<script[^>]*>', 'javascript:', 'onload\s*=', 'onerror\s*=', 'onclick\s*=', 'onmouseover\s*=', 'alert\s*\(', 'document\.cookie', 'window\.location' ], 'reason' => 'XSS-атака']
    ];
    
    private $blocked = false;
    private $block_reason = '';
    private $client_ip = '';
    private $user_agent = '';
    private $request_uri = '';
    
    public function init() {
        add_action('plugins_loaded', [$this, 'run_checks'], 1);
    }
    
    public function run_checks() {
        $settings = get_option('rls_settings', []);
        if (empty($settings['enable_firewall'])) return;
        
        $this->init_request_data();
        
        if (current_user_can('manage_options')) return;
        
        // --- ОБНОВЛЕННАЯ ЛОГИКА ПРОВЕРОК ---
        // Сначала проверяем на хороших ботов. Если это хороший бот, прекращаем все дальнейшие проверки.
        if ($this->is_good_bot()) {
            return;
        }

        if ($this->is_ip_blocked()) {
            $this->block('IP адрес находится в черном списке');
        } else {
            $this->perform_security_checks();
        }
        
        if ($this->blocked) {
            $this->trigger_block();
        }
    }
    
    private function init_request_data() {
        $this->client_ip = $this->get_client_ip();
        $this->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->request_uri = $_SERVER['REQUEST_URI'] ?? '';
    }
    
    /**
     * НОВЫЙ МЕТОД: Проверяет, является ли посетитель разрешенным поисковым ботом.
     * @return bool
     */
    private function is_good_bot() {
        if (empty($this->user_agent)) return false;

        $user_agent_lower = strtolower($this->user_agent);
        $settings = get_option('rls_settings', []);

        $good_bots = [
            'allow_googlebot' => 'googlebot',
            'allow_yandexbot' => 'yandexbot',
            'allow_bingbot'   => 'bingbot',
        ];

        foreach ($good_bots as $option_key => $bot_ua) {
            if (!empty($settings[$option_key]) && strpos($user_agent_lower, $bot_ua) !== false) {
                // Дополнительно можно добавить проверку по DNS, но для базовой защиты этого достаточно
                return true;
            }
        }
        return false;
    }
    
    private function is_ip_blocked() {
        $blocked_ips = get_option('rls_blocked_ips', []);
        if (empty($blocked_ips) || !isset($blocked_ips[$this->client_ip])) return false;
        if (time() > $blocked_ips[$this->client_ip]['expires']) {
            unset($blocked_ips[$this->client_ip]);
            update_option('rls_blocked_ips', $blocked_ips);
            return false;
        }
        return true;
    }
    
    private function perform_security_checks() {
        $data_to_scan = $this->get_request_data();
        foreach (self::PATTERNS as $attack_type => $config) {
            foreach ($config['patterns'] as $pattern) {
                foreach ($data_to_scan as $data) {
                    if (preg_match('/' . $pattern . '/i', $data)) {
                        $this->block($config['reason']);
                        RLS_Stats_Helper::increment_stat('firewall_blocked');
                        return;
                    }
                }
            }
        }
        $this->check_bad_bots_and_scanners();
    }
    
    private function get_request_data() {
        $data = [];
        $data[] = strtolower(rawurldecode($this->request_uri));
        if (!empty($_GET)) $data[] = strtolower(rawurldecode(json_encode($_GET)));
        if (!empty($_POST)) $data[] = strtolower(rawurldecode(json_encode($_POST)));
        if (!empty($_COOKIE)) $data[] = strtolower(rawurldecode(json_encode($_COOKIE)));
        return $data;
    }

    private function check_bad_bots_and_scanners() {
        if (empty($this->user_agent)) return;
        $user_agent_lower = strtolower($this->user_agent);
        $suspicious_agents = ['nmap', 'nikto', 'sqlmap', 'w3af', 'acunetix', 'nessus', 'havij', 'burp', 'dirbuster', 'scan', 'bot', 'crawl', 'spider'];
        foreach ($suspicious_agents as $agent) {
            if (strpos($user_agent_lower, $agent) !== false) {
                $this->block("Подозрительный User-Agent");
                RLS_Stats_Helper::increment_stat('bad_bots_blocked'); 
                return;
            }
        }
    }
    
    private function block($reason) {
        if ($this->blocked) return;
        $this->blocked = true;
        $this->block_reason = $reason;
        $blocked_ips = get_option('rls_blocked_ips', []);
        $blocked_ips[$this->client_ip] = ['reason' => $reason, 'expires' => time() + self::BLOCK_DURATION];
        update_option('rls_blocked_ips', $blocked_ips);
    }
    
    private function trigger_block() {
        $this->log_blocked_request();
        status_header(403);
        $this->display_block_page();
        exit;
    }
    
    private function log_blocked_request() {
        $log_entries = get_option(self::FIREWALL_LOG_OPTION, []);
        $log_entry = ['timestamp' => current_time('mysql'), 'ip' => $this->client_ip, 'user_agent' => esc_html(substr($this->user_agent, 0, 255)), 'request_uri' => esc_html(substr($this->request_uri, 0, 500)), 'reason' => esc_html($this->block_reason), 'method' => esc_html($_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN')];
        array_unshift($log_entries, $log_entry);
        if (count($log_entries) > self::MAX_LOG_ENTRIES) {
            $log_entries = array_slice($log_entries, 0, self::MAX_LOG_ENTRIES);
        }
        update_option(self::FIREWALL_LOG_OPTION, $log_entries);
    }
    
    private function display_block_page() {
        $page_html = "<!DOCTYPE html><html><head><title>403 Forbidden - Доступ запрещен</title><style>body{font-family:Arial,sans-serif;background:#f1f1f1;color:#333;text-align:center;padding:50px;} .container{max-width:600px;margin:0 auto;background:#fff;padding:30px;border-radius:5px;box-shadow:0 0 10px rgba(0,0,0,0.1);} h1{color:#d9534f;} p{font-size:1.1em;}</style></head><body><div class='container'><h1>403 Forbidden</h1><p>Ваш запрос был заблокирован системой безопасности Rybinsk Lab Security.</p><p><small>Ваш IP: " . esc_html($this->client_ip) . "</small></p></div></body></html>";
        echo $page_html;
    }
    
    private function get_client_ip() {
        $ip_keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP) !== false) return $ip;
                }
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    }
}
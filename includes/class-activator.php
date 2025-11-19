<?php
/**
 * Класс RLS_Activator
 * Выполняет действия при активации и деактивации плагина.
 * Финальная версия: создает опции для белого списка и фильтра ботов.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

// Прямой доступ запрещен
if (!defined('WPINC')) {
    die;
}

class RLS_Activator {

    /**
     * Статический метод, вызываемый при активации плагина.
     */
    public static function activate() {
        self::setup_options();
        self::schedule_cron_jobs();
        RLS_API_Client::report_activation();
    }

    /**
     * Статический метод, вызываемый при деактивации плагина.
     */
    public static function deactivate() {
        RLS_API_Client::report_deactivation();
        self::clear_cron_jobs();
    }
    
    /**
     * Устанавливает/обновляет начальные значения опций плагина.
     */
    private static function setup_options() {
        
        // Базовый (бесплатный) набор сигнатур
        $default_signatures = [
            'FilesMan', 'r57shell', 'c99shell', 'IndoXploit', 'shell_exec("uname -a")',
            'eval(gzinflate(base64_decode', 'eval(base64_decode($_POST', 'eval(base64_decode($_GET',
            'preg_replace("/.*/e"', 'Wp-Vcd', 'scanRootPaths(); die(\'!ended!\');', '<?php $upgrading =',
            'eval($_HEADERS', 'file_put_contents("wp-content/uploads/\'.md5', "md5(\$_GET['pass'])"
        ];
        update_option('rls_base_signatures', $default_signatures);

        // --- Все остальные опции добавляем, только если они не существуют ---
        
        // Опция для хранения общих настроек (массив)
        if (get_option('rls_settings') === false) {
            add_option('rls_settings', [
                'enable_firewall' => 0,
                'enable_login_security' => 0,
                'login_questions_count' => 1,
                'license_key' => '',
                'allow_googlebot' => 1, // Разрешаем Google по умолчанию
                'allow_yandexbot' => 1, // Разрешаем Яндекс по умолчанию
                'allow_bingbot' => 0,
            ]);
        }

        // Опции для лицензирования
        if (get_option('rls_license_status') === false) { add_option('rls_license_status', ''); }
        if (get_option('rls_license_expires_at') === false) { add_option('rls_license_expires_at', ''); }

        // Опции для пользовательских сигнатур
        if (get_option('rls_custom_signatures') === false) { add_option('rls_custom_signatures', []); }
        
        // Опции для сканера изменений (снимков)
        if (get_option('rls_snapshot_data') === false) { add_option('rls_snapshot_data', []); }
        if (get_option('rls_snapshot_time') === false) { add_option('rls_snapshot_time', 0); }
        
        // Опция для хранения глобальных вопросов и ответов
        if (get_option('rls_login_questions') === false) { add_option('rls_login_questions', []); }
        
        // Опция для хранения локальной статистики
        if (get_option('rls_stats') === false) {
            add_option('rls_stats', [
                'firewall_blocked' => 0,
                'viruses_found' => 0,
                'login_attempts_blocked' => 0,
                'bad_bots_blocked' => 0, // Новый счетчик для плохих ботов
            ]);
        }

        // НОВАЯ ОПЦИЯ: Белый список для файлов, проверенных по хэшу или AI
        if (get_option('rls_whitelist') === false) {
            add_option('rls_whitelist', []); // Будет массивом вида ['/path/to/file.php' => 'md5_hash']
        }
    }
    
    /**
     * Планирует Cron-задачи с помощью WordPress Cron API.
     */
    private static function schedule_cron_jobs() {
        if (!wp_next_scheduled('rls_daily_event')) {
            wp_schedule_event(time(), 'daily', 'rls_daily_event');
        }
        if (!wp_next_scheduled('rls_hourly_signature_update_event')) {
            wp_schedule_event(time(), 'hourly', 'rls_hourly_signature_update_event');
        }
    }
    
    /**
     * Полностью удаляет Cron-задачи при деактивации плагина.
     */
    private static function clear_cron_jobs() {
        wp_clear_scheduled_hook('rls_daily_event');
        wp_clear_scheduled_hook('rls_hourly_signature_update_event');
    }
}
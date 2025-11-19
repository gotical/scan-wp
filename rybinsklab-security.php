<?php
/**
 * Plugin Name:       Rybinsk Lab Security
 * Plugin URI:        https://rybinsklab.ru/scan-wp/
 * Description:       Комплексное решение для безопасности: сканер вредоносного кода, базовый фаервол (WAF), мониторинг файлов, защита входа и сбор статистики. Авторское право: Усачёв Денис.
 * Version:           1.3.0
 * Author:            Усачёв Денис
 * Author URI:        https://rybinsklab.ru/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       rybinsklab-security
 */

// Прямой доступ к файлу запрещен.
if (!defined('WPINC')) {
    die;
}

/**
 * Определяем основные константы плагина.
 */
define('RLS_VERSION', '1.4.2');
define('RLS_API_URL', 'https://rybinsklab.ru/scan-wp/api/index.php');
define('RLS_PLUGIN_FILE', __FILE__);
define('RLS_PLUGIN_PATH', plugin_dir_path(__FILE__));

/**
 * Подключаем файлы с основными классами.
 */
// Модуль 1: Фаервол (WAF)
require_once RLS_PLUGIN_PATH . 'includes/class-firewall.php';
// Модуль 2: Защита входа (Контрольные вопросы) - НОВЫЙ
require_once RLS_PLUGIN_PATH . 'includes/class-login-security.php';
// Вспомогательные и фоновые классы
require_once RLS_PLUGIN_PATH . 'includes/class-api-client.php';
require_once RLS_PLUGIN_PATH . 'includes/class-activator.php';
require_once RLS_PLUGIN_PATH . 'includes/class-cron.php';
// Классы для админ-панели
require_once RLS_PLUGIN_PATH . 'includes/admin/class-admin-pages.php';
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-engine.php';
require_once RLS_PLUGIN_PATH . 'includes/admin/class-dashboard-widget.php';


/**
 * Регистрируем хуки активации и деактивации.
 */
register_activation_hook(RLS_PLUGIN_FILE, ['RLS_Activator', 'activate']);
register_deactivation_hook(RLS_PLUGIN_FILE, ['RLS_Activator', 'deactivate']);


/**
 * Основная функция-инициализатор плагина.
 */
function rls_run_plugin() {
    // Инициализируем фаервол.
    $firewall = new RLS_Firewall();
    $firewall->init();

    // Инициализируем модуль защиты входа - НОВЫЙ
    $login_security = new RLS_Login_Security();
    $login_security->init();
    
    // Инициализируем Cron-задачи.
    $cron = new RLS_Cron();
    $cron->init();

    // Запускаем административные модули только если мы находимся в админ-панели.
    if (is_admin()) {
        // Инициализируем страницы настроек и сканера
        $admin_pages = new RLS_Admin_Pages();
        $admin_pages->init();

        // Инициализируем AJAX-обработчики для сканера
        $scanner_engine = new RLS_Scanner_Engine();
        $scanner_engine->init();

        // Инициализируем виджет на главной странице консоли
        $dashboard_widget = new RLS_Dashboard_Widget();
        $dashboard_widget->init();
    }
}

// Запускаем наш плагин, когда все плагины WordPress уже загружены
add_action('plugins_loaded', 'rls_run_plugin');
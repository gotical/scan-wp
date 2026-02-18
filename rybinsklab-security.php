<?php
/**
 * Plugin Name:       Rybinsk Lab Security
 * Plugin URI:        https://rybinsklab.ru/scan-wp/
 * Description:       Комплексное решение для безопасности: WAF, Глобальный черный список IP, Сканер, Защита входа и Журнал атак.
 * Version:           1.7.9
 * Author:            Усачёв Денис
 * Author URI:        https://rybinsklab.ru/
 * License:           GPL v2 or later
 * Text Domain:       rybinsklab-security
 * Domain Path:       /languages
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Константы
 */
define( 'RLS_VERSION', '1.7.9' );
define( 'RLS_API_URL', 'https://rybinsklab.ru/scan-wp/api/index.php' );
define( 'RLS_PLUGIN_FILE', __FILE__ );
define( 'RLS_PLUGIN_PATH', plugin_dir_path( __FILE__ ) );
define( 'RLS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Подключение классов
 */

// Ядро защиты
require_once RLS_PLUGIN_PATH . 'includes/class-firewall.php';
require_once RLS_PLUGIN_PATH . 'includes/class-login-security.php';

// Вспомогательные классы
require_once RLS_PLUGIN_PATH . 'includes/class-api-client.php';
require_once RLS_PLUGIN_PATH . 'includes/class-activator.php';
require_once RLS_PLUGIN_PATH . 'includes/class-cron.php';
require_once RLS_PLUGIN_PATH . 'includes/class-updater.php';
require_once RLS_PLUGIN_PATH . 'includes/class-logger.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-rls-quarantine.php';

// Модули сканера и админки
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scan-history.php';
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-engine.php';
require_once RLS_PLUGIN_PATH . 'includes/admin/class-admin-pages.php';
require_once RLS_PLUGIN_PATH . 'includes/admin/class-dashboard-widget.php';

/**
 * Хуки активации
 */
register_activation_hook( RLS_PLUGIN_FILE, [ 'RLS_Activator', 'activate' ] );
register_deactivation_hook( RLS_PLUGIN_FILE, [ 'RLS_Activator', 'deactivate' ] );

/**
 * Инициализация
 */
function rls_run_plugin(): void {
    load_plugin_textdomain(
        'rybinsklab-security',
        false,
        dirname( plugin_basename( RLS_PLUGIN_FILE ) ) . '/languages'
    );

    // Инициализация ядра безопасности
    $firewall = new RLS_Firewall();
    $firewall->init();

    $login_security = new RLS_Login_Security();
    $login_security->init();

    $cron = new RLS_Cron();
    $cron->init();

    // Инициализация авто-обновления
    new RLS_Updater( 
        RLS_VERSION, 
        plugin_basename( RLS_PLUGIN_FILE ), 
        RLS_API_URL 
    );

    // Инициализация админки
    if ( is_admin() ) {
        $admin_pages = new RLS_Admin_Pages();
        $admin_pages->init();

        $scanner_engine = new RLS_Scanner_Engine();
        $scanner_engine->init();

        $dashboard_widget = new RLS_Dashboard_Widget();
        $dashboard_widget->init();
    }
}

add_action( 'plugins_loaded', 'rls_run_plugin' );
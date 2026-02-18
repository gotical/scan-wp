<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Проверяем опцию, которую мы сохранили при деактивации через JS окно
$wipe_data = get_option( 'rls_wipe_data_on_uninstall', false );

// Если пользователь выбрал "Сохранить настройки" или просто удалил без выбора — мы НЕ удаляем данные
if ( ! $wipe_data ) {
    return;
}

global $wpdb;

// 1. Удаляем таблицы
$table_scan = $wpdb->prefix . 'rls_scan_history';
$table_log  = $wpdb->prefix . 'rls_attack_log';

$wpdb->query( "DROP TABLE IF EXISTS $table_scan" );
$wpdb->query( "DROP TABLE IF EXISTS $table_log" );

// 2. Удаляем опции
$options_to_delete = [
    'rls_settings',
    'rls_base_signatures',
    'rls_premium_signatures',
    'rls_custom_signatures',
    'rls_license_status',
    'rls_license_expires_at',
    'rls_stats',
    'rls_stats_last_sync_snapshot',
    'rls_ip_whitelist',
    'rls_manual_blacklist',
    'rls_global_blacklist',
    'rls_auto_scan_frequency',
    'rls_last_auto_scan_timestamp',
    'rls_activation_report_sent',
    'rls_login_questions',
    'rls_locked_ips',
    'rls_snapshot_data',
    'rls_snapshot_time',
    'rls_comparison_results',
    'rls_comparison_time',
    'rls_last_scan_results',
    'rls_last_scan_time',
    'rls_whitelist',
    'rls_firewall_log',
    'rls_wipe_data_on_uninstall' // Саму метку тоже удаляем
];

foreach ( $options_to_delete as $option ) {
    delete_option( $option );
}

// 3. Удаляем транзиенты
delete_transient( 'rls_scan_file_list' );
delete_transient( 'rls_dirs_to_scan' );
delete_transient( 'rls_failed_log' );
delete_transient( 'rls_last_pulse_sent' );
delete_transient( 'rls_admin_heartbeat_sent' );
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

require_once __DIR__ . '/includes/class-activator.php';

if ( class_exists( 'RLS_Activator' ) ) {
    RLS_Activator::purge_plugin_data();
}

<?php
/**
 * Multisite support helpers.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Multisite {

    public function init() {
        if ( ! is_multisite() ) return;
        add_action( 'network_admin_notices', [ $this, 'network_admin_notice' ] );
        add_filter( 'wpmu_drop_tables', [ $this, 'drop_tables_on_blog_delete' ] );
        add_action( 'wp_initialize_site', [ $this, 'on_new_site' ], 10, 1 );
    }

    /**
     * Returns a per-site option, falling back to the network-wide option if not set.
     */
    public static function get_option( $option, $default = false, $site_id = null ) {
        if ( ! is_multisite() ) {
            return get_option( $option, $default );
        }
        $site_id = $site_id ?: get_current_blog_id();
        $value = get_blog_option( $site_id, $option, $default );
        // Network-wide override: if empty, fall back to network option.
        if ( empty( $value ) || ( is_array( $value ) && empty( $value ) ) ) {
            $network_value = get_site_option( $option, $default );
            if ( ! empty( $network_value ) ) {
                $value = $network_value;
            }
        }
        return $value;
    }

    /**
     * On network admin: print a notice that the plugin is network-active.
     */
    public function network_admin_notice() {
        if ( ! is_plugin_active_for_network( plugin_basename( RLS_PLUGIN_FILE ) ) ) return;
        echo '<div class="rls-notice is-info"><span class="dashicons dashicons-admin-multisite"></span><div><strong>Rybinsk Lab Security активна в сети.</strong> Настройки можно централизовать на уровне сети или задавать per-site.</div></div>';
    }

    /**
     * Drop the per-site plugin tables when a site is deleted from the network.
     */
    public function drop_tables_on_blog_delete( $tables ) {
        global $wpdb;
        $tables[] = $wpdb->get_blog_prefix( get_current_blog_id() ) . 'rls_attack_log';
        $tables[] = $wpdb->get_blog_prefix( get_current_blog_id() ) . 'rls_scan_history';
        return $tables;
    }

    /**
     * When a new site is created on the network, create the per-site tables.
     */
    public function on_new_site( $site ) {
        if ( ! class_exists( 'RLS_Activator' ) ) return;
        switch_to_blog( $site->blog_id );
        RLS_Activator::create_database_tables();
        RLS_Activator::setup_options();
        restore_current_blog();
    }
}

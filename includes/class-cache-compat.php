<?php
/**
 * Caching plugin compatibility: detect popular cache/security stacks
 * and apply compatible exclusions for the firewall and WAF.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Cache_Compat {

    const OPT_SETTINGS = 'rls_cache_compat';

    public function init() {
        add_filter( 'rls_excluded_ips', [ $this, 'filter_excluded_ips' ] );
        add_action( 'rls_admin_notices', [ $this, 'render_admin_notice' ] );
    }

    /**
     * Detect crawler IPs from common caching / CDN stacks and inject them
     * into the WAF's exclusion list to avoid false positives during cache warmup.
     */
    public function filter_excluded_ips( $ips ) {
        if ( ! is_array( $ips ) ) $ips = [];

        $cache_plugins = $this->detect_cache_plugins();
        foreach ( $cache_plugins as $slug => $label ) {
            $ips = array_merge( $ips, $this->get_user_agents_for( $slug ) );
        }

        // Allow operators to extend.
        $ips = (array) apply_filters( 'rls_cache_compat_ips', $ips, $cache_plugins );
        return array_values( array_unique( array_filter( $ips, function( $v ) {
            return is_string( $v ) && ( filter_var( $v, FILTER_VALIDATE_IP ) || strpos( $v, '/' ) !== false );
        } ) ) );
    }

    /**
     * Returns the list of detected caching/security plugins active on this site.
     */
    public function detect_cache_plugins() {
        $detected = [];
        if ( defined( 'WP_ROCKET_VERSION' ) ) {
            $detected['wp-rocket'] = 'WP Rocket';
        }
        if ( defined( 'W3TC_VERSION' ) ) {
            $detected['w3tc'] = 'W3 Total Cache';
        }
        if ( defined( 'LSCACHE_ADV_CACHE' ) || class_exists( '\\LiteSpeed\\LiteSpeed_Cache' ) ) {
            $detected['litespeed'] = 'LiteSpeed Cache';
        }
        if ( defined( 'WPFC_VERSION' ) ) {
            $detected['wp-fastest-cache'] = 'WP Fastest Cache';
        }
        if ( class_exists( 'WPOptimize' ) || defined( 'WPOPTIMIZE_VERSION' ) ) {
            $detected['wp-optimize'] = 'WP-Optimize';
        }
        if ( function_exists( 'autoptimize' ) ) {
            $detected['autoptimize'] = 'Autoptimize';
        }
        if ( class_exists( 'RedisCachePro' ) || class_exists( 'RedisObjectCache' ) || defined( 'WP_REDIS_VERSION' ) ) {
            $detected['redis'] = 'Redis Object Cache';
        }
        return $detected;
    }

    /**
     * Returns a list of (IP CIDR) ranges for crawler/prewarming IPs by slug.
     * Note: these are conservative defaults; admins should verify with their provider.
     */
    public function get_user_agents_for( $slug ) {
        $map = [
            'wp-rocket'      => [], // WP Rocket runs in-process; no remote crawler.
            'w3tc'           => [],
            'litespeed'      => [],
            'wp-fastest-cache'=> [],
            'wp-optimize'    => [],
            'autoptimize'    => [],
            'redis'          => [],
        ];
        return $map[ $slug ] ?? [];
    }

    public function render_admin_notice() {
        $detected = $this->detect_cache_plugins();
        if ( empty( $detected ) ) return;
        echo '<div class="rls-notice is-info"><span class="dashicons dashicons-info"></span><div><strong>Обнаружены плагины кэширования:</strong> ';
        echo esc_html( implode( ', ', array_values( $detected ) ) );
        echo '. Плагин <code>Rybinsk Lab Security</code> применяет совместимые правила исключений автоматически.</div></div>';
    }
}

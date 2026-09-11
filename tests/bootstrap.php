<?php
/**
 * PHPUnit bootstrap for Rybinsk Lab Security tests.
 *
 * Runs against a stub WordPress environment (no DB, no real WP) so the tests
 * focus on pure logic — TOTP, base32, path validation, HIBP k-anonymity.
 */

define( 'ABSPATH', __DIR__ . '/' );
define( 'WPINC', 'wp-includes' );
define( 'WP_PLUGIN_DIR', __DIR__ . '/' );

// Mock WordPress functions used by the classes-under-test.
if ( ! function_exists( 'plugin_dir_path' ) ) {
    function plugin_dir_path( $f ) { return dirname( $f ) . '/'; }
}
if ( ! function_exists( 'apply_filters' ) ) {
    function apply_filters( $tag, $value ) { return $value; }
}
if ( ! function_exists( 'did_action' ) ) {
    function did_action( $tag ) { return 0; }
}
if ( ! function_exists( 'do_action' ) ) {
    function do_action( $tag, ...$args ) {}
}
if ( ! function_exists( 'get_option' ) ) {
    function get_option( $k, $d = false ) { return $d; }
}
if ( ! function_exists( 'update_option' ) ) {
    function update_option( $k, $v, $autoload = null ) { return true; }
}
if ( ! function_exists( 'wp_normalize_path' ) ) {
    function wp_normalize_path( $p ) {
        $p = str_replace( '\\', '/', $p );
        $p = preg_replace( '|/+|', '/', $p );
        return $p;
    }
}
if ( ! function_exists( 'trailingslashit' ) ) {
    function trailingslashit( $s ) { return rtrim( $s, '/\\' ) . '/'; }
}
if ( ! function_exists( 'untrailingslashit' ) ) {
    function untrailingslashit( $s ) { return rtrim( $s, '/\\' ); }
}
if ( ! function_exists( 'wp_upload_dir' ) ) {
    function wp_upload_dir() {
        return [
            'basedir' => '/tmp/wp-uploads',
            'baseurl' => 'http://example.test/wp-content/uploads',
        ];
    }
}
if ( ! function_exists( 'is_wp_error' ) ) {
    function is_wp_error( $x ) { return $x instanceof WP_Error; }
}
if ( ! class_exists( 'WP_Error' ) ) {
    class WP_Error {
        public $errors = [];
        public $error_data = [];
        public function __construct( $code = '', $message = '', $data = null ) {
            if ( $code ) $this->errors[ $code ][] = $message;
        }
        public function get_error_code() { $codes = array_keys( $this->errors ); return $codes[0] ?? ''; }
        public function get_error_message() { $codes = array_keys( $this->errors ); return $this->errors[ $codes[0] ][0] ?? ''; }
    }
}
if ( ! function_exists( 'wp_remote_get' ) ) {
    function wp_remote_get( $url, $args = [] ) {
        return [ 'response' => [ 'code' => 200 ], 'body' => '' ];
    }
}
if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
    function wp_remote_retrieve_response_code( $r ) { return $r['response']['code'] ?? 200; }
}
if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
    function wp_remote_retrieve_body( $r ) { return $r['body'] ?? ''; }
}
if ( ! function_exists( 'wp_date' ) ) {
    function wp_date( $fmt, $ts = null ) { return gmdate( $fmt, $ts ?? time() ); }
}
if ( ! function_exists( 'home_url' ) ) {
    function home_url() { return 'http://example.test'; }
}
if ( ! function_exists( '__' ) ) {
    function __( $s, $d = null ) { return $s; }
}
if ( ! function_exists( 'current_time' ) ) {
    function current_time( $type ) { return gmdate( 'Y-m-d H:i:s' ); }
}
if ( ! function_exists( 'is_ssl' ) ) {
    function is_ssl() { return false; }
}
if ( ! function_exists( 'wp_cache_get' ) ) {
    function wp_cache_get( $k, $g = '' ) { return false; }
}
if ( ! function_exists( 'wp_cache_set' ) ) {
    function wp_cache_set( $k, $v, $g = '', $e = 0 ) { return true; }
}
if ( ! function_exists( 'wp_cache_delete' ) ) {
    function wp_cache_delete( $k, $g = '' ) { return true; }
}
if ( ! defined( 'DAY_IN_SECONDS' ) )  { define( 'DAY_IN_SECONDS', 86400 ); }
if ( ! defined( 'HOUR_IN_SECONDS' ) ) { define( 'HOUR_IN_SECONDS', 3600 ); }
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) { define( 'MINUTE_IN_SECONDS', 60 ); }
if ( ! defined( 'COOKIEPATH' ) )      { define( 'COOKIEPATH', '/' ); }
if ( ! defined( 'COOKIE_DOMAIN' ) )   { define( 'COOKIE_DOMAIN', '' ); }
if ( ! defined( 'RLS_VERSION' ) )     { define( 'RLS_VERSION', 'test' ); }
if ( ! defined( 'RLS_PLUGIN_PATH' ) ) { define( 'RLS_PLUGIN_PATH', __DIR__ . '/' ); }
if ( ! defined( 'RLS_API_URL' ) )     { define( 'RLS_API_URL', 'https://api.example.test/' ); }

require_once __DIR__ . '/../includes/class-2fa.php';
require_once __DIR__ . '/../includes/class-password-policy.php';

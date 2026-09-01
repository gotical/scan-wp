<?php
/**
 * Класс RLS_Updater
 * Реализует систему обновлений с сервера Rybinsk Lab.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Updater {

    private $current_version;
    private $plugin_slug;
    private $plugin_base;
    private $api_url;
    private $license_key;

    public function __construct( $current_version, $plugin_base, $api_url ) {
        $this->current_version = $current_version;
        $this->plugin_base     = $plugin_base;
        $this->plugin_slug     = dirname( $plugin_base );
        $this->api_url         = $api_url;

        $settings = get_option( 'rls_settings', [] );
        $this->license_key = $settings['license_key'] ?? '';

        add_filter( 'pre_set_site_transient_update_plugins', [ $this, 'check_for_update' ] );
        add_filter( 'site_transient_update_plugins', [ $this, 'inject_update_into_transient' ] );
        add_filter( 'plugins_api', [ $this, 'plugin_popup_info' ], 10, 3 );
        add_action( 'admin_init', [ $this, 'maybe_prime_update_transient' ] );
    }

    public function check_for_update( $transient ) {
        if ( empty( $transient->checked ) ) return $transient;

        $remote_info = $this->request_info();

        if ( 
            $remote_info && 
            isset( $remote_info->new_version ) && 
            version_compare( $this->current_version, $remote_info->new_version, '<' ) 
        ) {
            $transient->response[ $this->plugin_base ] = $this->build_update_payload( $remote_info );
        } elseif ( isset( $transient->response[ $this->plugin_base ] ) ) {
            unset( $transient->response[ $this->plugin_base ] );
        }

        return $transient;
    }

    public function inject_update_into_transient( $transient ) {
        if ( ! is_object( $transient ) ) {
            $transient = new stdClass();
        }

        if ( ! isset( $transient->checked ) || ! is_array( $transient->checked ) ) {
            $transient->checked = [];
        }

        if ( empty( $transient->checked[ $this->plugin_base ] ) ) {
            $transient->checked[ $this->plugin_base ] = $this->current_version;
        }

        return $this->check_for_update( $transient );
    }

    public function plugin_popup_info( $res, $action, $args ) {
        if ( 'plugin_information' !== $action ) return $res;
        if ( $this->plugin_slug !== $args->slug ) return $res;

        $remote_info = $this->request_info();

        if ( $remote_info ) {
            $res = new stdClass();
            $res->name = $remote_info->name ?? 'Rybinsk Lab Security';
            $res->slug = $this->plugin_slug;
            $res->version = $remote_info->new_version;
            $res->author = $remote_info->author ?? 'Rybinsk Lab';
            $res->homepage = $remote_info->homepage ?? ( $remote_info->url ?? '' );
            $res->download_link = $remote_info->package;
            $res->trunk = $remote_info->package;
            $res->last_updated = $remote_info->last_updated ?? date('Y-m-d H:i:s');

            if ( isset( $remote_info->requires ) ) $res->requires = $remote_info->requires;
            if ( isset( $remote_info->requires_php ) ) $res->requires_php = $remote_info->requires_php;
            if ( isset( $remote_info->tested ) ) $res->tested = $remote_info->tested;
            
            if ( isset( $remote_info->sections ) ) $res->sections = (array)$remote_info->sections;
            if ( isset( $remote_info->icons ) ) $res->icons = (array)$remote_info->icons;
            if ( isset( $remote_info->banners ) ) $res->banners = (array)$remote_info->banners;

            return $res;
        }

        return $res;
    }

    public function maybe_prime_update_transient() {
        if ( ! is_admin() || ! current_user_can( 'update_plugins' ) ) {
            return;
        }

        $last_check = (int) get_site_option( 'rls_last_update_check', 0 );
        $is_force_check = isset( $_GET['force-check'] );
        $is_updates_screen = isset( $GLOBALS['pagenow'] ) && in_array( $GLOBALS['pagenow'], [ 'plugins.php', 'update-core.php' ], true );

        if ( ! $is_force_check && ! $is_updates_screen && ( time() - $last_check ) < HOUR_IN_SECONDS ) {
            return;
        }

        $remote_info = $this->request_info();
        $transient = get_site_transient( 'update_plugins' );

        if ( ! is_object( $transient ) ) {
            $transient = new stdClass();
        }

        if ( ! isset( $transient->checked ) || ! is_array( $transient->checked ) ) {
            $transient->checked = [];
        }

        if ( ! isset( $transient->response ) || ! is_array( $transient->response ) ) {
            $transient->response = [];
        }

        $transient->checked[ $this->plugin_base ] = $this->current_version;
        $transient->last_checked = time();

        if (
            $remote_info &&
            isset( $remote_info->new_version ) &&
            version_compare( $this->current_version, $remote_info->new_version, '<' )
        ) {
            $transient->response[ $this->plugin_base ] = $this->build_update_payload( $remote_info );
        } elseif ( isset( $transient->response[ $this->plugin_base ] ) ) {
            unset( $transient->response[ $this->plugin_base ] );
        }

        set_site_transient( 'update_plugins', $transient );
        update_site_option( 'rls_last_update_check', time() );
    }

    private function request_info() {
        $body = [
            'action'      => 'check_update',
            'license_key' => $this->license_key,
            'slug'        => $this->plugin_slug,
            'version'     => $this->current_version,
            'site_url'    => home_url()
        ];

        $args = [
            'timeout'   => 15,
            'body'      => $body,
            'sslverify' => false 
        ];

        $request = wp_remote_post( $this->api_url, $args );

        if ( is_wp_error( $request ) || wp_remote_retrieve_response_code( $request ) !== 200 ) {
            return false;
        }

        $response = json_decode( wp_remote_retrieve_body( $request ), true );
        
        if ( isset($response['status']) && $response['status'] === 'success' && isset($response['data']) ) {
            return $this->normalize_remote_info( (object) $response['data'] );
        }

        return false;
    }

    private function normalize_remote_info( $remote_info ) {
        if ( ! is_object( $remote_info ) ) {
            return false;
        }

        if ( empty( $remote_info->new_version ) && ! empty( $remote_info->version ) ) {
            $remote_info->new_version = $remote_info->version;
        }

        if ( empty( $remote_info->package ) && ! empty( $remote_info->download_link ) ) {
            $remote_info->package = $remote_info->download_link;
        }

        if ( empty( $remote_info->url ) && ! empty( $remote_info->homepage ) ) {
            $remote_info->url = $remote_info->homepage;
        }

        return $remote_info;
    }

    private function build_update_payload( $remote_info ) {
        $res = new stdClass();
        $res->id = $remote_info->id ?? ( $remote_info->homepage ?? $this->api_url );
        $res->slug = $this->plugin_slug;
        $res->plugin = $this->plugin_base;
        $res->new_version = $remote_info->new_version;
        $res->package = $remote_info->package;
        $res->url = $remote_info->url ?? '';

        if ( isset( $remote_info->tested ) ) {
            $res->tested = $remote_info->tested;
        }

        if ( isset( $remote_info->requires ) ) {
            $res->requires = $remote_info->requires;
        }

        if ( isset( $remote_info->requires_php ) ) {
            $res->requires_php = $remote_info->requires_php;
        }
        
        if ( isset( $remote_info->icons ) ) $res->icons = (array) $remote_info->icons;
        if ( isset( $remote_info->banners ) ) $res->banners = (array) $remote_info->banners;

        return $res;
    }
}

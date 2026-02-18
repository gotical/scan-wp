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
        add_filter( 'plugins_api', [ $this, 'plugin_popup_info' ], 10, 3 );
    }

    public function check_for_update( $transient ) {
        if ( empty( $transient->checked ) ) return $transient;

        $remote_info = $this->request_info();

        if ( 
            $remote_info && 
            isset( $remote_info->new_version ) && 
            version_compare( $this->current_version, $remote_info->new_version, '<' ) 
        ) {
            $res = new stdClass();
            $res->slug = $this->plugin_slug;
            $res->plugin = $this->plugin_base;
            $res->new_version = $remote_info->new_version;
            $res->package = $remote_info->package;
            $res->url = $remote_info->url;
            
            if ( isset( $remote_info->icons ) ) $res->icons = (array)$remote_info->icons;
            if ( isset( $remote_info->banners ) ) $res->banners = (array)$remote_info->banners;

            $transient->response[ $this->plugin_base ] = $res;
        }

        return $transient;
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
            $res->download_link = $remote_info->package;
            $res->trunk = $remote_info->package;
            $res->last_updated = date('Y-m-d H:i:s');
            
            if ( isset( $remote_info->sections ) ) $res->sections = (array)$remote_info->sections;
            if ( isset( $remote_info->banners ) ) $res->banners = (array)$remote_info->banners;

            return $res;
        }

        return $res;
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
            return (object) $response['data'];
        }

        return false;
    }
}
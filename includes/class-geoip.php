<?php
/**
 * Геолокация по IP через IP2Location.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_GeoIP {
    const OPT_DB_PATH = 'rls_ip2location_db_path';
    const DOWNLOAD_TOKEN = '4IDNmWxzNbOaDN0ESo8YnOKzZrUyJFLDAkqZBE0SDPYDPwVYP2Xh68KAzZIyJsw1';
    private static $ip2location_instance = null;

    public static function get_bundled_database_path() {
        $paths = [
            RLS_PLUGIN_PATH . 'assets/geo/IP2LOCATION-LITE-DB1.BIN',
            RLS_PLUGIN_PATH . 'IP2LOCATION-LITE-DB1.BIN',
        ];

        foreach ( $paths as $path ) {
            if ( is_file( $path ) ) {
                return $path;
            }
        }

        return $paths[0];
    }

    public static function ensure_seed_database( $force = false ) {
        $bundled = self::get_bundled_database_path();
        if ( ! is_file( $bundled ) ) {
            return false;
        }

        $target = self::get_database_path();
        $uploads = wp_upload_dir();
        $dir = trailingslashit( $uploads['basedir'] ) . 'rybinsklab-security';
        if ( ! wp_mkdir_p( $dir ) ) {
            return false;
        }

        if ( ! $force && is_file( $target ) && filesize( $target ) > 0 ) {
            return true;
        }

        $copied = @copy( $bundled, $target );
        if ( $copied ) {
            update_option( self::OPT_DB_PATH, $target, false );
            if ( ! get_option( 'rls_geo_db_last_update', 0 ) ) {
                update_option( 'rls_geo_db_last_update', time(), false );
            }
            self::$ip2location_instance = null;
            return true;
        }

        return false;
    }

    public static function is_premium_enabled() {
        return get_option( 'rls_license_status' ) === 'valid';
    }

    public static function get_database_path() {
        $custom = get_option( self::OPT_DB_PATH, '' );
        if ( ! empty( $custom ) ) {
            return $custom;
        }

        $uploads = wp_upload_dir();
        $dir = trailingslashit( $uploads['basedir'] ) . 'rybinsklab-security';
        return trailingslashit( $dir ) . 'IP2LOCATION-LITE-DB1.BIN';
    }

    public static function download_lite_database() {
        if ( ! self::is_premium_enabled() ) {
            return new WP_Error( 'premium_required', 'Функция доступна только в Premium версии.' );
        }

        $uploads = wp_upload_dir();
        $dir = trailingslashit( $uploads['basedir'] ) . 'rybinsklab-security';
        if ( ! wp_mkdir_p( $dir ) ) {
            return new WP_Error( 'mkdir_failed', 'Не удалось создать директорию для базы GeoIP.' );
        }

        $target = self::get_database_path();
        $url = sprintf(
            'https://www.ip2location.com/download/?token=%s&file=DB1LITEBIN',
            rawurlencode( self::DOWNLOAD_TOKEN )
        );

        $response = wp_remote_get( $url, [ 'timeout' => 120, 'sslverify' => true ] );
        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code( $response );
        $body = wp_remote_retrieve_body( $response );
        if ( $code !== 200 || empty( $body ) ) {
            return new WP_Error( 'download_failed', 'Не удалось скачать базу IP2Location.' );
        }

        if ( file_put_contents( $target, $body ) === false ) {
            return new WP_Error( 'write_failed', 'Не удалось сохранить файл базы IP2Location.' );
        }

        update_option( self::OPT_DB_PATH, $target, false );
        update_option( 'rls_geo_db_last_update', time(), false );
        return $target;
    }

    public static function lookup_country_code( $ip ) {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return '';
        }

        $cache_key = 'rls_geo_' . md5( $ip );
        $cached = get_transient( $cache_key );
        if ( is_string( $cached ) && $cached !== '' ) {
            return $cached;
        }

        $country = self::lookup_via_local_database( $ip );
        if ( ! $country ) {
            $country = self::lookup_via_public_geo_apis( $ip );
        }
        if ( ! $country ) {
            $country = self::lookup_via_ip2location_api( $ip );
        }
        if ( $country ) {
            set_transient( $cache_key, $country, DAY_IN_SECONDS );
            return $country;
        }

        return '';
    }

    private static function lookup_via_public_geo_apis( $ip ) {
        $endpoints = [
            [
                'url' => 'https://ipwho.is/' . rawurlencode( $ip ),
                'parser' => function ( $data ) {
                    if ( ! is_array( $data ) || empty( $data['success'] ) ) {
                        return '';
                    }
                    return strtoupper( trim( (string) ( $data['country_code'] ?? '' ) ) );
                },
            ],
            [
                'url' => 'https://ipapi.co/' . rawurlencode( $ip ) . '/json/',
                'parser' => function ( $data ) {
                    if ( ! is_array( $data ) ) {
                        return '';
                    }
                    return strtoupper( trim( (string) ( $data['country_code'] ?? '' ) ) );
                },
            ],
            [
                'url' => 'http://ip-api.com/json/' . rawurlencode( $ip ) . '?fields=status,countryCode',
                'parser' => function ( $data ) {
                    if ( ! is_array( $data ) || ( $data['status'] ?? '' ) !== 'success' ) {
                        return '';
                    }
                    return strtoupper( trim( (string) ( $data['countryCode'] ?? '' ) ) );
                },
            ],
        ];

        foreach ( $endpoints as $endpoint ) {
            $response = wp_remote_get( $endpoint['url'], [ 'timeout' => 8, 'sslverify' => true ] );
            if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
                continue;
            }

            $data = json_decode( wp_remote_retrieve_body( $response ), true );
            $country = call_user_func( $endpoint['parser'], $data );
            if ( preg_match( '/^[A-Z]{2}$/', $country ) ) {
                return $country;
            }
        }

        return '';
    }

    private static function lookup_via_ip2location_api( $ip ) {
        $url = add_query_arg(
            [
                'key'    => self::DOWNLOAD_TOKEN,
                'ip'     => $ip,
                'format' => 'json',
            ],
            'https://api.ip2location.io/'
        );

        $response = wp_remote_get( $url, [ 'timeout' => 10, 'sslverify' => true ] );
        if ( is_wp_error( $response ) ) {
            return '';
        }

        if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
            return '';
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) ) {
            return '';
        }

        $country = strtoupper( trim( (string) ( $data['country_code'] ?? '' ) ) );
        if ( preg_match( '/^[A-Z]{2}$/', $country ) ) {
            return $country;
        }

        return '';
    }

    private static function lookup_via_local_database( $ip ) {
        $lib_path = RLS_PLUGIN_PATH . 'vendor/ip2location/IP2Location.php';
        if ( ! is_file( $lib_path ) ) {
            return '';
        }

        $db_candidates = [];
        $configured = self::get_database_path();
        if ( ! empty( $configured ) ) {
            $db_candidates[] = $configured;
        }
        $bundled = self::get_bundled_database_path();
        if ( ! empty( $bundled ) ) {
            $db_candidates[] = $bundled;
        }

        // Если база в uploads отсутствует/битая, пробуем положить seed и использовать локальный BIN из плагина.
        if ( ! is_file( $configured ) || filesize( $configured ) <= 0 ) {
            self::ensure_seed_database( false );
            $seeded = self::get_database_path();
            if ( ! empty( $seeded ) ) {
                $db_candidates[] = $seeded;
            }
        }

        $db_candidates = array_values( array_unique( array_filter( $db_candidates ) ) );
        if ( empty( $db_candidates ) ) {
            return '';
        }

        require_once $lib_path;

        foreach ( $db_candidates as $db_path ) {
            if ( ! is_file( $db_path ) || filesize( $db_path ) <= 0 ) {
                continue;
            }

            try {
                self::$ip2location_instance = new IP2Location( $db_path, IP2Location::FILE_IO );
                $record = self::$ip2location_instance->lookup( $ip, IP2Location::COUNTRY_CODE );
                $country = strtoupper( trim( (string) ( $record->countryCode ?? '' ) ) );
                if ( preg_match( '/^[A-Z]{2}$/', $country ) ) {
                    return $country;
                }
            } catch ( Exception $e ) {
                continue;
            }
        }

        return '';
    }
}


<?php
/**
 * Scanner: WordPress.org checksums verification.
 * Detects modified core/plugin/theme files vs official repository.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Scanner_Checksums {

    const TRANSIENT_KEY = 'rls_wp_checksums';
    const CACHE_TTL = 12 * HOUR_IN_SECONDS;
    const OPT_LAST_RUN = 'rls_checksums_last_run';

    /**
     * Run the checksums check.
     */
    public static function scan() {
        $findings = [];
        $findings = array_merge( $findings, self::check_core() );
        $findings = array_merge( $findings, self::check_plugins() );
        $findings = array_merge( $findings, self::check_themes() );
        update_option( self::OPT_LAST_RUN, time() );
        return $findings;
    }

    /**
     * Check WordPress core files against WP.org checksums.
     */
    private static function check_core() {
        $findings = [];
        require_once ABSPATH . 'wp-admin/includes/update.php';
        $checksums = get_core_checksums( get_bloginfo( 'version' ), get_locale() );
        if ( ! is_array( $checksums ) ) {
            return [
                [
                    'type'     => 'core',
                    'location' => 'core-checksums',
                    'severity' => 0,
                    'rule_id'  => 'core-no-checksums',
                    'snippet'  => 'Не удалось получить checksums',
                ],
            ];
        }
        foreach ( $checksums as $file => $expected_hash ) {
            $full_path = ABSPATH . $file;
            if ( ! file_exists( $full_path ) ) continue;
            $actual = @md5_file( $full_path );
            if ( is_string( $actual ) && ! hash_equals( $expected_hash, $actual ) ) {
                $findings[] = [
                    'type'     => 'core',
                    'location' => $file,
                    'severity' => 90,
                    'rule_id'  => 'core-file-modified',
                    'snippet'  => sprintf( 'Expected: %s, Actual: %s', substr( $expected_hash, 0, 8 ), substr( $actual, 0, 8 ) ),
                ];
            }
        }
        return $findings;
    }

    /**
     * Check installed plugins against WP.org.
     */
    private static function check_plugins() {
        $findings = [];
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $plugins = get_plugins();
        $installed = [];

        foreach ( $plugins as $file => $plugin_data ) {
            $slug = self::plugin_slug_from_file( $file );
            if ( ! $slug ) continue;
            $installed[ $slug ] = $plugin_data['Version'] ?? 'unknown';
        }

        if ( empty( $installed ) ) return $findings;

        // Fetch WP.org API.
        $api_data = self::fetch_plugin_api( array_keys( $installed ) );
        foreach ( $installed as $slug => $local_version ) {
            if ( ! isset( $api_data[ $slug ] ) ) continue;
            $remote = $api_data[ $slug ];
            // Note: comparing checksums for plugins requires fetching the zip
            // which is expensive. For now we just report version mismatch.
            if ( version_compare( $local_version, $remote['version'], '<' ) ) {
                $findings[] = [
                    'type'     => 'plugin',
                    'location' => $slug,
                    'severity' => 40,
                    'rule_id'  => 'plugin-outdated',
                    'snippet'  => sprintf( 'Local: %s, Remote: %s', $local_version, $remote['version'] ),
                ];
            }
        }
        return $findings;
    }

    /**
     * Check installed themes against WP.org.
     */
    private static function check_themes() {
        $findings = [];
        $themes = wp_get_themes();
        foreach ( $themes as $theme ) {
            $slug = $theme->get_stylesheet();
            if ( ! $slug || in_array( $slug, [ 'twentytwentyone', 'twentytwentytwo', 'twentytwentythree', 'twentytwentyfour', 'twentytwentyfive' ], true ) ) {
                continue;
            }
            // Themes are harder to verify (need zip download). Skip for now.
            // Just check existence + version string format.
        }
        return $findings;
    }

    private static function plugin_slug_from_file( $file ) {
        $parts = explode( '/', $file );
        return $parts[0] ?? '';
    }

    /**
     * Batch fetch plugin metadata from WP.org.
     */
    private static function fetch_plugin_api( array $slugs ) {
        $cached = get_transient( self::TRANSIENT_KEY );
        if ( is_array( $cached ) ) return $cached;
        $result = [];
        if ( empty( $slugs ) ) return $result;
        $args = [ 'plugins' => $slugs ];
        $url = add_query_arg( [ 'action' => 'plugin_information' ], 'https://api.wordpress.org/plugins/info/1.2/' );
        foreach ( array_chunk( $slugs, 10 ) as $chunk ) {
            $response = wp_remote_post( $url, [
                'body'      => [ 'plugins' => (array) $chunk ],
                'timeout'   => 8,
                'sslverify' => true,
                'user-agent' => 'RybinskLabSecurity/' . ( defined( 'RLS_VERSION' ) ? RLS_VERSION : '1' ),
            ] );
            if ( is_wp_error( $response ) ) continue;
            $body = json_decode( wp_remote_retrieve_body( $response ), true );
            if ( is_array( $body ) ) {
                foreach ( $body as $slug => $info ) {
                    if ( ! empty( $info['version'] ) ) {
                        $result[ $slug ] = [ 'version' => $info['version'] ];
                    }
                }
            }
        }
        set_transient( self::TRANSIENT_KEY, $result, self::CACHE_TTL );
        return $result;
    }
}

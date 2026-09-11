<?php
/**
 * WordPress Hardening Module.
 * Adds .htaccess rules, security headers, version hiding, REST API restriction,
 * author enumeration blocking, and HTTP method whitelisting.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Hardening {

    const MARKER              = '# BEGIN RYBINSK LAB SECURITY';
    const MARKER_END          = '# END RYBINSK LAB SECURITY';
    const WPINCLUDES_MARKER   = '# BEGIN RLS WP-INCLUDES';
    const WPINCLUDES_END      = '# END RLS WP-INCLUDES';
    const UPLOADS_MARKER      = '# BEGIN RLS UPLOADS';
    const UPLOADS_END         = '# END RLS UPLOADS';

    public function init() {
        $settings = get_option( 'rls_settings', [] );

        // Always-on security headers (independent of firewall toggle).
        add_action( 'send_headers', [ $this, 'apply_security_headers' ], 1 );

        if ( ! empty( $settings['hardening_enabled'] ) ) {
            add_action( 'init', [ $this, 'block_author_enumeration' ], 1 );
            add_filter( 'rest_authentication_errors', [ $this, 'restrict_rest_api' ] );
            add_action( 'init', [ $this, 'block_bad_http_methods' ], 0 );
            add_action( 'plugins_loaded', [ $this, 'apply_wp_config_filters' ], 1 );
            add_filter( 'the_generator', '__return_empty_string' );
            add_filter( 'wp_generator', '__return_empty_string' );
            add_filter( 'script_loader_src', [ $this, 'strip_wp_version_from_assets' ], 15, 2 );
            add_filter( 'style_loader_src', [ $this, 'strip_wp_version_from_assets' ], 15, 2 );
            add_filter( 'get_the_generator_html', '__return_empty_string' );
            add_filter( 'get_the_generator_xhtml', '__return_empty_string' );
            add_filter( 'get_the_generator_atom', '__return_empty_string' );
            add_filter( 'get_the_generator_rss2', '__return_empty_string' );
            add_filter( 'get_the_generator_rdf', '__return_empty_string' );
            add_filter( 'get_the_generator_comment', '__return_empty_string' );
            add_filter( 'wp_calculate_image_srcset', '__return_empty_array' );
        }

        add_action( 'admin_init', [ $this, 'admin_actions' ] );
        add_action( 'wp_ajax_rls_apply_hardening', [ $this, 'ajax_apply_hardening' ] );
        add_action( 'wp_ajax_rls_remove_hardening', [ $this, 'ajax_remove_hardening' ] );
        add_action( 'wp_ajax_rls_get_hardening_status', [ $this, 'ajax_get_status' ] );
    }

    public function admin_actions() {
        if ( ! current_user_can( 'manage_options' ) ) return;
        if ( ! empty( $_GET['rls_dismiss_hardening_notice'] ) ) {
            check_admin_referer( 'rls_hardening_notice' );
            update_option( 'rls_hardening_notice_dismissed', 1 );
            wp_safe_redirect( remove_query_arg( [ 'rls_dismiss_hardening_notice', '_wpnonce' ] ) );
            exit;
        }
    }

    public function apply_security_headers() {
        if ( headers_sent() ) return;
        $settings = get_option( 'rls_settings', [] );

        // Strict-Transport-Security is only meaningful over HTTPS.
        if ( is_ssl() ) {
            header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
        }

        // Permissions-Policy: deny features we never use.
        header( 'Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()' );

        // Cross-Origin-Opener-Policy for Spectre mitigation.
        header( 'Cross-Origin-Opener-Policy: same-origin' );

        if ( ! empty( $settings['hardening_enabled'] ) ) {
            // Content-Security-Policy — admin gets a stricter policy, front-end allows common CDNs.
            if ( is_admin() ) {
                header( "Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' data:;" );
            } else {
                $csp = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; font-src 'self' data: https:; frame-ancestors 'self'";
                header( 'Content-Security-Policy: ' . $csp );
            }
            // Cross-Origin-Embedder-Policy requires CORP for resources; allow credentialled.
            header( 'Cross-Origin-Resource-Policy: same-origin' );
        }

        // Always hide the WP generator regardless of hardening toggle.
        header( 'X-Powered-By: Rybinsk Lab Security' );
        header_remove( 'X-Powered-By' );
    }

    /**
     * Block user enumeration via ?author=N and /author/N/.
     * Anyone reaching these is redirected to home, so legitimate crawlers get clean URLs.
     */
    public function block_author_enumeration() {
        if ( ! is_admin() && ! is_user_logged_in() ) {
            // ?author=N
            if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
                wp_safe_redirect( home_url(), 301 );
                exit;
            }
            // /author/N/ (pretty permalinks)
            $req_path = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
            if ( is_string( $req_path ) && preg_match( '#^/author/\d+/?$#', $req_path ) ) {
                wp_safe_redirect( home_url(), 301 );
                exit;
            }
        }
    }

    /**
     * Block unauthenticated access to sensitive REST endpoints (users, settings).
     * Public endpoints (posts, pages) continue to work.
     */
    public function restrict_rest_api( $result ) {
        if ( ! empty( $result ) ) {
            return $result;
        }
        if ( is_user_logged_in() ) {
            return $result;
        }

        $req_uri = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
        $query    = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_QUERY );
        $req_uri = is_string( $req_uri ) ? $req_uri : '';
        $query    = is_string( $query ) ? $query : '';

        // Endpoint whitelist that must remain public for front-end functionality.
        $public_patterns = [
            '#/wp-json/(?:wp/v[12]/)?posts#',
            '#/wp-json/(?:wp/v[12]/)?pages#',
            '#/wp-json/(?:wp/v[12]/)?categories#',
            '#/wp-json/(?:wp/v[12]/)?tags#',
            '#/wp-json/(?:wp/v[12]/)?media#',
            '#/wp-json/(?:wp/v[12]/)?types#',
            '#/wp-json/(?:wp/v[12]/)?statuses#',
            '#/wp-json/(?:wp/v[12]/)?search#',
            '#/wp-json/oembed#',
        ];
        foreach ( $public_patterns as $p ) {
            if ( preg_match( $p, $req_uri ) ) {
                return $result;
            }
        }

        // Everything else (users, settings, plugins, themes, edit-context) requires auth.
        return new WP_Error(
            'rls_rest_forbidden',
            __( 'REST API access restricted to authenticated users.', 'rybinsklab-security' ),
            [ 'status' => 401 ]
        );
    }

    /**
     * Reject uncommon HTTP methods at the edge.
     * GET, HEAD, POST are required for WP; OPTIONS for CORS preflight; PUT/PATCH for the REST API.
     */
    public function block_bad_http_methods() {
        $method = strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) );
        $allowed = [ 'GET', 'HEAD', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE' ];
        // DELETE/PUT/PATCH are blocked unless explicitly needed by REST.
        $blocked = [ 'TRACE', 'TRACK', 'DEBUG', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'VERSION-CONTROL' ];

        if ( in_array( $method, $blocked, true ) ) {
            status_header( 405 );
            header( 'Allow: ' . implode( ', ', $allowed ) );
            exit;
        }

        // Stricter default: only the WP-essential methods pass.
        $essential = [ 'GET', 'HEAD', 'POST', 'OPTIONS' ];
        if ( ! in_array( $method, $essential, true ) ) {
            // REST API routes still need PUT/PATCH/DELETE; allow them only when targeting the REST endpoint.
            $req_uri = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
            if ( is_string( $req_uri ) && strpos( $req_uri, '/wp-json/' ) === 0 ) {
                return;
            }
            status_header( 405 );
            header( 'Allow: ' . implode( ', ', $essential ) );
            exit;
        }
    }

    public function apply_wp_config_filters() {
        // We can't edit wp-config.php at runtime; instead we filter the constants WP reads.
        // Disable file editing from admin (theme/plugin editors).
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            define( 'DISALLOW_FILE_EDIT', true );
        }
        if ( ! defined( 'DISALLOW_FILE_MODS' ) ) {
            define( 'DISALLOW_FILE_MODS', false );
        }
        // Reduce post revision noise.
        if ( ! defined( 'WP_POST_REVISIONS' ) ) {
            define( 'WP_POST_REVISIONS', 10 );
        }
        // Autosave interval (default 60s) bumped to 120s to reduce load.
        if ( ! defined( 'AUTOSAVE_INTERVAL' ) ) {
            define( 'AUTOSAVE_INTERVAL', 120 );
        }
        // Empty trash days (default 30) reduced to 7.
        if ( ! defined( 'EMPTY_TRASH_DAYS' ) ) {
            define( 'EMPTY_TRASH_DAYS', 7 );
        }
    }

    /**
     * Remove `ver=6.x` query string from script/style URLs (WP version leak).
     */
    public function strip_wp_version_from_assets( $src, $handle = '' ) {
        if ( ! is_string( $src ) || $src === '' ) return $src;
        // Replace `?ver=6.x.y` and `&ver=6.x.y` with cache-buster based on filemtime instead.
        if ( strpos( $src, 'ver=' ) !== false ) {
            $src = remove_query_arg( 'ver', $src );
        }
        return $src;
    }

    /**
     * Apply .htaccess hardening (wp-config protection, wp-includes lockdown, uploads PHP block).
     * Uses ABSPATH .htaccess as primary location with separate blocks for sub-directories.
     */
    public static function apply_htaccess_rules() {
        $abspath = wp_normalize_path( ABSPATH );
        $htaccess_path = $abspath . '.htaccess';

        $existing = file_exists( $htaccess_path ) ? file_get_contents( $htaccess_path ) : '';
        $existing = self::strip_block( $existing, self::MARKER );

        $rules = self::build_root_block();
        $new_content = self::insert_block( $existing, self::MARKER, self::MARKER_END, $rules );
        if ( $new_content !== null ) {
            $tmp = $htaccess_path . '.tmp';
            if ( @file_put_contents( $tmp, $new_content ) !== false ) {
                @rename( $tmp, $htaccess_path );
            }
        }

        // wp-includes .htaccess
        $wpi = $abspath . 'wp-includes/.htaccess';
        if ( file_exists( $abspath . 'wp-includes' ) ) {
            $rules_wpi = self::build_wpincludes_block();
            $existing_wpi = file_exists( $wpi ) ? file_get_contents( $wpi ) : '';
            $existing_wpi = self::strip_block( $existing_wpi, self::WPINCLUDES_MARKER );
            $new_wpi = self::insert_block( $existing_wpi, self::WPINCLUDES_MARKER, self::WPINCLUDES_END, $rules_wpi );
            if ( $new_wpi !== null ) {
                $tmp = $wpi . '.tmp';
                if ( @file_put_contents( $tmp, $new_wpi ) !== false ) {
                    @rename( $tmp, $wpi );
                }
            }
        }

        // Uploads PHP-execution block
        $uploads = wp_upload_dir();
        $uploads_dir = isset( $uploads['basedir'] ) ? wp_normalize_path( $uploads['basedir'] ) : '';
        if ( $uploads_dir && file_exists( $uploads_dir ) ) {
            $uploads_ht = $uploads_dir . '/.htaccess';
            $rules_up = self::build_uploads_block();
            $existing_up = file_exists( $uploads_ht ) ? file_get_contents( $uploads_ht ) : '';
            $existing_up = self::strip_block( $existing_up, self::UPLOADS_MARKER );
            $new_up = self::insert_block( $existing_up, self::UPLOADS_MARKER, self::UPLOADS_END, $rules_up );
            if ( $new_up !== null ) {
                $tmp = $uploads_ht . '.tmp';
                if ( @file_put_contents( $tmp, $new_up ) !== false ) {
                    @rename( $tmp, $uploads_ht );
                }
            }
        }
    }

    public static function remove_htaccess_rules() {
        $abspath = wp_normalize_path( ABSPATH );
        $htaccess_path = $abspath . '.htaccess';
        if ( file_exists( $htaccess_path ) ) {
            $existing = file_get_contents( $htaccess_path );
            $stripped = self::strip_block( $existing, self::MARKER );
            if ( $stripped !== $existing ) {
                $tmp = $htaccess_path . '.tmp';
                @file_put_contents( $tmp, $stripped );
                @rename( $tmp, $htaccess_path );
            }
        }
        $wpi = $abspath . 'wp-includes/.htaccess';
        if ( file_exists( $wpi ) ) {
            $existing = file_get_contents( $wpi );
            $stripped = self::strip_block( $existing, self::WPINCLUDES_MARKER );
            if ( $stripped !== $existing ) {
                @file_put_contents( $wpi, $stripped );
            }
        }
        $uploads = wp_upload_dir();
        $uploads_dir = isset( $uploads['basedir'] ) ? wp_normalize_path( $uploads['basedir'] ) : '';
        if ( $uploads_dir && file_exists( $uploads_dir ) ) {
            $uploads_ht = $uploads_dir . '/.htaccess';
            if ( file_exists( $uploads_ht ) ) {
                $existing = file_get_contents( $uploads_ht );
                $stripped = self::strip_block( $existing, self::UPLOADS_MARKER );
                if ( $stripped !== $existing ) {
                    @file_put_contents( $uploads_ht, $stripped );
                }
            }
        }
    }

    private static function build_root_block() {
        return self::MARKER . "\n"
            . "# Protect wp-config.php\n"
            . "<FilesMatch \"^(wp-config\\.php|wp-config-sample\\.php)\">\n"
            . "    Require all denied\n"
            . "</FilesMatch>\n\n"
            . "# Disable directory listing\n"
            . "Options -Indexes\n\n"
            . "# Block access to sensitive files\n"
            . "<FilesMatch \"^(\\.|README|license|readme|changelog|CHANGELOG|LICENSE)\">\n"
            . "    Require all denied\n"
            . "</FilesMatch>\n\n"
            . "# Block phpinfo and similar probes\n"
            . "<FilesMatch \"(phpinfo|info|i)\\.php$\">\n"
            . "    Require all denied\n"
            . "</FilesMatch>\n\n"
            . self::MARKER_END . "\n";
    }

    private static function build_wpincludes_block() {
        return self::WPINCLUDES_MARKER . "\n"
            . "# Block direct PHP execution inside wp-includes\n"
            . "<IfModule mod_rewrite.c>\n"
            . "    RewriteEngine On\n"
            . "    RewriteBase /\n"
            . "    RewriteRule ^wp-includes/.*\\.(php|phtml|phar)$ - [F,L]\n"
            . "</IfModule>\n"
            . "<FilesMatch \"\\.(php|phtml|phar)$\">\n"
            . "    Require all denied\n"
            . "</FilesMatch>\n"
            . self::WPINCLUDES_END . "\n";
    }

    private static function build_uploads_block() {
        return self::UPLOADS_MARKER . "\n"
            . "# Disable PHP execution inside uploads\n"
            . "<FilesMatch \"\\.(php|phtml|phar|php3|php4|php5|php7|pht|htaccess)$\">\n"
            . "    Require all denied\n"
            . "</FilesMatch>\n"
            . self::UPLOADS_END . "\n";
    }

    private static function insert_block( $content, $start_marker, $end_marker, $block ) {
        // Always replace if exists; otherwise append.
        $stripped = self::strip_block( $content, $start_marker );
        return rtrim( $stripped, "\n" ) . "\n\n" . $block;
    }

    private static function strip_block( $content, $marker ) {
        if ( $content === '' || $content === false ) return '';
        $pattern = '/' . preg_quote( $marker, '/' ) . '.*?' . preg_quote( str_replace( 'BEGIN', 'END', $marker ), '/' ) . '\\s*/s';
        return preg_replace( $pattern, '', $content );
    }

    public function ajax_apply_hardening() {
        check_ajax_referer( 'rls_hardening_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Доступ запрещен.' );
        }
        if ( ! self::is_htaccess_writable() ) {
            wp_send_json_error( '.htaccess недоступен для записи.' );
        }
        self::apply_htaccess_rules();
        update_option( 'rls_hardening_applied', 1 );
        wp_send_json_success( 'Правила .htaccess применены.' );
    }

    public function ajax_remove_hardening() {
        check_ajax_referer( 'rls_hardening_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Доступ запрещен.' );
        }
        self::remove_htaccess_rules();
        delete_option( 'rls_hardening_applied' );
        wp_send_json_success( 'Правила .htaccess удалены.' );
    }

    public function ajax_get_status() {
        check_ajax_referer( 'rls_hardening_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error();
        }
        wp_send_json_success( [
            'htaccess_writable' => self::is_htaccess_writable(),
            'applied'           => (bool) get_option( 'rls_hardening_applied' ),
        ] );
    }

    public static function is_htaccess_writable() {
        $htaccess = wp_normalize_path( ABSPATH ) . '.htaccess';
        if ( ! file_exists( $htaccess ) ) {
            return is_writable( wp_normalize_path( ABSPATH ) );
        }
        return is_writable( $htaccess );
    }
}

<?php
/**
 * Scanner hash cache + incremental scanning.
 * Tracks per-file md5/size/mtime + risk history to skip unchanged files.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Scanner_Cache {

    const OPT_CACHE   = 'rls_scanner_file_cache';
    const OPT_PROGRESS = 'rls_scan_progress';
    const MAX_CACHE_ENTRIES = 50000;

    /**
     * Returns the cached record for a path, or null if not present.
     */
    public static function get( $path ) {
        $cache = get_option( self::OPT_CACHE, [] );
        if ( ! is_array( $cache ) ) return null;
        $norm = wp_normalize_path( $path );
        return $cache[ $norm ] ?? null;
    }

    /**
     * Check if a file is unchanged since last scan.
     */
    public static function is_unchanged( $path ) {
        $cached = self::get( $path );
        if ( ! is_array( $cached ) ) return false;
        $current_size = @filesize( $path );
        $current_mtime = @filemtime( $path );
        if ( $current_size === false || $current_mtime === false ) return false;
        return (int) $cached['size'] === (int) $current_size
            && (int) $cached['mtime'] === (int) $current_mtime;
    }

    /**
     * Persist the hash + metadata for a file.
     */
    public static function put( $path, $threat_count = 0, $risk_score = 0 ) {
        $cache = get_option( self::OPT_CACHE, [] );
        if ( ! is_array( $cache ) ) $cache = [];
        $norm = wp_normalize_path( $path );
        $hash = @md5_file( $path );
        $cache[ $norm ] = [
            'hash'        => is_string( $hash ) ? $hash : '',
            'size'        => (int) @filesize( $path ),
            'mtime'       => (int) @filemtime( $path ),
            'scanned_at'  => time(),
            'threats'     => (int) $threat_count,
            'risk_score'  => (int) $risk_score,
        ];
        // Cap cache size.
        if ( count( $cache ) > self::MAX_CACHE_ENTRIES ) {
            // Drop oldest entries.
            uasort( $cache, function( $a, $b ) {
                return ( $a['scanned_at'] ?? 0 ) - ( $b['scanned_at'] ?? 0 );
            } );
            $cache = array_slice( $cache, 0, self::MAX_CACHE_ENTRIES, true );
        }
        update_option( self::OPT_CACHE, $cache, false );
    }

    /**
     * Remove a file from the cache (e.g., when quarantined).
     */
    public static function forget( $path ) {
        $cache = get_option( self::OPT_CACHE, [] );
        if ( ! is_array( $cache ) ) return;
        $norm = wp_normalize_path( $path );
        unset( $cache[ $norm ] );
        update_option( self::OPT_CACHE, $cache, false );
    }

    /**
     * Returns files that should be re-scanned: those whose size/mtime
     * differ from cache, plus any path not in cache.
     */
    public static function filter_changed( array $paths ) {
        $changed = [];
        foreach ( $paths as $path ) {
            if ( ! self::is_unchanged( $path ) ) {
                $changed[] = $path;
            }
        }
        return $changed;
    }

    /**
     * Compute incremental savings: how many files were skipped.
     */
    public static function skipped_count() {
        $progress = self::get_progress();
        return (int) ( $progress['skipped'] ?? 0 );
    }

    /* === Progress tracking (real-time) === */

    public static function set_progress( $data ) {
        $current = self::get_progress();
        $merged = array_merge( $current, $data );
        $merged['updated_at'] = time();
        update_option( self::OPT_PROGRESS, $merged, false );
    }

    public static function get_progress() {
        $p = get_option( self::OPT_PROGRESS, [] );
        return is_array( $p ) ? $p : [];
    }

    public static function reset_progress( $total = 0 ) {
        update_option( self::OPT_PROGRESS, [
            'active'     => true,
            'started_at' => time(),
            'updated_at' => time(),
            'total'      => (int) $total,
            'scanned'    => 0,
            'skipped'    => 0,
            'threats'    => 0,
            'current'    => '',
            'finished'   => false,
        ], false );
    }

    public static function increment_scanned( $current_file = '' ) {
        $p = self::get_progress();
        $p['scanned'] = (int) ( $p['scanned'] ?? 0 ) + 1;
        if ( $current_file ) $p['current'] = $current_file;
        $p['updated_at'] = time();
        update_option( self::OPT_PROGRESS, $p, false );
    }

    public static function increment_skipped() {
        $p = self::get_progress();
        $p['skipped'] = (int) ( $p['skipped'] ?? 0 ) + 1;
        $p['updated_at'] = time();
        update_option( self::OPT_PROGRESS, $p, false );
    }

    public static function increment_threats( $count = 1 ) {
        $p = self::get_progress();
        $p['threats'] = (int) ( $p['threats'] ?? 0 ) + $count;
        $p['updated_at'] = time();
        update_option( self::OPT_PROGRESS, $p, false );
    }

    public static function finish_progress() {
        $p = self::get_progress();
        $p['active'] = false;
        $p['finished'] = true;
        $p['updated_at'] = time();
        update_option( self::OPT_PROGRESS, $p, false );
    }

    /* === Whitelist with comments + expiration === */

    public static function get_whitelist_entry( $path ) {
        $list = get_option( 'rls_whitelist_v2', [] );
        return is_array( $list ) ? ( $list[ wp_normalize_path( $path ) ] ?? null ) : null;
    }

    public static function add_whitelist( $path, $comment = '', $expiration_days = 0, $scope = 'file' ) {
        $list = get_option( 'rls_whitelist_v2', [] );
        if ( ! is_array( $list ) ) $list = [];
        $norm = wp_normalize_path( $path );
        $list[ $norm ] = [
            'comment'    => (string) $comment,
            'added_at'   => time(),
            'expires_at' => $expiration_days > 0 ? time() + ( $expiration_days * 86400 ) : 0,
            'scope'      => in_array( $scope, [ 'file', 'dir', 'pattern' ], true ) ? $scope : 'file',
            'hash'       => (string) @md5_file( $path ),
        ];
        update_option( 'rls_whitelist_v2', $list, false );
        return $list[ $norm ];
    }

    public static function remove_whitelist( $path ) {
        $list = get_option( 'rls_whitelist_v2', [] );
        if ( ! is_array( $list ) ) return;
        unset( $list[ wp_normalize_path( $path ) ] );
        update_option( 'rls_whitelist_v2', $list, false );
    }

    /**
     * Returns true if a file is whitelisted and not expired.
     */
    public static function is_whitelisted( $path ) {
        $entry = self::get_whitelist_entry( $path );
        if ( ! $entry ) return false;
        if ( ! empty( $entry['expires_at'] ) && $entry['expires_at'] < time() ) {
            self::remove_whitelist( $path );
            return false;
        }
        return true;
    }

    /**
     * Cleanup expired whitelist entries.
     */
    public static function cleanup_expired() {
        $list = get_option( 'rls_whitelist_v2', [] );
        if ( ! is_array( $list ) ) return;
        foreach ( $list as $path => $entry ) {
            if ( ! empty( $entry['expires_at'] ) && $entry['expires_at'] < time() ) {
                unset( $list[ $path ] );
            }
        }
        update_option( 'rls_whitelist_v2', $list, false );
    }

    public static function get_all_whitelist() {
        return get_option( 'rls_whitelist_v2', [] );
    }

}

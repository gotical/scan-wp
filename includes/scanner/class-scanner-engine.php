<?php
/**
 * Класс RLS_Scanner_Engine
 * Логика сканирования файлов.
 * Версия 1.6.3: Исправлено ежедневное сканирование (Cron Fix).
 */

if ( ! defined( 'ABSPATH' ) ) {
    die;
}

class RLS_Scanner_Engine {

    const TIME_LIMIT = 25; // seconds per AJAX step
const BATCH_SIZE = 5;   // tiny batches to never time out
const MAX_FILES = 1500; // hard cap to prevent memory issues
    const MAX_FILE_SIZE = 2097152; // 2MB

    // Очищенные паттерны Regex (Без ложных срабатываний)
    const REGEX_PATTERNS = [
        '#preg_replace\s*\(\s*[\"\']\s*(\W)(?-s).*\1[imsxADSUXJu\s]*e[imsxADSUXJu\s]*[\"\'].*\)#isS',
        '#preg_match\s*\(\s*\"\s*/\s*bot\s*/\s*\"#isS',
        '#eval[\s/\*\#]*\(stripslashes[\s/\*\#]*\([\s/\*\#]*\$_(REQUEST|POST|GET)\s*\[\s*\\\s*[\'\"]\s*asc\s*\\\s*[\'\"]#isS',
        '#preg_replace\s*\(\s*[\"\'\”]\s*/\s*\.\s*\*\s*/\s*e\s*[\"\'\”]\s*,\s*[\"\'\”]\s*\\x65\\x76\\x61\\x6c#isS',
        '#(include|require)(_once)*\s*[\"\'][\w\W\s/\*]*php://input[\w\W\s/\*]*[\"\']#isS',
        '#data:;base64#isS',
        '#GIF89a.*[\r\n]*.*<\?php#isS',
        '#\$ip[\w\W\s/\*]*=[\w\W\s/\*]*getenv\(["\']REMOTE_ADDR["\']\);[\w\W\s/\*]*[\r\n]\$message#isS',
        '#\$_F\s*=\s*__FILE__\s*;\s*\$_X\s*=#isS',
        '#\\\\x([abcdef0-9]{2}){3,}#isS'
    ];

    const SUSPICIOUS_FILES = [
        'r57.php', 'c99.php', 'c100.php', 'phpinfo.php', 'perlinfo.php', 'ofc_upload_image.php'
    ];

    private $excluded_paths = [
        '.git', '.svn', '.hg', '.bzr',
        'node_modules', 'vendor', 'bower_components',
        'cache', 'backups', 'backup', 'tmp', 'temp',
        'wp-content/cache', 'wp-content/backups', 'wp-content/backup*',
        'wp-content/upgrade', 'wp-content/ai1wm-backups',
        'wp-content/uploads', 'wp-content/w3tc-config',
        'wp-content/wflogs', 'wp-content/debug.log',
        // Plugins where legitimate code is very rare for virus injection (mostly build/js):
        'wp-content/plugins/wordfence',
        'wp-content/plugins/akismet',
        'wp-content/plugins/woocommerce',
        'wp-content/plugins/elementor',
        'wp-content/plugins/elementor-pro',
        'wp-content/plugins/wpforms-lite',
        'wp-content/plugins/jetpack',
        'wp-content/plugins/updraftplus',
        'wp-content/plugins/all-in-one-seo-pack',
        'wp-content/plugins/autoptimize',
        'wp-content/plugins/wp-rocket',
        'wp-content/plugins/litespeed-cache',
        'wp-content/plugins/redirection',
        'wp-content/plugins/really-simple-ssl',
        'wp-content/plugins/wordpress-seo',
        'wp-content/plugins/duplicate-post',
        'wp-content/plugins/regenerate-thumbnails',
        'wp-content/plugins/contact-form-7',
        'wp-content/plugins/wpforms',
        'wp-content/plugins/classic-editor',
        'wp-content/plugins/loco-translate',
        'wp-content/plugins/wp-google-maps',
        'wp-content/plugins/tablepress',
        'wp-content/plugins/ninja-forms',
        'wp-content/plugins/duplicate-page',
        'wp-content/plugins/svg-support',
        'wp-content/plugins/wordfence-assistant',
        // Common themes with 1000+ files (Elementor, Avada, etc.):
        'wp-content/themes/astra',
        'wp-content/themes/avada',
        'wp-content/themes/generatepress',
        'wp-content/themes/divi',
        'wp-content/themes/flavor',
        'wp-content/themes/responsive',
        // Media uploads:
        'wp-content/uploads',
        // Core dirs:
        'wp-admin',
        'languages', 'i18n',
    ];

    public function init() {
        add_action( 'wp_ajax_rls_start_file_discovery', [ $this, 'ajax_start_file_discovery' ] );
        add_action( 'wp_ajax_rls_discover_files_step', [ $this, 'ajax_discover_files_step' ] );
        add_action( 'wp_ajax_rls_perform_scan_step', [ $this, 'ajax_perform_scan_step' ] );
        add_action( 'wp_ajax_rls_finalize_scan', [ $this, 'ajax_finalize_scan' ] );
        add_action( 'wp_ajax_rls_create_snapshot_step', [ $this, 'ajax_create_snapshot_step' ] );
        add_action( 'wp_ajax_rls_finalize_snapshot', [ $this, 'ajax_finalize_snapshot' ] );
        add_action( 'wp_ajax_rls_compare_snapshot_step', [ $this, 'ajax_compare_snapshot_step' ] );
        add_action( 'wp_ajax_rls_finalize_comparison', [ $this, 'ajax_finalize_comparison' ] );
        add_action( 'wp_ajax_rls_neutralize_file', [ $this, 'ajax_neutralize_file' ] );
        // v2.6.0 endpoints.
        add_action( 'wp_ajax_rls_get_scan_progress', [ $this, 'ajax_get_scan_progress' ] );
        add_action( 'wp_ajax_rls_export_scan', [ $this, 'ajax_export_scan' ] );
        add_action( 'wp_ajax_rls_db_scan', [ $this, 'ajax_db_scan' ] );
        add_action( 'wp_ajax_rls_checksums_scan', [ $this, 'ajax_checksums_scan' ] );
        add_action( 'wp_ajax_rls_diff_scans', [ $this, 'ajax_diff_scans' ] );
        add_action( 'wp_ajax_rls_report_false_positive', [ $this, 'ajax_report_false_positive' ] );
        add_action( 'wp_ajax_rls_auto_quarantine_critical', [ $this, 'ajax_auto_quarantine_critical' ] );

        // WP-CLI integration.
        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            WP_CLI::add_command( 'rls scan', [ $this, 'cli_scan' ] );
            WP_CLI::add_command( 'rls status', [ $this, 'cli_status' ] );
        }
    }

    private function get_scan_mode_context() {
        $mode = get_transient( 'rls_scan_mode' );
        $mode = is_string( $mode ) ? sanitize_key( $mode ) : 'important';

        if ( ! in_array( $mode, [ 'quick', 'important', 'full' ], true ) ) {
            $mode = 'important';
        }

        return $mode;
    }

    private function get_scan_profile( $mode ) {
        $profiles = [
            'quick' => [
                'max_size'    => 1048576,
                'extensions'  => [ 'php', 'phtml', 'php5', 'phar', 'js', 'htaccess' ],
            ],
            'important' => [
                'max_size'    => 2097152,
                'extensions'  => [ 'php', 'phtml', 'php5', 'phar', 'inc', 'module', 'theme', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'htaccess', 'ini', 'conf', 'cfg', 'json', 'xml', 'yml', 'yaml', 'txt', 'log', 'md', 'tpl', 'twig', 'cgi', 'pl', 'py', 'sh', 'bash', 'bat', 'cmd', 'ps1', 'asp', 'aspx', 'jsp', 'cshtml' ],
            ],
            'full' => [
                'max_size'    => 8388608,
                'extensions'  => [],
            ],
        ];

        $mode = sanitize_key( (string) $mode );
        if ( ! isset( $profiles[ $mode ] ) ) {
            $mode = 'important';
        }

        return $profiles[ $mode ];
    }

    private function get_scan_file_size_limit() {
        $mode = $this->get_scan_mode_context();
        $profile = $this->get_scan_profile( $mode );
        return (int) $profile['max_size'];
    }

    private function should_include_discovered_file( $path, $item, $mode ) {
        if ( $this->is_path_excluded( $path ) ) {
            return false;
        }

        $mode = sanitize_key( (string) $mode );
        if ( $mode === 'full' ) {
            return true;
        }

        $profile = $this->get_scan_profile( $mode );
        $filename = basename( (string) $item );
        $ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

        if ( in_array( $filename, self::SUSPICIOUS_FILES, true ) ) {
            return true;
        }

        return in_array( $ext, $profile['extensions'], true );
    }

    // --- 1. ИНДЕКСАЦИЯ ФАЙЛОВ ---
    public function ajax_start_file_discovery() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $mode = sanitize_key( (string) ( $_POST['mode'] ?? 'important' ) );
        if ( ! in_array( $mode, [ 'quick', 'important', 'full' ], true ) ) {
            $mode = 'important';
        }
        delete_transient( 'rls_scan_file_list' );
        delete_transient( 'rls_dirs_to_scan' );
        delete_transient( 'rls_scan_mode' );
        delete_transient( 'rls_scan_max_file_size' );
        set_transient( 'rls_dirs_to_scan', [ ABSPATH ], HOUR_IN_SECONDS );
        set_transient( 'rls_scan_file_list', [], HOUR_IN_SECONDS );
        set_transient( 'rls_scan_mode', $mode, HOUR_IN_SECONDS );
        set_transient( 'rls_scan_max_file_size', $this->get_scan_profile( $mode )['max_size'], HOUR_IN_SECONDS );
        wp_send_json_success( [ 'status' => 'started', 'mode' => $mode ] );
    }

    public function ajax_discover_files_step() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        if (function_exists('set_time_limit')) @set_time_limit(60);

        $dirs = get_transient( 'rls_dirs_to_scan' );
        $files = get_transient( 'rls_scan_file_list' );
        $mode = $this->get_scan_mode_context();
        
        if ( $dirs === false ) wp_send_json_error( 'Session expired' );
        
        $start_time = microtime(true);
        $dirs_processed = 0;

        while ( ! empty( $dirs ) ) {
            if ( (microtime(true) - $start_time) > self::TIME_LIMIT ) break;
            if ( count( $files ) >= self::MAX_FILES ) break;

            $current_dir = array_shift( $dirs );
            $dirs_processed++;

            try {
                if ( ! is_dir( $current_dir ) || ! is_readable( $current_dir ) ) continue;
                $items = @scandir( $current_dir );
                if ( ! $items ) continue;

                foreach ( $items as $item ) {
                    if ( $item === '.' || $item === '..' ) continue;
                    $path = $current_dir . DIRECTORY_SEPARATOR . $item;

                    if ( $this->is_path_excluded( $path, $mode ) ) continue;

                    if ( is_dir( $path ) && ! is_link( $path ) ) {
                        $dirs[] = $path;
                    } elseif ( is_file( $path ) ) {
                        if ( count( $files ) >= self::MAX_FILES ) break;
                        if ( $this->should_include_discovered_file( $path, $item, $mode ) ) {
                            $files[] = $path;
                        }
                    }
                }
            } catch ( Exception $e ) { continue; }
        }
        
        set_transient( 'rls_dirs_to_scan', $dirs, HOUR_IN_SECONDS );
        set_transient( 'rls_scan_file_list', $files, HOUR_IN_SECONDS );
        
        wp_send_json_success( [ 'done' => empty( $dirs ), 'files_found' => count( $files ) ] );
    }

    // --- 2. СКАНИРОВАНИЕ ---
    public function ajax_perform_scan_step() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        if (function_exists('set_time_limit')) @set_time_limit(60);

        // Try to raise memory limit to avoid crashes on large scans.
        if ( function_exists( 'wp_raise_memory_limit' ) ) {
            @wp_raise_memory_limit( 'admin' );
        } elseif ( function_exists( 'ini_set' ) ) {
            @ini_set( 'memory_limit', '512M' );
        }
        @ini_set( 'max_execution_time', 120 );

        $offset = isset( $_POST['offset'] ) ? intval( $_POST['offset'] ) : 0;
        $file_list = get_transient( 'rls_scan_file_list' );
        $max_file_size = $this->get_scan_file_size_limit();

        if ( $file_list === false ) {
            wp_send_json_error( 'Session expired (no file list)' );
        }

        // Limit batch size to prevent memory issues.
        $batch_limit = self::BATCH_SIZE;
        $total_files = count($file_list);
        $processed = 0;
        $found_threats = [];
        $skipped = 0;
        $last_file = '';
        $start_time = microtime(true);

        while ( ($offset + $processed) < $total_files && $processed < $batch_limit ) {
            if ( (microtime(true) - $start_time) > self::TIME_LIMIT ) break;

            $idx = $offset + $processed;
            if ( isset($file_list[$idx]) ) {
                $fp = $file_list[$idx];
                $size = @filesize( $fp );
                if ( $size !== false && $size > $max_file_size ) {
                    $skipped++;
                    $processed++;
                    continue;
                }
                $threats = $this->scan_single_file_enhanced( $fp, true );
                if ( ! empty($threats) ) {
                    $found_threats = array_merge( $found_threats, $threats );
                }
                $last_file = $fp;
            }
            $processed++;
        }

        wp_send_json_success( [
            'found_threats'  => $found_threats,
            'scanned_count'  => $processed,
            'skipped'        => $skipped,
            'last_file'      => $last_file,
            'progress_total' => $total_files,
        ] );
    }

    // --- ЯДРО СКАНИРОВАНИЯ ---
    private function scan_single_file( $file_path ) {
        static $signatures = null;
        static $whitelist = null;

        // 1. Проверка имени файла
        $filename = basename($file_path);
        if ( in_array( $filename, self::SUSPICIOUS_FILES ) ) {
            return [[ 'file' => $file_path, 'signature' => 'Suspicious Filename (' . $filename . ')' ]];
        }

        // 2. Инициализация белых списков
        if ($whitelist === null) $whitelist = get_option( 'rls_whitelist', [] );
        $normalized_path = wp_normalize_path( $file_path );
        $whitelist_entry = $whitelist[ $normalized_path ] ?? ( $whitelist[ $file_path ] ?? null );
        if ( $whitelist_entry !== null ) {
            $current_mtime = (int) @filemtime( $file_path );
            $current_hash  = @md5_file( $file_path );

            if ( is_array( $whitelist_entry ) ) {
                $saved_mtime = (int) ( $whitelist_entry['mtime'] ?? 0 );
                if ( $saved_mtime > 0 && $current_mtime === $saved_mtime ) return [];
            } elseif ( is_string( $whitelist_entry ) && $current_hash === $whitelist_entry ) {
                return [];
            }
        }
        $max_file_size = $this->get_scan_file_size_limit();
        if ( @filesize( $file_path ) > $max_file_size ) return [];
        
        $content = @file_get_contents( $file_path );
        if ( ! $content ) return [];
        
        // 3. Загрузка и очистка сигнатур (с кэшированием в object cache)
        if ($signatures === null) {
            $cache_key = 'rls_signatures_' . wp_cache_get( 'rls_signatures_version', 'rls' );
            $signatures = wp_cache_get( $cache_key, 'rls' );

            if ( ! is_array( $signatures ) ) {
                $signatures = get_option( 'rls_base_signatures', [] );
                if ( get_option( 'rls_license_status' ) === 'valid' ) {
                    $prem = get_option( 'rls_premium_signatures', [] );
                    if ( is_array( $prem ) ) $signatures = array_merge( $signatures, $prem );
                }
                $custom = get_option( 'rls_custom_signatures', [] );
                if ( ! empty( $custom ) ) $signatures = array_merge( $signatures, $custom );
                wp_cache_set( $cache_key, $signatures, 'rls', HOUR_IN_SECONDS );
            } else {
                // Use cached value but still merge custom signatures fresh (frequent changes).
                $custom = get_option( 'rls_custom_signatures', [] );
                if ( ! empty( $custom ) ) $signatures = array_merge( $signatures, $custom );
            }
            
            // Фильтрация для удаления $GLOBALS и мусора
            $signatures = array_filter(array_unique($signatures), function($s) {
                if (empty($s)) return false;
                if ($s === '$GLOBALS') return false; 
                if ($s === 'base64_decode') return false; 
                if (strlen($s) < 4) return false;
                return true;
            });
        }

        // 4. Проверка строк
        foreach ( $signatures as $signature ) {
            if ( strpos( $content, $signature ) !== false ) {
                if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( 'LOCAL_SCAN', 'virus', basename($file_path) . " found" );
                return [[ 'file' => $file_path, 'signature' => $signature ]];
            }
        }

        // 5. Проверка Regex
        foreach ( self::REGEX_PATTERNS as $pattern ) {
            if ( @preg_match( $pattern, $content ) ) {
                if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( 'LOCAL_SCAN', 'virus', basename($file_path) . " found (Regex)" );
                $reason = 'Heuristic Detection';
                if (strpos($pattern, 'preg_replace') !== false) $reason = 'Obfuscated Eval (preg_replace)';
                if (strpos($pattern, 'base64') !== false) $reason = 'Base64 Encoded Malware';
                return [[ 'file' => $file_path, 'signature' => $reason ]];
            }
        }

        return [];
    }

    private function is_path_excluded( $path, $mode = 'important' ) {
        $path = str_replace( '\\', '/', $path );
        // Always exclude our own plugin directory.
        if ( strpos( $path, '/wp-content/plugins/rybinsklab-security/' ) !== false ) return true;
        // Full scan: include everything (admin user request).
        if ( sanitize_key( (string) $mode ) === 'full' ) {
            // But still skip huge irrelevant dirs to avoid timeout.
            foreach ( [ 'node_modules', 'vendor', '.git', 'wp-content/uploads/' ] as $ex ) {
                if ( strpos( $path, '/' . $ex . '/' ) !== false ) return true;
            }
            return false;
        }
        foreach ( $this->excluded_paths as $ex ) {
            if ( strpos( $path, '/' . $ex . '/' ) !== false ) return true;
        }
        return false;
    }

    // --- SNAPSHOT & FINALIZE ---
    public function ajax_create_snapshot_step() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $offset = intval( $_POST['offset'] ); 
        $file_list = get_transient('rls_scan_file_list');
        $max_file_size = $this->get_scan_file_size_limit();
        if($file_list===false) wp_send_json_error('Session expired');
        
        $total = count($file_list);
        $processed = 0;
        $snapshot_part = [];
        $start_time = microtime(true);

        while ( ($offset + $processed) < $total ) {
            if ( (microtime(true) - $start_time) > self::TIME_LIMIT ) break;
            $idx = $offset + $processed;
            $file = $file_list[$idx];
            $snapshot_part[$file] = (@filesize($file) > $max_file_size) ? 'SKIPPED' : @md5_file($file);
            $processed++;
        }
        wp_send_json_success(['snapshot_part'=>$snapshot_part, 'processed_count'=>$processed]);
    }

    public function ajax_compare_snapshot_step() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $offset = intval($_POST['offset']); 
        $file_list = get_transient('rls_scan_file_list'); 
        $max_file_size = $this->get_scan_file_size_limit();
        $orig = get_option('rls_snapshot_data',[]); 
        if($file_list===false) wp_send_json_error('Session expired');
        
        $total = count($file_list);
        $processed = 0;
        $changes = ['added'=>[], 'modified'=>[]]; 
        $start_time = microtime(true);
        
        while ( ($offset + $processed) < $total ) {
            if ( (microtime(true) - $start_time) > self::TIME_LIMIT ) break;
            $idx = $offset + $processed;
            $p = $file_list[$idx];
            if(!isset($orig[$p])) $changes['added'][]=$p; 
            else { 
                if(@filesize($p) <= $max_file_size && @md5_file($p) !== $orig[$p]) {
                    $changes['modified'][]=$p; 
                }
            }
            $processed++;
        }
        wp_send_json_success(['changes'=>$changes, 'processed_count'=>$processed]);
    }

    public function ajax_finalize_scan() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $threats = json_decode( stripslashes( $_POST['threats'] ), true ) ?: [];
        update_option( 'rls_last_scan_results', $threats ); update_option( 'rls_last_scan_time', time() );
        if ( count( $threats ) > 0 ) {
            $stats = get_option( 'rls_stats', [] ); $stats['viruses_found'] = ($stats['viruses_found'] ?? 0) + count( $threats ); update_option( 'rls_stats', $stats );
            if ( class_exists( 'RLS_Cron' ) ) RLS_Cron::sync_detailed_stats();
        }
        if ( class_exists( 'RLS_Scan_History' ) ) RLS_Scan_History::add_entry( 'manual', $threats, 0 );
        delete_transient( 'rls_scan_file_list' ); delete_transient( 'rls_dirs_to_scan' ); delete_transient( 'rls_scan_mode' ); delete_transient( 'rls_scan_max_file_size' );
        wp_send_json_success();
    }

    public function ajax_finalize_snapshot() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $s = json_decode(stripslashes($_POST['snapshot']),true); 
        if(is_array($s)){ update_option('rls_snapshot_data',$s); update_option('rls_snapshot_time',time()); }
        delete_transient('rls_scan_file_list'); delete_transient('rls_dirs_to_scan'); delete_transient('rls_scan_mode'); delete_transient('rls_scan_max_file_size');
        wp_send_json_success();
    }

    public function ajax_finalize_comparison() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $c = json_decode(stripslashes($_POST['changes']),true); 
        update_option('rls_comparison_results',$c); update_option('rls_comparison_time',time());
        delete_transient('rls_scan_file_list'); delete_transient('rls_dirs_to_scan'); delete_transient('rls_scan_mode'); delete_transient('rls_scan_max_file_size');
        wp_send_json_success();
    }

    public function ajax_neutralize_file() {
        check_ajax_referer('rls_scanner_nonce', 'nonce');
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Доступ запрещен.' );
        }
        $fp = trim( wp_unslash( $_POST['filepath'] ?? '' ) );
        $sig = trim( wp_unslash( $_POST['signature'] ?? '' ) );
        if ( empty( $fp ) ) {
            wp_send_json_error( 'Путь не указан.' );
        }
        if ( ! $this->is_safe_file_path( $fp ) ) {
            wp_send_json_error( 'Недопустимый путь.' );
        }
        $fp = wp_normalize_path( $fp );
        if ( ! file_exists( $fp ) ) {
            wp_send_json_error( 'Файл не найден' );
        }

        require_once( ABSPATH . 'wp-admin/includes/update.php' );
        $rel = str_replace( ABSPATH, '', $fp ); global $wp_version; $sums = get_core_checksums( $wp_version, get_locale() );
        if ( is_array( $sums ) && isset( $sums[$rel] ) && md5_file($fp) === $sums[$rel] ) {
            $this->add_to_whitelist_safe( $fp );
            wp_send_json_success(['result' => 'whitelisted']);
            return;
        }

        $c = file_get_contents( $fp );
        if ( $c === false ) {
            wp_send_json_error( 'Не удалось прочитать файл.' );
        }
        $max_ai_bytes = 204800;
        if ( class_exists( 'RLS_API_Client' ) && method_exists( 'RLS_API_Client', 'get_ai_snippet_limit_bytes' ) ) {
            $max_ai_bytes = (int) RLS_API_Client::get_ai_snippet_limit_bytes();
        }
        if ( $max_ai_bytes > 0 && strlen( $c ) > $max_ai_bytes ) {
            $head_bytes = max( 1, (int) floor( $max_ai_bytes / 2 ) );
            $tail_bytes = max( 1, $max_ai_bytes - $head_bytes );
            $head = substr( $c, 0, $head_bytes );
            $tail = substr( $c, -$tail_bytes );
            $snip = $head . "\n...\n" . $tail;
        } else {
            $snip = $c;
        }
        // SECURITY: free the original content from memory; only the snippet travels.
        unset( $c );

        if(class_exists('RLS_API_Client')) {
            $ai = RLS_API_Client::analyze_code_snippet($snip);
            if(!is_wp_error($ai) && isset($ai['data']['verdict'])) {
                if($ai['data']['verdict'] === 'Virus') {
                    wp_send_json_success(['result' => 'ai_virus', 'snippet' => $snip]);
                } else {
                    $this->add_to_whitelist_safe( $fp );
                    wp_send_json_success(['result' => 'ai_legitimate']);
                }
            } else wp_send_json_error('AI Error');
        } else wp_send_json_error('API Error');
    }

    /**
     * Whitelist-safe path check: must be inside ABSPATH/WP_CONTENT_DIR and not
     * point at the quarantine directory or the plugin itself.
     */
    private function is_safe_file_path( $filepath ) {
        $filepath = wp_normalize_path( (string) $filepath );
        if ( empty( $filepath ) || strlen( $filepath ) > 1024 ) return false;
        if ( strpos( $filepath, '..' ) !== false || strpos( $filepath, "\0" ) !== false ) return false;
        $abspath    = wp_normalize_path( ABSPATH );
        $wp_content = wp_normalize_path( WP_CONTENT_DIR );
        $inside_root = ( strpos( $filepath, $abspath ) === 0 || strpos( $filepath, $wp_content ) === 0 );
        if ( ! $inside_root ) return false;
        $quarantine = wp_normalize_path( wp_upload_dir()['basedir'] . '/rls-quarantine' );
        if ( strpos( $filepath, $quarantine ) === 0 ) return false;
        if ( strpos( $filepath, wp_normalize_path( WP_PLUGIN_DIR . '/rybinsklab-security' ) ) === 0 ) return false;
        return true;
    }

    private function add_to_whitelist_safe( $filepath ) {
        $filepath = wp_normalize_path( $filepath );
        $w = get_option( 'rls_whitelist', [] );
        $w[ $filepath ] = [
            'hash'  => (string) md5_file( $filepath ),
            'mtime' => (int) @filemtime( $filepath ),
        ];
        update_option( 'rls_whitelist', $w, false );
    }
    
    // --- МЕТОДЫ ДЛЯ CRON (ДОБАВЛЕНО) ---
    // Это те методы, которых не хватало, и из-за которых не запускалось фоновое сканирование

    public function get_critical_files_list() {
        $files_to_scan = [];
        
        // 1. Корневые файлы
        $root_files = @scandir( ABSPATH );
        if ( $root_files ) {
            foreach ( $root_files as $file ) {
                if ( $file === '.' || $file === '..' ) continue;
                $path = ABSPATH . $file;
                if ( is_file( $path ) && preg_match( '/\.(php|phtml|htaccess)$/i', $file ) ) {
                    $files_to_scan[] = $path;
                }
            }
        }
        
        // 2. Индексные файлы
        $files_to_scan[] = WP_CONTENT_DIR . '/index.php';
        
        return $files_to_scan;
    }

    public function scan_files_direct( $file_list, $options = [] ) {
        $threats = [];
        $incremental = ! empty( $options['incremental'] );
        $with_heuristics = ! empty( $options['heuristics'] );

        if ( class_exists( 'RLS_Scanner_Cache' ) ) {
            RLS_Scanner_Cache::reset_progress( count( $file_list ) );
        }

        foreach ( $file_list as $file_path ) {
            if ( ! file_exists( $file_path ) ) continue;

            // Incremental: skip unchanged files.
            if ( $incremental && class_exists( 'RLS_Scanner_Cache' ) && RLS_Scanner_Cache::is_unchanged( $file_path ) ) {
                RLS_Scanner_Cache::increment_skipped();
                continue;
            }

            if ( class_exists( 'RLS_Scanner_Cache' ) ) {
                RLS_Scanner_Cache::increment_scanned( $file_path );
            }

            $result = $this->scan_single_file_enhanced( $file_path, $with_heuristics );
            if ( ! empty( $result ) ) {
                $threats = array_merge( $threats, $result );
                if ( class_exists( 'RLS_Scanner_Cache' ) ) {
                    RLS_Scanner_Cache::increment_threats( count( $result ) );
                }
            }

            // Cache this file's state.
            if ( class_exists( 'RLS_Scanner_Cache' ) ) {
                $risk = 0;
                foreach ( $result as $r ) {
                    $risk = max( $risk, (int) ( $r['risk_score'] ?? 0 ) );
                }
                RLS_Scanner_Cache::put( $file_path, count( $result ), $risk );
            }
        }

        if ( class_exists( 'RLS_Scanner_Cache' ) ) {
            RLS_Scanner_Cache::finish_progress();
        }
        return $threats;
    }

    /**
     * Enhanced single-file scanner with heuristics + risk score.
     * Public wrapper that uses heuristics by default.
     */
    public function scan_single_file_enhanced( $file_path, $with_heuristics = true ) {
        if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) return [];
        // Skip very large files (>1MB) to avoid memory issues.
        $size = @filesize( $file_path );
        if ( $size !== false && $size > 1024 * 1024 ) return [];
        $content = @file_get_contents( $file_path );
        if ( $content === false ) return [];
        if ( strlen( $content ) > 1024 * 1024 ) return [];

        $findings = [];

        // 1. Substring signatures (legacy).
        $signatures = $this->get_signatures();
        foreach ( $signatures as $sig ) {
            if ( strpos( $content, $sig ) !== false ) {
                $findings[] = [
                    'file'        => $file_path,
                    'signature'   => $sig,
                    'detector'    => 'signature',
                    'severity'    => 80,
                    'tags'        => [ 'signature' ],
                    'risk_score'  => 80,
                    'line'        => self::find_line_for_substring( $content, $sig ),
                ];
            }
        }

        // 2. Heuristic regex rules + entropy detection.
        if ( $with_heuristics && class_exists( 'RLS_Scanner_Heuristics' ) ) {
            $heuristic_findings = RLS_Scanner_Heuristics::scan_content( $content, $file_path );
            foreach ( $heuristic_findings as $hf ) {
                $findings[] = array_merge( [
                    'file'       => $file_path,
                    'detector'   => 'heuristic',
                    'risk_score' => (int) $hf['severity'],
                ], $hf );
            }
            $obf_findings = RLS_Scanner_Heuristics::detect_obfuscation( $content );
            foreach ( $obf_findings as $of ) {
                $findings[] = array_merge( [
                    'file'       => $file_path,
                    'detector'   => 'heuristic',
                    'risk_score' => (int) $of['severity'],
                ], $of );
            }
        }

        // 3. Aggregate risk score.
        $aggregated_findings = [];
        if ( ! empty( $findings ) ) {
            $by_file = [];
            foreach ( $findings as $f ) {
                $key = ( $f['file'] ?? $file_path ) . ':' . ( $f['line'] ?? 0 );
                if ( ! isset( $by_file[ $key ] ) ) {
                    $by_file[ $key ] = [];
                }
                $by_file[ $key ][] = $f;
            }
            foreach ( $by_file as $key => $group ) {
                $risk = class_exists( 'RLS_Scanner_Heuristics' )
                    ? RLS_Scanner_Heuristics::aggregate_risk_score( $group )
                    : max( array_column( $group, 'risk_score' ) ?: [ 0 ] );
                $primary = $group[0];
                $aggregated_findings[] = array_merge( $primary, [
                    'risk_score'   => $risk,
                    'all_findings' => $group,
                    'count'        => count( $group ),
                ] );
            }
        }
        return $aggregated_findings;
    }

    private static function find_line_for_substring( $content, $needle ) {
        $offset = strpos( $content, $needle );
        if ( $offset === false ) return 0;
        return substr_count( substr( $content, 0, $offset ), "\n" ) + 1;
    }

    /**
     * Returns a list of files for full / incremental scan.
     */
    public function get_all_critical_files() {
        $files = $this->get_critical_files_list();
        // Include wp-config.php and uploads/*.php specifically.
        $wp_config = ABSPATH . 'wp-config.php';
        if ( file_exists( $wp_config ) ) $files[] = $wp_config;
        return array_values( array_unique( $files ) );
    }

    /**
     * Quick incremental scan: only files changed since last full scan.
     */
    public function scan_incremental( $file_list ) {
        return $this->scan_files_direct( $file_list, [ 'incremental' => true, 'heuristics' => true ] );
    }

    /**
     * Full scan with all detections.
     */
    public function scan_full( $file_list ) {
        // Reset cache for full scan to ensure fresh data.
        return $this->scan_files_direct( $file_list, [ 'incremental' => false, 'heuristics' => true ] );
    }

    /* =====================================================================
     * v2.6.0 NEW AJAX ENDPOINTS + WP-CLI
     * ===================================================================== */

    public function ajax_get_scan_progress() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        if ( ! class_exists( 'RLS_Scanner_Cache' ) ) wp_send_json_error();
        $progress = RLS_Scanner_Cache::get_progress();
        $eta = '';
        if ( ! empty( $progress['started_at'] ) && ! empty( $progress['scanned'] ) && $progress['scanned'] > 0 ) {
            $elapsed = time() - (int) $progress['started_at'];
            $per_file = $elapsed / max( 1, (int) $progress['scanned'] );
            $remaining = max( 0, (int) $progress['total'] - (int) $progress['scanned'] );
            $eta = (int) ( $per_file * $remaining );
        }
        wp_send_json_success( array_merge( $progress, [ 'eta_seconds' => $eta ] ) );
    }

    public function ajax_export_scan() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Access denied' );
        $format = sanitize_key( $_GET['format'] ?? 'json' );
        $scan_id = (int) ( $_GET['scan_id'] ?? 0 );

        global $wpdb;
        $table = $wpdb->prefix . 'rls_scan_history';
        $row = $scan_id
            ? $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE id = %d", $scan_id ), ARRAY_A )
            : $wpdb->get_row( "SELECT * FROM $table ORDER BY id DESC LIMIT 1", ARRAY_A );

        if ( ! $row ) wp_die( 'No scan found' );
        $threats = json_decode( $row['scan_details'], true );
        if ( ! is_array( $threats ) ) $threats = [];

        $filename = 'rls-scan-' . gmdate( 'Ymd-His' ) . ( $scan_id ? '-' . $scan_id : '' );
        if ( $format === 'csv' ) {
            nocache_headers();
            header( 'Content-Type: text/csv; charset=utf-8' );
            header( 'Content-Disposition: attachment; filename="' . $filename . '.csv"' );
            echo "file,risk_score,rule,line,severity,type\n";
            foreach ( $threats as $t ) {
                $file = isset( $t['file'] ) ? str_replace( [ "\n", '"' ], [ ' ', '""' ], $t['file'] ) : '';
                $rule = isset( $t['rule_name'] ) ? str_replace( [ "\n", '"' ], [ ' ', '""' ], $t['rule_name'] ) : '';
                echo '"' . $file . '",' . (int) ( $t['risk_score'] ?? 0 ) . ',"' . $rule . '",' . (int) ( $t['line'] ?? 0 ) . ',' . (int) ( $t['severity'] ?? 0 ) . ',' . sanitize_key( $t['detector'] ?? 'signature' ) . "\n";
            }
            exit;
        }
        // JSON default.
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="' . $filename . '.json"' );
        echo wp_json_encode( [
            'scan'     => $row,
            'threats'  => $threats,
            'exported' => gmdate( 'c' ),
            'site'     => home_url(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
        exit;
    }

    public function ajax_db_scan() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        if ( ! class_exists( 'RLS_Scanner_Database' ) ) wp_send_json_error( 'DB scanner not available' );
        $findings = RLS_Scanner_Database::scan();
        wp_send_json_success( [
            'findings' => $findings,
            'count'    => count( $findings ),
            'message'  => sprintf( 'DB scan: %d подозрительных записей', count( $findings ) ),
        ] );
    }

    public function ajax_checksums_scan() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        if ( ! class_exists( 'RLS_Scanner_Checksums' ) ) wp_send_json_error( 'Checksums scanner not available' );
        $findings = RLS_Scanner_Checksums::scan();
        wp_send_json_success( [
            'findings' => $findings,
            'count'    => count( $findings ),
            'message'  => sprintf( 'WP.org checksums: %d модифицированных файлов', count( $findings ) ),
        ] );
    }

    public function ajax_diff_scans() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        global $wpdb;
        $table = $wpdb->prefix . 'rls_scan_history';
        $a_id = (int) ( $_POST['scan_a'] ?? 0 );
        $b_id = (int) ( $_POST['scan_b'] ?? 0 );
        if ( ! $a_id || ! $b_id ) wp_send_json_error( 'Не указаны ID сканов' );
        $a = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE id = %d", $a_id ), ARRAY_A );
        $b = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE id = %d", $b_id ), ARRAY_A );
        if ( ! $a || ! $b ) wp_send_json_error( 'Сканы не найдены' );
        $a_threats = (array) json_decode( $a['scan_details'] ?? '[]', true );
        $b_threats = (array) json_decode( $b['scan_details'] ?? '[]', true );
        $a_files = array_unique( array_column( $a_threats, 'file' ) );
        $b_files = array_unique( array_column( $b_threats, 'file' ) );
        $new_threats = array_values( array_diff( $b_files, $a_files ) );
        $fixed_threats = array_values( array_diff( $a_files, $b_files ) );
        $persistent_threats = array_values( array_intersect( $a_files, $b_files ) );
        wp_send_json_success( [
            'scan_a' => $a_id,
            'scan_b' => $b_id,
            'new'       => $new_threats,
            'fixed'     => $fixed_threats,
            'persistent'=> $persistent_threats,
        ] );
    }

    public function ajax_report_false_positive() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        $file = sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) );
        $rule = sanitize_text_field( wp_unslash( $_POST['rule'] ?? '' ) );
        if ( ! $file || ! $rule ) wp_send_json_error( 'Не указаны file/rule' );
        $stats = get_option( 'rls_stats', [] );
        $stats['false_positives'] = ( $stats['false_positives'] ?? 0 ) + 1;
        update_option( 'rls_stats', $stats );

        // Add to whitelist with comment.
        $whitelist = get_option( 'rls_whitelist', [] );
        $norm = wp_normalize_path( $file );
        $whitelist[ $norm ] = [
            'hash'         => (string) md5_file( $file ),
            'mtime'        => (int) filemtime( $file ),
            'reason'       => 'False positive report',
            'rule'         => $rule,
            'reported_at'  => time(),
        ];
        update_option( 'rls_whitelist', $whitelist );
        wp_send_json_success( 'Добавлено в whitelist' );
    }

    public function ajax_auto_quarantine_critical() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        $threshold = 90; // Only critical threats.
        $count = 0;
        $quarantined = [];

        global $wpdb;
        $table = $wpdb->prefix . 'rls_scan_history';
        $latest = $wpdb->get_row( "SELECT scan_details FROM $table ORDER BY id DESC LIMIT 1", ARRAY_A );
        if ( ! $latest ) wp_send_json_error( 'Нет данных о последнем сканировании' );
        $threats = (array) json_decode( $latest['scan_details'] ?? '[]', true );
        foreach ( $threats as $t ) {
            if ( (int) ( $t['risk_score'] ?? 0 ) < $threshold ) continue;
            $file = $t['file'] ?? '';
            if ( ! $file || ! file_exists( $file ) ) continue;
            $quarantine = new RLS_Quarantine();
            if ( method_exists( $quarantine, 'is_safe_quarantine_path' ) && $quarantine->is_safe_quarantine_path( $file ) ) {
                // Move via reflection-friendly path (file ops directly).
                $quarantine_dir = wp_normalize_path( wp_upload_dir()['basedir'] . '/rls-quarantine' );
                if ( ! file_exists( $quarantine_dir ) ) continue;
                $hash = md5( $file . microtime( true ) );
                $new_file = $quarantine_dir . '/' . $hash . '.suspected';
                if ( @rename( $file, $new_file ) ) {
                    $index_path = $quarantine_dir . '/index_map.json';
                    $index = file_exists( $index_path ) ? json_decode( file_get_contents( $index_path ), true ) : [];
                    if ( ! is_array( $index ) ) $index = [];
                    $index[ $hash ] = [
                        'original_path' => $file,
                        'quarantined_at' => current_time( 'mysql' ),
                        'auto' => true,
                        'threat' => $t,
                    ];
                    @file_put_contents( $index_path, wp_json_encode( $index ) );
                    $count++;
                    $quarantined[] = $file;
                }
            }
        }
        wp_send_json_success( [
            'message' => sprintf( 'Auto-quarantined: %d файлов', $count ),
            'files'   => $quarantined,
        ] );
    }

    /* === WP-CLI === */
    public function cli_scan( $args, $assoc_args ) {
        $mode = $assoc_args['mode'] ?? 'full';
        $files = $this->get_all_critical_files();
        WP_CLI::log( sprintf( 'Starting scan in %s mode (%d files)', $mode, count( $files ) ) );
        $threats = ( $mode === 'incremental' )
            ? $this->scan_incremental( $files )
            : $this->scan_full( $files );
        if ( class_exists( 'RLS_Scan_History' ) ) {
            RLS_Scan_History::add_entry( 'cli-' . $mode, $threats, 0 );
        }
        WP_CLI::log( sprintf( 'Found %d threats', count( $threats ) ) );
        if ( ! empty( $threats ) ) {
            WP_CLI\Utils\format_items( 'table', $threats, [ 'file', 'risk_score', 'rule_name', 'line' ] );
        } else {
            WP_CLI::success( 'Site is clean!' );
        }
    }

    public function cli_status() {
        $stats = get_option( 'rls_stats', [] );
        $cache = class_exists( 'RLS_Scanner_Cache' ) ? RLS_Scanner_Cache::get_progress() : [];
        WP_CLI::log( 'Rybinsk Lab Security Status' );
        WP_CLI::log( sprintf( 'Firewall blocked: %d', $stats['firewall_blocked'] ?? 0 ) );
        WP_CLI::log( sprintf( 'Login attempts blocked: %d', $stats['login_attempts_blocked'] ?? 0 ) );
        WP_CLI::log( sprintf( 'Viruses found: %d', $stats['viruses_found'] ?? 0 ) );
        WP_CLI::log( sprintf( 'False positives: %d', $stats['false_positives'] ?? 0 ) );
        if ( ! empty( $cache['active'] ) ) {
            WP_CLI::log( sprintf( 'Scan in progress: %d/%d', $cache['scanned'] ?? 0, $cache['total'] ?? 0 ) );
        }
    }

}

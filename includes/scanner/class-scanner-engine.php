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

    const TIME_LIMIT = 5; 
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
        '.git', '.svn', 'node_modules', 'vendor', 
        'cache', 'backups', 'backup', 
        'wp-content/cache', 'wp-content/backups', 
        'wp-content/upgrade', 'wp-content/ai1wm-backups',
        'wp-content/uploads' 
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
    }

    // --- 1. ИНДЕКСАЦИЯ ФАЙЛОВ ---
    public function ajax_start_file_discovery() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        delete_transient( 'rls_scan_file_list' );
        delete_transient( 'rls_dirs_to_scan' );
        set_transient( 'rls_dirs_to_scan', [ ABSPATH ], HOUR_IN_SECONDS );
        set_transient( 'rls_scan_file_list', [], HOUR_IN_SECONDS );
        wp_send_json_success( [ 'status' => 'started' ] );
    }

    public function ajax_discover_files_step() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        if (function_exists('set_time_limit')) @set_time_limit(60);

        $dirs = get_transient( 'rls_dirs_to_scan' );
        $files = get_transient( 'rls_scan_file_list' );
        
        if ( $dirs === false ) wp_send_json_error( 'Session expired' );
        
        $start_time = microtime(true);
        $dirs_processed = 0;

        while ( ! empty( $dirs ) ) {
            if ( (microtime(true) - $start_time) > self::TIME_LIMIT ) break;

            $current_dir = array_shift( $dirs );
            $dirs_processed++;
            
            try {
                if ( ! is_dir( $current_dir ) || ! is_readable( $current_dir ) ) continue;
                $items = @scandir( $current_dir );
                if ( ! $items ) continue;

                foreach ( $items as $item ) {
                    if ( $item === '.' || $item === '..' ) continue;
                    $path = $current_dir . DIRECTORY_SEPARATOR . $item;
                    
                    if ( $this->is_path_excluded( $path ) ) continue;
                    
                    if ( is_dir( $path ) && ! is_link( $path ) ) {
                        $dirs[] = $path;
                    } elseif ( is_file( $path ) ) {
                        if ( preg_match( '/\.(php|phtml|php5|pl|py|cgi|htaccess|js)$/i', $item ) ) {
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
        
        $offset = isset( $_POST['offset'] ) ? intval( $_POST['offset'] ) : 0;
        $file_list = get_transient( 'rls_scan_file_list' );
        
        if ( $file_list === false ) wp_send_json_error( 'Session expired' );

        $total_files = count($file_list);
        $processed = 0;
        $found_threats = [];
        $start_time = microtime(true);

        while ( ($offset + $processed) < $total_files ) {
            if ( (microtime(true) - $start_time) > self::TIME_LIMIT ) break;

            $idx = $offset + $processed;
            if ( isset($file_list[$idx]) ) {
                $threats = $this->scan_single_file( $file_list[$idx] );
                if ( ! empty($threats) ) $found_threats = array_merge( $found_threats, $threats );
            }
            $processed++;
        }
        
        wp_send_json_success( [ 'found_threats' => $found_threats, 'scanned_count' => $processed ] );
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
        if ( isset( $whitelist[ $file_path ] ) && @md5_file( $file_path ) === $whitelist[ $file_path ] ) return [];
        if ( @filesize( $file_path ) > self::MAX_FILE_SIZE ) return [];
        
        $content = @file_get_contents( $file_path );
        if ( ! $content ) return [];
        
        // 3. Загрузка и очистка сигнатур
        if ($signatures === null) {
            $signatures = get_option( 'rls_base_signatures', [] );
            if ( get_option( 'rls_license_status' ) === 'valid' ) {
                $prem = get_option( 'rls_premium_signatures', [] );
                if ( is_array( $prem ) ) $signatures = array_merge( $signatures, $prem );
            }
            $custom = get_option( 'rls_custom_signatures', [] );
            if ( ! empty( $custom ) ) $signatures = array_merge( $signatures, $custom );
            
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

    private function is_path_excluded( $path ) {
        $path = str_replace( '\\', '/', $path );
        if ( strpos( $path, 'wp-content/plugins/rybinsklab-security' ) !== false ) return true;
        foreach ( $this->excluded_paths as $ex ) if ( strpos( $path, '/' . $ex . '/' ) !== false ) return true;
        return false;
    }

    // --- SNAPSHOT & FINALIZE ---
    public function ajax_create_snapshot_step() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $offset = intval( $_POST['offset'] ); 
        $file_list = get_transient('rls_scan_file_list');
        if($file_list===false) wp_send_json_error('Session expired');
        
        $total = count($file_list);
        $processed = 0;
        $snapshot_part = [];
        $start_time = microtime(true);

        while ( ($offset + $processed) < $total ) {
            if ( (microtime(true) - $start_time) > self::TIME_LIMIT ) break;
            $idx = $offset + $processed;
            $file = $file_list[$idx];
            $snapshot_part[$file] = (@filesize($file) > self::MAX_FILE_SIZE) ? 'SKIPPED' : @md5_file($file);
            $processed++;
        }
        wp_send_json_success(['snapshot_part'=>$snapshot_part, 'processed_count'=>$processed]);
    }

    public function ajax_compare_snapshot_step() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $offset = intval($_POST['offset']); 
        $file_list = get_transient('rls_scan_file_list'); 
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
                if(@filesize($p) <= self::MAX_FILE_SIZE && @md5_file($p) !== $orig[$p]) {
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
        delete_transient( 'rls_scan_file_list' ); delete_transient( 'rls_dirs_to_scan' );
        wp_send_json_success();
    }

    public function ajax_finalize_snapshot() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $s = json_decode(stripslashes($_POST['snapshot']),true); 
        if(is_array($s)){ update_option('rls_snapshot_data',$s); update_option('rls_snapshot_time',time()); }
        delete_transient('rls_scan_file_list'); delete_transient('rls_dirs_to_scan');
        wp_send_json_success();
    }

    public function ajax_finalize_comparison() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $c = json_decode(stripslashes($_POST['changes']),true); 
        update_option('rls_comparison_results',$c); update_option('rls_comparison_time',time());
        delete_transient('rls_scan_file_list'); delete_transient('rls_dirs_to_scan');
        wp_send_json_success();
    }

    public function ajax_neutralize_file() {
        check_ajax_referer('rls_scanner_nonce', 'nonce'); 
        $fp = trim(stripslashes($_POST['filepath'] ?? '')); $sig = trim(stripslashes($_POST['signature'] ?? ''));
        if (empty($fp) || !file_exists($fp)) wp_send_json_error('Файл не найден');
        
        require_once( ABSPATH . 'wp-admin/includes/update.php' );
        $rel = str_replace( ABSPATH, '', $fp ); global $wp_version; $sums = get_core_checksums( $wp_version, get_locale() );
        if ( isset( $sums[$rel] ) && md5_file($fp) === $sums[$rel] ) {
            $w = get_option('rls_whitelist', []); $w[$fp] = md5_file($fp); update_option('rls_whitelist', $w);
            wp_send_json_success(['result' => 'whitelisted']); return;
        }

        $c = file_get_contents($fp); $snip = (strlen($c)>2000) ? substr($c,0,1000)."\n...\n".substr($c,-1000) : $c;
        if(class_exists('RLS_API_Client')) {
            $ai = RLS_API_Client::analyze_code_snippet($snip);
            if(!is_wp_error($ai) && isset($ai['data']['verdict'])) {
                if($ai['data']['verdict'] === 'Virus') wp_send_json_success(['result' => 'ai_virus', 'snippet' => $snip]);
                else { 
                    $w = get_option('rls_whitelist', []); $w[$fp] = md5_file($fp); update_option('rls_whitelist', $w); 
                    wp_send_json_success(['result' => 'ai_legitimate']); 
                }
            } else wp_send_json_error('AI Error');
        } else wp_send_json_error('API Error');
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

    public function scan_files_direct( $file_list ) {
        $threats = [];
        foreach ( $file_list as $file_path ) {
            if ( ! file_exists( $file_path ) ) continue;
            $result = $this->scan_single_file( $file_path );
            if ( ! empty( $result ) ) {
                $threats = array_merge( $threats, $result );
            }
        }
        return $threats;
    }
}
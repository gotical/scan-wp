<?php
/**
 * Класс RLS_Scanner_Engine
 * Улучшенная версия: возвращает не только файл, но и найденную в нем сигнатуру.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) {
    die;
}

class RLS_Scanner_Engine {

    const SCAN_BATCH_SIZE = 50;
    const DISCOVERY_BATCH_SIZE = 1;

    private $excluded_paths = ['.git', '.svn', 'node_modules', 'vendor', 'cache', 'backups', 'backup', 'uploads', 'wp-content/cache', 'wp-content/backups', 'wp-content/upgrade', 'wp-content/ai1wm-backups'];

    public function init() {
        // Фаза 1: Поиск файлов
        add_action('wp_ajax_rls_start_file_discovery', [$this, 'ajax_start_file_discovery']);
        add_action('wp_ajax_rls_discover_files_step', [$this, 'ajax_discover_files_step']);
        
        // Фаза 2: Сканирование
        add_action('wp_ajax_rls_perform_scan_step', [$this, 'ajax_perform_scan_step']);
        add_action('wp_ajax_rls_finalize_scan', [$this, 'ajax_finalize_scan']);
        
        // Функции для снимков
        add_action('wp_ajax_rls_create_snapshot_step', [$this, 'ajax_create_snapshot_step']);
        add_action('wp_ajax_rls_finalize_snapshot', [$this, 'ajax_finalize_snapshot']);
        add_action('wp_ajax_rls_compare_snapshot_step', [$this, 'ajax_compare_snapshot_step']);
        add_action('wp_ajax_rls_finalize_comparison', [$this, 'ajax_finalize_comparison']);
    }

    public function ajax_start_file_discovery() {
        check_ajax_referer('rls_scanner_nonce', 'nonce');
        delete_transient('rls_scan_file_list');
        delete_transient('rls_dirs_to_scan');
        $dirs_to_scan = [ABSPATH];
        set_transient('rls_dirs_to_scan', $dirs_to_scan, HOUR_IN_SECONDS);
        set_transient('rls_scan_file_list', [], HOUR_IN_SECONDS);
        wp_send_json_success(['status' => 'started', 'dirs_count' => 1]);
    }

    public function ajax_discover_files_step() {
        check_ajax_referer('rls_scanner_nonce', 'nonce');
        $dirs_to_scan = get_transient('rls_dirs_to_scan');
        $file_list = get_transient('rls_scan_file_list');
        if ($dirs_to_scan === false || $file_list === false) {
            wp_send_json_error('Сессия поиска истекла. Начните заново.');
        }
        $last_processed_dir = 'N/A';
        for ($i = 0; $i < self::DISCOVERY_BATCH_SIZE && !empty($dirs_to_scan); $i++) {
            $current_dir = array_shift($dirs_to_scan);
            $last_processed_dir = str_replace(ABSPATH, '', $current_dir);
            try {
                $items = new DirectoryIterator($current_dir);
                foreach ($items as $item) {
                    if ($item->isDot()) continue;
                    $path = $item->getPathname();
                    if ($this->is_path_excluded($path)) continue;
                    if ($item->isDir() && $item->isReadable()) {
                        $dirs_to_scan[] = $path;
                    } elseif ($item->isFile() && $item->isReadable()) {
                        $file_list[] = $path;
                    }
                }
            } catch (Exception $e) { continue; }
        }
        set_transient('rls_dirs_to_scan', $dirs_to_scan, HOUR_IN_SECONDS);
        set_transient('rls_scan_file_list', $file_list, HOUR_IN_SECONDS);
        wp_send_json_success(['done' => empty($dirs_to_scan), 'dirs_left' => count($dirs_to_scan), 'files_found' => count($file_list), 'last_dir' => $last_processed_dir]);
    }

    private function is_path_excluded($path) {
        $normalized_path = str_replace('\\', '/', $path);
        foreach ($this->excluded_paths as $excluded) {
            if (strpos($normalized_path, '/' . $excluded . '/') !== false || substr($normalized_path, -strlen('/' . $excluded)) === '/' . $excluded) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * AJAX: Шаг 2 (Сканер вирусов). Сканирует порцию файлов.
     * ЭТОТ МЕТОД ТЕПЕРЬ ГАРАНТИРОВАННО ВОЗВРАЩАЕТ ОБЪЕКТЫ {file, signature}.
     */
    public function ajax_perform_scan_step() {
        check_ajax_referer('rls_scanner_nonce', 'nonce');
        $offset = isset($_POST['offset']) ? intval($_POST['offset']) : 0;
        $file_list = get_transient('rls_scan_file_list');
        if ($file_list === false) wp_send_json_error('Сессия сканирования истекла.');

        $files_to_scan = array_slice($file_list, $offset, self::SCAN_BATCH_SIZE);
        $signatures = get_option('rls_base_signatures', []);
        if (get_option('rls_license_status') === 'valid') {
            $premium_signatures = get_option('rls_premium_signatures', []);
            if (is_array($premium_signatures)) $signatures = array_merge($signatures, $premium_signatures);
        }
        $custom_signatures = get_option('rls_custom_signatures', []);
        if (!empty($custom_signatures) && is_array($custom_signatures)) {
            $signatures = array_merge($signatures, $custom_signatures);
        }
        $signatures = array_unique($signatures);
        
        $found_threats = [];
        foreach ($files_to_scan as $file_path) {
            $content = @file_get_contents($file_path);
            if ($content === false) continue;
            foreach ($signatures as $signature) {
                $trimmed_sig = trim($signature);
                if (empty($trimmed_sig)) continue;
                if (strpos($content, $trimmed_sig) !== false) {
                    $found_threats[] = [
                        'file' => $file_path,
                        'signature' => $trimmed_sig
                    ];
                    break;
                }
            }
        }
        wp_send_json_success(['found_threats' => $found_threats, 'scanned_count' => count($files_to_scan)]);
    }

    public function ajax_finalize_scan() {
        check_ajax_referer('rls_scanner_nonce', 'nonce');
        $all_threats = isset($_POST['threats']) ? json_decode(stripslashes($_POST['threats']), true) : [];
        $threats_count = is_array($all_threats) ? count($all_threats) : 0;
        update_option('rls_last_scan_results', $all_threats);
        update_option('rls_last_scan_time', time());
        if ($threats_count > 0) {
            $stats = get_option('rls_stats', []);
            $stats['viruses_found'] = ($stats['viruses_found'] ?? 0) + $threats_count;
            update_option('rls_stats', $stats);
        }
        delete_transient('rls_scan_file_list');
        delete_transient('rls_dirs_to_scan');
        wp_send_json_success('Сканирование на вирусы завершено.');
    }
    
    // Остальные методы для снимков остаются без изменений
    public function ajax_create_snapshot_step(){ check_ajax_referer('rls_scanner_nonce','nonce');$offset=isset($_POST['offset'])?intval($_POST['offset']):0;$file_list=get_transient('rls_scan_file_list');if($file_list===false)wp_send_json_error('Сессия истекла.');$files_to_process=array_slice($file_list,$offset,self::SCAN_BATCH_SIZE);$snapshot_part=[];foreach($files_to_process as $file_path){$snapshot_part[$file_path]=@md5_file($file_path);}wp_send_json_success(['snapshot_part'=>$snapshot_part,'processed_count'=>count($files_to_process)]);}
    public function ajax_finalize_snapshot(){check_ajax_referer('rls_scanner_nonce','nonce');$full_snapshot=isset($_POST['snapshot'])?json_decode(stripslashes($_POST['snapshot']),true):[];if(is_array($full_snapshot)){update_option('rls_snapshot_data',$full_snapshot);update_option('rls_snapshot_time',time());}delete_transient('rls_scan_file_list');delete_transient('rls_dirs_to_scan');wp_send_json_success('Снимок успешно создан/обновлен.');}
    public function ajax_compare_snapshot_step(){check_ajax_referer('rls_scanner_nonce','nonce');$offset=isset($_POST['offset'])?intval($_POST['offset']):0;$file_list=get_transient('rls_scan_file_list');$original_snapshot=get_option('rls_snapshot_data',[]);if($file_list===false)wp_send_json_error('Сессия истекла.');$files_to_process=array_slice($file_list,$offset,self::SCAN_BATCH_SIZE);$changes=['added'=>[],'modified'=>[]];foreach($files_to_process as $file_path){if(!isset($original_snapshot[$file_path])){$changes['added'][]=$file_path;}else{$current_hash=@md5_file($file_path);if($current_hash!==$original_snapshot[$file_path]){$changes['modified'][]=$file_path;}}}wp_send_json_success(['changes'=>$changes,'processed_count'=>count($files_to_process)]);}
    public function ajax_finalize_comparison(){check_ajax_referer('rls_scanner_nonce','nonce');$current_files=get_transient('rls_scan_file_list');$original_snapshot_files=array_keys(get_option('rls_snapshot_data',[]));$changes=isset($_POST['changes'])?json_decode(stripslashes($_POST['changes']),true):['added'=>[],'modified'=>[]];$deleted_files=array_diff($original_snapshot_files,$current_files);$changes['deleted']=array_values($deleted_files);update_option('rls_comparison_results',$changes);update_option('rls_comparison_time',time());delete_transient('rls_scan_file_list');delete_transient('rls_dirs_to_scan');wp_send_json_success('Сравнение со снимком завершено.');}
}
<?php
/**
 * Класс RLS_Quarantine
 * Управление изоляцией опасных файлов.
 * Версия 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Quarantine {

    private $upload_dir;
    private $quarantine_dir;
    private $index_file;

    public function __construct() {
        $upload_info = wp_upload_dir();
        $this->upload_dir = $upload_info['basedir'];
        $this->quarantine_dir = $this->upload_dir . '/rls-quarantine';
        $this->index_file = $this->quarantine_dir . '/index_map.json'; 
    }

    public function init() {
        add_action( 'wp_ajax_rls_quarantine_file', [ $this, 'ajax_quarantine_file' ] );
        add_action( 'wp_ajax_rls_restore_file', [ $this, 'ajax_restore_file' ] );
        add_action( 'wp_ajax_rls_delete_quarantine', [ $this, 'ajax_delete_quarantine' ] );
        
        $this->check_setup();
    }

    private function check_setup() {
        if ( ! file_exists( $this->quarantine_dir ) ) {
            wp_mkdir_p( $this->quarantine_dir );
            $htaccess = "Order Deny,Allow\nDeny from all\n<Files ~ '\.(php|php5|phtml|pl|py|cgi)$'>\nOrder Allow,Deny\nDeny from all\n</Files>";
            file_put_contents( $this->quarantine_dir . '/.htaccess', $htaccess );
            file_put_contents( $this->quarantine_dir . '/index.php', '<?php // Silence is golden' );
        }
    }

    public function get_quarantined_files() {
        if ( ! file_exists( $this->index_file ) ) return [];
        $data = json_decode( file_get_contents( $this->index_file ), true );
        return is_array( $data ) ? $data : [];
    }

    public function ajax_quarantine_file() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Access Denied' );

        $filepath = wp_normalize_path( trim( stripslashes( $_POST['filepath'] ?? '' ) ) );

        if ( empty( $filepath ) || ! file_exists( $filepath ) ) {
            wp_send_json_error( 'Файл не найден на сервере.' );
        }

        $filename = basename( $filepath );
        $hash = md5( $filepath . time() );
        $new_filename = $hash . '.suspected';
        $destination = $this->quarantine_dir . '/' . $new_filename;

        if ( @rename( $filepath, $destination ) ) {
            $index = $this->get_quarantined_files();
            $index[ $hash ] = [
                'original_path' => $filepath,
                'filename'      => $filename,
                'quarantined_at'=> date( 'Y-m-d H:i:s' ),
                'stored_file'   => $new_filename
            ];
            $this->save_index( $index );
            wp_send_json_success( [ 'message' => 'Файл перемещен в карантин.' ] );
        } else {
            wp_send_json_error( 'Не удалось переместить файл (ошибка прав).' );
        }
    }

    public function ajax_restore_file() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $id = sanitize_text_field( $_POST['id'] ?? '' );
        $index = $this->get_quarantined_files();

        if ( ! isset( $index[ $id ] ) ) wp_send_json_error( 'Запись не найдена.' );

        $info = $index[ $id ];
        $stored_file = $this->quarantine_dir . '/' . $info['stored_file'];
        $original_path = $info['original_path'];

        if ( ! file_exists( $stored_file ) ) {
            unset( $index[ $id ] );
            $this->save_index( $index );
            wp_send_json_error( 'Файл отсутствует в хранилище.' );
        }

        $dir = dirname( $original_path );
        if ( ! file_exists( $dir ) ) wp_mkdir_p( $dir );

        if ( @rename( $stored_file, $original_path ) ) {
            unset( $index[ $id ] );
            $this->save_index( $index );
            wp_send_json_success( [ 'message' => 'Файл восстановлен.' ] );
        } else {
            wp_send_json_error( 'Ошибка восстановления (права на запись).' );
        }
    }

    public function ajax_delete_quarantine() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $id = sanitize_text_field( $_POST['id'] ?? '' );
        $index = $this->get_quarantined_files();

        if ( isset( $index[ $id ] ) ) {
            $file = $this->quarantine_dir . '/' . $index[ $id ]['stored_file'];
            if ( file_exists( $file ) ) @unlink( $file );
            unset( $index[ $id ] );
            $this->save_index( $index );
        }
        wp_send_json_success( [ 'message' => 'Удалено.' ] );
    }

    private function save_index( $data ) {
        file_put_contents( $this->index_file, json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
        $txt_content = "RLS Quarantine Log\n==================\n";
        foreach ($data as $hash => $info) {
            $txt_content .= "Date: " . $info['quarantined_at'] . "\nOriginal: " . $info['original_path'] . "\nStored: " . $info['stored_file'] . "\n------------------\n";
        }
        file_put_contents( $this->quarantine_dir . '/readable_log.txt', $txt_content );
    }
}
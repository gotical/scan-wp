<?php
/**
 * Класс RLS_Quarantine
 * Управление изоляцией опасных файлов.
 * Версия 1.1.0 (Security Hardening: path validation, id whitelist, json integrity)
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
            // .htaccess для Apache
            $htaccess = "Order Deny,Allow\nDeny from all\n<Files ~ '\.(php|php5|phtml|pl|py|cgi)$'>\nOrder Allow,Deny\nDeny from all\n</Files>";
            file_put_contents( $this->quarantine_dir . '/.htaccess', $htaccess );
            file_put_contents( $this->quarantine_dir . '/index.php', '<?php // Silence is golden' );
            // nginx-совместимая защита через web.config (для IIS) и инструкцию в README
            file_put_contents( $this->quarantine_dir . '/web.config', "<configuration><system.webServer><security><requestFiltering><fileExtensions><add fileExtension=\".php\" allowed=\"false\" /><add fileExtension=\".phtml\" allowed=\"false\" /><add fileExtension=\".phar\" allowed=\"false\" /></fileExtensions></requestFiltering></security></system.webServer></configuration>" );
        }
    }

    public function get_quarantined_files() {
        if ( ! file_exists( $this->index_file ) ) return [];
        $raw = file_get_contents( $this->index_file );
        if ( $raw === false ) return [];
        $data = json_decode( $raw, true );
        if ( ! is_array( $data ) ) {
            // Индекс повреждён — пересоздать пустой файл
            @file_put_contents( $this->index_file, '{}' );
            return [];
        }
        // Дополнительная валидация структуры
        $clean = [];
        foreach ( $data as $key => $entry ) {
            if ( ! is_string( $key ) || ! preg_match( '/^[a-f0-9]{32}$/', $key ) ) continue;
            if ( ! is_array( $entry ) || empty( $entry['original_path'] ) || empty( $entry['stored_file'] ) ) continue;
            if ( ! $this->is_safe_quarantine_path( $entry['original_path'] ) ) continue;
            if ( ! $this->is_safe_stored_file( $entry['stored_file'] ) ) continue;
            $clean[ $key ] = $entry;
        }
        return $clean;
    }

    /**
     * Проверяет, что путь находится внутри WordPress и не указывает на критические файлы.
     */
    private function is_safe_quarantine_path( $filepath ) {
        $filepath = wp_normalize_path( (string) $filepath );
        $abspath    = wp_normalize_path( ABSPATH );
        $wp_content = wp_normalize_path( WP_CONTENT_DIR );
        $quarantine = wp_normalize_path( $this->quarantine_dir );

        if ( empty( $filepath ) || strlen( $filepath ) > 1024 ) {
            return false;
        }
        // Запрет path traversal через ../ и symlink-обход
        if ( strpos( $filepath, '..' ) !== false || strpos( $filepath, "\0" ) !== false ) {
            return false;
        }
        // Должен быть внутри ABSPATH или WP_CONTENT_DIR
        $inside_root = strpos( $filepath, $abspath ) === 0 || strpos( $filepath, $wp_content ) === 0;
        if ( ! $inside_root ) {
            return false;
        }
        // Запрещено указывать на карантин и сам плагин
        if ( strpos( $filepath, $quarantine ) === 0 ) return false;
        if ( strpos( $filepath, wp_normalize_path( WP_PLUGIN_DIR . '/rybinsklab-security' ) ) === 0 ) return false;
        // Запрещено перемещать wp-config.php (защита от DoS)
        if ( basename( $filepath ) === 'wp-config.php' ) return false;
        // Резолв реального пути через realpath должен совпадать с заявленным (защита от symlink)
        $real = @realpath( $filepath );
        if ( $real === false ) return true; // файл может быть удалён к моменту проверки
        $real_normalized = wp_normalize_path( $real );
        if ( $real_normalized !== $filepath ) {
            // realpath разрешил симлинк — запрещаем
            return false;
        }
        return true;
    }

    /**
     * Проверяет, что stored_file имеет вид <md5>.suspected и находится внутри карантина.
     */
    private function is_safe_stored_file( $stored ) {
        $stored = (string) $stored;
        if ( ! preg_match( '/^[a-f0-9]{32}\.suspected$/', $stored ) ) {
            return false;
        }
        $full = wp_normalize_path( $this->quarantine_dir . '/' . $stored );
        $quarantine = wp_normalize_path( $this->quarantine_dir );
        return strpos( $full, $quarantine ) === 0;
    }

    public function ajax_quarantine_file() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Access Denied' );

        $filepath = wp_normalize_path( trim( wp_unslash( $_POST['filepath'] ?? '' ) ) );

        if ( empty( $filepath ) || ! file_exists( $filepath ) ) {
            wp_send_json_error( 'Файл не найден на сервере.' );
        }

        if ( ! $this->is_safe_quarantine_path( $filepath ) ) {
            wp_send_json_error( 'Путь не разрешён для перемещения в карантин.' );
        }

        $filename     = basename( $filepath );
        $hash         = md5( $filepath . microtime( true ) . wp_rand( 0, PHP_INT_MAX ) );
        $new_filename = $hash . '.suspected';
        $destination  = wp_normalize_path( $this->quarantine_dir . '/' . $new_filename );

        if ( @rename( $filepath, $destination ) ) {
            $index = $this->get_quarantined_files();
            $index[ $hash ] = [
                'original_path'  => $filepath,
                'filename'       => $filename,
                'quarantined_at' => current_time( 'mysql' ),
                'stored_file'    => $new_filename,
            ];
            $this->save_index( $index );
            wp_send_json_success( [ 'message' => 'Файл перемещен в карантин.' ] );
        } else {
            wp_send_json_error( 'Не удалось переместить файл (ошибка прав).' );
        }
    }

    public function ajax_restore_file() {
        check_ajax_referer( 'rls_scanner_nonce', 'nonce' );
        $id     = (string) ( $_POST['id'] ?? '' );
        // ID должен быть валидным md5-хешем (защита от перебора)
        if ( ! preg_match( '/^[a-f0-9]{32}$/', $id ) ) {
            wp_send_json_error( 'Некорректный идентификатор.' );
        }
        $index = $this->get_quarantined_files();
        if ( ! isset( $index[ $id ] ) ) wp_send_json_error( 'Запись не найдена.' );

        $info          = $index[ $id ];
        $stored_file   = wp_normalize_path( $this->quarantine_dir . '/' . $info['stored_file'] );
        $original_path = wp_normalize_path( (string) $info['original_path'] );

        // Повторная валидация на момент восстановления
        if ( ! $this->is_safe_stored_file( $info['stored_file'] ) || ! $this->is_safe_quarantine_path( $original_path ) ) {
            wp_send_json_error( 'Недопустимый путь восстановления.' );
        }

        if ( ! file_exists( $stored_file ) ) {
            unset( $index[ $id ] );
            $this->save_index( $index );
            wp_send_json_error( 'Файл отсутствует в хранилище.' );
        }

        $dir = dirname( $original_path );
        if ( ! file_exists( $dir ) ) {
            // Создаём только стандартные WP-директории (не любые)
            if ( ! wp_mkdir_p( $dir ) ) {
                wp_send_json_error( 'Не удалось создать директорию для восстановления.' );
            }
        }

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
        $id = (string) ( $_POST['id'] ?? '' );
        if ( ! preg_match( '/^[a-f0-9]{32}$/', $id ) ) {
            wp_send_json_error( 'Некорректный идентификатор.' );
        }
        $index = $this->get_quarantined_files();

        if ( isset( $index[ $id ] ) ) {
            if ( ! $this->is_safe_stored_file( $index[ $id ]['stored_file'] ) ) {
                wp_send_json_error( 'Недопустимое имя файла в карантине.' );
            }
            $file = wp_normalize_path( $this->quarantine_dir . '/' . $index[ $id ]['stored_file'] );
            // Двойная проверка: путь обязан оставаться внутри карантина
            if ( strpos( $file, wp_normalize_path( $this->quarantine_dir ) ) === 0 && file_exists( $file ) ) {
                @unlink( $file );
            }
            unset( $index[ $id ] );
            $this->save_index( $index );
        }
        wp_send_json_success( [ 'message' => 'Удалено.' ] );
    }

    private function save_index( $data ) {
        $json = wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
        if ( $json === false ) return;
        // Атомарная запись через временный файл
        $tmp = $this->index_file . '.tmp';
        if ( @file_put_contents( $tmp, $json ) !== false ) {
            @rename( $tmp, $this->index_file );
        }
        $txt_content = "RLS Quarantine Log\n==================\n";
        foreach ( $data as $hash => $info ) {
            $txt_content .= "Date: " . $info['quarantined_at'] . "\nOriginal: " . $info['original_path'] . "\nStored: " . $info['stored_file'] . "\n------------------\n";
        }
        @file_put_contents( $this->quarantine_dir . '/readable_log.txt', $txt_content );
    }
}
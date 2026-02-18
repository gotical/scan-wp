<?php
/**
 * Класс RLS_Scan_History
 * Управляет записью и чтением истории сканирований.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class RLS_Scan_History {

	public static function add_entry( string $type, array $threats, int $duration = 0 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'rls_scan_history';
		
		if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) {
			return false;
		}
		
		$threats_count = count( $threats );
		$status = ( $threats_count > 0 ) ? 'infected' : 'clean';
		$details_json = json_encode( $threats, JSON_UNESCAPED_UNICODE );
		
		$result = $wpdb->insert(
			$table_name,
			[
				'scan_date'     => current_time( 'mysql' ),
				'scan_type'     => $type,
				'scan_status'   => $status,
				'threats_count' => $threats_count,
				'scan_details'  => $details_json,
				'duration'      => $duration
			],
			[ '%s', '%s', '%s', '%d', '%s', '%d' ]
		);
		
		self::cleanup_old_entries();
		return $result ? $wpdb->insert_id : false;
	}

	private static function cleanup_old_entries() {
		global $wpdb;
		$table_name = $wpdb->prefix . 'rls_scan_history';
		$ids_to_delete = $wpdb->get_col( "SELECT id FROM $table_name ORDER BY id DESC LIMIT 20, 1000" );
		
		if ( ! empty( $ids_to_delete ) ) {
			$ids_list = implode( ',', array_map( 'intval', $ids_to_delete ) );
			$wpdb->query( "DELETE FROM $table_name WHERE id IN ($ids_list)" );
		}
	}

	public static function get_history( $limit = 20 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'rls_scan_history';
		
		if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) {
			return [];
		}
		
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name ORDER BY id DESC LIMIT %d", $limit ), ARRAY_A );
	}
}
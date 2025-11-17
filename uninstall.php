<?php
/**
 * Uninstall Login LockDown
 *
 * Removes all plugin data from the database when the plugin is deleted.
 *
 * @package LoginLockDown
 * @since 2.2.0
 * @license GPLv2
 *
 * Co-authors:
 * - Ojārs Kapteinis <ojars@kapteinis.lv>
 * - Claude <code@claude.ai>
 */

// If uninstall not called from WordPress, exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Handle multisite installations
if ( is_multisite() ) {
	$blog_ids = $wpdb->get_col( "SELECT blog_id FROM $wpdb->blogs" );

	foreach ( $blog_ids as $blog_id ) {
		switch_to_blog( $blog_id );
		loginlockdown_uninstall_single_site();
	}

	restore_current_blog();
} else {
	loginlockdown_uninstall_single_site();
}

/**
 * Uninstall for a single site
 *
 * Removes all database tables and options created by the plugin.
 */
function loginlockdown_uninstall_single_site() {
	global $wpdb;

	// Drop database tables
	$table_login_fails = $wpdb->prefix . 'login_fails';
	$table_lockdowns = $wpdb->prefix . 'lockdowns';

	// Use safe table name escaping
	$table_login_fails_safe = esc_sql( $table_login_fails );
	$table_lockdowns_safe = esc_sql( $table_lockdowns );

	$wpdb->query( "DROP TABLE IF EXISTS `$table_login_fails_safe`" );
	$wpdb->query( "DROP TABLE IF EXISTS `$table_lockdowns_safe`" );

	// Delete all plugin options
	delete_option( 'loginlockdown_admin_options' );
	delete_option( 'loginlockdown_db_version' );
	delete_option( 'loginlockdown_ms_run_once' );

	// Delete any legacy options (from older versions)
	delete_option( 'loginlockdownAdminOptions' );
	delete_option( 'loginlockdownmsrunonce' );
	delete_option( 'loginlockdown_db1_version' );
	delete_option( 'loginlockdown_db2_version' );

	// Clear any cached data
	wp_cache_flush();
}

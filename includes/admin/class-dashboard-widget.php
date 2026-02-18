<?php
/**
 * Виджет консоли WordPress.
 * Версия 1.5.2
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Dashboard_Widget {

    public function init() {
        add_action( 'wp_dashboard_setup', [ $this, 'register_widget' ] );
    }
    
    public function register_widget() {
        if ( current_user_can( 'manage_options' ) ) {
            wp_add_dashboard_widget(
                'rls_security_dashboard_widget',
                'Rybinsk Lab Security',
                [ $this, 'render_widget_content' ]
            );
        }
    }
    
    public function render_widget_content() {
        $stats = get_option( 'rls_stats', [] );
        
        $firewall = intval( $stats['firewall_blocked'] ?? 0 );
        $login    = intval( $stats['login_attempts_blocked'] ?? 0 );
        $viruses  = intval( $stats['viruses_found'] ?? 0 );
        $total    = $firewall + $login; 
        
        $license = get_option( 'rls_license_status', 'free' );
        $is_prem = ( $license === 'valid' );
        
        ?>
        <div class="rls-widget-container">
            <div class="rls-header" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <span class="rls-status" style="color: #46b450; font-weight:600;">
                    <span class="dashicons dashicons-shield-alt"></span> Защита активна
                </span>
                <span class="rls-badge" style="background:<?php echo $is_prem ? '#f0ad4e' : '#e5e5e5'; ?>; color:<?php echo $is_prem ? '#fff' : '#333'; ?>; padding:2px 6px; border-radius:4px; font-size:10px; text-transform:uppercase;">
                    <?php echo $is_prem ? 'PREMIUM' : 'FREE'; ?>
                </span>
            </div>

            <div class="rls-stats-grid" style="display:flex; gap:10px; margin:15px 0;">
                <div class="rls-stat-box" style="flex:1; text-align:center; padding:10px; background:#f8f9fa; border:1px solid #ddd; border-radius:4px;">
                    <div style="font-size:20px; font-weight:bold; color:#2271b1;"><?php echo number_format_i18n($total); ?></div>
                    <div style="font-size:11px; color:#666;">Атак отражено</div>
                </div>
                <div class="rls-stat-box" style="flex:1; text-align:center; padding:10px; background:<?php echo $viruses>0 ? '#fbeaea' : '#f8f9fa'; ?>; border:1px solid <?php echo $viruses>0 ? '#dc3545' : '#ddd'; ?>; border-radius:4px;">
                    <div style="font-size:20px; font-weight:bold; color:<?php echo $viruses>0 ? '#dc3545' : '#46b450'; ?>;"><?php echo number_format_i18n($viruses); ?></div>
                    <div style="font-size:11px; color:#666;">Вирусов</div>
                </div>
            </div>

            <div class="rls-footer" style="border-top:1px solid #eee; padding-top:10px; font-size:12px; display:flex; justify-content:space-between;">
                <a href="<?php echo admin_url('admin.php?page=rls-settings#tab-logs'); ?>">Журнал атак</a>
                <a href="<?php echo admin_url('admin.php?page=rls-settings'); ?>">Настройки</a>
            </div>
        </div>
        <?php
    }
}
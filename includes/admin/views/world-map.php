<?php
/**
 * Attack Map page — world map with attack origins.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Attack_Map' ) ) {
    echo '<div class="rls-notice is-danger">RLS Attack Map не загружен.</div>';
    return;
}

$days = isset( $_GET['rls_days'] ) ? max( 1, min( 90, (int) $_GET['rls_days'] ) ) : 7;
?>
<div class="rls-wrap">
    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    Карта атак
                    <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                </h1>
                <p class="rls-page-subtitle">География источников угроз. Маркеры показывают IP атакующих с группировкой по странам.</p>
            </div>
            <div class="rls-hero-actions">
                <select id="rls-map-days" style="background: rgba(255,255,255,0.12); color:#fff; border:1px solid rgba(255,255,255,0.18); padding:6px 12px; border-radius:6px;">
                    <option value="1"  <?php selected( $days, 1 ); ?>>24 часа</option>
                    <option value="7"  <?php selected( $days, 7 ); ?>>7 дней</option>
                    <option value="14" <?php selected( $days, 14 ); ?>>14 дней</option>
                    <option value="30" <?php selected( $days, 30 ); ?>>30 дней</option>
                    <option value="90" <?php selected( $days, 90 ); ?>>90 дней</option>
                </select>
            </div>
        </div>
    </div>

    <!-- STATS -->
    <div class="rls-widget-grid" id="rls-map-stats"></div>

    <!-- MAP -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-admin-site"></span> Мировая карта</h2>
        <div id="rls-attack-map" style="height: 600px; border-radius: var(--rls-radius); overflow: hidden;"></div>
        <div style="display:flex; gap:14px; margin-top:10px; font-size:12px; color:var(--rls-text-muted); flex-wrap:wrap;">
            <span><span style="display:inline-block; width:10px; height:10px; background:#dc2626; border-radius:50%; margin-right:4px;"></span> Атаки (WAF)</span>
            <span><span style="display:inline-block; width:10px; height:10px; background:#d97706; border-radius:50%; margin-right:4px;"></span> Brute force</span>
            <span><span style="display:inline-block; width:10px; height:10px; background:#0284c7; border-radius:50%; margin-right:4px;"></span> Логины</span>
            <span><span style="display:inline-block; width:10px; height:10px; background:#7c3aed; border-radius:50%; margin-right:4px;"></span> Спам</span>
            <span><span style="display:inline-block; width:10px; height:10px; background:#50575e; border-radius:50%; margin-right:4px;"></span> Другое</span>
        </div>
    </div>

    <!-- TOP COUNTRIES -->
    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:18px;">
        <div class="rls-box">
            <h2><span class="dashicons dashicons-admin-site"></span> Top-10 стран атак</h2>
            <table class="wp-list-table widefat striped" id="rls-map-top-countries">
                <thead><tr><th>Страна</th><th>Атак</th><th>Неудачных входов</th><th>IP</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>

        <div class="rls-box">
            <h2><span class="dashicons dashicons-networking"></span> Top-10 IP</h2>
            <table class="wp-list-table widefat striped" id="rls-map-top-ips">
                <thead><tr><th>IP</th><th>Страна</th><th>Атак</th><th>Неудачных входов</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
</div>

<!-- Leaflet CSS/JS -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

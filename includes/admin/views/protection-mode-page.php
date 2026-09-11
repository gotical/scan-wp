<?php
/**
 * Protection Mode page — redesigned for v2.5.1.
 * Profiles, site-type presets, per-module toggles, impact preview, emergency modes.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Mode_Manager' ) ) {
    echo '<div class="rls-notice is-danger">RLS Mode Manager не загружен.</div>';
    return;
}

$current       = RLS_Mode_Manager::get_current_profile();
$current_key   = $current['key'];
$overrides     = RLS_Mode_Manager::get_custom_overrides();
$recommended   = RLS_Mode_Manager::detect_recommended_preset();
$active_emerge = RLS_Mode_Manager::get_active_emergency();
$modules       = RLS_Mode_Manager::get_modules();
$presets       = RLS_Mode_Manager::get_site_presets();
$settings      = get_option( 'rls_settings', [] );
if ( ! is_array( $settings ) ) $settings = [];

$is_custom = ! empty( $overrides );
?>
<div class="rls-page-hero">
    <div class="rls-page-hero-top">
        <div>
            <div class="rls-page-kicker">Rybinsk Lab Security</div>
            <h1 class="rls-page-title">
                Режим защиты
                <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
            </h1>
            <p class="rls-page-subtitle">Выберите профиль защиты, пресет для вашего типа сайта или настройте модули вручную. Изменения применяются сразу после сохранения.</p>
        </div>
        <div class="rls-hero-actions">
            <span class="rls-status-pill <?php echo $is_custom ? 'is-warn' : 'is-on'; ?>" style="background: rgba(255,255,255,0.18); color: #fff;">
                <?php echo $is_custom ? 'Кастомные правки' : 'Стандартный профиль'; ?>
            </span>
        </div>
    </div>
</div>

<?php if ( $active_emerge ) : ?>
    <div class="rls-notice is-danger" style="border-left-width: 6px; padding: 16px 20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
            <div>
                <strong style="font-size: 15px;">🚨 Активен аварийный режим: <?php echo esc_html( strtoupper( $active_emerge['mode'] ) ); ?></strong>
                <p style="margin: 4px 0 0; font-size: 13px;">Истекает через <strong><?php echo gmdate( 'H:i:s', $active_emerge['left_sec'] ); ?></strong> (<?php echo esc_html( wp_date( 'Y-m-d H:i:s', $active_emerge['until'] ) ); ?>)</p>
            </div>
            <button type="button" class="button" id="rls-emergency-disable" data-emergency-mode="<?php echo esc_attr( $active_emerge['mode'] ); ?>" style="background:#fff; color: var(--rls-danger); border-color: var(--rls-danger); font-weight:600;">
                Деактивировать аварийный режим
            </button>
        </div>
    </div>
<?php endif; ?>

<!-- ==== ACTIVE PROFILE ==== -->
<div class="rls-box">
    <h2><span class="dashicons dashicons-shield"></span> Активный профиль</h2>

    <div class="rls-active-mode-card" style="display:flex; gap:16px; padding:16px; background:var(--rls-primary-soft); border:1px solid var(--rls-border); border-radius:var(--rls-radius); margin-bottom:14px;">
        <div style="width:48px; height:48px; background:<?php echo esc_attr( $current['color'] ); ?>; color:#fff; border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <span class="dashicons <?php echo esc_attr( $current['icon'] ); ?>" style="font-size:24px; width:24px; height:24px;"></span>
        </div>
        <div style="flex:1;">
            <strong style="font-size:16px;"><?php echo esc_html( $current['name'] ); ?></strong>
            <p style="margin:4px 0 0; color:var(--rls-text-muted); font-size:13px;"><?php echo esc_html( $current['description'] ); ?></p>
            <?php if ( $is_custom ) : ?>
                <p style="margin:8px 0 0; font-size:12px; color:var(--rls-warning);">
                    ⚠️ У вас <?php echo count( $overrides ); ?> кастомных правок к этому профилю.
                </p>
            <?php endif; ?>
        </div>
    </div>

    <?php if ( $is_custom ) : ?>
        <details style="margin-top:12px;">
            <summary style="cursor:pointer; font-weight:500; color:var(--rls-text-muted); font-size:13px;">Показать кастомные правки (<?php echo count( $overrides ); ?>)</summary>
            <ul style="margin-top:10px; padding-left:18px; line-height:1.7; font-size:13px;">
                <?php foreach ( $overrides as $ovr ) : ?>
                    <li>
                        <strong><?php echo esc_html( $ovr['module']['name'] ); ?></strong> —
                        <?php if ( $ovr['direction'] === 'enabled' ) : ?>
                            <span style="color:var(--rls-success);">включено вами</span> (профиль: выключено)
                        <?php else : ?>
                            <span style="color:var(--rls-danger);">выключено вами</span> (профиль: включено)
                        <?php endif; ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        </details>
    <?php endif; ?>
</div>

<!-- ==== PROFILES ==== -->
<div class="rls-box">
    <h2><span class="dashicons dashicons-admin-settings"></span> Профили защиты</h2>
    <p>Выберите уровень защиты. Каждый профиль включает определённый набор модулей; ниже можно точечно отключить или включить отдельные.</p>

    <div class="rls-mode-grid">
        <?php foreach ( RLS_Mode_Manager::get_profiles() as $key => $profile ) :
            $is_active = ( $current_key === $key && ! $is_custom );
            ?>
            <div class="rls-mode-card rls-profile-card" data-profile="<?php echo esc_attr( $key ); ?>" style="cursor:pointer;">
                <div style="display:flex; align-items:flex-start; gap:12px;">
                    <div style="width:36px; height:36px; background:<?php echo esc_attr( $profile['color'] ); ?>; color:#fff; border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
                        <span class="dashicons <?php echo esc_attr( $profile['icon'] ); ?>" style="font-size:18px; width:18px; height:18px;"></span>
                    </div>
                    <div style="flex:1;">
                        <strong class="rls-mode-card-title"><?php echo esc_html( $profile['name'] ); ?></strong>
                        <p style="margin:4px 0 0; font-size:12.5px; color:var(--rls-text-muted); line-height:1.5;"><?php echo esc_html( $profile['description'] ); ?></p>
                        <p style="margin:6px 0 0; font-size:11px; color:var(--rls-text-subtle);"><?php echo esc_html( $profile['long'] ); ?></p>
                    </div>
                    <?php if ( $is_active ) : ?>
                        <span class="rls-status-pill is-on" style="font-size:10px;">Активен</span>
                    <?php endif; ?>
                </div>
                <button type="button" class="button button-primary rls-mode-apply" data-profile="<?php echo esc_attr( $key ); ?>" style="margin-top:12px; width:100%;">
                    <?php echo $is_active ? 'Применить снова' : 'Применить'; ?>
                </button>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<!-- ==== SITE-TYPE PRESETS ==== -->
<div class="rls-box">
    <h2><span class="dashicons dashicons-admin-site"></span> Пресеты по типу сайта</h2>
    <p>Быстрая настройка под типичный сценарий. Мы рекомендуем <strong><?php echo esc_html( $presets[ $recommended ]['name'] ?? 'Блог' ); ?></strong> для вашего сайта (на основе установленных плагинов).</p>

    <div class="rls-preset-grid">
        <?php foreach ( $presets as $key => $preset ) :
            $is_recommended = ( $key === $recommended );
            ?>
            <div class="rls-preset-card" data-preset="<?php echo esc_attr( $key ); ?>">
                <?php if ( $is_recommended ) : ?>
                    <span class="rls-status-pill is-on rls-recommended-badge">Рекомендуем</span>
                <?php endif; ?>
                <div class="rls-preset-icon"><?php echo $preset['icon']; ?></div>
                <strong class="rls-preset-name"><?php echo esc_html( $preset['name'] ); ?></strong>
                <p class="rls-preset-desc"><?php echo esc_html( $preset['description'] ); ?></p>
                <div class="rls-preset-actions">
                    <button type="button" class="button button-secondary rls-mode-preview" data-preset="<?php echo esc_attr( $key ); ?>" data-profile="<?php echo esc_attr( $preset['profile'] ); ?>">
                        Предпросмотр
                    </button>
                    <button type="button" class="button button-primary rls-mode-apply-preset" data-preset="<?php echo esc_attr( $key ); ?>" data-profile="<?php echo esc_attr( $preset['profile'] ); ?>">
                        Применить
                    </button>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<!-- ==== PER-MODULE TOGGLES ==== -->
<div class="rls-box">
    <h2><span class="dashicons dashicons-admin-generic"></span> Модули защиты</h2>
    <p>Точечная настройка. Эти переключатели действуют как overrides поверх выбранного профиля.</p>

    <div class="rls-modules-grid">
        <?php foreach ( $modules as $key => $module ) :
            $profile_expected = (int) ( $current['config'][ $key ] ?? 0 );
            $actual = isset( $settings[ $key ] ) ? (int) (bool) $settings[ $key ] : $profile_expected;
            // Map to legacy key for the form.
            $form_key = $key;
            $legacy_map = [
                'enable_firewall'          => 'enable_firewall',
                'enable_login_security'    => 'enable_login_security',
                'enable_bot_blocking'      => 'enable_bot_blocking',
                'enable_geo_blocking'      => 'geo_blocking_enabled',
                'enable_language_filter'   => 'language_filter_enabled',
                'enable_captcha_users'     => 'captcha_enabled_users',
                'enable_captcha_admin'     => 'captcha_enabled_admin',
                'enable_2fa_required'      => '2fa_required_admin',
                'enable_session_hardening' => 'session_hardening_enabled',
                'enable_hardening'         => 'hardening_enabled',
                'enable_hotlink'           => 'hotlink_protection',
                'enable_antispam'          => 'antispam_enabled',
                'enable_password_policy'   => 'password_policy_enabled',
            ];
            $form_key = $legacy_map[ $key ] ?? $key;
            $form_value = isset( $settings[ $form_key ] ) ? (int) (bool) $settings[ $form_key ] : 0;
            // Special: for legacy keys not in current schema, fallback to module name
            if ( ! isset( $settings[ $form_key ] ) ) {
                $form_value = $profile_expected;
            }
            $is_overridden = ( $form_value !== $profile_expected );
            ?>
            <div class="rls-module-card <?php echo $form_value ? 'is-on' : 'is-off'; ?>" data-module="<?php echo esc_attr( $key ); ?>">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
                    <div style="flex:1;">
                        <strong class="rls-module-name">
                            <?php echo esc_html( $module['name'] ); ?>
                            <?php if ( $module['critical'] ?? false ) : ?>
                                <span class="rls-badge-log orange" style="font-size:9px; margin-left:6px;">Critical</span>
                            <?php endif; ?>
                        </strong>
                        <p class="rls-module-desc"><?php echo esc_html( $module['description'] ); ?></p>
                        <?php if ( $module['risk_low'] ?? false ) : ?>
                            <p class="rls-module-risk">⚠️ Может повлиять на UX (проверьте после включения)</p>
                        <?php endif; ?>
                    </div>
                    <label class="rls-toggle">
                        <input type="checkbox" name="rls_settings[<?php echo esc_attr( $form_key ); ?>]" value="1" <?php checked( 1, $form_value ); ?> data-module-key="<?php echo esc_attr( $key ); ?>" />
                        <span class="rls-toggle-slider"></span>
                    </label>
                </div>
                <?php if ( $is_overridden ) : ?>
                    <span class="rls-status-pill is-warn" style="font-size:9px; margin-top:6px; align-self:flex-start;">Override</span>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<!-- ==== EMERGENCY MODES ==== -->
<div class="rls-box" style="border-left: 4px solid var(--rls-danger);">
    <h2 style="color: var(--rls-danger);"><span class="dashicons dashicons-warning"></span> Аварийные режимы</h2>
    <p style="color: var(--rls-text-muted);">Эти режимы включайте только при активной атаке. Они блокируют нормальную работу сайта.</p>

    <div class="rls-emergency-grid">
        <?php foreach ( RLS_Mode_Manager::get_emergency_modes() as $key => $emergency ) : ?>
            <div class="rls-emergency-card" data-emergency="<?php echo esc_attr( $key ); ?>">
                <strong class="rls-emergency-name"><?php echo esc_html( $emergency['name'] ); ?></strong>
                <p class="rls-emergency-desc"><?php echo esc_html( $emergency['description'] ); ?></p>
                <p class="rls-emergency-duration">⏱ По умолчанию: <?php echo esc_html( gmdate( 'H:i:s', $emergency['duration'] ) ); ?></p>
                <button type="button" class="button rls-emergency-activate" data-emergency="<?php echo esc_attr( $key ); ?>" data-duration="<?php echo esc_attr( $emergency['duration'] ); ?>" style="background: var(--rls-danger); color: #fff; border-color: var(--rls-danger); font-weight:600;">
                    Активировать
                </button>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<!-- ==== IMPACT PREVIEW MODAL ==== -->
<div id="rls-impact-modal" class="rls-modal-backdrop" style="display:none;">
    <div class="rls-modal" style="max-width: 580px;">
        <div class="rls-modal-header">
            <div class="rls-modal-icon" style="background: var(--rls-info);">
                <span class="dashicons dashicons-info"></span>
            </div>
            <h3 class="rls-modal-title">Предпросмотр изменений</h3>
        </div>
        <div class="rls-modal-body" id="rls-impact-body">
            <!-- Filled by JS -->
        </div>
        <div class="rls-modal-footer">
            <button type="button" class="button" id="rls-impact-cancel">Отмена</button>
            <button type="button" class="button button-primary" id="rls-impact-confirm">Применить</button>
        </div>
    </div>
</div>

<!-- ==== EMERGENCY CONFIRM MODAL ==== -->
<div id="rls-emergency-modal" class="rls-modal-backdrop" style="display:none;">
    <div class="rls-modal is-danger">
        <div class="rls-modal-header">
            <div class="rls-modal-icon">!</div>
            <h3 class="rls-modal-title">Подтвердите активацию</h3>
        </div>
        <div class="rls-modal-body" id="rls-emergency-body">
            <p>Этот аварийный режим <strong>заблокирует все запросы</strong> к сайту для обычных посетителей. Только админ-логины с белого списка IP будут работать.</p>
            <p style="margin-top:10px;">Активировать?</p>
        </div>
        <div class="rls-modal-footer">
            <button type="button" class="button" id="rls-emergency-cancel">Отмена</button>
            <button type="button" class="button" id="rls-emergency-confirm" style="background: var(--rls-danger); color: #fff; border-color: var(--rls-danger);">Активировать</button>
        </div>
    </div>
</div>

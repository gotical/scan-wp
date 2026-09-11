<?php
/**
 * Protection mode manager.
 * Handles profiles, site-type presets, emergency modes, and impact previews.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Mode_Manager {

    /**
     * All known profiles (top-level protection levels).
     * Each profile returns the values it forces; admin can further customize within Custom.
     */
    public static function get_profiles() {
        return [
            'standard' => [
                'key'         => 'standard',
                'name'        => 'Standard',
                'short'       => 'STD',
                'icon'        => 'dashicons-shield-alt',
                'color'       => '#2271b1',
                'description' => 'Сбалансированная защита. Рекомендуется для большинства сайтов.',
                'long'        => 'Включает WAF, защиту входа, сканер, базовую блокировку ботов и комментариев. Без обязательной 2FA, без GeoIP.',
                'config'      => self::standard_config(),
            ],
            'maximum' => [
                'key'         => 'maximum',
                'name'        => 'Maximum',
                'short'       => 'MAX',
                'icon'        => 'dashicons-shield',
                'color'       => '#dc2626',
                'description' => 'Все защитные модули включены на максимум.',
                'long'        => 'Включает всё из Standard + 2FA обязательна для админов, session hardening, hardening .htaccess, hotlink protection, password policy, антиспам.',
                'config'      => self::maximum_config(),
            ],
            'light' => [
                'key'         => 'light',
                'name'        => 'Light (legacy)',
                'short'       => 'LGT',
                'icon'        => 'dashicons-shield',
                'color'       => '#d97706',
                'description' => 'Совместимость со старой версией. Базовая защита без GeoIP, ботов и языков.',
                'long'        => 'Эквивалент режима "Лёгкая защита" из v2.3. Сохранён для обратной совместимости.',
                'config'      => self::light_config(),
            ],
            'scanner_only' => [
                'key'         => 'scanner_only',
                'name'        => 'Scanner Only',
                'short'       => 'SCN',
                'icon'        => 'dashicons-search',
                'color'       => '#8b94a3',
                'description' => 'Защитные модули отключены. Только сканер вирусов.',
                'long'        => 'Плагин работает как пассивный сканер. Firewall, защита входа и уведомления отключены.',
                'config'      => self::scanner_only_config(),
            ],
        ];
    }

    /**
     * Site-type presets (one-click configurations).
     */
    public static function get_site_presets() {
        return [
            'blog' => [
                'key'         => 'blog',
                'name'        => 'Блог / Личный сайт',
                'icon'        => '📝',
                'description' => 'Стандартная защита + антиспам комментариев',
                'profile'     => 'standard',
                'overrides'   => [
                    'enable_antispam' => 1,
                ],
            ],
            'woocommerce' => [
                'key'         => 'woocommerce',
                'name'        => 'WooCommerce / Магазин',
                'icon'        => '🛒',
                'description' => 'Защита покупателей + обязательная 2FA для админов + session hardening',
                'profile'     => 'standard',
                'overrides'   => [
                    'captcha_enabled_users'   => 1,
                    'enable_2fa_required'     => 1,
                    'enable_session_hardening'=> 1,
                    'enable_password_policy'  => 1,
                    'enable_hardening'        => 1,
                ],
            ],
            'membership' => [
                'key'         => 'membership',
                'name'        => 'Подписки / Membership',
                'icon'        => '👥',
                'description' => 'Максимальная защита для сайтов с платным доступом',
                'profile'     => 'maximum',
                'overrides'   => [],
            ],
            'community' => [
                'key'         => 'community',
                'name'        => 'Сообщество / Мульти-автор',
                'icon'        => '💬',
                'description' => 'Стандарт + 2FA обязательна + антиспам комментариев',
                'profile'     => 'standard',
                'overrides'   => [
                    'enable_2fa_required' => 1,
                    'enable_antispam'     => 1,
                    'enable_antispam_min_seconds' => 5,
                ],
            ],
            'landing' => [
                'key'         => 'landing',
                'name'        => 'Лендинг / Маркетинг',
                'icon'        => '🎯',
                'description' => 'Стандарт + агрессивная блокировка ботов + защита от хотлинков',
                'profile'     => 'standard',
                'overrides'   => [
                    'enable_bot_blocking' => 1,
                    'enable_hotlink'      => 1,
                    'enable_geo_blocking' => 1,
                    'geo_blocking_enabled'=> 1,
                ],
            ],
            'developer' => [
                'key'         => 'developer',
                'name'        => 'Разработка / Staging',
                'icon'        => '🛠️',
                'description' => 'Только сканер без активной защиты',
                'profile'     => 'scanner_only',
                'overrides'   => [],
            ],
        ];
    }

    /**
     * Emergency modes.
     */
    public static function get_emergency_modes() {
        return [
            'panic' => [
                'key'         => 'panic',
                'name'        => '🔴 Panic Mode',
                'icon'        => 'dashicons-warning',
                'description' => 'Блокировать ВСЕ запросы кроме админ-логинов с белого списка IP. Включайте при активной атаке.',
                'duration'    => 3600, // 1 hour default
                'config'      => [
                    'enable_firewall'       => 1,
                    'emergency_panic_active'=> 1,
                    'emergency_panic_until' => 0, // computed at apply time
                    'emergency_panic_whitelist' => [],
                ],
            ],
            'lockdown' => [
                'key'         => 'lockdown',
                'name'        => '🟠 Lockdown',
                'icon'        => 'dashicons-lock',
                'description' => 'Только админ-логины разрешены. Все остальные запросы возвращают 503.',
                'duration'    => 7200, // 2 hours
                'config'      => [
                    'enable_firewall'        => 1,
                    'emergency_lockdown_active' => 1,
                    'emergency_lockdown_until'  => 0,
                ],
            ],
        ];
    }

    /**
     * Available per-module toggles (within Standard/Maximum profile).
     */
    public static function get_modules() {
        return [
            'enable_firewall' => [
                'key'         => 'enable_firewall',
                'name'        => 'WAF Firewall',
                'description' => 'Фильтрация вредоносных запросов (SQLi, XSS, RCE, LFI)',
                'group'       => 'edge',
                'critical'    => true,
                'risk_low'    => false,
            ],
            'enable_login_security' => [
                'key'         => 'enable_login_security',
                'name'        => 'Защита входа',
                'description' => 'Brute-force защита, honeypot, контрольные вопросы',
                'group'       => 'auth',
                'critical'    => true,
                'risk_low'    => false,
            ],
            'enable_bot_blocking' => [
                'key'         => 'enable_bot_blocking',
                'name'        => 'Блокировка ботов',
                'description' => 'Bad bots, агрессивные crawlers, fake user agents',
                'group'       => 'edge',
                'critical'    => false,
                'risk_low'    => false,
            ],
            'enable_geo_blocking' => [
                'key'         => 'enable_geo_blocking',
                'name'        => 'GeoIP фильтрация',
                'description' => 'Блок/разрешение по странам',
                'group'       => 'edge',
                'critical'    => false,
                'risk_low'    => false,
                'premium'     => false,
            ],
            'enable_language_filter' => [
                'key'         => 'enable_language_filter',
                'name'        => 'Языковой фильтр',
                'description' => 'Блок по Accept-Language (боты с нерелевантными языками)',
                'group'       => 'edge',
                'critical'    => false,
                'risk_low'    => true,  // может мешать реальным пользователям с VPN
            ],
            'enable_captcha_users' => [
                'key'         => 'enable_captcha_users',
                'name'        => 'Captcha для пользователей',
                'description' => 'Yandex SmartCaptcha на форме логина для посетителей',
                'group'       => 'auth',
                'critical'    => false,
                'risk_low'    => true,  // может ухудшить UX
            ],
            'enable_captcha_admin' => [
                'key'         => 'enable_captcha_admin',
                'name'        => 'Captcha для админки',
                'description' => 'Captcha на wp-login.php и wp-admin',
                'group'       => 'auth',
                'critical'    => false,
                'risk_low'    => false,
            ],
            'enable_2fa_required' => [
                'key'         => 'enable_2fa_required',
                'name'        => 'Обязательная 2FA для админов',
                'description' => 'Все администраторы должны включить TOTP',
                'group'       => 'auth',
                'critical'    => false,
                'risk_low'    => true,  // может заблокировать админа без TOTP
                'premium'     => true,
            ],
            'enable_session_hardening' => [
                'key'         => 'enable_session_hardening',
                'name'        => 'Session Hardening',
                'description' => 'Привязка сессии к IP/UA, лимит одновременных сессий',
                'group'       => 'auth',
                'critical'    => false,
                'risk_low'    => true,  // может разлогинить при смене IP (мобильный интернет)
            ],
            'enable_hardening' => [
                'key'         => 'enable_hardening',
                'name'        => 'Hardening (.htaccess + headers)',
                'description' => 'CSP, защита wp-config, скрытие версии WP',
                'group'       => 'hardening',
                'critical'    => false,
                'risk_low'    => true,  // CSP может сломать сторонние скрипты
            ],
            'enable_hotlink' => [
                'key'         => 'enable_hotlink',
                'name'        => 'Hotlink Protection',
                'description' => 'Запрет встраивания изображений на чужих сайтах',
                'group'       => 'edge',
                'critical'    => false,
                'risk_low'    => false,
            ],
            'enable_antispam' => [
                'key'         => 'enable_antispam',
                'name'        => 'Антиспам комментариев',
                'description' => 'Honeypot + time-token на форме комментариев',
                'group'       => 'comments',
                'critical'    => false,
                'risk_low'    => true,  // может блокировать старые браузеры без JS
            ],
            'enable_password_policy' => [
                'key'         => 'enable_password_policy',
                'name'        => 'Password Policy (HIBP)',
                'description' => 'Сложность пароля + проверка через HaveIBeenPwned',
                'group'       => 'auth',
                'critical'    => false,
                'risk_low'    => false,
            ],
        ];
    }

    /* === Profile configurations === */

    private static function standard_config() {
        return [
            'enable_firewall'             => 1,
            'enable_login_security'       => 1,
            'enable_bot_blocking'         => 1,
            'enable_antispam'             => 1,
            'enable_geo_blocking'         => 0,
            'enable_language_filter'      => 0,
            'enable_captcha_users'        => 0,
            'enable_captcha_admin'        => 0,
            'enable_2fa_required'         => 0,
            'enable_session_hardening'    => 0,
            'enable_hardening'            => 0,
            'enable_hotlink'              => 0,
            'enable_password_policy'      => 1,
            'auto_scan_frequency'         => 'weekly',
        ];
    }

    private static function maximum_config() {
        return [
            'enable_firewall'             => 1,
            'enable_login_security'       => 1,
            'enable_bot_blocking'         => 1,
            'enable_antispam'             => 1,
            'enable_geo_blocking'         => 1,
            'enable_language_filter'      => 1,
            'enable_captcha_users'        => 1,
            'enable_captcha_admin'        => 1,
            'enable_2fa_required'         => 1,
            'enable_session_hardening'    => 1,
            'enable_hardening'            => 1,
            'enable_hotlink'              => 1,
            'enable_password_policy'      => 1,
            'auto_scan_frequency'         => 'daily',
        ];
    }

    private static function light_config() {
        return [
            'enable_firewall'             => 1,
            'enable_login_security'       => 1,
            'enable_bot_blocking'         => 0,
            'enable_antispam'             => 0,
            'enable_geo_blocking'         => 0,
            'enable_language_filter'      => 0,
            'enable_captcha_users'        => 0,
            'enable_captcha_admin'        => 0,
            'enable_2fa_required'         => 0,
            'enable_session_hardening'    => 0,
            'enable_hardening'            => 0,
            'enable_hotlink'              => 0,
            'enable_password_policy'      => 0,
            'auto_scan_frequency'         => 'weekly',
        ];
    }

    private static function scanner_only_config() {
        return [
            'enable_firewall'             => 0,
            'enable_login_security'       => 0,
            'enable_bot_blocking'         => 0,
            'enable_antispam'             => 0,
            'enable_geo_blocking'         => 0,
            'enable_language_filter'      => 0,
            'enable_captcha_users'        => 0,
            'enable_captcha_admin'        => 0,
            'enable_2fa_required'         => 0,
            'enable_session_hardening'    => 0,
            'enable_hardening'            => 0,
            'enable_hotlink'              => 0,
            'enable_password_policy'      => 0,
            'auto_scan_frequency'         => 'daily',
        ];
    }

    /* === Resolution: which profile is active + is anything custom? === */

    public static function get_current_profile() {
        $settings = get_option( 'rls_settings', [] );
        if ( ! is_array( $settings ) ) $settings = [];

        // Map legacy values to new profiles.
        $legacy_map = [
            'full' => 'standard', // 'full' used to mean everything on; standard ≈ that
        ];
        $mode = $settings['protection_mode'] ?? 'standard';
        if ( isset( $legacy_map[ $mode ] ) ) {
            $mode = $legacy_map[ $mode ];
        }

        $profiles = self::get_profiles();
        return $profiles[ $mode ] ?? $profiles['standard'];
    }

    /**
     * Returns an array of modules that the admin has overridden away from the profile default.
     */
    public static function get_custom_overrides() {
        $settings = get_option( 'rls_settings', [] );
        if ( ! is_array( $settings ) ) $settings = [];

        $profile = self::get_current_profile();
        $expected = $profile['config'];
        $overrides = [];

        foreach ( self::get_modules() as $module_key => $module_def ) {
            $actual = isset( $settings[ $module_key ] ) ? (int) (bool) $settings[ $module_key ] : (int) ( $expected[ $module_key ] ?? 0 );
            $expected_val = (int) ( $expected[ $module_key ] ?? 0 );
            if ( $actual !== $expected_val ) {
                $overrides[ $module_key ] = [
                    'actual'    => $actual,
                    'expected'  => $expected_val,
                    'direction' => $actual > $expected_val ? 'enabled' : 'disabled',
                    'module'    => $module_def,
                ];
            }
        }
        return $overrides;
    }

    /**
     * Detects installed plugins and recommends a site-type preset.
     */
    public static function detect_recommended_preset() {
        $active = (array) get_option( 'active_plugins', [] );
        foreach ( $active as $plugin ) {
            // WooCommerce
            if ( strpos( $plugin, 'woocommerce/woocommerce.php' ) !== false ) {
                return 'woocommerce';
            }
            // Membership plugins
            if ( strpos( $plugin, 'memberpress' ) !== false ||
                 strpos( $plugin, 'paid-memberships-pro' ) !== false ||
                 strpos( $plugin, 'restrict-content-pro' ) !== false ) {
                return 'membership';
            }
            // Community / forum plugins
            if ( strpos( $plugin, 'bbpress' ) !== false ||
                 strpos( $plugin, 'buddypress' ) !== false ) {
                return 'community';
            }
        }
        return 'blog';
    }

    /**
     * Returns the impact preview for a given profile/preset combination:
     * - what will be enabled (green)
     * - what will be disabled (red)
     * - estimated performance / UX impact
     */
    public static function compute_impact_preview( $profile_key, $preset_key = null ) {
        $profiles = self::get_profiles();
        $profile = $profiles[ $profile_key ] ?? $profiles['standard'];
        $expected = $profile['config'];

        // Apply preset overrides.
        if ( $preset_key && isset( self::get_site_presets()[ $preset_key ] ) ) {
            $preset = self::get_site_presets()[ $preset_key ];
            if ( $preset['profile'] !== $profile_key && isset( $preset['overrides'] ) ) {
                $expected = array_merge( $expected, $preset['overrides'] );
            }
        }

        $current = get_option( 'rls_settings', [] );
        if ( ! is_array( $current ) ) $current = [];

        $will_enable = [];
        $will_disable = [];
        foreach ( self::get_modules() as $module_key => $module_def ) {
            $current_val = isset( $current[ $module_key ] ) ? (int) (bool) $current[ $module_key ] : 0;
            $expected_val = (int) ( $expected[ $module_key ] ?? 0 );
            if ( $expected_val !== $current_val ) {
                if ( $expected_val === 1 ) {
                    $will_enable[] = $module_def;
                } else {
                    $will_disable[] = $module_def;
                }
            }
        }

        // Performance estimate.
        $perf_score = self::estimate_performance( $expected );
        $security_score = self::estimate_security( $expected );

        return [
            'profile'        => $profile_key,
            'preset'         => $preset_key,
            'will_enable'    => $will_enable,
            'will_disable'   => $will_disable,
            'performance'    => $perf_score,
            'security_score' => $security_score,
            'risk_notes'     => self::collect_risks( $expected ),
        ];
    }

    private static function estimate_performance( $config ) {
        $load = 0;
        if ( ! empty( $config['enable_firewall'] ) ) $load += 5;
        if ( ! empty( $config['enable_bot_blocking'] ) ) $load += 8;
        if ( ! empty( $config['enable_geo_blocking'] ) ) $load += 3;
        if ( ! empty( $config['enable_language_filter'] ) ) $load += 2;
        if ( ! empty( $config['enable_captcha_users'] ) ) $load += 4;
        if ( ! empty( $config['enable_captcha_admin'] ) ) $load += 4;
        if ( ! empty( $config['enable_2fa_required'] ) ) $load += 5;
        if ( ! empty( $config['enable_session_hardening'] ) ) $load += 2;
        if ( ! empty( $config['enable_hardening'] ) ) $load += 1;
        if ( ! empty( $config['enable_hotlink'] ) ) $load += 1;
        if ( ! empty( $config['enable_antispam'] ) ) $load += 2;
        if ( ! empty( $config['enable_password_policy'] ) ) $load += 3;

        if ( $load < 10 ) return [ 'level' => 'minimal', 'label' => 'Минимальная нагрузка', 'ms' => '<1ms' ];
        if ( $load < 25 ) return [ 'level' => 'low',     'label' => 'Низкая нагрузка',     'ms' => '~1-2ms' ];
        if ( $load < 45 ) return [ 'level' => 'moderate','label' => 'Умеренная нагрузка',  'ms' => '~2-5ms' ];
        return [ 'level' => 'high', 'label' => 'Высокая нагрузка', 'ms' => '~5-10ms' ];
    }

    private static function estimate_security( $config ) {
        $score = 0;
        $modules = self::get_modules();
        foreach ( $modules as $key => $def ) {
            if ( ! empty( $config[ $key ] ) ) {
                $score += $def['critical'] ? 15 : 8;
            }
        }
        return min( 100, $score );
    }

    private static function collect_risks( $config ) {
        $risks = [];
        if ( ! empty( $config['enable_2fa_required'] ) ) {
            $risks[] = 'Обязательная 2FA может заблокировать админа без TOTP — заранее включите 2FA для всех.';
        }
        if ( ! empty( $config['enable_session_hardening'] ) ) {
            $risks[] = 'Привязка к IP может разлогинить пользователей с динамическим IP (мобильный интернет, VPN).';
        }
        if ( ! empty( $config['enable_hardening'] ) ) {
            $risks[] = 'CSP может заблокировать сторонние скрипты — протестируйте функциональность после включения.';
        }
        if ( ! empty( $config['enable_antispam'] ) ) {
            $risks[] = 'Honeypot может блокировать комментарии со старых браузеров без JS.';
        }
        if ( ! empty( $config['enable_language_filter'] ) ) {
            $risks[] = 'Языковой фильтр может отсеять реальных пользователей с неожиданным Accept-Language.';
        }
        return $risks;
    }

    /**
     * Applies a profile + preset: writes the config to wp_options.
     * Returns the impact preview for the response.
     */
    public static function apply_profile( $profile_key, $preset_key = null, $merge_with_existing = true ) {
        $profiles = self::get_profiles();
        if ( ! isset( $profiles[ $profile_key ] ) ) {
            return new WP_Error( 'rls_invalid_profile', 'Неизвестный профиль защиты.' );
        }
        $profile = $profiles[ $profile_key ];
        $config = $profile['config'];

        // Apply preset overrides.
        if ( $preset_key && isset( self::get_site_presets()[ $preset_key ] ) ) {
            $preset = self::get_site_presets()[ $preset_key ];
            $config = array_merge( $config, $preset['overrides'] );
        }

        $settings = get_option( 'rls_settings', [] );
        if ( ! is_array( $settings ) ) $settings = [];

        // Map profile flags to legacy settings keys for compatibility.
        $mapping = [
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
        foreach ( $mapping as $profile_key_name => $setting_key ) {
            $settings[ $setting_key ] = isset( $config[ $profile_key_name ] ) ? (int) (bool) $config[ $profile_key_name ] : 0;
        }

        $settings['protection_mode'] = $profile_key;
        $settings['applied_preset']  = $preset_key;

        if ( ! $merge_with_existing ) {
            // Start from scratch — wipe only module-related keys.
            foreach ( $mapping as $setting_key ) {
                $settings[ $setting_key ] = 0;
            }
            // Re-apply profile values.
            foreach ( $mapping as $profile_key_name => $setting_key ) {
                $settings[ $setting_key ] = isset( $config[ $profile_key_name ] ) ? (int) (bool) $config[ $profile_key_name ] : 0;
            }
            $settings['protection_mode'] = $profile_key;
        }

        update_option( 'rls_settings', $settings );

        return self::compute_impact_preview( $profile_key, $preset_key );
    }

    /**
     * Activate / deactivate emergency mode.
     */
    public static function set_emergency_mode( $mode_key, $duration_seconds = null ) {
        $emergencies = self::get_emergency_modes();
        if ( ! isset( $emergencies[ $mode_key ] ) ) {
            return new WP_Error( 'rls_invalid_emergency', 'Неизвестный аварийный режим.' );
        }
        $emergency = $emergencies[ $mode_key ];

        $settings = get_option( 'rls_settings', [] );
        if ( ! is_array( $settings ) ) $settings = [];

        $duration = $duration_seconds ?? $emergency['duration'];
        $until = time() + (int) $duration;

        $config = $emergency['config'];
        foreach ( $config as $k => $v ) {
            $settings[ $k ] = $v;
        }
        if ( strpos( $mode_key, 'panic' ) !== false ) {
            $settings['emergency_panic_until'] = $until;
        } elseif ( strpos( $mode_key, 'lockdown' ) !== false ) {
            $settings['emergency_lockdown_until'] = $until;
        }
        $settings['emergency_mode'] = $mode_key;
        update_option( 'rls_settings', $settings );
        return [ 'mode' => $mode_key, 'until' => $until, 'duration' => $duration ];
    }

    public static function deactivate_emergency_mode() {
        $settings = get_option( 'rls_settings', [] );
        if ( ! is_array( $settings ) ) $settings = [];
        unset(
            $settings['emergency_panic_active'],
            $settings['emergency_panic_until'],
            $settings['emergency_panic_whitelist'],
            $settings['emergency_lockdown_active'],
            $settings['emergency_lockdown_until'],
            $settings['emergency_mode']
        );
        update_option( 'rls_settings', $settings );
        return true;
    }

    public static function get_active_emergency() {
        $settings = get_option( 'rls_settings', [] );
        if ( ! is_array( $settings ) ) return null;
        $mode = $settings['emergency_mode'] ?? null;
        if ( ! $mode ) return null;
        $until_key = strpos( $mode, 'panic' ) !== false ? 'emergency_panic_until' : 'emergency_lockdown_until';
        $until = (int) ( $settings[ $until_key ] ?? 0 );
        if ( $until > 0 && $until < time() ) {
            self::deactivate_emergency_mode();
            return null;
        }
        return [
            'mode'     => $mode,
            'until'    => $until,
            'left_sec' => max( 0, $until - time() ),
        ];
    }
}

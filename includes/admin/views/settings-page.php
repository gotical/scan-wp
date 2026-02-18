<?php
/**
 * HTML-шаблон для страницы настроек.
 * Версия 1.6.0 (Added: Manual Database Update Buttons)
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

// --- ЛОГИКА РУЧНОЙ ПРОВЕРКИ ЛИЦЕНЗИИ И ОБНОВЛЕНИЯ БАЗ ---
if ( isset( $_POST['rls_action'] ) && $_POST['rls_action'] === 'manual_sync' ) {
    // Проверка безопасности (Nonce)
    if ( ! check_admin_referer( 'rls_force_sync_nonce', 'rls_sync_nonce_field' ) ) {
        wp_die( 'Ошибка безопасности. Ссылка устарела. Обновите страницу.' );
    }

    $set = get_option( 'rls_settings', [] );
    $key = $set['license_key'] ?? '';
    
    if ( ! empty( $key ) ) {
        // 1. Отправка статистики
        if ( class_exists( 'RLS_Cron' ) ) {
            RLS_Cron::sync_detailed_stats(); 
        }
        
        // 2. Валидация ключа
        $res = RLS_API_Client::validate_license_key( $key );
        
        if ( is_array( $res ) && isset( $res['status'] ) && $res['status'] === 'success' ) {
            update_option( 'rls_license_status', 'valid' );
            if ( isset( $res['data']['expires_at'] ) ) {
                update_option( 'rls_license_expires_at', $res['data']['expires_at'] );
            }
            
            // 3. Загрузка сигнатур (Premium)
            $sig_res = RLS_API_Client::get_signatures( $key );
            if ( isset( $sig_res['status'] ) && $sig_res['status'] === 'success' ) {
                update_option( 'rls_premium_signatures', $sig_res['data']['signatures'] );
            }

            // 4. Загрузка Глобального Черного Списка IP (НОВОЕ)
            $ip_res = RLS_API_Client::get_global_blacklist();
            if ( isset( $ip_res['status'] ) && $ip_res['status'] === 'success' ) {
                if ( ! empty( $ip_res['data']['ips'] ) ) {
                    update_option( 'rls_global_blacklist', $ip_res['data']['ips'], false );
                }
            }
            
            add_settings_error( 'rls_messages', 'rls_success', 'Успешно! Лицензия подтверждена, базы сигнатур и IP обновлены.', 'updated' );
        } else {
            update_option( 'rls_license_status', 'invalid' );
            update_option( 'rls_premium_signatures', [] );
            add_settings_error( 'rls_messages', 'rls_error', 'Ошибка: Ключ недействителен или срок действия истек.', 'error' );
        }
    } else {
        add_settings_error( 'rls_messages', 'rls_error', 'Пожалуйста, сначала введите и сохраните лицензионный ключ.', 'error' );
    }
}

// --- ПОДГОТОВКА ДАННЫХ ---
$settings = get_option( 'rls_settings', [] );
$license_key = $settings['license_key'] ?? '';
$license_status = get_option( 'rls_license_status' );

$whitelist = get_option( 'rls_ip_whitelist', [] );
$blacklist = get_option( 'rls_manual_blacklist', [] );
$global_blacklist = get_option( 'rls_global_blacklist', [] );

$base_sigs = get_option( 'rls_base_signatures', [] );
$premium_sigs = get_option( 'rls_premium_signatures', [] );
$custom_sigs = get_option( 'rls_custom_signatures', [] );
$total_sigs = count($base_sigs) + count($premium_sigs) + count($custom_sigs);

$all_login_questions = get_option( 'rls_login_questions', [] );
?>

<div class="wrap rls-wrap">
    <h1>
        Rybinsk Lab Security 
        <span style="font-size: 13px; color: #666; font-weight:normal; background:#e0e0e0; padding:2px 6px; border-radius:4px;">v<?php echo RLS_VERSION; ?></span>
    </h1>
    
    <?php settings_errors( 'rls_messages' ); ?>
    
    <!-- НАВИГАЦИЯ ПО ВКЛАДКАМ -->
    <div class="nav-tab-wrapper rls-nav-tabs" style="margin-bottom: 20px;">
        <a href="#tab-general" class="nav-tab nav-tab-active">Основные настройки</a>
        <a href="#tab-firewall" class="nav-tab">Фаервол (WAF)</a>
        <a href="#tab-lists" class="nav-tab">IP Списки</a>
        <a href="#tab-scanner" class="nav-tab">Сканер и Сигнатуры</a>
        <a href="#tab-logs" class="nav-tab" style="color: #d63638;"><span class="dashicons dashicons-list-view" style="margin-top:4px;"></span> Журнал атак</a>
    </div>

    <!-- ГЛАВНАЯ ФОРМА СОХРАНЕНИЯ (ОДНА НА ВСЕ ВКЛАДКИ) -->
    <form method="post" action="options.php">
        <?php settings_fields( 'rls_settings_group' ); ?>
        
        <!-- ТАБ 1: ОСНОВНЫЕ -->
        <div class="rls-tab-content active" id="tab-general">
            
            <div class="rls-box">
                <h2><span class="dashicons dashicons-admin-network"></span> Лицензия и Статус</h2>
                <p>Введите ключ активации для доступа к облачным базам угроз и автоматическим обновлениям.</p>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Ключ активации</th>
                        <td>
                            <input type="text" name="rls_settings[license_key]" value="<?php echo esc_attr( $license_key ); ?>" class="regular-text" placeholder="SCANWP-XXXX-XXXX" />
                            <br>
                            <div style="margin-top: 10px;">
                                 <strong>Текущий статус:</strong>
                                 <?php if($license_status === 'valid'): ?>
                                    <span style="color:green; font-weight:bold; background:#e6fffa; padding:2px 8px; border-radius:4px; border:1px solid #b2f5ea;">Активен (Premium)</span>
                                 <?php elseif($license_status === 'invalid'): ?>
                                    <span style="color:red; font-weight:bold;">Недействителен</span>
                                 <?php else: ?>
                                    <span style="color:#666;">Бесплатная версия</span>
                                 <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
            
            <div class="rls-box">
                <h2><span class="dashicons dashicons-lock"></span> Защита Входа (Anti-BruteForce)</h2>
                <p>Настройки для защиты страницы <code>wp-login.php</code> от подбора паролей.</p>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Активация</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[enable_login_security]" id="rls_enable_login_security_cb" value="1" <?php checked( 1, $settings['enable_login_security'] ?? 0 ); ?> /> 
                                <strong>Включить "Контрольные вопросы" и скрытую ловушку (Honeypot)</strong>
                            </label>
                            <p class="description">Добавляет поле с вопросом на форму входа. Боты не умеют на них отвечать.</p>
                        </td>
                    </tr>
                </table>
                
                <div class="login-questions-settings-row" style="background:#f9f9f9; padding:15px; border:1px solid #ddd; border-radius:5px; margin-top:10px;">
                    <h3>Настройка вопросов</h3>
                    <p>Количество вопросов при входе: 
                        <select name="rls_settings[login_questions_count]">
                            <option value="1" <?php selected( $settings['login_questions_count'] ?? 1, 1 ); ?>>1</option>
                            <option value="2" <?php selected( $settings['login_questions_count'] ?? 1, 2 ); ?>>2</option>
                            <option value="3" <?php selected( $settings['login_questions_count'] ?? 1, 3 ); ?>>3</option>
                        </select>
                    </p>
                    
                    <table class="wp-list-table widefat striped fixed" style="margin-bottom: 10px;">
                        <thead><tr><th>Вопрос</th><th style="width: 80px;">Действие</th></tr></thead>
                        <tbody id="rls-login-questions-tbody">
                            <?php if ( empty( $all_login_questions ) ): ?>
                                <tr class="no-items"><td colspan="2">Список вопросов пуст. Добавьте хотя бы один.</td></tr>
                            <?php else: foreach ( $all_login_questions as $key => $q_data ): ?>
                                <tr data-key="<?php echo esc_attr( $key ); ?>">
                                    <td><?php echo esc_html( $q_data['q'] ); ?></td>
                                    <td><button class="button-link-delete rls-delete-login-question-button" style="color:#b32d2e;">Удалить</button></td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                    
                    <div style="display:flex; gap:10px; align-items:center;">
                        <input type="text" id="rls-new-login-question" placeholder="Вопрос (Например: 2+2?)" class="regular-text" style="flex:1;">
                        <input type="text" id="rls-new-login-answer" placeholder="Ответ (4)" class="regular-text" style="flex:1;">
                        <button id="rls-add-login-question-button" class="button button-secondary">Добавить</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- ТАБ 2: ФАЕРВОЛ -->
        <div class="rls-tab-content" id="tab-firewall">
            <div class="rls-box">
                <h2><span class="dashicons dashicons-shield"></span> Настройки WAF (Web Application Firewall)</h2>
                <p>Фаервол анализирует весь входящий трафик и блокирует хакерские запросы до того, как они навредят сайту.</p>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Основная защита</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[enable_firewall]" value="1" <?php checked( 1, $settings['enable_firewall'] ?? 0 ); ?> /> 
                                <strong>Включить WAF</strong>
                            </label>
                            <p class="description">Защищает от SQL-инъекций, XSS, RCE атак и подозрительных ботов.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Протокол XML-RPC</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[disable_xmlrpc]" value="1" <?php checked( 1, $settings['disable_xmlrpc'] ?? 0 ); ?> /> 
                                <strong>Блокировать доступ к <code>xmlrpc.php</code></strong>
                            </label>
                            <p class="description">Рекомендуется включить. Через этот файл часто проводят DDoS атаки и перебор паролей. Отключите, если используете Jetpack.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Cloudflare / Proxy</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[trust_cloudflare]" value="1" <?php checked( 1, $settings['trust_cloudflare'] ?? 0 ); ?> /> 
                                <strong>Я использую Cloudflare (или другой прокси)</strong>
                            </label>
                            <p class="description">Включите это, если реальный IP посетителя не определяется. Плагин будет смотреть заголовок <code>CF-Connecting-IP</code>.</p>
                        </td>
                    </tr>
                </table>
                
                <hr>
                <h3>Разрешенные поисковые боты</h3>
                <p class="description">Отметьте ботов, которых нужно пропускать (при условии, что они настоящие). Фейковые боты, маскирующиеся под них, будут заблокированы.</p>
                <div style="margin-top:10px;">
                    <label style="margin-right:20px;"><input type="checkbox" name="rls_settings[allow_googlebot]" value="1" <?php checked( 1, $settings['allow_googlebot'] ?? 1 ); ?>> Google Bot</label>
                    <label style="margin-right:20px;"><input type="checkbox" name="rls_settings[allow_yandexbot]" value="1" <?php checked( 1, $settings['allow_yandexbot'] ?? 1 ); ?>> Yandex Bot</label>
                    <label><input type="checkbox" name="rls_settings[allow_bingbot]" value="1" <?php checked( 1, $settings['allow_bingbot'] ?? 0 ); ?>> Bing Bot</label>
                </div>
            </div>
        </div>

        <!-- ТАБ 3: СПИСКИ IP -->
        <div class="rls-tab-content" id="tab-lists">
            <div class="rls-row" style="display:flex; gap:20px; flex-wrap: wrap;">
                
                <!-- Белый список -->
                <div class="rls-col rls-box" style="flex:1; min-width: 300px;">
                    <h2 style="color:green; border-bottom: 2px solid green; padding-bottom: 10px;">Белый список IP (Whitelist)</h2>
                    <p class="description">IP из этого списка <strong>полностью игнорируют</strong> все проверки (WAF, Лимиты входа).</p>
                    
                    <div class="rls-ip-input-group" style="display:flex; gap:5px; margin-bottom: 10px;">
                        <input type="text" id="rls-new-white-ip" placeholder="192.168.1.1" style="width:100%;">
                        <button class="button button-secondary rls-add-ip-btn" data-list="white">Добавить</button>
                    </div>
                    
                    <ul class="rls-ip-list" id="rls-white-list">
                        <?php foreach($whitelist as $ip): ?>
                            <li><span><?php echo esc_html($ip); ?></span> <a href="#" class="rls-del-ip" data-ip="<?php echo esc_attr($ip); ?>" data-list="white">&times;</a></li>
                        <?php endforeach; ?>
                    </ul>
                </div>

                <!-- Черный список -->
                <div class="rls-col rls-box" style="flex:1; min-width: 300px;">
                    <h2 style="color:red; border-bottom: 2px solid red; padding-bottom: 10px;">Черный список IP (Blacklist)</h2>
                    <p class="description">IP из этого списка получают вечный бан (403 Forbidden).</p>
                    
                    <div class="rls-ip-input-group" style="display:flex; gap:5px; margin-bottom: 10px;">
                        <input type="text" id="rls-new-black-ip" placeholder="10.0.0.1" style="width:100%;">
                        <button class="button button-secondary rls-add-ip-btn" data-list="black">Забанить</button>
                    </div>
                    
                    <ul class="rls-ip-list" id="rls-black-list">
                        <?php foreach($blacklist as $ip): ?>
                            <li><span><?php echo esc_html($ip); ?></span> <a href="#" class="rls-del-ip" data-ip="<?php echo esc_attr($ip); ?>" data-list="black">&times;</a></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
            
            <div class="rls-box" style="margin-top: 20px; background: #f0f0f1; border-color: #999;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h3><span class="dashicons dashicons-cloud"></span> Глобальный Черный список (Rybinsk Lab)</h3>
                        <p>Загружено IP адресов из облачной базы угроз: <strong style="font-size: 1.2em;"><?php echo count($global_blacklist); ?></strong></p>
                        <p class="description">Этот список обновляется автоматически при наличии лицензии.</p>
                    </div>
                    <div>
                        <!-- КНОПКА ОБНОВЛЕНИЯ IP -->
                        <button type="button" class="button button-secondary" onclick="document.getElementById('rls-manual-sync-form').submit();">
                            <span class="dashicons dashicons-update"></span> Обновить список IP
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- ТАБ 4: СКАНЕР И СИГНАТУРЫ -->
        <div class="rls-tab-content" id="tab-scanner">
             <div class="rls-box">
                <h2>Автоматическое сканирование</h2>
                <p>Как часто плагин должен проверять файлы на наличие вирусов?</p>
                <select name="rls_auto_scan_frequency">
                    <option value="disabled" <?php selected( get_option( 'rls_auto_scan_frequency' ), 'disabled' ); ?>>Отключено (Только вручную)</option>
                    <option value="daily" <?php selected( get_option( 'rls_auto_scan_frequency' ), 'daily' ); ?>>Ежедневно (В фоновом режиме)</option>
                    <option value="weekly" <?php selected( get_option( 'rls_auto_scan_frequency' ), 'weekly' ); ?>>Еженедельно (В фоновом режиме)</option>
                </select>
             </div>
             
             <div class="rls-box">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                    <div>
                        <h2>База Сигнатур Вирусов</h2>
                        <p>Всего активных сигнатур: <strong><?php echo $total_sigs; ?></strong></p>
                        <ul style="list-style:disc; margin-left:20px; color:#666; font-size:13px;">
                            <li>Базовые (Встроенные): <?php echo count($base_sigs); ?></li>
                            <li>Premium (Cloud): <?php echo count($premium_sigs); ?> (доступно с ключом)</li>
                            <li>Пользовательские: <?php echo count($custom_sigs); ?></li>
                        </ul>
                    </div>
                    <div>
                        <!-- КНОПКА ОБНОВЛЕНИЯ СИГНАТУР -->
                        <button type="button" class="button button-primary" onclick="document.getElementById('rls-manual-sync-form').submit();">
                            <span class="dashicons dashicons-update" style="line-height:1.3"></span> Обновить базу сигнатур
                        </button>
                    </div>
                </div>
                
                <hr>
                <h3>Добавить свою сигнатуру</h3>
                <p class="description">Если вы знаете фрагмент кода вируса, добавьте его сюда. Плагин будет искать его в файлах.</p>
                <div style="display:flex; gap:10px; margin-bottom:10px;">
                    <input type="text" id="rls-new-signature-input" class="large-text" placeholder="Пример: eval(base64_decode" style="width:100%;">
                    <button id="rls-add-signature-button" class="button button-secondary">Добавить</button>
                </div>
                
                <table class="wp-list-table widefat striped fixed">
                    <thead><tr><th>Сигнатура</th><th style="width: 80px;">Действие</th></tr></thead>
                    <tbody id="rls-signatures-table-body">
                        <?php if ( empty( $custom_sigs ) ): ?>
                            <tr class="no-items"><td colspan="2">Нет пользовательских сигнатур.</td></tr>
                        <?php else: foreach ( $custom_sigs as $sig ): ?>
                            <tr data-signature="<?php echo esc_attr( $sig ); ?>">
                                <td><code><?php echo esc_html( $sig ); ?></code></td>
                                <td><button class="button-link-delete rls-delete-signature-button" style="color:#b32d2e;">Удалить</button></td>
                            </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
             </div>
        </div>

        <!-- ТАБ 5: ЖУРНАЛ АТАК -->
        <div class="rls-tab-content" id="tab-logs">
            <div class="rls-box">
                <h2>Последние отраженные атаки (Журнал)</h2>
                <p class="description">Здесь отображаются последние 50 записей о заблокированных угрозах. Эта информация также отправляется в центр мониторинга для улучшения защиты.</p>
                
                <?php 
                $logs = class_exists('RLS_Logger') ? RLS_Logger::get_logs(50) : [];
                ?>
                
                <table class="wp-list-table widefat striped fixed">
                    <thead>
                        <tr>
                            <th style="width: 140px;">Время</th>
                            <th style="width: 130px;">IP Адрес</th>
                            <th style="width: 100px;">Тип</th>
                            <th>Причина / Запрос</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ( empty( $logs ) ): ?>
                            <tr><td colspan="4">Журнал пуст. Атак пока не зафиксировано.</td></tr>
                        <?php else: foreach ( $logs as $log ): ?>
                            <tr>
                                <td><?php echo date_i18n( 'd.m H:i:s', strtotime( $log['event_date'] ) ); ?></td>
                                <td>
                                    <strong><?php echo esc_html( $log['ip'] ); ?></strong>
                                    <br>
                                    <a href="https://2ip.ru/info/<?php echo esc_attr($log['ip']); ?>/" target="_blank" class="button button-small" style="margin-top:5px; font-size:11px; display:inline-flex; align-items:center; gap:3px;">
                                        Whois (2ip) <span class="dashicons dashicons-external" style="font-size:12px; width:12px; height:12px;"></span>
                                    </a>
                                </td>
                                <td>
                                    <?php 
                                        $cls = 'gray';
                                        if($log['type']=='waf') $cls = 'red';
                                        if($log['type']=='brute') $cls = 'orange';
                                        if($log['type']=='bot') $cls = 'gray';
                                        echo '<span class="rls-badge-log '.$cls.'">'.strtoupper($log['type']).'</span>';
                                    ?>
                                </td>
                                <td>
                                    <span style="color:#d63638; font-weight:600;"><?php echo esc_html( $log['reason'] ); ?></span><br>
                                    <code style="font-size:0.85em; color:#666;"><?php echo esc_html( substr($log['request_uri'], 0, 50) ); ?></code>
                                </td>
                            </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- КНОПКА СОХРАНЕНИЯ (ЕДИНАЯ ДЛЯ ВСЕХ ТАБОВ) -->
        <div style="position: sticky; bottom: 0; background: rgba(255,255,255,0.9); padding: 10px 20px; border-top: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; margin-top: 20px; box-shadow: 0 -2px 10px rgba(0,0,0,0.05); z-index: 100;">
            <span class="description">Все изменения вступают в силу сразу после сохранения.</span>
            <?php submit_button( 'Сохранить настройки', 'primary', 'submit', false ); ?>
        </div>

    </form>
    
    <!-- ОТДЕЛЬНАЯ ФОРМА ДЛЯ ПРОВЕРКИ ЛИЦЕНЗИИ И ОБНОВЛЕНИЯ БАЗ -->
    <!-- Все кнопки обновления ссылаются на эту скрытую форму -->
    <div style="display:none;">
        <form id="rls-manual-sync-form" method="post" action="">
            <input type="hidden" name="rls_action" value="manual_sync">
            <?php wp_nonce_field( 'rls_force_sync_nonce', 'rls_sync_nonce_field' ); ?>
        </form>
    </div>
    
    <!-- Кнопка сверху (переименована для ясности) -->
    <div style="position: absolute; top: 10px; right: 20px;">
        <button type="button" class="button button-secondary" onclick="document.getElementById('rls-manual-sync-form').submit();">
            <span class="dashicons dashicons-cloud-upload" style="line-height:1.3"></span> Проверить лицензию и обновить базы
        </button>
    </div>

</div>

<style>
/* CSS для интерфейса */
.rls-tab-content { display: none; }
.rls-tab-content.active { display: block; }

.rls-ip-list { margin-top:10px; border:1px solid #ddd; max-height:200px; overflow-y:auto; background:#fff; list-style: none; padding: 0; }
.rls-ip-list li { padding: 8px 10px; border-bottom:1px solid #eee; display:flex; justify-content:space-between; align-items: center; margin:0; }
.rls-ip-list li:nth-child(odd) { background: #f9f9f9; }
.rls-del-ip { color: #dc3545; text-decoration: none; font-weight: bold; font-size: 20px; line-height: 1; }
.rls-del-ip:hover { color: #a71d2a; }

.rls-badge-log { padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; color: #fff; text-transform: uppercase; }
.rls-badge-log.red { background: #d63638; }
.rls-badge-log.orange { background: #f0ad4e; }
.rls-badge-log.gray { background: #646970; }
</style>
<?php
/**
 * Страница сканера безопасности.
 * Версия 3.0.1 — Полностью на русском, читаемый UI, прогресс-бар + консоль.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$snapshot_time     = get_option( 'rls_snapshot_time', 0 );
$scan_history      = class_exists( 'RLS_Scan_History' ) ? RLS_Scan_History::get_history( 20 ) : [];
$license_ui        = function_exists( 'rls_get_license_ui_state' ) ? rls_get_license_ui_state() : [];
$mode_ui           = function_exists( 'rls_get_protection_mode_ui_state' ) ? rls_get_protection_mode_ui_state() : [];

// Загружаем данные карантина.
$quarantined_files = [];
if ( class_exists( 'RLS_Quarantine' ) ) {
    $q_obj = new RLS_Quarantine();
    $quarantined_files = $q_obj->get_quarantined_files();
}
?>
<div class="wrap rls-wrap">

    <!-- ЗАГОЛОВОК СТРАНИЦЫ -->
    <h1 class="rls-page-heading">
        <span class="dashicons dashicons-shield-alt"></span>
        Сканер безопасности
        <span class="rls-page-version">v<?php echo esc_html( RLS_VERSION ); ?></span>
        <span class="rls-mode-badge <?php echo esc_attr( $mode_ui['mode'] ?? 'full' ); ?>">
            <?php echo esc_html( $mode_ui['label'] ?? 'Полная защита' ); ?>
        </span>
    </h1>

    <!-- ВКЛАДКИ -->
    <div class="nav-tab-wrapper" style="margin-bottom:14px;">
        <a href="#malware-scanner" class="nav-tab nav-tab-active" data-tab="malware-scanner">
            <span class="dashicons dashicons-search"></span> Поиск вирусов
        </a>
        <a href="#snapshot-scanner" class="nav-tab" data-tab="snapshot-scanner">
            <span class="dashicons dashicons-camera"></span> Снимок файлов
        </a>
        <a href="#quarantine" class="nav-tab" data-tab="quarantine">
            <span class="dashicons dashicons-shield"></span> Карантин
        </a>
        <a href="#scan-history" class="nav-tab" data-tab="scan-history">
            <span class="dashicons dashicons-list-view"></span> История
        </a>
    </div>

    <!-- ВКЛАДКА 1: СКАНЕР НА ВИРУСЫ -->
    <div id="malware-scanner" class="rls-tab-panel active">
        <div class="rls-box">
            <h3><span class="dashicons dashicons-search"></span> Поиск вредоносного кода</h3>
            <p>Быстрое сканирование проверяет PHP-файлы на типичные сигнатуры угроз. Полное сканирование проходит по всем файлам, включая изображения и неизвестные расширения.</p>
            <div class="rls-scan-controls">
                <button id="rls-start-scan-button" class="button button-primary button-hero">
                    <span class="dashicons dashicons-shield"></span> Начать сканирование
                </button>
                <button id="rls-start-full-scan-button" class="button button-secondary" type="button" title="Проверить все расширения, включая изображения и неизвестные типы файлов">
                    Полное сканирование
                </button>
            </div>

            <!-- ПРОГРЕСС — появляется прямо под кнопкой после старта -->
            <div id="rls-scan-progress-area" class="rls-progress-card" style="display:none;">
                <div class="rls-progress-header">
                    <div class="rls-progress-title">
                        <span class="dashicons dashicons-update rls-spin-icon"></span>
                        <strong id="rls-scan-status-title">Выполняется сканирование…</strong>
                    </div>
                    <div class="rls-progress-meta">
                        <div class="rls-progress-meta-item">
                            <span class="rls-progress-meta-label">ETA</span>
                            <strong id="rls-scan-eta">--:--</strong>
                        </div>
                        <div class="rls-progress-meta-item">
                            <span class="rls-progress-meta-label">Прогресс</span>
                            <strong id="rls-scan-progress-pct">0%</strong>
                        </div>
                    </div>
                </div>

                <div class="rls-progress-bar">
                    <div class="rls-progress-fill" id="rls-scan-progress-fill"></div>
                </div>

                <div class="rls-progress-stats">
                    <div class="rls-progress-stat">
                        <div class="rls-progress-stat-num" id="rls-scan-stat-total">0</div>
                        <div class="rls-progress-stat-label">Всего файлов</div>
                    </div>
                    <div class="rls-progress-stat">
                        <div class="rls-progress-stat-num" id="rls-scan-stat-scanned">0</div>
                        <div class="rls-progress-stat-label">Проверено</div>
                    </div>
                    <div class="rls-progress-stat">
                        <div class="rls-progress-stat-num" id="rls-scan-stat-skipped">0</div>
                        <div class="rls-progress-stat-label">Пропущено</div>
                    </div>
                    <div class="rls-progress-stat rls-progress-stat--danger">
                        <div class="rls-progress-stat-num" id="rls-scan-stat-threats">0</div>
                        <div class="rls-progress-stat-label">Угроз</div>
                    </div>
                </div>

                <div class="rls-progress-current" id="rls-scan-current-file">
                    <span class="dashicons dashicons-media-default"></span>
                    <span>Ожидание запуска…</span>
                </div>

                <div class="rls-progress-console-wrap">
                    <div class="rls-progress-console-header">
                        <span class="dashicons dashicons-list-view"></span>
                        <strong>Журнал выполнения</strong>
                        <button type="button" class="button rls-console-clear">Очистить</button>
                    </div>
                    <div class="rls-progress-console" id="rls-scan-console"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- ВКЛАДКА 2: СНИМОК ФАЙЛОВОЙ СИСТЕМЫ -->
    <div id="snapshot-scanner" class="rls-tab-panel">
        <div class="rls-box">
            <h3><span class="dashicons dashicons-camera"></span> Снимок файловой системы</h3>
            <p>Создайте эталонный снимок (Snapshot) ваших файлов. Это позволяет отслеживать любые изменения: новые файлы, измененные или удаленные. Идеально для обнаружения скрытых вирусов.</p>

            <div class="rls-snapshot-status <?php echo $snapshot_time ? 'exists' : 'empty'; ?>">
                <?php if ( $snapshot_time ) : ?>
                    <span class="dashicons dashicons-yes"></span>
                    Последний снимок создан: <strong><?php echo date_i18n( 'd.m.Y H:i', $snapshot_time ); ?></strong>
                <?php else : ?>
                    <span class="dashicons dashicons-warning"></span>
                    Снимок еще не создан. Рекомендуется создать его прямо сейчас.
                <?php endif; ?>
            </div>

            <div class="rls-scan-controls">
                <?php if ( $snapshot_time ) : ?>
                    <button id="rls-compare-snapshot-button" class="button button-primary">
                        Сравнить с текущим состоянием
                    </button>
                <?php endif; ?>
                <button id="rls-create-snapshot-button" class="button <?php echo $snapshot_time ? '' : 'button-primary'; ?>">
                    <?php echo $snapshot_time ? 'Обновить снимок' : 'Создать снимок'; ?>
                </button>
            </div>
        </div>
    </div>

    <!-- ВКЛАДКА 3: КАРАНТИН -->
    <div id="quarantine" class="rls-tab-panel">
        <div class="rls-box">
            <h3><span class="dashicons dashicons-shield"></span> Карантин (Изолированные файлы)</h3>
            <p>Файлы, признанные опасными, перемещаются в защищённую папку <code>wp-content/uploads/rls-quarantine/</code> с предварительным <code>.bak</code>. Они не могут навредить сайту.</p>

            <?php if ( empty( $quarantined_files ) ) : ?>
                <div class="rls-empty-state">
                    <img src="<?php echo esc_url( plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/images/shield-empty.svg' ); ?>" alt="Пусто" width="180" />
                    <h3>Карантин пуст</h3>
                    <p>Все чисто — ни один файл не был помещён в карантин.</p>
                </div>
            <?php else : ?>
                <table class="wp-list-table widefat striped rls-quarantine-table">
                    <thead>
                        <tr>
                            <th style="width:50%;">Оригинальный путь</th>
                            <th style="width:15%;">Имя файла</th>
                            <th style="width:20%;">Дата изоляции</th>
                            <th style="width:15%;">Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $quarantined_files as $id => $file ) : ?>
                            <tr id="q-row-<?php echo esc_attr( $id ); ?>">
                                <td><code class="rls-path"><?php echo esc_html( $file['original_path'] ); ?></code></td>
                                <td><code class="rls-name"><?php echo esc_html( $file['filename'] ); ?></code></td>
                                <td><?php echo esc_html( $file['quarantined_at'] ); ?></td>
                                <td>
                                    <button class="button button-primary rls-restore-btn" data-id="<?php echo esc_attr( $id ); ?>">Восстановить</button>
                                    <button class="button rls-delete-q-btn" data-id="<?php echo esc_attr( $id ); ?>" style="color:#dc2626; border-color:#dc2626; margin-left:4px;">Удалить</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- ВКЛАДКА 4: ИСТОРИЯ + DIFF -->
    <div id="scan-history" class="rls-tab-panel">
        <div class="rls-box">
            <h3><span class="dashicons dashicons-list-view"></span> История сканирований</h3>
            <p>Журнал последних 20 проверок системы (ручные и автоматические). Доступно сравнение любых двух сканов.</p>

            <div class="rls-diff-controls">
                <label>
                    <span>Скан A:</span>
                    <select id="rls-diff-scan-a">
                        <option value="">— выберите —</option>
                        <?php foreach ( $scan_history as $entry ) : ?>
                            <option value="<?php echo (int) $entry['id']; ?>">
                                #<?php echo (int) $entry['id']; ?> — <?php echo esc_html( date_i18n( 'd.m.Y H:i', strtotime( $entry['scan_date'] ) ) ); ?>
                                (<?php echo intval( $entry['threats_count'] ); ?> угроз)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label>
                    <span>Скан B:</span>
                    <select id="rls-diff-scan-b">
                        <option value="">— выберите —</option>
                        <?php foreach ( $scan_history as $entry ) : ?>
                            <option value="<?php echo (int) $entry['id']; ?>">
                                #<?php echo (int) $entry['id']; ?> — <?php echo esc_html( date_i18n( 'd.m.Y H:i', strtotime( $entry['scan_date'] ) ) ); ?>
                                (<?php echo intval( $entry['threats_count'] ); ?> угроз)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <button type="button" class="button button-primary" id="rls-run-diff">Сравнить сканы</button>
            </div>
            <div id="rls-diff-result" style="display:none;"></div>

            <hr style="margin:18px 0;">

            <?php if ( empty( $scan_history ) ) : ?>
                <div class="rls-empty-state">
                    <img src="<?php echo esc_url( plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/images/scan-empty.svg' ); ?>" alt="Нет истории" width="180" />
                    <h3>История пуста</h3>
                    <p>Запустите первое сканирование, чтобы увидеть результаты здесь.</p>
                </div>
            <?php else : ?>
                <table class="wp-list-table widefat striped">
                    <thead>
                        <tr>
                            <th>Дата</th>
                            <th>Тип</th>
                            <th>Статус</th>
                            <th>Результат</th>
                            <th>Длительность</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $scan_history as $entry ) :
                            $is_infected = ( $entry['scan_status'] === 'infected' );
                            $type_label = ( $entry['scan_type'] === 'auto' ) ? 'Авто' : 'Ручной';
                            $status_class = $is_infected ? 'rls-status-pill is-err' : 'rls-status-pill is-on';
                            $status_text = $is_infected ? '⚠ Угроза' : '✓ Чисто';
                            ?>
                            <tr>
                                <td><?php echo esc_html( date_i18n( 'd.m.Y H:i', strtotime( $entry['scan_date'] ) ) ); ?></td>
                                <td><?php echo esc_html( $type_label ); ?></td>
                                <td><span class="<?php echo $status_class; ?>"><?php echo $status_text; ?></span></td>
                                <td><?php echo $is_infected ? esc_html( $entry['threats_count'] ) . ' угроз' : 'Угроз не обнаружено'; ?></td>
                                <td><?php echo intval( $entry['duration'] ); ?> сек</td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>

    <div id="rls-scan-results" class="rls-box" style="display:none;">
        <h3 id="rls-results-title" class="results-title">Результаты</h3>
        <div id="rls-results-content"></div>
    </div>

    <!-- MODAL: детали угрозы -->
    <div id="rls-threat-modal" class="rls-modal-backdrop" style="display:none;">
        <div class="rls-modal">
            <div class="rls-modal-header">
                <h2>Детали угрозы</h2>
                <button type="button" class="button" id="rls-threat-modal-close">Закрыть</button>
            </div>
            <div class="rls-modal-body"></div>
        </div>
    </div>

</div>

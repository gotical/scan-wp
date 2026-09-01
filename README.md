# Rybinsk Lab Security (rybinsklab-security)

Комплексный плагин безопасности для WordPress: WAF, глобальный чёрный список IP,
сканер, защита входа и журнал атак.

- **Plugin Name:** Rybinsk Lab Security
- **Plugin URI:** https://rybinsklab.ru/scan-wp/
- **Version:** 2.3.0
- **Author:** Усачёв Денис (https://rybinsklab.ru/)
- **License:** GPL v2 or later
- **Text Domain:** rybinsklab-security

## Возможности

- **WAF (Web Application Firewall)** — фильтрация вредоносных запросов.
- **Глобальный чёрный список IP** — синхронизация с сервером `rybinsklab.ru/scan-wp`.
- **Сканер** — поиск вредоносного кода и изменений файлов (FIM).
- **Защита входа** — ограничение попыток входа, капча.
- **Журнал атак** — логирование и статистика.
- **Карантин** — изоляция подозрительных файлов.
- **GeoIP** — определение геолокации по IP.

## Установка

1. Скопируйте папку `rybinsklab-security` в `wp-content/plugins/`.
2. Активируйте плагин в разделе «Плагины».

Либо загрузите ZIP-архив через «Плагины → Добавить новый → Загрузить плагин».

## Требования

- WordPress 5.0+
- PHP 7.4+ (рекомендуется PHP 8.x)

## Структура

```
rybinsklab-security/
├── rybinsklab-security.php   # Главный файл плагина
├── uninstall.php             # Очистка при удалении
├── assets/                   # CSS, JS, GeoIP-данные
├── includes/                 # Классы плагина (WAF, сканер, API, и т.д.)
└── vendor/                   # Сторонние библиотеки (IP2Location)
```

## API-сервер

Плагин взаимодействует с API-сервером:
`https://rybinsklab.ru/scan-wp/api/index.php`

## Разработка

Этот репозиторий содержит исходный код плагина для дальнейшей доработки и
публикации. Версия 2.3.0 получена с сервера `rybinsklab.ru/scan-wp/`.

## Лицензия

GPL v2 or later. См. файл [LICENSE](LICENSE).

---
*Первый релиз: 2.3.0 · Исходники: rybinsklab.ru/scan-wp/*

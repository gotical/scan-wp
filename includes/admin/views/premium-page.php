<?php
/**
 * Premium upsell / showcase page.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$is_prem = function_exists( 'rls_is_premium_license_active' ) && rls_is_premium_license_active();
$user = wp_get_current_user();

$premium_url = 'https://rybinsklab.ru/scan-wp/?utm_source=plugin&utm_medium=page&utm_campaign=premium';
$protected_sites = (int) get_option( 'rls_social_protected_sites', 18500 );
?>
<div class="rls-wrap">
    <?php
    // Banner at top — CTA for free, showcase for premium.
    $this->render_premium_banner( [ 'variant' => ( $is_prem ? 'showcase' : 'cta' ) ] );
    ?>

    <?php if ( ! $is_prem ) : ?>
        <!-- ============ COMPARISON TABLE FOR FREE USERS ============ -->
        <div class="rls-box rls-premium-compare">
            <h2><span class="dashicons dashicons-columns"></span> Сравнение Free и Premium</h2>

            <table class="wp-list-table widefat striped rls-premium-table">
                <thead>
                    <tr>
                        <th>Функция</th>
                        <th class="rls-col-free">Free</th>
                        <th class="rls-col-premium">Premium</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $features = [
                        [ 'name' => 'WAF + базовая защита',                 'free' => '✓', 'premium' => '✓' ],
                        [ 'name' => 'Сканер вирусов (базовые сигнатуры)',  'free' => '✓', 'premium' => '✓' ],
                        [ 'name' => 'Brute force защита',                  'free' => '✓', 'premium' => '✓' ],
                        [ 'name' => 'Premium сигнатуры вирусов',           'free' => '✕', 'premium' => '✓', 'highlight' => true ],
                        [ 'name' => 'Облачный blacklist 24/7',             'free' => '✕', 'premium' => '✓', 'highlight' => true ],
                        [ 'name' => 'AI-анализ подозрительного кода',       'free' => '✕', 'premium' => '✓', 'highlight' => true ],
                        [ 'name' => 'Геоблокировка',                       'free' => 'до 5 стран', 'premium' => '∞ стран', 'highlight' => true ],
                        [ 'name' => 'Автоматические обновления баз',       'free' => '✕', 'premium' => '✓' ],
                        [ 'name' => 'Приоритетная поддержка',              'free' => '✕', 'premium' => '4 ч ответ' ],
                        [ 'name' => 'Мониторинг dashboard',                'free' => 'базовый', 'premium' => 'полный' ],
                        [ 'name' => 'Ранний доступ к новинкам',            'free' => '✕', 'premium' => '✓' ],
                        [ 'name' => 'Брендирование панели',                'free' => '✕', 'premium' => '✓' ],
                    ];
                    foreach ( $features as $f ) :
                        $hl = ! empty( $f['highlight'] );
                        ?>
                        <tr class="<?php echo $hl ? 'rls-row-highlight' : ''; ?>">
                            <td><strong><?php echo esc_html( $f['name'] ); ?></strong></td>
                            <td class="rls-col-free"><?php echo esc_html( $f['free'] ); ?></td>
                            <td class="rls-col-premium">
                                <?php if ( $f['premium'] === '✓' ) : ?>
                                    <span class="dashicons dashicons-yes"></span>
                                <?php elseif ( $f['premium'] === '✕' ) : ?>
                                    <span class="dashicons dashicons-dismiss"></span>
                                <?php else : ?>
                                    <strong><?php echo esc_html( $f['premium'] ); ?></strong>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <div class="rls-premium-cta-center">
                <a href="<?php echo esc_url( $premium_url ); ?>" target="_blank" rel="noopener" class="button button-primary rls-premium-button">
                    <span class="dashicons dashicons-cart"></span>
                    Купить Premium
                </a>
            </div>
        </div>

        <!-- ============ TESTIMONIALS ============ -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-format-quote"></span> Отзывы пользователей</h2>
            <div class="rls-testimonials">
                <div class="rls-testimonial">
                    <div class="rls-testimonial__stars">★★★★★</div>
                    <p>"Установил Premium за 5 минут. За первую неделю отразил 14 атак на wp-login. Окупилось в первый же день."</p>
                    <strong>— Алексей, интернет-магазин</strong>
                </div>
                <div class="rls-testimonial">
                    <div class="rls-testimonial__stars">★★★★★</div>
                    <p>"AI-анализ нашёл бэкдор в старой теме, который другие сканеры пропустили. Спас данные клиентов."</p>
                    <strong>— Марина, веб-студия</strong>
                </div>
                <div class="rls-testimonial">
                    <div class="rls-testimonial__stars">★★★★★</div>
                    <p>"Геоблокировка закрыла половину трафика от ботов. Сайт стал в 3 раза быстрее."</p>
                    <strong>— Дмитрий, блог</strong>
                </div>
            </div>
        </div>

        <!-- ============ FAQ ============ -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-info"></span> Частые вопросы</h2>
            <details class="rls-faq">
                <summary>Можно ли вернуть деньги?</summary>
                <p>Да, 30-дневная гарантия возврата средств без объяснения причин.</p>
            </details>
            <details class="rls-faq">
                <summary>На сколько сайтов действует ключ?</summary>
                <p>Один ключ = один сайт. Для нескольких сайлов есть мульти-лицензия со скидкой.</p>
            </details>
            <details class="rls-faq">
                <summary>Нужна ли карта для триала?</summary>
                <p>Нет, 14-дневный триал активируется без привязки карты.</p>
            </details>
            <details class="rls-faq">
                <summary>Что будет после окончания подписки?</summary>
                <p>Плагин продолжит работать в Free-режиме. Ваши данные сохранятся.</p>
            </details>
        </div>

    <?php else : ?>
        <!-- ============ PREMIUM MEMBER PAGE ============ -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-heart"></span> Спасибо за поддержку!</h2>
            <p style="font-size:15px; line-height:1.7;">
                Каждый Premium-подписчик помогает нам развивать плагин и защищать всё больше сайтов.
                Без вас этого бы не было. <strong>Спасибо!</strong>
            </p>
        </div>

        <!-- ============ EXCLUSIVE FEATURES ============ -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-unlock"></span> Ваши эксклюзивные возможности</h2>
            <div class="rls-premium-features-grid">
                <div class="rls-premium-feature rls-premium-feature--unlocked">
                    <span class="dashicons dashicons-cloud"></span>
                    <div>
                        <strong>Облачный blacklist</strong>
                        <span>Глобальная база угроз синхронизируется каждые 5 минут.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--unlocked">
                    <span class="dashicons dashicons-shield"></span>
                    <div>
                        <strong>Premium сигнатуры</strong>
                        <span><?php echo (int) ( get_option( 'rls_premium_signatures', [] ) ? count( (array) get_option( 'rls_premium_signatures' ) ) : 0 ); ?> активных правил.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--unlocked">
                    <span class="dashicons dashicons-chart-line"></span>
                    <div>
                        <strong>AI-анализ</strong>
                        <span>Нейросеть проверяет подозрительный код автоматически.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--unlocked">
                    <span class="dashicons dashicons-admin-site"></span>
                    <div>
                        <strong>Геоблокировка без лимитов</strong>
                        <span>Можно добавить до 250 стран в каждом списке.</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- ============ ROADMAP ============ -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-chart-bar"></span> Что скоро появится</h2>
            <div class="rls-roadmap">
                <div class="rls-roadmap-item">
                    <span class="rls-roadmap-item__quarter">Q4 2026</span>
                    <strong>AI security assistant</strong>
                    <p>Чат-бот для анализа угроз прямо в админке.</p>
                    <span class="rls-status-pill is-warn">Скоро</span>
                </div>
                <div class="rls-roadmap-item">
                    <span class="rls-roadmap-item__quarter">Q1 2027</span>
                    <strong>Real-time attack map</strong>
                    <p>Карта мира с источниками атак в реальном времени.</p>
                    <span class="rls-status-pill is-off">В планах</span>
                </div>
                <div class="rls-roadmap-item">
                    <span class="rls-roadmap-item__quarter">Q2 2027</span>
                    <strong>Multi-site network view</strong>
                    <p>Управление всеми сайтами из одной панели.</p>
                    <span class="rls-status-pill is-off">В планах</span>
                </div>
            </div>
        </div>

        <!-- ============ ACHIEVEMENTS ============ -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-awards"></span> Ваши достижения</h2>
            <div class="rls-achievements">
                <?php
                $stats = get_option( 'rls_stats', [] );
                $blocked = (int) ( $stats['firewall_blocked'] ?? 0 );
                $login_blocked = (int) ( $stats['login_attempts_blocked'] ?? 0 );
                $viruses = (int) ( $stats['viruses_found'] ?? 0 );
                ?>
                <div class="rls-achievement <?php echo $blocked > 0 ? 'is-unlocked' : 'is-locked'; ?>">
                    <span class="rls-achievement__icon">🛡️</span>
                    <strong>Первая защита</strong>
                    <span>Отражена хотя бы одна атака</span>
                </div>
                <div class="rls-achievement <?php echo $blocked >= 100 ? 'is-unlocked' : 'is-locked'; ?>">
                    <span class="rls-achievement__icon">⚔️</span>
                    <strong>Защитник</strong>
                    <span>100+ отраженных атак</span>
                </div>
                <div class="rls-achievement <?php echo $blocked >= 1000 ? 'is-unlocked' : 'is-locked'; ?>">
                    <span class="rls-achievement__icon">🏆</span>
                    <strong>Страж</strong>
                    <span>1000+ отраженных атак</span>
                </div>
                <div class="rls-achievement <?php echo $viruses > 0 ? 'is-unlocked' : 'is-locked'; ?>">
                    <span class="rls-achievement__icon">🔍</span>
                    <strong>Охотник</strong>
                    <span>Найден хотя бы один вирус</span>
                </div>
                <div class="rls-achievement is-unlocked">
                    <span class="rls-achievement__icon">👑</span>
                    <strong>Premium member</strong>
                    <span>Поддерживаете проект</span>
                </div>
            </div>
        </div>

        <!-- ============ SUPPORT ============ -->
        <div class="rls-box" style="background: linear-gradient(135deg, var(--rls-surface-alt), var(--rls-primary-soft)); border-color: var(--rls-primary);">
            <h2><span class="dashicons dashicons-email-alt"></span> Нужна помощь?</h2>
            <p>Как Premium-подписчик вы получаете приоритетную поддержку:</p>
            <ul style="line-height:1.9;">
                <li>📧 Ответ в течение <strong>4 часов</strong> в будние дни</li>
                <li>💬 Прямой контакт с разработчиками</li>
                <li>🚀 Приоритет в очереди feature requests</li>
            </ul>
            <p>
                <a href="https://rybinsklab.ru/scan-wp/support/" target="_blank" rel="noopener" class="button button-primary">
                    <span class="dashicons dashicons-email"></span>
                    Связаться с поддержкой
                </a>
            </p>
        </div>
    <?php endif; ?>
</div>

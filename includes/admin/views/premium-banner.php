<?php
/**
 * Premium banner component.
 * Renders CTA for free users, showcase for premium users.
 *
 * Variants: 'cta' (default), 'showcase', 'compact' (inline)
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$variant  = isset( $args['variant'] ) ? $args['variant'] : 'cta';
$is_prem  = function_exists( 'rls_is_premium_license_active' ) && rls_is_premium_license_active();

$user = wp_get_current_user();
$user_display = $user->display_name ?: $user->user_login;
$user_email   = $user->user_email;

// Stats for premium users.
$stats = is_array( get_option( 'rls_stats', [] ) ) ? get_option( 'rls_stats', [] ) : [];
$blocked = (int) ( $stats['firewall_blocked'] ?? 0 );
$login_blocked = (int) ( $stats['login_attempts_blocked'] ?? 0 );
$viruses = (int) ( $stats['viruses_found'] ?? 0 );

// Site count for social proof (placeholder — admin can update).
$protected_sites = (int) ( get_option( 'rls_social_protected_sites', 18500 ) );
$rating = get_option( 'rls_social_rating', '4.8' );
$reviews_count = (int) ( get_option( 'rls_social_reviews', 213 ) );

// Premium URL.
$premium_url = 'https://rybinsklab.ru/scan-wp/?utm_source=plugin&utm_medium=banner&utm_campaign=premium';

// Show showcase only for premium users.
if ( $variant !== 'compact' ) {
    if ( $is_prem ) {
        $variant = 'showcase';
    }
}

if ( $variant === 'showcase' ) :
    // ============ PREMIUM SHOWCASE ============ ?>
    <div class="rls-premium-banner rls-premium-banner--showcase">
        <div class="rls-premium-banner__bg"></div>
        <div class="rls-premium-banner__inner">
            <div class="rls-premium-banner__crown">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M3 18L4 8L8 11L12 5L16 11L20 8L21 18H3Z" fill="url(#crown-grad)" stroke="rgba(255,255,255,0.6)" stroke-width="1"/>
                    <path d="M3 21H21" stroke="rgba(255,255,255,0.4)" stroke-width="1.5"/>
                    <circle cx="8" cy="11" r="1" fill="#fff"/>
                    <circle cx="16" cy="11" r="1" fill="#fff"/>
                    <defs>
                        <linearGradient id="crown-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#fde047"/>
                            <stop offset="100%" stop-color="#f59e0b"/>
                        </linearGradient>
                    </defs>
                </svg>
            </div>

            <div class="rls-premium-banner__title">
                <span class="rls-premium-banner__greeting">Premium Member</span>
                <h2 class="rls-premium-banner__heading">Спасибо за поддержку, <span class="rls-premium-banner__name"><?php echo esc_html( $user_display ); ?></span>!</h2>
                <p class="rls-premium-banner__subtitle">Ваш сайт под максимальной защитой Premium.</p>
            </div>

            <div class="rls-premium-banner__stats">
                <div class="rls-premium-stat">
                    <div class="rls-premium-stat__value rls-counter" data-target="<?php echo $blocked; ?>">0</div>
                    <div class="rls-premium-stat__label">Атак отражено</div>
                </div>
                <div class="rls-premium-stat">
                    <div class="rls-premium-stat__value rls-counter" data-target="<?php echo $login_blocked; ?>">0</div>
                    <div class="rls-premium-stat__label">Brute force блок</div>
                </div>
                <div class="rls-premium-stat">
                    <div class="rls-premium-stat__value rls-counter" data-target="<?php echo $viruses; ?>">0</div>
                    <div class="rls-premium-stat__label">Вирусов найдено</div>
                </div>
            </div>

            <div class="rls-premium-banner__perks">
                <div class="rls-premium-perk"><span class="dashicons dashicons-yes"></span> Облачный blacklist</div>
                <div class="rls-premium-perk"><span class="dashicons dashicons-yes"></span> Premium сигнатуры</div>
                <div class="rls-premium-perk"><span class="dashicons dashicons-yes"></span> AI-анализ кода</div>
                <div class="rls-premium-perk"><span class="dashicons dashicons-yes"></span> Геоблокировка без лимитов</div>
                <div class="rls-premium-perk"><span class="dashicons dashicons-yes"></span> Приоритетный саппорт</div>
                <div class="rls-premium-perk"><span class="dashicons dashicons-yes"></span> Ранний доступ к новинкам</div>
            </div>
        </div>
    </div>
    <?php
elseif ( $variant === 'compact' ) :
    // ============ COMPACT CTA (for inline use) ============ ?>
    <div class="rls-premium-compact">
        <span class="rls-premium-compact__icon">👑</span>
        <div class="rls-premium-compact__text">
            <strong>Эта функция доступна в Premium</strong>
            <span>Получите облачный blacklist, AI-анализ и многое другое.</span>
        </div>
        <a href="<?php echo esc_url( $premium_url ); ?>" target="_blank" rel="noopener" class="button button-primary">
            Купить Premium →
        </a>
    </div>
    <?php
else :
    // ============ CTA FOR FREE USERS ============ ?>
    <div class="rls-premium-banner rls-premium-banner--cta">
        <div class="rls-premium-banner__bg"></div>
        <div class="rls-premium-banner__sparkles">
            <span class="rls-sparkle" style="top:10%; left:8%; animation-delay: 0s;">✦</span>
            <span class="rls-sparkle" style="top:20%; left:80%; animation-delay: 0.8s;">✧</span>
            <span class="rls-sparkle" style="top:70%; left:15%; animation-delay: 1.6s;">✦</span>
            <span class="rls-sparkle" style="top:60%; left:75%; animation-delay: 2.4s;">✧</span>
            <span class="rls-sparkle" style="top:40%; left:50%; animation-delay: 3.2s;">✦</span>
        </div>

        <div class="rls-premium-banner__inner">
            <div class="rls-premium-banner__head">
                <div class="rls-premium-banner__badge">
                    <span class="dashicons dashicons-star-filled"></span>
                    <span>PREMIUM</span>
                </div>
                <h2 class="rls-premium-banner__heading">Защитите сайт на максимум</h2>
                <p class="rls-premium-banner__subtitle">Откройте облачный blacklist, AI-анализ вирусов и другие возможности Premium.</p>
            </div>

            <div class="rls-premium-banner__features">
                <div class="rls-premium-feature rls-premium-feature--locked">
                    <span class="dashicons dashicons-cloud"></span>
                    <div>
                        <strong>Облачный blacklist 24/7</strong>
                        <span>Синхронизация с глобальной базой угроз в реальном времени.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--locked">
                    <span class="dashicons dashicons-shield"></span>
                    <div>
                        <strong>Premium сигнатуры вирусов</strong>
                        <span>Расширенная база образцов + автообновления.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--locked">
                    <span class="dashicons dashicons-chart-line"></span>
                    <div>
                        <strong>AI-анализ подозрительного кода</strong>
                        <span>Нейросеть анализирует код и выносит вердикт.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--locked">
                    <span class="dashicons dashicons-admin-site"></span>
                    <div>
                        <strong>Геоблокировка без лимитов</strong>
                        <span>До 250 стран в одном списке вместо 3-5 в Free.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--locked">
                    <span class="dashicons dashicons-update"></span>
                    <div>
                        <strong>Автоматические обновления</strong>
                        <span>Сигнатуры и базы обновляются на сервере.</span>
                    </div>
                </div>
                <div class="rls-premium-feature rls-premium-feature--locked">
                    <span class="dashicons dashicons-email"></span>
                    <div>
                        <strong>Приоритетный саппорт</strong>
                        <span>Ответ в течение 4 часов в будние дни.</span>
                    </div>
                </div>
            </div>

            <div class="rls-premium-banner__cta">
                <a href="<?php echo esc_url( $premium_url ); ?>" target="_blank" rel="noopener" class="button button-primary rls-premium-button">
                    <span class="dashicons dashicons-cart"></span>
                    Купить Premium
                    <span class="rls-premium-button__price">от 990 ₽ / год</span>
                </a>
                <p class="rls-premium-banner__trial">14 дней бесплатно · Без привязки карты</p>
            </div>

            <div class="rls-premium-banner__social-proof">
                <div class="rls-trust-item">
                    <span class="dashicons dashicons-shield-alt"></span>
                    <strong class="rls-counter" data-target="<?php echo $protected_sites; ?>">0</strong>
                    <span>сайтов под защитой</span>
                </div>
                <div class="rls-trust-item">
                    <span class="dashicons dashicons-star-filled"></span>
                    <strong><?php echo esc_html( $rating ); ?></strong>
                    <span><?php echo $reviews_count; ?> отзывов</span>
                </div>
                <div class="rls-trust-item">
                    <span class="dashicons dashicons-undo"></span>
                    <strong>30 дней</strong>
                    <span>гарантия возврата</span>
                </div>
                <div class="rls-trust-item">
                    <span class="dashicons dashicons-lock"></span>
                    <strong>SSL</strong>
                    <span>безопасная оплата</span>
                </div>
            </div>
        </div>
    </div>
<?php endif;

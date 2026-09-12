<?php
/**
 * Справочник типов атак — все типы с подробными описаниями на русском.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Attack_Types' ) ) {
    echo '<div class="rls-notice is-danger">RLS Attack Types не загружен.</div>';
    return;
}

$types = RLS_Attack_Types::all();
$grouped = [
    'critical' => [],
    'high'     => [],
    'medium'   => [],
    'low'      => [],
    'info'     => [],
];
foreach ( $types as $key => $t ) {
    $grouped[ $t['severity'] ][] = [ 'key' => $key ] + $t;
}
$group_labels = [
    'critical' => [ 'label' => '🚨 Критические', 'description' => 'Угрозы максимальной опасности. Требуют немедленных действий.' ],
    'high'     => [ 'label' => '🔴 Высокий риск', 'description' => 'Серьёзные угрозы, требуют внимания в течение часов.' ],
    'medium'   => [ 'label' => '🟠 Средний риск', 'description' => 'Угрозы, которые могут привести к проблемам.' ],
    'low'      => [ 'label' => '🟡 Низкий риск', 'description' => 'Слабые угрозы, полезно знать для общего понимания.' ],
    'info'     => [ 'label' => '🔵 Информационные', 'description' => 'Не признак атаки, но полезно для понимания контекста.' ],
];
?>
<div class="rls-wrap">
    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    Справочник типов атак
                    <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                </h1>
                <p class="rls-page-subtitle">Все типы угроз, которые детектирует плагин. Каждый содержит подробное описание на русском, вектор атаки и рекомендации по реагированию.</p>
            </div>
            <div class="rls-hero-actions">
                <span class="rls-status-pill is-on" style="background: rgba(255,255,255,0.18); color: #fff;">
                    <?php echo count( $types ); ?> типов
                </span>
            </div>
        </div>
    </div>

    <?php foreach ( $grouped as $severity_key => $group_types ) :
        if ( empty( $group_types ) ) continue;
        $info = $group_labels[ $severity_key ];
        ?>
        <div class="rls-box">
            <h2 style="border-left-color: <?php echo $severity_key === 'critical' ? '#dc2626' : ( $severity_key === 'high' ? '#ea580c' : ( $severity_key === 'medium' ? '#d97706' : ( $severity_key === 'low' ? '#65a30d' : '#0284c7' ) ) ); ?>;">
                <?php echo esc_html( $info['label'] ); ?>
            </h2>
            <p style="color: var(--rls-text-muted); margin-bottom: 16px;">
                <?php echo esc_html( $info['description'] ); ?>
            </p>
            <div class="rls-attack-types-grid">
                <?php foreach ( $group_types as $t ) :
                    $icon = $t['icon'] ?? 'dashicons-marker';
                    $color = $t['color'] ?? '#6b7280';
                    ?>
                    <div class="rls-attack-type-card" style="border-left-color: <?php echo esc_attr( $color ); ?>;">
                        <div class="rls-attack-type-card__header">
                            <span class="rls-attack-type-card__icon" style="background: <?php echo esc_attr( $color ); ?>;">
                                <span class="dashicons <?php echo esc_attr( $icon ); ?>"></span>
                            </span>
                            <div>
                                <strong class="rls-attack-type-card__name"><?php echo esc_html( $t['label'] ); ?></strong>
                                <small class="rls-attack-type-card__name-en"><?php echo esc_html( $t['label_en'] ); ?></small>
                            </div>
                        </div>
                        <p class="rls-attack-type-card__short"><?php echo esc_html( $t['short'] ); ?></p>
                        <p class="rls-attack-type-card__description"><?php echo esc_html( $t['description'] ); ?></p>
                        <div class="rls-attack-type-card__meta">
                            <div class="rls-attack-type-card__meta-item">
                                <strong>Вектор:</strong>
                                <span><?php echo esc_html( $t['attack_vector'] ); ?></span>
                            </div>
                            <div class="rls-attack-type-card__meta-item">
                                <strong>Пример:</strong>
                                <code><?php echo esc_html( $t['real_example'] ); ?></code>
                            </div>
                            <div class="rls-attack-type-card__meta-item rls-attack-type-card__meta-response">
                                <strong>Что делать:</strong>
                                <span><?php echo esc_html( $t['how_to_respond'] ); ?></span>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endforeach; ?>
</div>

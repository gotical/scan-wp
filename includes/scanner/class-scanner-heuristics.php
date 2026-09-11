<?php
/**
 * Scanner heuristics: regex signatures, entropy analysis, suspicious pattern detection.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Scanner_Heuristics {

    const OPT_RULES = 'rls_scanner_custom_rules';

    /**
     * Built-in regex rules. Each rule has:
     *   - id        unique identifier
     *   - name      human-readable name
     *   - pattern   PCRE regex with /i flag (case-insensitive)
     *   - severity  0-100 risk score
     *   - tags      array of tags (web-shell, obfuscation, backdoor, etc.)
     *   - enabled   bool
     */
    public static function built_in_rules() {
        return [
            // === Web shells (high confidence) ===
            [
                'id'       => 'ws-classic-eval',
                'name'     => 'Classic eval() webshell',
                'pattern'  => 'eval\s*\(\s*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)\s*\[',
                'severity' => 95,
                'tags'     => [ 'web-shell', 'critical' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'ws-system-exec',
                'name'     => 'System command execution',
                'pattern'  => '\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*(\$_|\$\{|base64_decode|gzinflate|str_rot13)',
                'severity' => 90,
                'tags'     => [ 'rce', 'critical' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'ws-assert-exec',
                'name'     => 'PHP assert() with code',
                'pattern'  => '\bassert\s*\(\s*["\']?\s*\$|assert\s*\(\s*(base64_decode|gzinflate|str_rot13)',
                'severity' => 80,
                'tags'     => [ 'rce' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'ws-create-function',
                'name'     => 'Dynamic function creation',
                'pattern'  => 'create_function\s*\(.*\$_(GET|POST|REQUEST|COOKIE)',
                'severity' => 90,
                'tags'     => [ 'rce' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'ws-file-get-eval',
                'name'     => 'Remote file include with eval',
                'pattern'  => '(file_get_contents|curl_init|fopen)\s*\(.*\$_|include\s*\(\s*\$_',
                'severity' => 85,
                'tags'     => [ 'rfi' ],
                'enabled'  => true,
            ],

            // === Obfuscation patterns ===
            [
                'id'       => 'obf-base64-long',
                'name'     => 'Long base64_decode chain',
                'pattern'  => '(base64_decode\s*\([^)]+\)\s*\.?\s*){3,}',
                'severity' => 70,
                'tags'     => [ 'obfuscation' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'obf-gzinflate',
                'name'     => 'Compressed obfuscated payload',
                'pattern'  => '(gzinflate|gzuncompress|gzdecode|rawurldecode|str_rot13)\s*\(\s*["\'][A-Za-z0-9+/=]{50,}',
                'severity' => 75,
                'tags'     => [ 'obfuscation' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'obf-hex-string',
                'name'     => 'Long hex-encoded string',
                'pattern'  => '["\']\\x[A-Fa-f0-9]{2}(\\x[A-Fa-f0-9]{2}){15,}',
                'severity' => 60,
                'tags'     => [ 'obfuscation' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'obf-char-codes',
                'name'     => 'Character code array obfuscation',
                'pattern'  => 'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr',
                'severity' => 65,
                'tags'     => [ 'obfuscation' ],
                'enabled'  => true,
            ],

            // === Backdoors & persistence ===
            [
                'id'       => 'bd-preg-replace-exec',
                'name'     => 'preg_replace with /e modifier (RCE)',
                'pattern'  => 'preg_replace\s*\(\s*["\'][^"\']*\/e[imsxu]*[\'"]\s*,',
                'severity' => 95,
                'tags'     => [ 'rce', 'critical' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'bd-backticks-exec',
                'name'     => 'Backtick execution',
                'pattern'  => '`[^`]*(?:\$_|base64|eval|exec)',
                'severity' => 70,
                'tags'     => [ 'rce' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'bd-call-user-func',
                'name'     => 'Dynamic function call',
                'pattern'  => '(call_user_func|call_user_func_array)\s*\(\s*["\']?(assert|eval|exec|system|passthru|shell_exec)',
                'severity' => 90,
                'tags'     => [ 'rce' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'bd-array-map-exec',
                'name'     => 'array_map with exec function',
                'pattern'  => 'array_(map|filter|walk)\s*\(.*["\'](assert|eval|exec|system)',
                'severity' => 85,
                'tags'     => [ 'rce' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'bd-hidden-eval',
                'name'     => 'Obfuscated eval()',
                'pattern'  => '[\'"](eval|exec|system|assert)["\']\s*\)\s*;?\s*$|\\x65\\x76\\x61\\x6c',
                'severity' => 60,
                'tags'     => [ 'obfuscation' ],
                'enabled'  => true,
            ],

            // === SQL injection patterns in code (not runtime) ===
            [
                'id'       => 'sqli-dynamic-query',
                'name'     => 'Unsafe dynamic SQL query',
                'pattern'  => '\$wpdb\s*->\s*query\s*\(\s*["\'].*\$_',
                'severity' => 60,
                'tags'     => [ 'sqli' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'sqli-unescaped',
                'name'     => 'Unescaped SQL variable',
                'pattern'  => '\$wpdb\s*->\s*(get_results|get_row|get_var|query)\s*\(\s*["\'][^"\']*["\']?\s*\.\s*\$',
                'severity' => 50,
                'tags'     => [ 'sqli' ],
                'enabled'  => true,
            ],

            // === XSS patterns ===
            [
                'id'       => 'xss-echo-request',
                'name'     => 'Unescaped request echo',
                'pattern'  => '\b(echo|print|printf)\s+\$_(GET|POST|REQUEST)',
                'severity' => 55,
                'tags'     => [ 'xss' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'xss-inline-script-tag',
                'name'     => 'Inline script from user input',
                'pattern'  => '<script[^>]*>\s*<\?php\s+echo?\s+\$_(GET|POST|REQUEST)',
                'severity' => 75,
                'tags'     => [ 'xss' ],
                'enabled'  => true,
            ],

            // === Suspicious headers / behaviors ===
            [
                'id'       => 'suspicious-noindex',
                'name'     => 'PHP file in uploads directory',
                'pattern'  => 'wp-content[\\\\/]uploads[\\\\/].*\.php$',
                'severity' => 80,
                'tags'     => [ 'suspicious-location' ],
                'enabled'  => true,
            ],

            // === Crypto / mining ===
            [
                'id'       => 'crypto-miner',
                'name'     => 'Crypto miner signature',
                'pattern'  => '(cryptonight|stratum\+tcp|monero|coinhive|minero|cryptoloot)',
                'severity' => 95,
                'tags'     => [ 'crypto-miner', 'critical' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'crypto-wallet',
                'name'     => 'Hardcoded crypto wallet',
                'pattern'  => '\b(bc1[0-9a-z]{39}|0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b',
                'severity' => 50,
                'tags'     => [ 'crypto' ],
                'enabled'  => true,
            ],

            // === Recon ===
            [
                'id'       => 'recon-phpinfo',
                'name'     => 'phpinfo() exposed',
                'pattern'  => '\bphpinfo\s*\(\s*\)',
                'severity' => 35,
                'tags'     => [ 'info-leak' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'recon-wp-config-leak',
                'name'     => 'Possible DB credentials leak',
                'pattern'  => 'define\s*\(\s*["\'](DB_PASSWORD|DB_USER|DB_HOST|DB_NAME)["\']\s*,',
                'severity' => 30,
                'tags'     => [ 'info-leak' ],
                'enabled'  => true,
            ],

            // === WordPress-specific ===
            [
                'id'       => 'wp-admin-ajax-backdoor',
                'name'     => 'Hidden admin AJAX action',
                'pattern'  => 'add_action\s*\(\s*["\']wp_ajax_(nopriv_)?[a-z0-9_]{16,}["\']',
                'severity' => 50,
                'tags'     => [ 'wp-specific' ],
                'enabled'  => true,
            ],
            [
                'id'       => 'wp-rest-backdoor',
                'name'     => 'Hidden REST route registration',
                'pattern'  => 'register_rest_route\s*\(.*["\'](admin-|secret|backdoor|hack)',
                'severity' => 60,
                'tags'     => [ 'wp-specific' ],
                'enabled'  => true,
            ],
        ];
    }

    /**
     * Get all enabled rules (built-in + custom).
     */
    public static function get_enabled_rules() {
        $custom = get_option( self::OPT_RULES, [] );
        if ( ! is_array( $custom ) ) $custom = [];
        $rules = self::built_in_rules();
        foreach ( $custom as $c ) {
            if ( ! empty( $c['enabled'] ) ) {
                $rules[] = wp_parse_args( $c, [
                    'id' => 'custom-' . wp_generate_password( 8, false ),
                    'severity' => 50,
                    'tags' => [ 'custom' ],
                ] );
            }
        }
        return array_filter( $rules, function( $r ) {
            return ! empty( $r['enabled'] );
        } );
    }

    /**
     * Save custom rules.
     */
    public static function save_custom_rules( $rules ) {
        if ( ! is_array( $rules ) ) $rules = [];
        update_option( self::OPT_RULES, $rules, false );
    }

    /**
     * Scan file content against all enabled regex rules.
     * Returns array of findings.
     */
    public static function scan_content( $content, $file_path = '' ) {
        $findings = [];
        $rules = self::get_enabled_rules();
        foreach ( $rules as $rule ) {
            $matches = self::match_rule( $rule, $content );
            if ( $matches ) {
                foreach ( $matches as $m ) {
                    $findings[] = [
                        'rule_id'   => $rule['id'],
                        'rule_name' => $rule['name'],
                        'severity'  => (int) ( $rule['severity'] ?? 50 ),
                        'tags'      => (array) ( $rule['tags'] ?? [] ),
                        'line'      => (int) ( $m['line'] ?? 0 ),
                        'snippet'   => (string) ( $m['snippet'] ?? '' ),
                        'match'     => (string) ( $m['match'] ?? '' ),
                    ];
                }
            }
        }
        return $findings;
    }

    /**
     * Match a single rule against content with line tracking.
     */
    private static function match_rule( $rule, $content ) {
        $pattern = $rule['pattern'];
        // Allow case-insensitive by default unless pattern already has /i.
        $regex = '~' . $pattern . '~i';
        $matches = [];
        $count = @preg_match_all( $regex, $content, $matches, PREG_OFFSET_CAPTURE );
        if ( ! $count ) return null;
        $results = [];
        $lines = explode( "\n", $content );
        foreach ( $matches[0] as $idx => $m ) {
            $offset = (int) $m[1];
            // Compute line number from offset.
            $line = 1;
            $running = 0;
            foreach ( $lines as $ln => $text ) {
                $running += strlen( $text ) + 1;
                if ( $running > $offset ) { $line = $ln + 1; break; }
            }
            $match_text = (string) $m[0];
            // Get snippet (line + context).
            $line_idx = max( 0, $line - 1 );
            $snippet_lines = [];
            for ( $i = max( 0, $line_idx - 2 ); $i <= min( count( $lines ) - 1, $line_idx + 2 ); $i++ ) {
                $snippet_lines[] = ( $i + 1 ) . ': ' . rtrim( $lines[ $i ] ?? '' );
            }
            $results[] = [
                'line'    => $line,
                'snippet' => implode( "\n", $snippet_lines ),
                'match'   => mb_substr( $match_text, 0, 200 ),
            ];
        }
        return $results;
    }

    /**
     * Compute Shannon entropy of a string.
     * High entropy (>6.5) suggests obfuscation/encryption.
     */
    public static function shannon_entropy( $string ) {
        if ( empty( $string ) ) return 0.0;
        $len = strlen( $string );
        $freq = [];
        for ( $i = 0; $i < $len; $i++ ) {
            $c = $string[ $i ];
            $freq[ $c ] = ( $freq[ $c ] ?? 0 ) + 1;
        }
        $entropy = 0.0;
        foreach ( $freq as $count ) {
            $p = $count / $len;
            $entropy -= $p * log( $p, 2 );
        }
        return $entropy;
    }

    /**
     * Detect suspicious obfuscation by combining entropy + base64/gzinflate presence.
     * Returns array of findings.
     */
    public static function detect_obfuscation( $content ) {
        $findings = [];

        // 1. Long base64 strings with suspicious context.
        if ( preg_match_all( '/["\']([A-Za-z0-9+\/=]{100,})["\']/', $content, $matches ) ) {
            foreach ( $matches[1] as $m ) {
                $decoded = @base64_decode( $m, true );
                if ( $decoded !== false && strlen( $decoded ) > 50 ) {
                    $entropy = self::shannon_entropy( $decoded );
                    if ( $entropy > 5.5 ) {
                        $findings[] = [
                            'rule_id'   => 'obf-base64-entropy',
                            'rule_name' => 'High-entropy base64 blob',
                            'severity'  => 65,
                            'tags'      => [ 'obfuscation' ],
                            'line'      => self::find_line( $content, $m ),
                            'snippet'   => mb_substr( $m, 0, 80 ) . '…',
                            'match'     => mb_substr( $m, 0, 80 ),
                        ];
                    }
                }
            }
        }

        // 2. Very high entropy in any line.
        $lines = explode( "\n", $content );
        foreach ( $lines as $idx => $line ) {
            $stripped = trim( $line );
            if ( strlen( $stripped ) < 100 ) continue;
            $entropy = self::shannon_entropy( $stripped );
            if ( $entropy > 7.0 && preg_match( '/[A-Za-z0-9+\/=]{20,}/', $stripped ) ) {
                $findings[] = [
                    'rule_id'   => 'entropy-high',
                    'rule_name' => 'High entropy line',
                    'severity'  => 60,
                    'tags'      => [ 'obfuscation', 'entropy' ],
                    'line'      => $idx + 1,
                    'snippet'   => mb_substr( $stripped, 0, 100 ) . '…',
                    'match'     => mb_substr( $stripped, 0, 100 ),
                ];
            }
        }

        return $findings;
    }

    private static function find_line( $content, $needle ) {
        $pos = strpos( $content, $needle );
        if ( $pos === false ) return 0;
        return substr_count( substr( $content, 0, $pos ), "\n" ) + 1;
    }

    /**
     * Aggregate risk score from findings.
     * Uses the highest severity as the base + bonuses for diversity.
     */
    public static function aggregate_risk_score( array $findings ) {
        if ( empty( $findings ) ) return 0;
        $max_severity = 0;
        $sum_severity = 0;
        $tags = [];
        foreach ( $findings as $f ) {
            $max_severity = max( $max_severity, $f['severity'] );
            $sum_severity += $f['severity'];
            foreach ( (array) ( $f['tags'] ?? [] ) as $tag ) {
                $tags[ $tag ] = true;
            }
        }
        // Base: max severity. Bonus for diversity and count.
        $bonus = min( 15, count( $findings ) * 2 );
        $diversity_bonus = min( 10, count( $tags ) * 2 );
        return min( 100, $max_severity + $bonus + $diversity_bonus );
    }

    /**
     * Get severity label from numeric score.
     */
    public static function severity_label( $score ) {
        if ( $score >= 90 ) return [ 'critical', 'Critical' ];
        if ( $score >= 70 ) return [ 'high', 'High' ];
        if ( $score >= 40 ) return [ 'medium', 'Medium' ];
        if ( $score >= 20 ) return [ 'low', 'Low' ];
        return [ 'info', 'Info' ];
    }
}

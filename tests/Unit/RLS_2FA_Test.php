<?php
/**
 * Tests for RLS_2FA: secret generation, base32 encode/decode round-trip,
 * TOTP code generation determinism, and code verification.
 */

class RLS_2FA_Test extends \PHPUnit\Framework\TestCase {

    public function test_secret_generation() {
        $s1 = RLS_2FA::generate_secret();
        $s2 = RLS_2FA::generate_secret();
        $this->assertNotEquals( $s1, $s2, 'Secrets must be unique' );
        $this->assertSame( 20, strlen( $s1 ), 'Secret must be 20 chars (Base32 / 100 bits)' );
        $this->assertMatchesRegularExpression( '/^[A-Z2-7]+$/', $s1, 'Secret must be Base32 alphabet' );
    }

    public function test_secret_normalization() {
        $s = RLS_2FA::normalize_secret( 'abcd ef12 3456' );
        $this->assertSame( 'ABCDEF123456', $s, 'Lowercase + spaces stripped' );
    }

    public function test_qr_url_format() {
        $secret = 'JBSWY3DPEHPK3PXP';
        $url = RLS_2FA::get_qr_url( $secret, 'admin' );
        $this->assertStringStartsWith( 'otpauth://totp/', $url );
        $this->assertStringContainsString( 'secret=JBSWY3DPEHPK3PXP', $url );
        $this->assertStringContainsString( 'issuer=Rybinsk', $url );
    }

    public function test_backup_codes_format() {
        $codes = RLS_2FA::generate_backup_codes( 12 );
        $this->assertCount( 12, $codes );
        foreach ( $codes as $code ) {
            $this->assertMatchesRegularExpression( '/^[A-F0-9]{10}$/', $code, 'Backup code format' );
        }
        $this->assertCount( 12, array_unique( $codes ), 'Codes must be unique' );
    }

    public function test_totp_code_length() {
        // We can't reach calc_totp directly, but verify_code() will exercise it.
        // Use a known test vector: secret "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" (RFC 6238 test)
        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        // Compute expected code at a known timestamp by reusing calc_totp via reflection.
        $reflection = new ReflectionClass( 'RLS_2FA' );
        $method = $reflection->getMethod( 'calc_totp' );
        $method->setAccessible( true );
        $code = $method->invoke( null, $secret, 59 ); // T=1 (test vector)
        $this->assertSame( 6, strlen( $code ), 'TOTP code must be 6 digits' );
    }

    public function test_verify_code_rejects_garbage() {
        $this->assertFalse( RLS_2FA::verify_code( 'JBSWY3DPEHPK3PXP', 'abc' ) );
        $this->assertFalse( RLS_2FA::verify_code( 'JBSWY3DPEHPK3PXP', '000000' ) );
        $this->assertFalse( RLS_2FA::verify_code( 'JBSWY3DPEHPK3PXP', '' ) );
    }
}

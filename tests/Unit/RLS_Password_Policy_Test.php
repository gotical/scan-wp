<?php
/**
 * Tests for RLS_Password_Policy::evaluate()
 */

class RLS_Password_Policy_Test extends \PHPUnit\Framework\TestCase {

    public function test_strong_password_passes() {
        $eval = RLS_Password_Policy::evaluate( 'X9!correctHorseBatteryStaple#42' );
        $this->assertTrue( $eval['valid'], 'Strong password should pass' );
        $this->assertEmpty( $eval['errors'] );
        $this->assertGreaterThanOrEqual( 5, $eval['score'] );
    }

    public function test_short_password_fails() {
        $eval = RLS_Password_Policy::evaluate( 'X1!a' );
        $this->assertFalse( $eval['valid'] );
        $this->assertNotEmpty( array_filter( $eval['errors'], function( $e ) {
            return strpos( $e, 'Минимум' ) !== false;
        } ) );
    }

    public function test_missing_uppercase() {
        $eval = RLS_Password_Policy::evaluate( 'longpasswordwithoutsymbols1' );
        $this->assertFalse( $eval['valid'] );
        $this->assertNotEmpty( array_filter( $eval['errors'], function( $e ) {
            return strpos( $e, 'заглавная' ) !== false;
        } ) );
    }

    public function test_missing_symbol() {
        $eval = RLS_Password_Policy::evaluate( 'LongpasswordWithoutDigits' );
        $this->assertFalse( $eval['valid'] );
        $this->assertNotEmpty( array_filter( $eval['errors'], function( $e ) {
            return strpos( $e, 'спецсимвол' ) !== false;
        } ) );
    }

    public function test_empty_password() {
        $eval = RLS_Password_Policy::evaluate( '' );
        $this->assertFalse( $eval['valid'] );
    }
}

<?php
/**
 * Tests de Request (IP del cliente).
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use TotalSecurityExpert\Request;
use TotalSecurityExpert\Settings;

/**
 * La IP solo sale de cabeceras cuando REMOTE_ADDR es un proxy de confianza.
 */
class RequestTest extends TestCase {

	public function test_remote_addr_is_the_default(): void {
		$server = array(
			'REMOTE_ADDR'          => '198.51.100.9',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
		);

		$this->assertSame( '198.51.100.9', Request::resolve_ip( $server, 'remote_addr', array( '198.51.100.9' ) ) );
	}

	public function test_header_is_ignored_when_remote_addr_is_not_a_trusted_proxy(): void {
		$server = array(
			'REMOTE_ADDR'           => '198.51.100.9',
			'HTTP_X_FORWARDED_FOR'  => '1.2.3.4',
			'HTTP_X_REAL_IP'        => '1.2.3.4',
			'HTTP_CF_CONNECTING_IP' => '1.2.3.4',
		);

		foreach ( array( 'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip' ) as $source ) {
			$this->assertSame( '198.51.100.9', Request::resolve_ip( $server, $source, array() ), $source );
			$this->assertSame( '198.51.100.9', Request::resolve_ip( $server, $source, array( '10.0.0.0/8' ) ), $source );
		}
	}

	public function test_xff_takes_the_rightmost_ip_that_is_not_a_trusted_proxy(): void {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.1',
			// El cliente ha puesto 6.6.6.6 a la izquierda para suplantar; el proxy anadio 203.0.113.5.
			'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.5, 10.0.0.2',
		);

		$this->assertSame( '203.0.113.5', Request::resolve_ip( $server, 'x_forwarded_for', array( '10.0.0.0/8' ) ) );
	}

	public function test_xff_with_only_trusted_proxies_or_garbage_falls_back_to_remote_addr(): void {
		$trusted = array( '10.0.0.0/8' );

		$all_trusted = array(
			'REMOTE_ADDR'          => '10.0.0.1',
			'HTTP_X_FORWARDED_FOR' => '10.0.0.7, 10.0.0.2',
		);
		$this->assertSame( '10.0.0.1', Request::resolve_ip( $all_trusted, 'x_forwarded_for', $trusted ) );

		$garbage = array(
			'REMOTE_ADDR'          => '10.0.0.1',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4, <script>',
		);
		$this->assertSame( '10.0.0.1', Request::resolve_ip( $garbage, 'x_forwarded_for', $trusted ) );
	}

	public function test_single_value_headers_from_a_trusted_proxy(): void {
		$server = array(
			'REMOTE_ADDR'           => '10.0.0.1',
			'HTTP_X_REAL_IP'        => '203.0.113.20',
			'HTTP_CF_CONNECTING_IP' => '2001:db8::5',
		);

		$this->assertSame( '203.0.113.20', Request::resolve_ip( $server, 'x_real_ip', array( '10.0.0.1' ) ) );
		$this->assertSame( '2001:db8::5', Request::resolve_ip( $server, 'cf_connecting_ip', array( '10.0.0.1' ) ) );

		$server['HTTP_X_REAL_IP'] = 'no-es-una-ip';
		$this->assertSame( '10.0.0.1', Request::resolve_ip( $server, 'x_real_ip', array( '10.0.0.1' ) ) );
	}

	public function test_cidr_matching_ipv4(): void {
		$this->assertTrue( Request::ip_matches( '10.1.2.3', '10.0.0.0/8' ) );
		$this->assertTrue( Request::ip_matches( '192.168.1.200', '192.168.1.128/25' ) );
		$this->assertFalse( Request::ip_matches( '192.168.1.100', '192.168.1.128/25' ) );
		$this->assertFalse( Request::ip_matches( '11.0.0.1', '10.0.0.0/8' ) );
		$this->assertTrue( Request::ip_matches( '1.2.3.4', '0.0.0.0/0' ) );
		$this->assertTrue( Request::ip_matches( '1.2.3.4', '1.2.3.4/32' ) );
		$this->assertFalse( Request::ip_matches( '1.2.3.5', '1.2.3.4/32' ) );
		$this->assertTrue( Request::ip_matches( '1.2.3.4', '1.2.3.4' ) );
	}

	public function test_cidr_matching_ipv6(): void {
		$this->assertTrue( Request::ip_matches( '2001:db8::1', '2001:db8::/32' ) );
		$this->assertFalse( Request::ip_matches( '2001:db9::1', '2001:db8::/32' ) );
		$this->assertTrue( Request::ip_matches( '2001:db8:0:1::1', '2001:db8::/48' ) );
		$this->assertFalse( Request::ip_matches( '2001:db8:0:1::1', '2001:db8::/64' ) );
		$this->assertTrue( Request::ip_matches( '::1', '::1/128' ) );
		$this->assertFalse( Request::ip_matches( '::2', '::1/128' ) );
	}

	public function test_ipv4_and_ipv6_never_match_each_other(): void {
		$this->assertFalse( Request::ip_matches( '10.0.0.1', '2001:db8::/32' ) );
		$this->assertFalse( Request::ip_matches( '2001:db8::1', '10.0.0.0/8' ) );
	}

	public function test_invalid_entries_never_match(): void {
		$this->assertFalse( Request::ip_matches( '10.0.0.1', '10.0.0.0/99' ) );
		$this->assertFalse( Request::ip_matches( '10.0.0.1', 'basura' ) );
		$this->assertFalse( Request::ip_matches( '10.0.0.1', '' ) );
		$this->assertFalse( Request::is_valid_ip_or_cidr( '10.0.0.0/-1' ) );
		$this->assertFalse( Request::is_valid_ip_or_cidr( '10.0.0.0/8/8' ) );
		$this->assertTrue( Request::is_valid_ip_or_cidr( '2001:db8::/128' ) );
		$this->assertFalse( Request::is_valid_ip_or_cidr( '2001:db8::/129' ) );
	}

	public function test_invalid_or_missing_remote_addr_gives_empty_string(): void {
		$this->assertSame( '', Request::resolve_ip( array(), 'remote_addr', array() ) );
		$this->assertSame( '', Request::resolve_ip( array( 'REMOTE_ADDR' => 'abc' ), 'remote_addr', array() ) );
		$this->assertSame( '', Request::resolve_ip( array( 'REMOTE_ADDR' => '999.1.1.1' ), 'x_forwarded_for', array( '0.0.0.0/0' ) ) );
	}

	public function test_ipv4_mapped_ipv6_is_normalized(): void {
		$this->assertSame( '1.2.3.4', Request::normalize_ip( '::ffff:1.2.3.4' ) );
		$this->assertSame( '2001:db8::1', Request::normalize_ip( '2001:0db8:0000:0000:0000:0000:0000:0001' ) );
		$this->assertSame( '', Request::normalize_ip( 'fe80::1%eth0' ) );
	}

	public function test_ip_bucket_is_the_ip_for_ipv4_and_the_slash_64_network_for_ipv6(): void {
		$this->assertSame( '203.0.113.7', Request::ip_bucket( '203.0.113.7' ) );
		$this->assertSame( '1.2.3.4', Request::ip_bucket( '::ffff:1.2.3.4' ), 'IPv4 mapeada se agrupa como IPv4.' );
		$this->assertSame( '2001:db8:1:2::/64', Request::ip_bucket( '2001:db8:1:2:aaaa:bbbb:cccc:dddd' ) );
		$this->assertSame( '2001:db8:1:2::/64', Request::ip_bucket( '2001:0DB8:0001:0002:0000:0000:0000:0001' ) );
		$this->assertSame( '::/64', Request::ip_bucket( '::1' ) );
	}

	public function test_ip_bucket_groups_a_whole_slash_64_together_and_separates_networks(): void {
		$this->assertSame( Request::ip_bucket( '2001:db8:1:2::1' ), Request::ip_bucket( '2001:db8:1:2:ffff:ffff:ffff:ffff' ) );
		$this->assertNotSame( Request::ip_bucket( '2001:db8:1:2::1' ), Request::ip_bucket( '2001:db8:1:3::1' ) );
		$this->assertNotSame( Request::ip_bucket( '10.0.0.1' ), Request::ip_bucket( '10.0.0.2' ) );
	}

	public function test_ip_bucket_is_empty_without_a_valid_ip_and_always_fits_in_45_characters(): void {
		$this->assertSame( '', Request::ip_bucket( '' ) );
		$this->assertSame( '', Request::ip_bucket( 'no-es-una-ip' ) );
		$this->assertSame( '', Request::ip_bucket( '999.1.1.1' ) );
		foreach ( array( 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', '255.255.255.255', '2001:db8:ffff:ffff::1' ) as $ip ) {
			$this->assertLessThanOrEqual( 45, strlen( Request::ip_bucket( $ip ) ), $ip );
		}
		$this->assertSame( 'ffff:ffff:ffff:ffff::/64', Request::ip_bucket( 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ) );
	}

	public function test_get_client_ip_bucket_uses_the_resolved_client_ip(): void {
		$settings = Mockery::mock( Settings::class );
		$settings->shouldReceive( 'get_general' )->andReturn( Settings::default_general() );
		$request = new Request( $settings );

		$this->set_server( array( 'REMOTE_ADDR' => '2001:db8:1:2:3:4:5:6' ) );
		$this->assertSame( '2001:db8:1:2::/64', $request->get_client_ip_bucket() );

		$this->set_server( array( 'REMOTE_ADDR' => '198.51.100.9' ) );
		$this->assertSame( '198.51.100.9', $request->get_client_ip_bucket() );

		$this->set_server( array() );
		$this->assertSame( '', $request->get_client_ip_bucket() );
	}

	/**
	 * Valores de cabecera con puerto o corchetes y la IP que deben dar.
	 *
	 * @return array<string,array{0:string,1:string}>
	 */
	public static function header_ip_values(): array {
		return array(
			'ipv4 plain'              => array( '203.0.113.5', '203.0.113.5' ),
			'ipv4 with port'          => array( '203.0.113.5:4711', '203.0.113.5' ),
			'ipv6 plain'              => array( '2001:db8::1', '2001:db8::1' ),
			'ipv6 brackets'           => array( '[2001:db8::1]', '2001:db8::1' ),
			'ipv6 brackets and port'  => array( '[2001:db8::1]:443', '2001:db8::1' ),
			'spaces around'           => array( '  203.0.113.5:80 ', '203.0.113.5' ),
			'port out of range'       => array( '203.0.113.5:99999', '' ),
			'port not numeric'        => array( '203.0.113.5:abc', '' ),
			'empty port'              => array( '203.0.113.5:', '' ),
			'unclosed bracket'        => array( '[2001:db8::1', '' ),
			'garbage after bracket'   => array( '[2001:db8::1]x', '' ),
			'ipv4 in brackets'        => array( '[203.0.113.5]:80', '203.0.113.5' ),
			'host name'               => array( 'example.com:80', '' ),
			'script'                  => array( '<script>', '' ),
			'bare ipv6 is not a port' => array( '2001:db8::1:443', '2001:db8::1:443' ),
		);
	}

	#[DataProvider( 'header_ip_values' )]
	public function test_header_ip_strips_port_and_brackets_before_validating( string $value, string $expected ): void {
		$this->assertSame( $expected, Request::normalize_header_ip( $value ) );
	}

	public function test_headers_with_port_and_brackets_are_resolved_from_a_trusted_proxy(): void {
		$trusted = array( '10.0.0.0/8' );

		$xff = array(
			'REMOTE_ADDR'          => '10.0.0.1',
			'HTTP_X_FORWARDED_FOR' => '[2001:db8::1]:443, 10.0.0.2:8080',
		);
		$this->assertSame( '2001:db8::1', Request::resolve_ip( $xff, 'x_forwarded_for', $trusted ) );

		$real = array(
			'REMOTE_ADDR'    => '10.0.0.1',
			'HTTP_X_REAL_IP' => '203.0.113.5:4711',
		);
		$this->assertSame( '203.0.113.5', Request::resolve_ip( $real, 'x_real_ip', $trusted ) );

		$cf = array(
			'REMOTE_ADDR'           => '10.0.0.1',
			'HTTP_CF_CONNECTING_IP' => '[2001:db8::7]',
		);
		$this->assertSame( '2001:db8::7', Request::resolve_ip( $cf, 'cf_connecting_ip', $trusted ) );

		$bad = array(
			'REMOTE_ADDR'    => '10.0.0.1',
			'HTTP_X_REAL_IP' => '203.0.113.5:99999',
		);
		$this->assertSame( '10.0.0.1', Request::resolve_ip( $bad, 'x_real_ip', $trusted ) );
	}

	public function test_trusted_proxy_entries_with_a_zero_prefix_are_rejected(): void {
		foreach ( array( '0.0.0.0/0', '::/0', '10.0.0.0/0', '2001:db8::/0' ) as $entry ) {
			$this->assertSame( '', Request::normalize_trusted_proxy( $entry ), $entry );
		}
		$this->assertSame( '10.0.0.0/8', Request::normalize_trusted_proxy( '10.0.0.0/8' ) );
		$this->assertSame( '2001:db8::/32', Request::normalize_trusted_proxy( '2001:db8::/32' ) );
		$this->assertSame( '10.0.0.1', Request::normalize_trusted_proxy( ' 10.0.0.1 ' ) );
		$this->assertSame( '::1', Request::normalize_trusted_proxy( '::1' ) );
		$this->assertSame( '', Request::normalize_trusted_proxy( 'basura' ) );
		$this->assertSame( '', Request::normalize_trusted_proxy( '10.0.0.0/33' ) );
	}

	public function test_prefixes_shorter_than_8_in_ipv4_and_32_in_ipv6_are_rejected(): void {
		foreach ( array( '0.0.0.0/1', '128.0.0.0/1', '10.0.0.0/7', '2001:db8::/31', '::/1', '::ffff:10.0.0.0/103' ) as $entry ) {
			$this->assertSame( '', Request::normalize_trusted_proxy( $entry ), $entry );
		}
		foreach ( array( '10.0.0.0/8', '2001:db8::/32', '173.245.48.0/20', '2400:cb00::/32' ) as $entry ) {
			$this->assertSame( $entry, Request::normalize_trusted_proxy( $entry ), $entry );
		}
	}

	public function test_a_stored_wide_range_never_makes_a_proxy_trusted(): void {
		$server = array(
			'REMOTE_ADDR'          => '198.51.100.9',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
		);
		$this->assertSame( '198.51.100.9', Request::resolve_ip( $server, 'x_forwarded_for', array( '128.0.0.0/1', '0.0.0.0/1' ) ) );
		$this->assertFalse( Request::is_trusted( '198.51.100.9', array( '192.0.0.0/2' ) ) );
		$this->assertTrue( Request::is_trusted( '173.245.48.9', array( '173.245.48.0/20' ) ) );
		$this->assertTrue( Request::is_trusted( '2400:cb00::1', array( '2400:cb00::/32' ) ) );
	}

	public function test_a_stored_zero_prefix_never_makes_a_proxy_trusted(): void {
		$server = array(
			'REMOTE_ADDR'          => '198.51.100.9',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
		);

		$this->assertSame( '198.51.100.9', Request::resolve_ip( $server, 'x_forwarded_for', array( '0.0.0.0/0' ) ) );
		$this->assertSame( '198.51.100.9', Request::resolve_ip( $server, 'x_forwarded_for', array( '::/0' ) ) );
	}

	public function test_ipv4_mapped_cidr_is_normalized_to_ipv4_or_rejected(): void {
		$this->assertSame( '10.0.0.0/8', Request::normalize_trusted_proxy( '::ffff:10.0.0.0/104' ) );
		$this->assertSame( '192.168.1.0/24', Request::normalize_trusted_proxy( '::ffff:192.168.1.0/120' ) );
		$this->assertSame( '10.0.0.1/32', Request::normalize_trusted_proxy( '::ffff:10.0.0.1/128' ) );
		// Un prefijo menor de /97 cubriria mas que el espacio IPv4 mapeado (o seria 0.0.0.0/0).
		$this->assertSame( '', Request::normalize_trusted_proxy( '::ffff:10.0.0.0/96' ) );
		$this->assertSame( '', Request::normalize_trusted_proxy( '::ffff:10.0.0.0/64' ) );
	}

	public function test_a_mapped_cidr_matches_the_ipv4_already_normalized(): void {
		$trusted = array( '::ffff:10.0.0.0/104' );
		$server  = array(
			'REMOTE_ADDR'          => '10.1.2.3',
			'HTTP_X_FORWARDED_FOR' => '203.0.113.9',
		);
		$this->assertSame( '203.0.113.9', Request::resolve_ip( $server, 'x_forwarded_for', $trusted ) );

		// REMOTE_ADDR llega en forma mapeada: se normaliza a IPv4 antes de comparar.
		$server['REMOTE_ADDR'] = '::ffff:10.1.2.3';
		$this->assertSame( '203.0.113.9', Request::resolve_ip( $server, 'x_forwarded_for', $trusted ) );

		// Fuera del rango: la cabecera se ignora.
		$server['REMOTE_ADDR'] = '11.1.2.3';
		$this->assertSame( '11.1.2.3', Request::resolve_ip( $server, 'x_forwarded_for', $trusted ) );
	}

	public function test_get_client_ip_reads_server_and_settings(): void {
		$this->set_server(
			array(
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.50',
			)
		);
		$settings = Mockery::mock( Settings::class );
		$settings->shouldReceive( 'get_general' )->andReturn(
			array(
				'ip_source'          => 'x_forwarded_for',
				'trusted_proxies'    => array( '10.0.0.0/8' ),
				'log_retention_days' => 30,
			)
		);

		$this->assertSame( '203.0.113.50', ( new Request( $settings ) )->get_client_ip() );
	}

	public function test_get_client_ip_defaults_to_remote_addr_and_ignores_spoofed_header(): void {
		$this->set_server(
			array(
				'REMOTE_ADDR'          => '198.51.100.9',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.50',
			)
		);
		$settings = Mockery::mock( Settings::class );
		$settings->shouldReceive( 'get_general' )->andReturn( Settings::default_general() );

		$this->assertSame( '198.51.100.9', ( new Request( $settings ) )->get_client_ip() );
	}
}

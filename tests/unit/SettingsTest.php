<?php
/**
 * Tests de Settings.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey\Functions;
use TotalSecurityExpert\Module_Loader;
use TotalSecurityExpert\Settings;
use TotalSecurityExpert\Tests\Fixtures\Safe_Mode_Loader;

/**
 * Saneado de la opcion unica de ajustes y lectura con valores por defecto.
 */
class SettingsTest extends TestCase {

	/**
	 * Crea Settings con los modulos falsos fake y throwing.
	 *
	 * @param array<string,mixed> $stored      Opciones guardadas.
	 * @param array<int,string>   $ids         Ids de fixture_registry().
	 * @param bool                $stub_errors Si es false, el test espera add_settings_error() con Functions\expect.
	 * @return Settings
	 */
	private function make_settings( array $stored = array(), array $ids = array( 'fake', 'throwing' ), bool $stub_errors = true ): Settings {
		$this->stub_options( $stored );
		if ( $stub_errors ) {
			// add_settings_error() existe solo en el admin de WordPress: sin esto, que exista o no dependeria del orden de los tests.
			Functions\when( 'add_settings_error' )->justReturn( null );
		}
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( $ids ) );
		return new Settings( $loader );
	}

	public function test_sanitize_discards_unknown_module_ids(): void {
		$settings = $this->make_settings();

		$out = $settings->sanitize(
			array(
				'modules' => array(
					'fake'       => array( 'enabled' => '1' ),
					'no-existe'  => array( 'enabled' => '1' ),
					'../../evil' => array( 'enabled' => '1' ),
				),
			)
		);

		$this->assertSame( array( 'fake', 'throwing' ), array_keys( $out['modules'] ) );
		$this->assertTrue( $out['modules']['fake']['enabled'] );
	}

	public function test_modules_are_off_unless_checkbox_is_sent(): void {
		$settings = $this->make_settings();

		$out = $settings->sanitize( array( 'modules' => array( 'fake' => array( 'enabled' => '0' ) ) ) );

		$this->assertFalse( $out['modules']['fake']['enabled'] );
		$this->assertFalse( $out['modules']['throwing']['enabled'] );
	}

	public function test_sanitize_survives_garbage_input(): void {
		$settings = $this->make_settings();

		foreach ( array(
			null,
			'texto',
			42,
			array(
				'general' => 'x',
				'modules' => 'y',
			),
			array( 'modules' => array( 'fake' => 'z' ) ),
		) as $input ) {
			$out = $settings->sanitize( $input );
			$this->assertSame( Settings::default_general(), $out['general'] );
			$this->assertFalse( $out['modules']['fake']['enabled'] );
		}
	}

	public function test_sanitize_general_validates_every_field(): void {
		$settings = $this->make_settings( array(), array( 'fake' ), false );
		Functions\expect( 'add_settings_error' )->once();

		$out = $settings->sanitize(
			array(
				'general' => array(
					'ip_source'          => 'cabecera_inventada',
					'trusted_proxies'    => "10.0.0.0/8\nno-es-ip\n2001:db8::/32\n300.1.1.1\n10.0.0.0/33\n10.0.0.0/8",
					'log_retention_days' => '9999',
				),
			)
		);

		$this->assertSame( 'remote_addr', $out['general']['ip_source'] );
		$this->assertSame( array( '10.0.0.0/8', '2001:db8::/32' ), $out['general']['trusted_proxies'] );
		$this->assertSame( 365, $out['general']['log_retention_days'] );
	}

	public function test_sanitize_general_accepts_valid_values_and_clamps_days(): void {
		$settings = $this->make_settings();

		$ok = $settings->sanitize_general(
			array(
				'ip_source'          => 'x_forwarded_for',
				'trusted_proxies'    => array( '192.168.1.1', '::1' ),
				'log_retention_days' => '90',
			)
		);
		$this->assertSame( 'x_forwarded_for', $ok['ip_source'] );
		$this->assertSame( array( '192.168.1.1', '::1' ), $ok['trusted_proxies'] );
		$this->assertSame( 90, $ok['log_retention_days'] );

		$this->assertSame( 1, $settings->sanitize_general( array( 'log_retention_days' => '-5' ) )['log_retention_days'] );
		$this->assertSame( 30, $settings->sanitize_general( array( 'log_retention_days' => 'abc' ) )['log_retention_days'] );
		$this->assertSame( 30, $settings->sanitize_general( array() )['log_retention_days'] );
	}

	public function test_sanitize_is_idempotent_for_general(): void {
		$settings = $this->make_settings();

		$first  = $settings->sanitize(
			array(
				'general' => array(
					'trusted_proxies' => "10.0.0.1\n10.0.0.2",
					'ip_source'       => 'x_real_ip',
				),
			)
		);
		$second = $settings->sanitize( $first );

		$this->assertSame( $first['general'], $second['general'] );
	}

	public function test_a_module_whose_sanitize_throws_does_not_break_the_rest(): void {
		$settings = $this->make_settings(
			array(
				Settings::OPTION => array(
					'modules' => array(
						'throwing' => array(
							'enabled'  => true,
							'settings' => array( 'flag' => false ),
						),
					),
				),
			),
			array( 'fake', 'throwing' ),
			false
		);
		Functions\expect( 'add_settings_error' )->once();

		$out = $settings->sanitize(
			array(
				'modules' => array(
					'fake'     => array(
						'enabled'  => '1',
						'settings' => array( 'limit' => '12' ),
					),
					'throwing' => array(
						'enabled'  => '1',
						'settings' => array( 'flag' => '1' ),
					),
				),
			)
		);

		$this->assertSame( array( 'limit' => 12 ), $out['modules']['fake']['settings'] );
		// El modulo roto conserva lo que habia guardado.
		$this->assertSame( array( 'flag' => false ), $out['modules']['throwing']['settings'] );
		// Y el error queda apuntado.
		$this->assertArrayHasKey( 'throwing', $this->options[ Module_Loader::ERRORS_OPTION ] );
	}

	public function test_sanitize_general_rejects_zero_prefix_and_normalizes_mapped_ipv4_cidr(): void {
		$settings = $this->make_settings();
		$dropped  = array();

		$out = $settings->sanitize_general(
			array(
				'trusted_proxies' => "0.0.0.0/0\n::/0\n10.0.0.0/8\n::ffff:192.168.0.0/112\n::ffff:10.0.0.0/64\nbasura",
			),
			$dropped
		);

		$this->assertSame( array( '10.0.0.0/8', '192.168.0.0/16' ), $out['trusted_proxies'] );
		$this->assertSame( array( '0.0.0.0/0', '::/0', '::ffff:10.0.0.0/64', 'basura' ), $dropped );
	}

	public function test_sanitize_general_rejects_too_wide_ranges_and_accepts_cloudflare_ones(): void {
		$settings = $this->make_settings();
		$dropped  = array();

		$out = $settings->sanitize_general(
			array(
				'trusted_proxies' => array( '0.0.0.0/1', '128.0.0.0/1', '10.0.0.0/7', '2001:db8::/31', '10.0.0.0/8', '2001:db8::/32', '173.245.48.0/20', '2400:cb00::/32' ),
			),
			$dropped
		);

		$this->assertSame( array( '10.0.0.0/8', '2001:db8::/32', '173.245.48.0/20', '2400:cb00::/32' ), $out['trusted_proxies'] );
		$this->assertSame( array( '0.0.0.0/1', '128.0.0.0/1', '10.0.0.0/7', '2001:db8::/31' ), $dropped );
	}

	public function test_sanitize_reports_discarded_proxy_entries_with_escaped_text(): void {
		$settings = $this->make_settings( array(), array( 'fake' ), false );
		$messages = array();
		Functions\expect( 'add_settings_error' )->once()->andReturnUsing(
			function ( $setting, $code, $message, $type ) use ( &$messages ) {
				$messages[] = array( $setting, $code, $message, $type );
			}
		);

		$out = $settings->sanitize( array( 'general' => array( 'trusted_proxies' => "0.0.0.0/0\n10.0.0.1\nfoo&bar" ) ) );

		$this->assertSame( array( '10.0.0.1' ), $out['general']['trusted_proxies'] );
		$this->assertSame( Settings::GROUP, $messages[0][0] );
		$this->assertStringContainsString( '0.0.0.0/0', $messages[0][2] );
		$this->assertStringContainsString( 'foo&amp;bar', $messages[0][2] );
		$this->assertStringNotContainsString( '10.0.0.1', $messages[0][2] );
		$this->assertSame( 'warning', $messages[0][3] );
	}

	public function test_sanitize_does_not_report_anything_when_every_proxy_entry_is_valid(): void {
		$settings = $this->make_settings( array(), array( 'fake' ), false );
		Functions\expect( 'add_settings_error' )->never();

		$settings->sanitize( array( 'general' => array( 'trusted_proxies' => "10.0.0.0/8\n2001:db8::/32" ) ) );
	}

	public function test_reading_general_never_emits_settings_errors(): void {
		$settings = $this->make_settings( array( Settings::OPTION => array( 'general' => array( 'trusted_proxies' => array( '0.0.0.0/0', '10.0.0.1' ) ) ) ), array( 'fake' ), false );
		Functions\expect( 'add_settings_error' )->never();

		$this->assertSame( array( '10.0.0.1' ), $settings->get_general()['trusted_proxies'] );
	}

	public function test_log_max_rows_is_clamped(): void {
		$settings = $this->make_settings();

		$this->assertSame( 50000, $settings->sanitize_general( array() )['log_max_rows'] );
		$this->assertSame( 1000, $settings->sanitize_general( array( 'log_max_rows' => '5' ) )['log_max_rows'] );
		$this->assertSame( 1000000, $settings->sanitize_general( array( 'log_max_rows' => '99999999' ) )['log_max_rows'] );
		$this->assertSame( 25000, $settings->sanitize_general( array( 'log_max_rows' => '25000' ) )['log_max_rows'] );
		$this->assertSame( 50000, $settings->sanitize_general( array( 'log_max_rows' => 'abc' ) )['log_max_rows'] );
	}

	public function test_sanitize_keeps_the_stored_block_of_a_module_that_is_not_loaded(): void {
		$stored = array(
			'enabled'  => true,
			'settings' => array(
				'secreto' => array( 'a', 'b' ),
				'n'       => 7,
			),
		);
		$this->stub_options( array( Settings::OPTION => array( 'modules' => array( 'missing' => $stored ) ) ) );
		// 'missing' esta en el registro pero su fichero no existe: no se carga.
		$loader   = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'missing', 'notmodule' ) ) );
		$settings = new Settings( $loader );

		$out = $settings->sanitize(
			array(
				'modules' => array(
					'fake'    => array(
						'enabled'  => '1',
						'settings' => array( 'limit' => '3' ),
					),
					'missing' => array(
						'enabled'  => '0',
						'settings' => array( 'n' => 1 ),
					),
				),
			)
		);

		$this->assertSame( $stored, $out['modules']['missing'], 'Se conserva tal cual, ignorando el formulario.' );
		$this->assertSame( array( 'limit' => 3 ), $out['modules']['fake']['settings'] );
		$this->assertArrayNotHasKey( 'notmodule', $out['modules'], 'Sin bloque guardado no se inventa uno.' );
	}

	public function test_sanitize_in_safe_mode_keeps_every_stored_module_block_without_loading_files(): void {
		$fake = array(
			'enabled'  => true,
			'settings' => array( 'limit' => 9 ),
		);
		$this->stub_options( array( Settings::OPTION => array( 'modules' => array( 'fake' => $fake ) ) ) );
		$loader   = new Safe_Mode_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'exploding' ) ) );
		$settings = new Settings( $loader );

		$out = $settings->sanitize( array( 'modules' => array( 'fake' => array( 'enabled' => '0' ) ) ) );

		$this->assertSame( array( 'fake' => $fake ), $out['modules'] );
		$this->assertSame( array(), $loader->get_errors() );
		$this->assertNotContains( realpath( $this->fixtures_path() . 'fixtures/Exploding_Module.php' ), get_included_files() );
	}

	public function test_module_settings_are_merged_with_defaults(): void {
		$settings = $this->make_settings(
			array(
				Settings::OPTION => array(
					'modules' => array(
						'fake' => array(
							'enabled'  => true,
							'settings' => array(),
						),
					),
				),
			)
		);

		$this->assertSame( array( 'limit' => 5 ), $settings->get_module_settings( 'fake' ) );
		$this->assertSame( array(), $settings->get_module_settings( 'no-existe' ) );
		$this->assertTrue( $settings->is_module_enabled( 'fake' ) );
		$this->assertFalse( $settings->is_module_enabled( 'throwing' ) );
	}

	public function test_reading_tolerates_a_corrupt_option(): void {
		$settings = $this->make_settings( array( Settings::OPTION => 'basura' ) );

		$all = $settings->get_all();

		$this->assertSame( Settings::default_general(), $all['general'] );
		$this->assertFalse( $all['modules']['fake']['enabled'] );
		$this->assertSame( array( 'limit' => 5 ), $all['modules']['fake']['settings'] );
	}
}

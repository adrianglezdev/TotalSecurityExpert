<?php
/**
 * Tests de Module_Loader.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use TotalSecurityExpert\Event_Log;
use TotalSecurityExpert\Module_Loader;
use TotalSecurityExpert\Request;
use TotalSecurityExpert\Settings;
use TotalSecurityExpert\Tests\Fixtures\Fake_Module;
use TotalSecurityExpert\Tests\Fixtures\Safe_Mode_Loader;

/**
 * Registro fijo, aislamiento de fallos, modo seguro y modulos apagados.
 */
class ModuleLoaderTest extends TestCase {

	/**
	 * Prepara los contadores del modulo falso y el almacen de opciones.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		Fake_Module::reset();
		$this->stub_options();
	}

	/**
	 * Settings con estos modulos activados.
	 *
	 * @param Module_Loader     $loader  Cargador.
	 * @param array<int,string> $enabled Ids activos.
	 * @return Settings
	 */
	private function settings_with( Module_Loader $loader, array $enabled ): Settings {
		$modules = array();
		foreach ( $enabled as $id ) {
			$modules[ $id ] = array(
				'enabled'  => true,
				'settings' => array(),
			);
		}
		$this->options[ Settings::OPTION ] = array( 'modules' => $modules );
		return new Settings( $loader );
	}

	/**
	 * Arranca los modulos del cargador con Event_Log y Request simulados.
	 *
	 * @param Module_Loader $loader   Cargador.
	 * @param Settings      $settings Ajustes.
	 * @return void
	 */
	private function boot( Module_Loader $loader, Settings $settings ): void {
		$loader->boot_modules( $settings, Mockery::mock( Event_Log::class ), Mockery::mock( Request::class ) );
	}

	public function test_default_registry_is_the_fixed_list_of_four(): void {
		$this->assertSame(
			array( 'login-limit', 'hardening', 'admin-alert', 'activity-log' ),
			array_keys( Module_Loader::REGISTRY )
		);
		$this->assertSame( 'TotalSecurityExpert\Modules\Login_Limit', Module_Loader::REGISTRY['login-limit']['class'] );
		$this->assertSame( 'modules/activity-log/class-activity-log.php', Module_Loader::REGISTRY['activity-log']['file'] );
	}

	public function test_missing_module_file_is_ignored_without_errors(): void {
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'missing' ) ) );

		$loader->load();

		$this->assertSame( array( 'fake' ), array_keys( $loader->get_modules() ) );
		$this->assertNull( $loader->get_module( 'missing' ) );
		$this->assertSame( array(), $this->options, 'Un fichero ausente no escribe nada en la BD.' );
	}

	public function test_registry_with_no_files_at_all_loads_nothing(): void {
		$loader = new Module_Loader( sys_get_temp_dir() . '/tsexp-no-such-dir/' );

		$this->assertSame( array(), $loader->get_modules() );
	}

	public function test_class_that_does_not_implement_module_is_discarded_and_reported(): void {
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'notmodule' ) ) );

		$this->assertSame( array( 'fake' ), array_keys( $loader->get_modules() ) );
		$this->assertArrayHasKey( 'notmodule', $loader->get_errors() );
	}

	public function test_safe_mode_boots_nothing(): void {
		$loader   = new class( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) ) extends Module_Loader {
			/**
			 * Modo seguro forzado.
			 *
			 * @return bool
			 */
			public function is_safe_mode(): bool {
				return true;
			}
		};
		$settings = $this->settings_with( $loader, array( 'fake' ) );

		$this->boot( $loader, $settings );

		$this->assertSame( 0, Fake_Module::$boot_calls );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_safe_mode_constant_true_boots_nothing(): void {
		define( 'TSEXP_SAFE_MODE', true );
		$loader   = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) );
		$settings = $this->settings_with( $loader, array( 'fake' ) );

		$this->assertTrue( $loader->is_safe_mode() );
		$this->boot( $loader, $settings );

		$this->assertSame( 0, Fake_Module::$boot_calls );
	}

	public function test_safe_mode_is_off_when_constant_is_not_defined(): void {
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) );

		$this->assertFalse( $loader->is_safe_mode() );
	}

	public function test_enabled_module_is_booted_with_its_settings(): void {
		$loader   = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) );
		$settings = $this->settings_with( $loader, array( 'fake' ) );

		$this->boot( $loader, $settings );

		$this->assertSame( 1, Fake_Module::$boot_calls );
		$this->assertSame( array( 'limit' => 5 ), Fake_Module::$last_settings );
	}

	public function test_disabled_module_is_not_booted(): void {
		$loader   = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) );
		$settings = $this->settings_with( $loader, array() );

		$this->boot( $loader, $settings );

		$this->assertSame( 0, Fake_Module::$boot_calls );
	}

	public function test_a_module_whose_boot_throws_is_recorded_and_the_others_still_boot(): void {
		$loader   = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'throwing', 'fake' ) ) );
		$settings = $this->settings_with( $loader, array( 'throwing', 'fake' ) );

		$this->boot( $loader, $settings );

		$this->assertSame( 1, Fake_Module::$boot_calls );
		$errors = $loader->get_errors();
		$this->assertArrayHasKey( 'throwing', $errors );
		$this->assertStringContainsString( 'boot roto', $errors['throwing']['message'] );
	}

	public function test_record_error_does_not_rewrite_the_option_when_nothing_changed(): void {
		$loader = new Module_Loader( $this->fixtures_path(), array() );
		$writes = 0;
		\Brain\Monkey\Functions\when( 'update_option' )->alias(
			function ( string $name, $value ) use ( &$writes ) {
				++$writes;
				$this->options[ $name ] = $value;
				return true;
			}
		);

		$loader->record_error( 'fake', 'mismo error' );
		$loader->record_error( 'fake', 'mismo error' );

		$this->assertSame( 1, $writes );

		// Pasado el bloqueo de 10 minutos, un mensaje distinto si se escribe.
		$this->transients = array();
		$loader->record_error( 'fake', 'otro error' );

		$this->assertSame( 2, $writes );
		$this->assertSame( 'otro error', $loader->get_errors()['fake']['message'] );
	}

	public function test_record_error_writes_at_most_once_per_module_every_ten_minutes_even_if_the_message_changes(): void {
		$loader = new Module_Loader( $this->fixtures_path(), array() );
		$writes = 0;
		\Brain\Monkey\Functions\when( 'update_option' )->alias(
			function ( string $name, $value ) use ( &$writes ) {
				++$writes;
				$this->options[ $name ] = $value;
				return true;
			}
		);

		// Un mensaje variable (p. ej. con un id o una hora) no debe provocar una escritura por peticion.
		for ( $i = 0; $i < 20; $i++ ) {
			$loader->record_error( 'fake', 'fallo numero ' . $i );
		}

		$this->assertSame( 1, $writes );
		$this->assertSame( 'fallo numero 0', $loader->get_errors()['fake']['message'] );
		$this->assertSame( 600, Module_Loader::LOCK_SECONDS );
		$this->assertArrayHasKey( 'tsexp_err_lock_fake', $this->transients );

		// Otro modulo tiene su propio bloqueo.
		$loader->record_error( 'hardening', 'otro fallo' );
		$this->assertSame( 2, $writes );
	}

	public function test_clear_errors_also_releases_the_locks(): void {
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) );
		$loader->record_error( 'fake', 'x' );
		$this->assertArrayHasKey( 'tsexp_err_lock_fake', $this->transients );

		$loader->clear_errors();

		$this->assertSame( array(), $this->transients );
		$this->assertSame( array(), $loader->get_errors() );
	}

	public function test_format_error_keeps_only_class_hook_and_a_message_cut_to_120_characters(): void {
		$e = new \RuntimeException( str_repeat( 'a', 300 ) . "\n" . '/var/www/secreto.php' );

		$text = Module_Loader::format_error( $e, 'init' );

		$this->assertSame( 'RuntimeException @ init: ' . str_repeat( 'a', 120 ), $text );
		$this->assertStringNotContainsString( 'secreto', $text );
		$this->assertSame( 'LogicException: x', Module_Loader::format_error( new \LogicException( 'x' ) ) );
	}

	public function test_a_boot_failure_is_stored_as_class_hook_and_short_message(): void {
		$loader   = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'throwing' ) ) );
		$settings = $this->settings_with( $loader, array( 'throwing' ) );

		$this->boot( $loader, $settings );

		$this->assertSame( 'RuntimeException @ boot: boot roto', $loader->get_errors()['throwing']['message'] );
	}

	public function test_safe_mode_never_requires_a_module_file(): void {
		$loader = new Safe_Mode_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'exploding' ) ) );

		$loader->load();

		$this->assertSame( array(), $loader->get_modules() );
		$this->assertNull( $loader->get_module( 'fake' ) );
		$this->assertSame( array(), $loader->get_errors(), 'Si se hubiera cargado el fixture, habria un error apuntado.' );
		$this->assertNotContains( realpath( $this->fixtures_path() . 'fixtures/Exploding_Module.php' ), get_included_files() );
		$this->assertSame( array( 'fake', 'exploding' ), $loader->get_registry_ids() );
	}

	public function test_safe_mode_boot_does_not_touch_modules_or_files(): void {
		$loader   = new Safe_Mode_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'exploding' ) ) );
		$settings = $this->settings_with( $loader, array( 'fake', 'exploding' ) );

		$this->boot( $loader, $settings );

		$this->assertSame( 0, Fake_Module::$boot_calls );
		$this->assertSame( array(), $loader->get_errors() );
		$this->assertNotContains( realpath( $this->fixtures_path() . 'fixtures/Exploding_Module.php' ), get_included_files() );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_without_safe_mode_the_exploding_fixture_is_loaded_and_its_failure_is_contained(): void {
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'exploding', 'fake' ) ) );

		$this->assertSame( array( 'fake' ), array_keys( $loader->get_modules() ) );
		$this->assertStringContainsString( 'RuntimeException @ load', $loader->get_errors()['exploding']['message'] );
	}

	/**
	 * Valores de TSEXP_SAFE_MODE: lo que activa el modo seguro y lo que no.
	 *
	 * @return array<string,array{0:mixed,1:bool}>
	 */
	public static function safe_mode_values(): array {
		return array(
			'true'          => array( true, true ),
			'int 1'         => array( 1, true ),
			'string 1'      => array( '1', true ),
			'string true'   => array( 'true', true ),
			'string TRUE'   => array( 'TRUE', true ),
			'false'         => array( false, false ),
			'int 0'         => array( 0, false ),
			'string 0'      => array( '0', false ),
			'string false'  => array( 'false', false ),
			'empty string'  => array( '', false ),
			'null'          => array( null, false ),
			'random string' => array( 'quizas', false ),
			'array'         => array( array( 'true' ), false ),
		);
	}

	#[DataProvider( 'safe_mode_values' )]
	public function test_safe_mode_accepted_values( $value, bool $expected ): void {
		$this->assertSame( $expected, Module_Loader::is_truthy( $value ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_safe_mode_constant_as_string_true_blocks_loading(): void {
		define( 'TSEXP_SAFE_MODE', 'true' );
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'exploding' ) ) );

		$this->assertTrue( $loader->is_safe_mode() );
		$this->assertSame( array(), $loader->get_modules() );
		$this->assertSame( array(), $loader->get_errors() );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_safe_mode_constant_false_does_not_block_loading(): void {
		define( 'TSEXP_SAFE_MODE', false );
		$loader = new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) );

		$this->assertFalse( $loader->is_safe_mode() );
		$this->assertSame( array( 'fake' ), array_keys( $loader->get_modules() ) );
	}

	public function test_record_error_never_throws_and_cleans_the_message(): void {
		$loader = new Module_Loader( $this->fixtures_path(), array() );
		\Brain\Monkey\Functions\when( 'update_option' )->alias(
			static function () {
				throw new \RuntimeException( 'BD caida' );
			}
		);

		$loader->record_error( 'fake', 'x' );

		$this->assertTrue( true ); // No ha lanzado.
	}

	public function test_errors_are_cleared_and_corrupt_stored_errors_are_ignored(): void {
		$loader                                        = new Module_Loader( $this->fixtures_path(), array() );
		$this->options[ Module_Loader::ERRORS_OPTION ] = array(
			'ok'  => array(
				'message' => 'm',
				'time'    => 5,
			),
			'bad' => 'texto',
		);

		$this->assertSame(
			array(
				'ok' => array(
					'message' => 'm',
					'time'    => 5,
				),
			),
			$loader->get_errors()
		);

		$loader->clear_errors();
		$this->assertSame( array(), $loader->get_errors() );
	}
}

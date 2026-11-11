<?php
/**
 * Tests de desactivacion, desinstalacion y crons del nucleo.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use Mockery;
use TotalSecurityExpert\Event_Log;
use TotalSecurityExpert\Module_Loader;
use TotalSecurityExpert\Plugin;
use TotalSecurityExpert\Request;
use TotalSecurityExpert\Settings;
use TotalSecurityExpert\Tests\Fixtures\Fake_Module;
use TotalSecurityExpert\Tests\Fixtures\Safe_Mode_Loader;

/**
 * Desactivar quita crons sin borrar datos; desinstalar borra tabla, opciones y transients.
 */
class PluginTest extends TestCase {

	/**
	 * Plugin sin pasar por el constructor, con estos servicios.
	 *
	 * @param array<string,object> $services loader, settings, request, event_log.
	 * @return Plugin
	 */
	private function make_plugin( array $services ): Plugin {
		$reflection = new \ReflectionClass( Plugin::class );
		$plugin     = $reflection->newInstanceWithoutConstructor();
		foreach ( $services as $name => $service ) {
			$property = $reflection->getProperty( $name );
			$property->setValue( $plugin, $service );
		}
		return $plugin;
	}

	public function test_deactivate_clears_both_crons_and_touches_no_data(): void {
		$wpdb = $this->mock_wpdb();
		$wpdb->shouldNotReceive( 'query' );
		Functions\expect( 'wp_clear_scheduled_hook' )->once()->with( 'tsexp_hourly' );
		Functions\expect( 'wp_clear_scheduled_hook' )->once()->with( 'tsexp_daily' );
		Functions\expect( 'delete_option' )->never();

		Plugin::deactivate();
	}

	public function test_uninstall_drops_the_table_and_deletes_only_tsexp_options_and_transients(): void {
		Fake_Module::reset();
		$wpdb    = $this->mock_wpdb( 'wp_' );
		$queries = array();
		$wpdb->shouldReceive( 'query' )->twice()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return 1;
			}
		);
		Functions\expect( 'wp_clear_scheduled_hook' )->twice();
		Functions\expect( 'wp_cache_delete' )->twice();

		// Cargador con los modulos de fixtures: el test no depende de los modulos reales.
		Plugin::uninstall( new Module_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake' ) ) ) );

		$this->assertSame( 1, Fake_Module::$uninstall_calls, 'Se llama a uninstall() de cada modulo cargado.' );
		$this->assertSame( 'DROP TABLE IF EXISTS `wp_tsexp_events`', $queries[0] );
		$this->assertStringStartsWith( 'DELETE FROM `wp_options` WHERE', $queries[1] );
		foreach ( array( 'tsexp\_%', '\_transient\_tsexp\_%', '\_transient\_timeout\_tsexp\_%' ) as $like ) {
			$this->assertStringContainsString( "option_name LIKE '" . addslashes( $like ) . "'", $queries[1] );
		}
		// Ningun patron generico que pudiera borrar opciones de otros plugins.
		$this->assertStringNotContainsString( "LIKE '%'", $queries[1] );
	}

	public function test_uninstall_in_safe_mode_does_not_load_module_files_but_still_cleans_the_core(): void {
		$wpdb    = $this->mock_wpdb( 'wp_' );
		$queries = array();
		$wpdb->shouldReceive( 'query' )->twice()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return 1;
			}
		);
		Functions\expect( 'wp_clear_scheduled_hook' )->twice();
		Functions\expect( 'wp_cache_delete' )->twice();

		Plugin::uninstall( new Safe_Mode_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'exploding' ) ) ) );

		$this->assertSame( 'DROP TABLE IF EXISTS `wp_tsexp_events`', $queries[0] );
		$this->assertNotContains( realpath( $this->fixtures_path() . 'fixtures/Exploding_Module.php' ), get_included_files() );
	}

	/**
	 * Ejecuta uninstall() en modo seguro con $wpdb simulado; devuelve las consultas y los patrones SHOW TABLES.
	 *
	 * @param array<string,array<int,string>> $tables_by_prefix Tablas que devuelve SHOW TABLES, por patron LIKE.
	 * @param string                          $base_prefix      Prefijo base (red).
	 * @return array{queries:array<int,string>,shows:array<int,string>}
	 */
	private function run_safe_mode_uninstall( array $tables_by_prefix, string $base_prefix = 'wp_' ): array {
		$wpdb              = $this->mock_wpdb( 'wp_' );
		$wpdb->base_prefix = $base_prefix;
		$queries           = array();
		$shows             = array();
		$wpdb->shouldReceive( 'get_col' )->andReturnUsing(
			function ( $query ) use ( &$shows, $tables_by_prefix ) {
				$shows[] = $query;
				foreach ( $tables_by_prefix as $needle => $tables ) {
					if ( str_contains( $query, "'" . $needle . "%'" ) ) {
						return $tables;
					}
				}
				return array();
			}
		);
		$wpdb->shouldReceive( 'query' )->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return 1;
			}
		);
		Functions\expect( 'wp_clear_scheduled_hook' )->twice();
		Functions\expect( 'wp_cache_delete' )->twice();

		Plugin::uninstall( new Safe_Mode_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'exploding' ) ) ) );

		return array(
			'queries' => $queries,
			'shows'   => $shows,
		);
	}

	public function test_uninstall_in_safe_mode_drops_module_tables_found_by_prefix(): void {
		$result = $this->run_safe_mode_uninstall(
			array( 'wp\\\\_tsexp\\\\_' => array( 'wp_tsexp_events', 'wp_tsexp_login_attempts' ) )
		);

		$this->assertSame( array( "SHOW TABLES LIKE 'wp\\\\_tsexp\\\\_%'" ), $result['shows'], 'Un solo patron si prefix y base_prefix coinciden, con _ escapado.' );
		$this->assertContains( 'DROP TABLE IF EXISTS `wp_tsexp_login_attempts`', $result['queries'] );
		$this->assertContains( 'DROP TABLE IF EXISTS `wp_tsexp_events`', $result['queries'] );
	}

	public function test_uninstall_also_sweeps_the_network_base_prefix(): void {
		$result = $this->run_safe_mode_uninstall(
			array( 'wp\\\\_tsexp\\\\_' => array( 'wp_tsexp_login_attempts' ) ),
			'net_'
		);

		$this->assertCount( 2, $result['shows'] );
		$this->assertStringContainsString( "'net\\\\_tsexp\\\\_%'", $result['shows'][1] );
	}

	public function test_uninstall_never_drops_tables_that_only_look_like_ours(): void {
		$result = $this->run_safe_mode_uninstall(
			array( 'wp\\\\_tsexp\\\\_' => array( 'wp_tsexpfoo', 'wp_other_tsexp_x', 'wp_tsexp_ok' ) )
		);

		$drops = array_filter(
			$result['queries'],
			static fn( $query ) => str_starts_with( $query, 'DROP TABLE' )
		);
		$this->assertNotContains( 'DROP TABLE IF EXISTS `wp_tsexpfoo`', $drops );
		$this->assertNotContains( 'DROP TABLE IF EXISTS `wp_other_tsexp_x`', $drops );
		$this->assertContains( 'DROP TABLE IF EXISTS `wp_tsexp_ok`', $drops );
	}

	public function test_activation_in_safe_mode_installs_the_core_without_loading_module_files(): void {
		$this->stub_options();
		Functions\when( 'wp_next_scheduled' )->justReturn( 123 );
		$loader = new Safe_Mode_Loader( $this->fixtures_path(), $this->fixture_registry( array( 'fake', 'exploding' ) ) );
		$plugin = $this->make_plugin(
			array(
				'loader'    => $loader,
				'event_log' => Mockery::mock( Event_Log::class )->shouldReceive( 'install' )->once()->getMock(),
			)
		);

		$plugin->install_all();

		$this->assertSame( array(), $loader->get_errors() );
		$this->assertSame( TSEXP_DB_VERSION, $this->options[ Plugin::DB_VERSION ] );
		$this->assertNotContains( realpath( $this->fixtures_path() . 'fixtures/Exploding_Module.php' ), get_included_files() );
	}

	public function test_hourly_cron_trims_the_log_to_the_configured_maximum(): void {
		$settings  = Mockery::mock( Settings::class );
		$event_log = Mockery::mock( Event_Log::class );
		$settings->shouldReceive( 'get_general' )->andReturn( array_merge( Settings::default_general(), array( 'log_max_rows' => 7777 ) ) );
		$event_log->shouldReceive( 'trim_to_max_rows' )->once()->with( 7777 );
		$loader = Mockery::mock( Module_Loader::class );
		$loader->shouldReceive( 'load' );
		$loader->shouldReceive( 'boot_modules' );
		$plugin = $this->make_plugin(
			array(
				'loader'    => $loader,
				'settings'  => $settings,
				'request'   => Mockery::mock( Request::class ),
				'event_log' => $event_log,
			)
		);
		Functions\when( 'is_admin' )->justReturn( false );
		Actions\expectAdded( Plugin::CRON_HOURLY )->once();

		$plugin->run();
		$plugin->trim_logs();
	}
}

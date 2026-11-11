<?php
/**
 * Clase base de los tests: Brain Monkey, stubs de WordPress y ayudantes.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Actions;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use TotalSecurityExpert\Context;
use TotalSecurityExpert\Event_Log;
use TotalSecurityExpert\Request;
use TotalSecurityExpert\Tests\Fixtures\Wpdb_Stub;

/**
 * Base para todos los tests del plugin (nucleo y modulos).
 *
 * Ayudantes:
 * - mock_wpdb( $prefix )                       $wpdb simulado en $GLOBALS['wpdb'].
 * - make_context( $module_id, $ip )            Context real con Event_Log y Request simulados.
 * - capture_hooks( 'hook', ... )               Guarda los callbacks que el codigo registra.
 * - do_captured_action( $hook, ...$args )      Ejecuta lo capturado para una accion.
 * - apply_captured_filter( $hook, $v, ...$a )  Ejecuta lo capturado para un filtro y devuelve el valor.
 * - set_server( array )                        Sustituye $_SERVER (se restaura solo).
 * - stub_options( array )                      get/update/delete_option y get/set/delete_transient en memoria
 *                                              ($this->options, $this->transients).
 * - fixture_registry() / fixtures_path()       Modulos falsos para probar Module_Loader.
 */
abstract class TestCase extends PHPUnitTestCase {

	use MockeryPHPUnitIntegration;

	/**
	 * Mock de Event_Log del ultimo make_context().
	 *
	 * @var MockInterface|Event_Log|null
	 */
	protected $event_log_mock = null;

	/**
	 * Mock de Request del ultimo make_context().
	 *
	 * @var MockInterface|Request|null
	 */
	protected $request_mock = null;

	/**
	 * Errores que el ultimo Context ha apuntado: lista de array( modulo, mensaje ).
	 *
	 * @var array<int,array{0:string,1:string}>
	 */
	protected array $reported_errors = array();

	/**
	 * Callbacks capturados: tipo => hook => lista de array( callback, prioridad, args ).
	 *
	 * @var array<string,array<string,array<int,array{0:callable,1:int,2:int}>>>
	 */
	private array $captured = array(
		'action' => array(),
		'filter' => array(),
	);

	/**
	 * Almacen de opciones de stub_options().
	 *
	 * @var array<string,mixed>
	 */
	protected array $options = array();

	/**
	 * Almacen de transients de stub_options().
	 *
	 * @var array<string,mixed>
	 */
	protected array $transients = array();

	/**
	 * Copia de $_SERVER para restaurarla.
	 *
	 * @var array<string,mixed>
	 */
	private array $server_backup = array();

	/**
	 * Prepara Brain Monkey y los stubs de funciones de WordPress.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();

		$this->server_backup   = $_SERVER;
		$this->captured        = array(
			'action' => array(),
			'filter' => array(),
		);
		$this->reported_errors = array();

		Functions\stubTranslationFunctions();
		Functions\stubEscapeFunctions();
		Functions\stubs(
			array(
				'sanitize_text_field' => static fn( $v ) => trim( preg_replace( '/<[^>]*>/', '', (string) $v ) ),
				'sanitize_key'        => static fn( $v ) => preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $v ) ),
				'wp_unslash'          => static fn( $v ) => is_string( $v ) ? stripslashes( $v ) : $v,
				'absint'              => static fn( $v ) => abs( (int) $v ),
				'wp_json_encode'      => static fn( $v ) => json_encode( $v ), // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Es el stub de wp_json_encode().
				'get_current_user_id' => 0,
			)
		);
	}

	/**
	 * Limpia Brain Monkey, $wpdb y $_SERVER.
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		unset( $GLOBALS['wpdb'] );
		$_SERVER = $this->server_backup;
		Monkey\tearDown();
		parent::tearDown();
	}

	/**
	 * Crea un $wpdb simulado (parcial: prepare() y esc_like() reales) y lo deja en $GLOBALS['wpdb'].
	 *
	 * @param string $prefix Prefijo de tablas.
	 * @return MockInterface|Wpdb_Stub
	 */
	protected function mock_wpdb( string $prefix = 'wp_' ) {
		$wpdb         = Mockery::mock( Wpdb_Stub::class )->makePartial();
		$wpdb->prefix = $prefix;

		$wpdb->base_prefix = $prefix;

		$wpdb->options = $prefix . 'options';

		$GLOBALS['wpdb'] = $wpdb; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Es el objetivo del helper: simular $wpdb en tests.
		return $wpdb;
	}

	/**
	 * Crea un Context real con Event_Log y Request simulados.
	 *
	 * Despues de llamarlo, $this->event_log_mock permite esperar llamadas a log()
	 * y $this->reported_errors recoge los errores que el Context apunte.
	 *
	 * @param string $module_id Id del modulo.
	 * @param string $ip        IP que devolvera get_client_ip().
	 * @return Context
	 */
	protected function make_context( string $module_id = 'test-module', string $ip = '203.0.113.7' ): Context {
		$this->event_log_mock = Mockery::mock( Event_Log::class );
		$this->request_mock   = Mockery::mock( Request::class );
		$this->request_mock->shouldReceive( 'get_client_ip' )->andReturn( $ip );
		$this->request_mock->shouldReceive( 'get_client_ip_bucket' )->andReturn( Request::ip_bucket( $ip ) );

		return new Context(
			$module_id,
			$this->event_log_mock,
			$this->request_mock,
			function ( string $id, string $message ): void {
				$this->reported_errors[] = array( $id, $message );
			}
		);
	}

	/**
	 * Empieza a capturar lo que se registre con add_action()/add_filter() para estos hooks.
	 * Llamar antes de ejecutar el codigo que registra (p. ej. antes de module->boot()).
	 *
	 * @param string ...$hooks Nombres de hook.
	 * @return void
	 */
	protected function capture_hooks( string ...$hooks ): void {
		foreach ( $hooks as $hook ) {
			foreach ( array( 'action', 'filter' ) as $type ) {
				$expectation = 'action' === $type ? Actions\expectAdded( $hook ) : Filters\expectAdded( $hook );
				$expectation->zeroOrMoreTimes()->whenHappen(
					function ( $callback, $priority = 10, $args = 1 ) use ( $type, $hook ) {
						$this->captured[ $type ][ $hook ][] = array( $callback, (int) $priority, (int) $args );
					}
				);
			}
		}
	}

	/**
	 * Callbacks capturados para un hook, en orden de registro.
	 *
	 * @param string $hook Nombre del hook.
	 * @return array<int,callable>
	 */
	protected function captured_callbacks( string $hook ): array {
		$out = array();
		foreach ( array( 'action', 'filter' ) as $type ) {
			foreach ( $this->captured[ $type ][ $hook ] ?? array() as $item ) {
				$out[] = $item[0];
			}
		}
		return $out;
	}

	/**
	 * Ejecuta los callbacks capturados de una accion.
	 *
	 * @param string $hook    Nombre del hook.
	 * @param mixed  ...$args Argumentos de la accion.
	 * @return void
	 */
	protected function do_captured_action( string $hook, ...$args ): void {
		foreach ( $this->captured['action'][ $hook ] ?? array() as $item ) {
			$item[0]( ...array_slice( $args, 0, $item[2] ) );
		}
	}

	/**
	 * Pasa un valor por los callbacks capturados de un filtro, en orden de registro.
	 *
	 * @param string $hook    Nombre del hook.
	 * @param mixed  $value   Valor inicial.
	 * @param mixed  ...$args Argumentos extra del filtro.
	 * @return mixed
	 */
	protected function apply_captured_filter( string $hook, $value, ...$args ) {
		foreach ( $this->captured['filter'][ $hook ] ?? array() as $item ) {
			$value = $item[0]( ...array_slice( array_merge( array( $value ), $args ), 0, $item[2] ) );
		}
		return $value;
	}

	/**
	 * Simula get_option/update_option/delete_option con un almacen en memoria.
	 * Despues, $this->options tiene el estado actual.
	 *
	 * @param array<string,mixed> $initial Opciones iniciales.
	 * @return void
	 */
	protected function stub_options( array $initial = array() ): void {
		$this->options    = $initial;
		$this->transients = array();

		Functions\when( 'get_option' )->alias(
			function ( string $name, $fallback = false ) {
				return array_key_exists( $name, $this->options ) ? $this->options[ $name ] : $fallback;
			}
		);
		Functions\when( 'update_option' )->alias(
			function ( string $name, $value ): bool {
				$this->options[ $name ] = $value;
				return true;
			}
		);
		Functions\when( 'delete_option' )->alias(
			function ( string $name ): bool {
				unset( $this->options[ $name ] );
				return true;
			}
		);
		Functions\when( 'get_transient' )->alias(
			function ( string $name ) {
				return array_key_exists( $name, $this->transients ) ? $this->transients[ $name ] : false;
			}
		);
		Functions\when( 'set_transient' )->alias(
			function ( string $name, $value ): bool {
				$this->transients[ $name ] = $value;
				return true;
			}
		);
		Functions\when( 'delete_transient' )->alias(
			function ( string $name ): bool {
				unset( $this->transients[ $name ] );
				return true;
			}
		);
	}

	/**
	 * Registro de modulos de prueba (ver tests/fixtures) para Module_Loader.
	 * Usar con: new Module_Loader( $this->fixtures_path(), $this->fixture_registry() ).
	 *
	 * @param array<int,string> $ids Ids a incluir (por defecto fake y throwing). 'exploding' falla al cargar el fichero.
	 * @return array<string,array{class:string,file:string}>
	 */
	protected function fixture_registry( array $ids = array( 'fake', 'throwing' ) ): array {
		$all = array(
			'fake'      => array(
				'class' => 'TotalSecurityExpert\Tests\Fixtures\Fake_Module',
				'file'  => 'fixtures/Fake_Module.php',
			),
			'throwing'  => array(
				'class' => 'TotalSecurityExpert\Tests\Fixtures\Throwing_Module',
				'file'  => 'fixtures/Throwing_Module.php',
			),
			'notmodule' => array(
				'class' => 'TotalSecurityExpert\Tests\Fixtures\Not_A_Module',
				'file'  => 'fixtures/Not_A_Module.php',
			),
			'exploding' => array(
				'class' => 'TotalSecurityExpert\Tests\Fixtures\Exploding_Module',
				'file'  => 'fixtures/Exploding_Module.php',
			),
			'missing'   => array(
				'class' => 'TotalSecurityExpert\Tests\Fixtures\Missing_Module',
				'file'  => 'fixtures/Missing_Module.php',
			),
		);
		return array_intersect_key( $all, array_flip( $ids ) );
	}

	/**
	 * Carpeta tests/ (con barra final), base de las rutas de fixture_registry().
	 *
	 * @return string
	 */
	protected function fixtures_path(): string {
		return dirname( __DIR__ ) . '/';
	}

	/**
	 * Sustituye $_SERVER por estos valores (se restaura en tearDown).
	 *
	 * @param array<string,mixed> $server Valores.
	 * @return void
	 */
	protected function set_server( array $server ): void {
		$_SERVER = $server;
	}
}

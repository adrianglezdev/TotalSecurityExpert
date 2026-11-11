<?php
/**
 * Tests del modulo login-limit.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey\Actions;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use Mockery;
use TotalSecurityExpert\Modules\Login_Limit;

require_once dirname( __DIR__, 2 ) . '/modules/login-limit/class-login-limit.php';
require_once __DIR__ . '/login-limit-wp-doubles.php';

/**
 * Lo que bloquea y lo que deja pasar el limite de intentos.
 *
 * La base de datos es una simulacion en memoria que entiende las consultas
 * del modulo; el SQL real (ON DUPLICATE KEY UPDATE) no se ejecuta aqui y se
 * comprueba en Playground.
 */
class LoginLimitTest extends TestCase {

	private const IP  = '203.0.113.7';
	private const V6A = '2001:db8:1:2::5';
	private const V6B = '2001:db8:1:2:aaaa::9';
	private const V6C = '2001:db8:1:3::5';

	/**
	 * Filas simuladas: grupo de IP => columnas.
	 *
	 * @var array<string,array<string,int>>
	 */
	private array $rows = array();

	/**
	 * SQL recibido por query().
	 *
	 * @var array<int,string>
	 */
	private array $queries = array();

	/**
	 * Si la simulacion lanza al leer (para probar que falla abierto).
	 *
	 * @var bool
	 */
	private bool $db_throws = false;

	/**
	 * Si la lectura de la fila no devuelve nada (tabla antigua o rota).
	 *
	 * @var bool
	 */
	private bool $db_unreadable = false;

	/**
	 * Si la tabla tiene la columna daily_count (para SHOW COLUMNS).
	 *
	 * @var bool
	 */
	private bool $has_column = true;

	/**
	 * Anchura simulada de la columna ip (para la comprobacion del esquema).
	 *
	 * @var int
	 */
	private int $ip_width = 64;

	/**
	 * Transients simulados.
	 *
	 * @var array<string,mixed>
	 */
	private array $ll_transients = array();

	/**
	 * Usuarios y correos que "existen".
	 *
	 * @var array<int,string>
	 */
	private array $known_users = array( 'admin', 'ana@example.test' );

	/**
	 * Monta $wpdb simulado y los stubs de WordPress.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->rows          = array();
		$this->queries       = array();
		$this->db_throws     = false;
		$this->db_unreadable = false;
		$this->has_column    = true;
		$this->ip_width      = 64;
		$this->ll_transients = array();
		$this->known_users   = array( 'admin', 'ana@example.test' );
		$this->stub_options();

		$wpdb = $this->mock_wpdb();
		$wpdb->shouldReceive( 'query' )->andReturnUsing( fn( $sql ) => $this->fake_query( $sql ) );
		$wpdb->shouldReceive( 'get_var' )->andReturnUsing( fn( $sql ) => $this->fake_get_var( $sql ) );
		$wpdb->shouldReceive( 'get_results' )->andReturnUsing( fn( $sql ) => $this->fake_get_results( $sql ) );
		$wpdb->shouldReceive( 'get_row' )->andReturnUsing( fn( $sql ) => $this->fake_get_row( $sql ) );

		Functions\when( 'home_url' )->justReturn( 'https://example.test' );
		Functions\when( 'site_url' )->justReturn( 'https://example.test/wp' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );
		Functions\when( 'username_exists' )->alias( fn( $name ) => in_array( $name, $this->known_users, true ) ? 1 : false );
		Functions\when( 'email_exists' )->alias( fn( $name ) => in_array( $name, $this->known_users, true ) ? 1 : false );
		Functions\when( 'get_transient' )->alias( fn( $name ) => $this->ll_transients[ $name ] ?? false );
		Functions\when( 'set_transient' )->alias(
			function ( $name, $value ) {
				$this->ll_transients[ $name ] = $value;
				return true;
			}
		);
		Functions\when( 'delete_transient' )->alias(
			function ( $name ) {
				unset( $this->ll_transients[ $name ] );
				return true;
			}
		);
	}

	// Simulacion de la base de datos.

	/**
	 * Ejecuta un INSERT/UPDATE/DELETE/DROP.
	 *
	 * @param string $sql SQL ya preparado.
	 * @return int
	 */
	private function fake_query( string $sql ): int {
		$this->queries[] = $sql;

		if ( preg_match( "/INSERT INTO `[^`]+` .*?VALUES \('([^']*)', 1, (\d+), 0, 0, 0, 1, (\d+)\)/s", $sql, $m ) ) {
			preg_match( '/first_attempt < (\d+) OR/', $sql, $c );
			preg_match( '/daily_start < (\d+), 1/', $sql, $d );
			$ip   = $m[1];
			$now  = (int) $m[2];
			$cut  = (int) $c[1];
			$dcut = (int) $d[1];
			if ( ! isset( $this->rows[ $ip ] ) ) {
				$this->rows[ $ip ] = $this->row(
					array(
						'attempts'      => 1,
						'first_attempt' => $now,
						'daily_count'   => 1,
						'daily_start'   => $now,
					)
				);
				return 1;
			}
			$r = $this->rows[ $ip ];
			if ( $r['locked_until'] > $now ) {
				return 0;
			}
			$expired = $r['locked_until'] > 0;
			if ( $r['first_attempt'] < $cut || $expired ) {
				$r['attempts']      = 1;
				$r['first_attempt'] = $now;
			} else {
				++$r['attempts'];
			}
			if ( $r['daily_start'] < $dcut ) {
				$r['daily_count'] = 1;
				$r['daily_start'] = $now;
			} else {
				++$r['daily_count'];
			}
			if ( $expired ) {
				$r['locked_until'] = 0;
			}
			$this->rows[ $ip ] = $r;
			return 2;
		}

		if ( preg_match( "/SET attempts = GREATEST\(attempts - 1, 0\), daily_count = GREATEST\(daily_count - 1, 0\) WHERE ip IN \(((?:'[^']*'(?:, )?)+)\) AND locked_until <= (\d+)/", $sql, $m ) ) {
			$done = 0;
			preg_match_all( "/'([^']*)'/", $m[1], $keys );
			foreach ( array_unique( $keys[1] ) as $ip ) {
				if ( isset( $this->rows[ $ip ] ) && $this->rows[ $ip ]['locked_until'] <= (int) $m[2] ) {
					$this->rows[ $ip ]['attempts']    = max( 0, $this->rows[ $ip ]['attempts'] - 1 );
					$this->rows[ $ip ]['daily_count'] = max( 0, $this->rows[ $ip ]['daily_count'] - 1 );
					++$done;
				}
			}
			return $done;
		}

		if ( preg_match( "/SET attempts = 0, daily_count = IF\((\d+) = 1, 0, daily_count\), locked_until = (\d+), lockouts = (\d+), last_lockout = (\d+) WHERE ip = '([^']*)' AND locked_until <= (\d+) AND \(attempts >= (\d+) OR daily_count >= (\d+)\)/", $sql, $m ) ) {
			if ( isset( $this->rows[ $m[5] ] ) ) {
				$r = $this->rows[ $m[5] ];
				if ( $r['locked_until'] <= (int) $m[6] && ( $r['attempts'] >= (int) $m[7] || $r['daily_count'] >= (int) $m[8] ) ) {
					$r['attempts']     = 0;
					$r['daily_count']  = 1 === (int) $m[1] ? 0 : $r['daily_count'];
					$r['locked_until'] = (int) $m[2];
					$r['lockouts']     = (int) $m[3];
					$r['last_lockout'] = (int) $m[4];

					$this->rows[ $m[5] ] = $r;
					return 1;
				}
			}
			return 0;
		}

		if ( preg_match( '/DELETE FROM `[^`]+` WHERE locked_until <= (\d+) AND first_attempt < (\d+) AND last_lockout < (\d+) AND daily_start < (\d+)/', $sql, $m ) ) {
			$deleted = 0;
			foreach ( $this->rows as $ip => $r ) {
				if ( $r['locked_until'] <= (int) $m[1] && $r['first_attempt'] < (int) $m[2] && $r['last_lockout'] < (int) $m[3] && $r['daily_start'] < (int) $m[4] ) {
					unset( $this->rows[ $ip ] );
					++$deleted;
				}
			}
			return $deleted;
		}

		return 0;
	}

	/**
	 * Ejecuta un SELECT de un valor.
	 *
	 * @param string $sql SQL.
	 * @return string|null
	 */
	private function fake_get_var( string $sql ) {
		if ( $this->db_throws ) {
			throw new \RuntimeException( 'BD caida' );
		}
		if ( str_contains( $sql, 'SHOW COLUMNS FROM `wp_tsexp_login_attempts` LIKE \'daily_count\'' ) ) {
			return $this->has_column ? 'daily_count' : null;
		}
		if ( preg_match( "/SELECT MAX\(locked_until\) FROM `[^`]+` WHERE ip IN \(((?:'[^']*'(?:, )?)+)\)/", $sql, $m ) ) {
			$values = array();
			preg_match_all( "/'([^']*)'/", $m[1], $keys );
			foreach ( $keys[1] as $ip ) {
				if ( isset( $this->rows[ $ip ] ) ) {
					$values[] = $this->rows[ $ip ]['locked_until'];
				}
			}
			return array() === $values ? null : (string) max( $values );
		}
		if ( str_contains( $sql, 'SELECT COUNT(*)' ) && preg_match( '/locked_until > (\d+)/', $sql, $m ) ) {
			return (string) count( array_filter( $this->rows, fn( $r ) => $r['locked_until'] > (int) $m[1] ) );
		}
		return null;
	}

	/**
	 * Ejecuta SHOW COLUMNS ... LIKE 'ip' (ip_width 0 = el motor no devuelve varchar(N)).
	 *
	 * @param string $sql SQL.
	 * @return array<string,string>|null
	 */
	private function fake_get_row( string $sql ): ?array {
		if ( str_contains( $sql, "SHOW COLUMNS FROM `wp_tsexp_login_attempts` LIKE 'ip'" ) ) {
			return array(
				'Field' => 'ip',
				'Type'  => $this->ip_width > 0 ? 'varchar(' . $this->ip_width . ')' : 'TEXT',
			);
		}
		return null;
	}

	/**
	 * Ejecuta un SELECT de filas.
	 *
	 * @param string $sql SQL.
	 * @return array<int,array<string,mixed>>
	 */
	private function fake_get_results( string $sql ): array {
		if ( $this->db_throws ) {
			throw new \RuntimeException( 'BD caida' );
		}
		if ( $this->db_unreadable ) {
			return array();
		}
		if ( preg_match( "/SELECT attempts, locked_until, lockouts, last_lockout, daily_count FROM `[^`]+` WHERE ip = '([^']*)'/", $sql, $m ) ) {
			return isset( $this->rows[ $m[1] ] ) ? array( $this->rows[ $m[1] ] ) : array();
		}
		if ( preg_match( '/SELECT ip, locked_until FROM .* locked_until > (\d+)/s', $sql, $m ) ) {
			$out = array();
			foreach ( $this->rows as $ip => $r ) {
				if ( $r['locked_until'] > (int) $m[1] ) {
					$out[] = array(
						'ip'           => $ip,
						'locked_until' => $r['locked_until'],
					);
				}
			}
			return $out;
		}
		return array();
	}

	/**
	 * Fila con valores por defecto.
	 *
	 * @param array<string,int> $values Valores a cambiar.
	 * @return array<string,int>
	 */
	private function row( array $values = array() ): array {
		return array_merge(
			array(
				'attempts'      => 0,
				'first_attempt' => 0,
				'locked_until'  => 0,
				'lockouts'      => 0,
				'last_lockout'  => 0,
				'daily_count'   => 0,
				'daily_start'   => 0,
			),
			$values
		);
	}

	/**
	 * Fila reciente (ventanas en curso) con valores a cambiar.
	 *
	 * @param array<string,int> $values Valores.
	 * @return array<string,int>
	 */
	private function fresh_row( array $values = array() ): array {
		return $this->row(
			array_merge(
				array(
					'first_attempt' => time(),
					'daily_start'   => time(),
				),
				$values
			)
		);
	}

	/**
	 * Crea el modulo arrancado con una IP y unos ajustes.
	 *
	 * @param string              $ip       IP del cliente.
	 * @param array<string,mixed> $settings Ajustes a cambiar.
	 * @return Login_Limit
	 */
	private function make_module( string $ip = self::IP, array $settings = array() ): Login_Limit {
		$module = new Login_Limit();
		$module->boot( $this->make_context( 'login-limit', $ip ), array_merge( array( 'max_attempts' => 3 ), $settings ) );
		return $module;
	}

	/**
	 * Un intento por authenticate con credenciales distintas cada vez.
	 *
	 * @param Login_Limit $module   Modulo.
	 * @param mixed       $user     Valor que llega a authenticate.
	 * @param string      $username Usuario.
	 * @param string|null $password Contrasena (por defecto una nueva cada vez).
	 * @return mixed
	 */
	private function attempt( Login_Limit $module, $user, string $username = 'admin', ?string $password = null ) {
		static $counter = 0;
		++$counter;
		return $module->filter_authenticate( $user, $username, $password ?? 'pw' . $counter );
	}

	/**
	 * Registra n fallos (cada uno con otra contrasena); devuelve el resultado del ultimo.
	 *
	 * @param Login_Limit $module   Modulo.
	 * @param int         $times    Veces.
	 * @param string      $username Usuario.
	 * @return mixed
	 */
	private function register_failures( Login_Limit $module, int $times, string $username = 'admin' ) {
		$result = null;
		for ( $i = 0; $i < $times; $i++ ) {
			$result = $this->attempt( $module, new \WP_Error( 'incorrect_password', 'x' ), $username );
		}
		return $result;
	}

	/**
	 * Cabeceras de la peticion.
	 *
	 * @param array<string,string> $headers Cabeceras $_SERVER.
	 * @return void
	 */
	private function with_headers( array $headers ): void {
		$this->set_server( array_merge( $_SERVER, $headers ) );
	}

	/**
	 * Codigos de un WP_Error.
	 *
	 * @param mixed $error WP_Error.
	 * @return array<int,string>
	 */
	private function codes( $error ): array {
		return $error instanceof \WP_Error ? $error->get_error_codes() : array();
	}

	// Registro de hooks.

	public function test_boot_registers_the_documented_hooks(): void {
		Filters\expectAdded( 'authenticate' )->once()->with( Mockery::type( \Closure::class ), 99, 3 );
		Filters\expectAdded( 'determine_current_user' )->once()->with( Mockery::type( \Closure::class ), 19, 1 );
		Filters\expectAdded( 'rest_authentication_errors' )->once()->with( Mockery::type( \Closure::class ), 5, 1 );
		Actions\expectAdded( 'application_password_failed_authentication' )->once()->with( Mockery::type( \Closure::class ), 10, 1 );
		Actions\expectAdded( 'wp_authenticate_application_password_errors' )->once()->with( Mockery::type( \Closure::class ), 10, 4 );
		Actions\expectAdded( 'admin_init' )->once()->with( Mockery::type( \Closure::class ), 10, 0 );
		Actions\expectAdded( 'tsexp_hourly' )->once()->with( Mockery::type( \Closure::class ), 10, 0 );
		// Un acceso correcto no reinicia nada y wp_login_failed ya no cuenta.
		Actions\expectAdded( 'wp_login' )->never();
		Actions\expectAdded( 'wp_login_failed' )->never();

		$this->make_module();
		$this->assertSame( 'login-limit', ( new Login_Limit() )->get_id() );
	}

	public function test_description_mentions_proxies_and_open_sessions(): void {
		$description = ( new Login_Limit() )->get_description();

		$this->assertStringContainsString( 'proxy', $description );
		$this->assertStringContainsString( 'sesión ya abierta', $description );
	}

	// 1. Un acceso correcto no reinicia el contador.

	public function test_successful_login_does_not_reset_the_counter(): void {
		$module = $this->make_module();

		$this->register_failures( $module, 2 );
		$this->assertSame( 2, $this->rows[ self::IP ]['attempts'] );

		$user = new \WP_User();
		$this->assertSame( $user, $this->attempt( $module, $user, 'atacante' ) );
		$this->assertSame( 2, $this->rows[ self::IP ]['attempts'], 'Entrar con una cuenta propia no limpia los fallos.' );
	}

	public function test_attacker_with_own_account_cannot_loop_forever(): void {
		$module = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once();
		$user = new \WP_User();

		$this->register_failures( $module, 2 );
		$this->assertSame( $user, $this->attempt( $module, $user, 'atacante' ) );
		$this->register_failures( $module, 1 );

		$this->assertGreaterThan( time(), $this->rows[ self::IP ]['locked_until'], 'El tercer intento contra admin bloquea aunque entre medias hubiera un acceso correcto.' );
		$this->assertContains( 'tsexp_locked', $this->codes( $this->attempt( $module, $user, 'atacante' ) ) );
	}

	// 2. Reserva atomica.

	public function test_locks_at_max_failures_and_not_before(): void {
		$module = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once()->with(
			'login-limit',
			'lockout',
			Mockery::type( 'string' ),
			Mockery::on(
				function ( array $data ): bool {
					return self::IP === $data['ip'] && self::IP === $data['bucket'] && 3 === $data['attempts'] && 1200 === $data['duration']
						&& 'admin' === $data['username'] && ! array_key_exists( 'password', $data ) && ! array_key_exists( 'pwd', $data );
				}
			),
			'warning'
		);
		$user = new \WP_User();

		$this->register_failures( $module, 2 );
		$this->assertSame( 0, $this->rows[ self::IP ]['locked_until'], 'Con 2 de 3 fallos aun no hay bloqueo.' );
		$this->assertSame( $user, $this->attempt( $module, $user ), 'Con 2 fallos, un acceso correcto entra.' );
		$this->register_failures( $module, 1 );

		$this->assertGreaterThan( time(), $this->rows[ self::IP ]['locked_until'], 'El fallo numero 3 bloquea.' );
		$result = $this->attempt( $module, $user );
		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
		$this->assertStringContainsString( '20', $result->get_error_message() );
	}

	public function test_exceeding_the_limit_blocks_even_with_the_correct_password(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'attempts' => 3 ) );
		$module                 = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once();

		$result = $this->attempt( $module, new \WP_User(), 'admin', 'la-correcta' );

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
		$this->assertGreaterThan( time(), $this->rows[ self::IP ]['locked_until'] );
	}

	public function test_parallel_requests_cannot_all_slip_past_the_limit(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'attempts' => 3 ) );
		$module                 = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once();

		// Peticiones que llegan "a la vez": todas reservan antes de saber el resultado.
		$results = array();
		for ( $i = 0; $i < 6; $i++ ) {
			$results[] = $this->attempt( $module, new \WP_User(), 'admin', 'guess' . $i );
		}

		foreach ( $results as $result ) {
			$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ), 'Ninguna pasa el limite.' );
		}
	}

	public function test_slot_is_reserved_before_the_outcome_and_only_that_slot_is_refunded(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'attempts' => 1 ) );
		$module                 = $this->make_module();
		$user                   = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ) );

		$this->assertCount( 2, $this->queries );
		$this->assertStringStartsWith( 'INSERT INTO', $this->queries[0] );
		$this->assertStringContainsString( 'ON DUPLICATE KEY UPDATE', $this->queries[0] );
		$this->assertStringContainsString( 'GREATEST(attempts - 1, 0)', $this->queries[1] );
		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'], 'Solo se devuelve la plaza propia.' );
	}

	public function test_only_real_login_attempts_are_counted(): void {
		$module = $this->make_module();

		$module->filter_authenticate( new \WP_Error( 'empty_username', 'x' ), '', '' );
		$module->filter_authenticate( new \WP_Error( 'empty_password', 'x' ), 'admin', '' );
		$module->filter_authenticate( null, '', 'pw' );

		$this->assertSame( array(), $this->rows );
		$this->assertSame( array(), $this->queries );
	}

	public function test_locked_ip_gets_the_error_even_without_credentials(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$module                 = $this->make_module();

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $module->filter_authenticate( null, '', '' ) ) );
	}

	public function test_failures_while_locked_are_not_counted_or_extended(): void {
		$until                  = time() + 600;
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => $until ) );
		$module                 = $this->make_module();

		$result = $this->register_failures( $module, 5 );

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
		$this->assertSame( 0, $this->rows[ self::IP ]['attempts'] );
		$this->assertSame( $until, $this->rows[ self::IP ]['locked_until'] );
	}

	public function test_same_attempt_in_the_same_request_is_not_counted_twice(): void {
		$module = $this->make_module();
		$error  = new \WP_Error( 'incorrect_password', 'x' );

		$module->filter_authenticate( $error, 'admin', 'misma' );
		$module->filter_authenticate( $error, 'admin', 'misma' );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_different_credentials_in_one_request_each_count(): void {
		$module = $this->make_module();
		$error  = new \WP_Error( 'incorrect_password', 'x' );

		// Por ejemplo un system.multicall de XML-RPC con varias contrasenas.
		$module->filter_authenticate( $error, 'admin', 'uno' );
		$module->filter_authenticate( $error, 'admin', 'dos' );

		$this->assertSame( 2, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_application_password_failure_and_authenticate_count_once(): void {
		$module = $this->make_module();
		$error  = new \WP_Error( 'incorrect_password', 'x' );

		// XML-RPC: falla la contrasena de aplicacion y despues falla el login normal.
		$module->on_app_password_failed( $error );
		$module->filter_authenticate( $error, 'admin', 'xmlrpc' );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_application_password_failure_then_valid_login_with_the_same_credentials_gives_the_slot_back(): void {
		$this->with_headers(
			array(
				'PHP_AUTH_USER' => 'admin',
				'PHP_AUTH_PW'   => 'normal',
			)
		);
		$module = $this->make_module();

		$module->on_app_password_failed( new \WP_Error( 'incorrect_password', 'x' ) );
		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
		$user = new \WP_User();
		$this->assertSame( $user, $module->filter_authenticate( $user, 'admin', 'normal' ) );

		$this->assertSame( 0, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_valid_login_with_other_credentials_does_not_clean_the_application_password_failure(): void {
		$this->with_headers(
			array(
				'PHP_AUTH_USER' => 'victima',
				'PHP_AUTH_PW'   => 'contrasena-ajena',
			)
		);
		$module = $this->make_module();

		$module->on_app_password_failed( new \WP_Error( 'incorrect_password', 'x' ) );
		$user = new \WP_User();
		$this->assertSame( $user, $module->filter_authenticate( $user, 'atacante', 'la-suya' ) );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'], 'El fallo sigue contado: la plaza no se devuelve.' );
	}

	public function test_valid_login_after_a_failure_with_unknown_credentials_does_not_give_the_slot_back(): void {
		$module = $this->make_module();

		$module->on_app_password_failed( new \WP_Error( 'incorrect_password', 'x' ) );
		$user = new \WP_User();
		$this->assertSame( $user, $module->filter_authenticate( $user, 'admin', 'normal' ) );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
		$this->assertCount( 1, array_filter( $this->queries, fn( $q ) => str_contains( $q, 'GREATEST' ) ), 'Solo se devuelve la plaza propia del acceso valido.' );
	}

	public function test_held_slot_covers_a_single_attempt_and_later_distinct_credentials_are_counted(): void {
		$module = $this->make_module( self::IP, array( 'max_attempts' => 10 ) );
		$error  = new \WP_Error( 'incorrect_password', 'x' );

		$module->on_app_password_failed( $error );
		$module->filter_authenticate( $error, 'admin', 'uno' );
		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'], 'El primer intento usa la plaza retenida.' );
		$module->filter_authenticate( $error, 'admin', 'dos' );
		$module->filter_authenticate( $error, 'admin', 'tres' );
		$module->filter_authenticate( $error, 'admin', 'tres' );

		$this->assertSame( 3, $this->rows[ self::IP ]['attempts'], 'Cada credencial distinta cuenta una vez; la repetida no.' );
	}

	public function test_held_slot_with_known_credentials_only_covers_the_matching_attempt(): void {
		$this->with_headers(
			array(
				'PHP_AUTH_USER' => 'admin',
				'PHP_AUTH_PW'   => 'basic',
			)
		);
		$module = $this->make_module( self::IP, array( 'max_attempts' => 10 ) );
		$error  = new \WP_Error( 'incorrect_password', 'x' );

		$module->on_app_password_failed( $error );
		$module->filter_authenticate( $error, 'admin', 'otra' );
		$module->filter_authenticate( $error, 'admin', 'basic' );

		$this->assertSame( 3, $this->rows[ self::IP ]['attempts'], 'El fallo Basic y cada credencial distinta cuentan; la plaza ya se consumio.' );
	}

	// 3. CSRF.

	public function test_cross_site_valid_login_gets_in_and_gives_the_slot_back_in_the_xs_bucket(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();
		$user   = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ), 'El boton de acceso de un panel (cPanel, Plesk) entra sin configurar nada.' );

		$this->assertSame( array( 'xs|' . self::IP ), array_keys( $this->rows ), 'Solo existe el contador cross-site.' );
		$this->assertSame( 0, $this->rows[ 'xs|' . self::IP ]['attempts'], 'La plaza se devuelve en el bucket xs.' );
		$refund = array_values( array_filter( $this->queries, fn( $q ) => str_contains( $q, 'GREATEST' ) ) );
		$this->assertCount( 1, $refund );
		$this->assertStringContainsString( "IN ('xs|" . self::IP . "')", $refund[0] );
	}

	public function test_cross_site_failures_count_only_in_the_xs_bucket(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();

		$result = $this->register_failures( $module, 2 );

		$this->assertSame( array( 'incorrect_password' ), $this->codes( $result ) );
		$this->assertSame( array( 'xs|' . self::IP ), array_keys( $this->rows ), 'El contador normal no se toca.' );
		$this->assertSame( 2, $this->rows[ 'xs|' . self::IP ]['attempts'] );
	}

	public function test_cross_site_failures_lock_with_the_cross_site_message(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once()->with(
			'login-limit',
			'lockout',
			Mockery::type( 'string' ),
			Mockery::on( fn( array $d ): bool => 'xs|' . self::IP === $d['bucket'] ),
			'warning'
		);

		$this->register_failures( $module, 3 );
		$result = $this->attempt( $module, new \WP_Error( 'incorrect_password', 'x' ) );

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
		$this->assertStringContainsString( 'desde otro sitio', $result->get_error_message() );
		$this->assertStringContainsString( 'directamente', $result->get_error_message() );
		$this->assertStringContainsString( '20', $result->get_error_message() );
		$this->assertGreaterThan( time(), $this->rows[ 'xs|' . self::IP ]['locked_until'] );
		$this->assertArrayNotHasKey( self::IP, $this->rows );
		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $this->attempt( $module, new \WP_User() ) ), 'Bloqueado aunque la contrasena sea buena.' );
	}

	public function test_cross_site_lock_does_not_block_the_normal_login(): void {
		$this->rows[ 'xs|' . self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'same-origin' ) );
		$module = $this->make_module();
		$user   = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ), 'Un bloqueo cross-site no alcanza al login normal.' );
		$this->assertNull( $module->filter_authenticate( null, '', '' ) );
		$this->register_failures( $module, 1 );
		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );

		$this->with_headers( array() );
		$this->assertSame( $user, $this->attempt( $this->make_module(), $user ), 'Tampoco sin cabeceras.' );
	}

	public function test_normal_lock_blocks_cross_site_attempts_with_the_normal_message(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();

		$result = $this->attempt( $module, new \WP_User() );

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
		$this->assertStringNotContainsString( 'desde otro sitio', $result->get_error_message(), 'Entrar directamente tampoco serviria: mensaje normal.' );
		$this->assertArrayNotHasKey( 'xs|' . self::IP, $this->rows, 'No se cuenta nada mientras hay bloqueo.' );
	}

	public function test_cross_site_lock_applies_to_empty_credentials_only_on_the_normal_counter(): void {
		$this->rows[ 'xs|' . self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();

		$this->assertNull( $module->filter_authenticate( null, '', '' ), 'Sin credenciales no es un intento.' );
	}

	public function test_cross_site_double_authenticate_call_counts_once(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();
		$error  = new \WP_Error( 'incorrect_password', 'x' );

		$module->filter_authenticate( $error, 'admin', 'misma' );
		$module->filter_authenticate( $error, 'admin', 'misma' );

		$this->assertSame( 1, $this->rows[ 'xs|' . self::IP ]['attempts'] );
		$this->assertArrayNotHasKey( self::IP, $this->rows );
	}

	public function test_cross_site_ipv6_uses_prefixed_fine_and_coarse_buckets(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module( self::V6A );

		$this->register_failures( $module, 1 );

		$this->assertSame( array( 'xs|2001:db8:1:2::/64', 'xs|2001:db8:1::/48' ), array_keys( $this->rows ) );
		$this->assertLessThanOrEqual( 64, strlen( 'xs|ffff:ffff:ffff:ffff::/64' ) );
	}

	public function test_origin_from_another_host_without_fetch_metadata_is_counted_as_cross_site(): void {
		$this->with_headers( array( 'HTTP_ORIGIN' => 'https://fuertehost.gestiondeservidor.net:2083' ) );
		$module = $this->make_module();
		$user   = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ) );
		$this->register_failures( $module, 1 );

		$this->assertSame( array( 'xs|' . self::IP ), array_keys( $this->rows ) );
		$this->assertSame( 1, $this->rows[ 'xs|' . self::IP ]['attempts'] );
	}

	public function test_opaque_or_absent_origin_with_cross_site_fetch_metadata_is_cross_site(): void {
		foreach ( array( array( 'HTTP_ORIGIN' => 'null' ), array() ) as $extra ) {
			$this->rows = array();
			$this->with_headers( array_merge( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ), $extra ) );
			$module = $this->make_module();

			$this->register_failures( $module, 1 );

			$this->assertSame( array( 'xs|' . self::IP ), array_keys( $this->rows ) );
		}
		$this->rows = array();
		$this->with_headers( array( 'HTTP_ORIGIN' => 'null' ) );
		$this->register_failures( $this->make_module(), 1 );
		$this->assertSame( array( 'xs|' . self::IP ), array_keys( $this->rows ), 'Origin null sin Sec-Fetch-Site tambien.' );
	}

	public function test_allowlisted_ip_is_not_counted_even_when_cross_site(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module( self::IP, array( 'allowlist' => array( self::IP ) ) );

		$this->register_failures( $module, 10 );

		$this->assertSame( array(), $this->rows );
		$this->assertSame( array(), $this->queries );
	}

	public function test_refund_and_lock_lookup_accept_four_ipv6_keys_with_prepared_placeholders(): void {
		$keys = array( '2001:db8:1:2::/64', '2001:db8:1::/48', 'xs|2001:db8:1:2::/64', 'xs|2001:db8:1::/48' );
		foreach ( $keys as $key ) {
			$this->rows[ $key ] = $this->fresh_row( array( 'attempts' => 2 ) );
		}
		$this->rows['xs|2001:db8:1::/48']['locked_until'] = time() + 300;
		$module = $this->make_module( self::V6A );
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$GLOBALS['wpdb']->shouldReceive( 'prepare' )->atLeast()->once()->passthru();

		$get_remaining = new \ReflectionMethod( $module, 'get_remaining_lock' );
		$refund        = new \ReflectionMethod( $module, 'refund' );

		$this->assertGreaterThan( 0, $get_remaining->invoke( $module, $keys ) );
		$this->assertSame( 0, $get_remaining->invoke( $module, array_slice( $keys, 0, 3 ) ) );
		$this->assertSame( 0, $get_remaining->invoke( $module, array() ) );

		$this->rows['xs|2001:db8:1::/48']['locked_until'] = 0;
		$refund->invoke( $module, $keys );

		foreach ( $keys as $key ) {
			$this->assertSame( 1, $this->rows[ $key ]['attempts'], $key );
		}
		$last = end( $this->queries );
		$this->assertStringContainsString( "IN ('2001:db8:1:2::/64', '2001:db8:1::/48', 'xs|2001:db8:1:2::/64', 'xs|2001:db8:1::/48')", $last );
	}

	public function test_a_key_with_quotes_is_escaped_in_the_in_list(): void {
		$module = $this->make_module();
		$GLOBALS['wpdb']->shouldReceive( 'prepare' )->atLeast()->once()->passthru();
		$refund = new \ReflectionMethod( $module, 'refund' );

		$refund->invoke( $module, array( "x'); DROP TABLE t;--", 'b' ) );

		$this->assertStringContainsString( "'x\\'); DROP TABLE t;--'", end( $this->queries ) );
	}

	public function test_purge_removes_expired_prefixed_rows_too(): void {
		$now                            = time();
		$this->rows[ 'xs|' . self::IP ] = $this->row(
			array(
				'first_attempt' => $now - 7200,
				'daily_start'   => $now - 2 * 86400,
			)
		);
		$this->rows['xs|198.51.100.1']  = $this->row( array( 'locked_until' => $now + 600 ) );

		$this->make_module()->purge_expired();

		$this->assertSame( array( 'xs|198.51.100.1' ), array_keys( $this->rows ) );
	}

	public function test_same_site_request_is_counted(): void {
		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'same-origin',
				'HTTP_ORIGIN'         => 'https://EXAMPLE.test',
			)
		);
		$module = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
		$user = new \WP_User();
		$this->assertSame( $user, $this->attempt( $module, $user ), 'La peticion del propio sitio con acceso valido entra.' );
	}

	public function test_requests_without_browser_headers_are_counted(): void {
		$module = $this->make_module();

		$this->register_failures( $module, 2 );

		$this->assertSame( 2, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_same_site_fetch_metadata_values_are_counted(): void {
		foreach ( array( 'same-origin', 'none' ) as $value ) {
			$this->rows = array();
			$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => $value ) );
			$module = $this->make_module();

			$this->register_failures( $module, 1 );

			$this->assertSame( 1, $this->rows[ self::IP ]['attempts'], $value );
		}
	}

	// Lo que deja pasar.

	public function test_authenticate_leaves_value_untouched_when_not_locked(): void {
		$module = $this->make_module();

		$this->assertNull( $module->filter_authenticate( null, '', '' ) );
		$foreign = new \WP_Error( 'otro_plugin', 'Error ajeno' );
		$this->assertSame( $foreign, $this->attempt( $module, $foreign ) );
		$user = new \WP_User();
		$this->assertSame( $user, $this->attempt( $module, $user ) );
	}

	public function test_authenticate_runs_through_the_registered_filter(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$this->capture_hooks( 'authenticate' );
		$this->make_module();

		$result = $this->apply_captured_filter( 'authenticate', new \WP_User(), 'admin', 'x' );

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
	}

	public function test_other_ip_is_not_affected(): void {
		$this->rows['198.51.100.9'] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$module                     = $this->make_module( self::IP );
		$user                       = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ) );
		$this->register_failures( $module, 2 );
		$this->assertSame( 0, $this->rows['198.51.100.9']['attempts'] );
	}

	public function test_allowlisted_ip_is_never_counted_or_locked(): void {
		$module = $this->make_module( self::IP, array( 'allowlist' => array( self::IP ) ) );

		$this->register_failures( $module, 20 );

		$this->assertSame( array(), $this->rows );
		$user = new \WP_User();
		$this->assertSame( $user, $this->attempt( $module, $user ) );
	}

	public function test_allowlisted_cidr_is_never_counted_or_locked(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$module                 = $this->make_module( self::IP, array( 'allowlist' => "10.0.0.0/8\n203.0.113.0/24" ) );

		$this->register_failures( $module, 20 );
		$user = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ), 'Aunque haya una fila bloqueada antigua, la lista blanca manda.' );
		$this->assertSame( 0, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_ip_outside_allowlist_cidr_is_still_limited(): void {
		$module = $this->make_module( self::IP, array( 'allowlist' => array( '203.0.114.0/24' ) ) );
		$this->event_log_mock->shouldReceive( 'log' )->once();

		$this->register_failures( $module, 3 );

		$this->assertGreaterThan( time(), $this->rows[ self::IP ]['locked_until'] );
	}

	public function test_expired_lock_lets_through_and_restarts_count(): void {
		$this->rows[ self::IP ] = $this->fresh_row(
			array(
				'locked_until'  => time() - 5,
				'first_attempt' => time() - 1300,
				'lockouts'      => 1,
				'last_lockout'  => time() - 5,
			)
		);
		$module                 = $this->make_module();
		$user                   = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ) );
		$this->assertSame( 0, $this->rows[ self::IP ]['locked_until'] );
		$this->register_failures( $module, 1 );
		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'], 'Cuenta desde el principio.' );
		$this->register_failures( $module, 1 );
		$this->assertSame( 2, $this->rows[ self::IP ]['attempts'], 'Y no se reinicia en cada fallo.' );
	}

	public function test_old_window_restarts_the_count(): void {
		$this->rows[ self::IP ] = $this->fresh_row(
			array(
				'attempts'      => 2,
				'first_attempt' => time() - 3600,
			)
		);
		$module                 = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'], 'Los fallos de fuera de la ventana no suman.' );
		$this->assertSame( 0, $this->rows[ self::IP ]['locked_until'] );
	}

	public function test_fails_open_when_database_throws(): void {
		$this->db_throws = true;
		$this->capture_hooks( 'authenticate' );
		$this->make_module();
		$user = new \WP_User();

		$this->assertSame( $user, $this->apply_captured_filter( 'authenticate', $user, 'a', 'b' ) );
		$this->assertCount( 1, $this->reported_errors );
	}

	// Escalada, limite diario y bloqueos largos.

	public function test_escalates_to_long_lockout(): void {
		$module = $this->make_module( self::IP, array( 'long_lockout_after' => 2 ) );
		$this->event_log_mock->shouldReceive( 'log' )->twice();

		$this->register_failures( $module, 3 );
		$this->assertEqualsWithDelta( 1200, $this->rows[ self::IP ]['locked_until'] - time(), 5, 'El primer bloqueo es el corto.' );

		$this->rows[ self::IP ]['locked_until'] = time() - 1; // Caduca.
		$this->register_failures( $module, 3 );
		$this->assertEqualsWithDelta( 24 * 3600, $this->rows[ self::IP ]['locked_until'] - time(), 5, 'El segundo bloqueo en 24 h es el largo.' );
		$this->assertSame( 2, $this->rows[ self::IP ]['lockouts'] );
	}

	public function test_escalation_works_with_lockouts_longer_than_a_day(): void {
		$module = $this->make_module(
			self::IP,
			array(
				'long_lockout_after' => 2,
				'lockout_minutes'    => 2000,
			)
		);
		$this->event_log_mock->shouldReceive( 'log' )->twice();

		$this->register_failures( $module, 3 );
		$first = $this->rows[ self::IP ]['locked_until'];
		$this->assertEqualsWithDelta( 2000 * 60, $first - time(), 5 );
		$this->assertSame( $first, $this->rows[ self::IP ]['last_lockout'], 'last_lockout guarda el FIN del bloqueo.' );

		// El bloqueo termina ahora: el siguiente cae dentro de las 24 h posteriores a su fin.
		$this->rows[ self::IP ]['locked_until'] = time() - 1;
		$this->rows[ self::IP ]['last_lockout'] = time() - 1;
		$this->register_failures( $module, 3 );

		$this->assertEqualsWithDelta( 24 * 3600, $this->rows[ self::IP ]['locked_until'] - time(), 5 );
		$this->assertSame( 2, $this->rows[ self::IP ]['lockouts'] );
	}

	public function test_lockouts_that_ended_more_than_a_day_ago_do_not_escalate(): void {
		$this->rows[ self::IP ] = $this->fresh_row(
			array(
				'lockouts'     => 5,
				'last_lockout' => time() - 2 * 86400,
			)
		);
		$module                 = $this->make_module( self::IP, array( 'long_lockout_after' => 2 ) );
		$this->event_log_mock->shouldReceive( 'log' )->once();

		$this->register_failures( $module, 3 );

		$this->assertEqualsWithDelta( 1200, $this->rows[ self::IP ]['locked_until'] - time(), 5 );
		$this->assertSame( 1, $this->rows[ self::IP ]['lockouts'] );
	}

	public function test_long_lockout_after_can_be_disabled(): void {
		$this->rows[ self::IP ] = $this->fresh_row(
			array(
				'lockouts'     => 50,
				'last_lockout' => time() - 60,
			)
		);
		$module                 = $this->make_module( self::IP, array( 'long_lockout_after' => 0 ) );
		$this->event_log_mock->shouldReceive( 'log' )->once();

		$this->register_failures( $module, 3 );

		$this->assertEqualsWithDelta( 1200, $this->rows[ self::IP ]['locked_until'] - time(), 5 );
	}

	public function test_daily_limit_triggers_a_long_lockout(): void {
		$module = $this->make_module(
			self::IP,
			array(
				'max_attempts' => 100,
				'daily_max'    => 4,
			)
		);
		$this->event_log_mock->shouldReceive( 'log' )->once()->with(
			'login-limit',
			'lockout',
			Mockery::type( 'string' ),
			Mockery::on( fn( array $d ): bool => true === $d['daily'] && true === $d['long'] ),
			'warning'
		);

		$this->register_failures( $module, 3 );
		$this->assertSame( 0, $this->rows[ self::IP ]['locked_until'], 'Con 3 de 4 aun no.' );
		$this->register_failures( $module, 1 );

		$this->assertEqualsWithDelta( 24 * 3600, $this->rows[ self::IP ]['locked_until'] - time(), 5 );
	}

	public function test_daily_limit_counts_across_expired_short_windows(): void {
		$module = $this->make_module(
			self::IP,
			array(
				'max_attempts'   => 100,
				'window_minutes' => 1,
				'daily_max'      => 4,
			)
		);
		$this->event_log_mock->shouldReceive( 'log' )->once();

		for ( $i = 0; $i < 4; $i++ ) {
			if ( isset( $this->rows[ self::IP ] ) ) {
				$this->rows[ self::IP ]['first_attempt'] = time() - 3600; // La ventana corta ya caduco.
			}
			$this->register_failures( $module, 1 );
		}

		$this->assertGreaterThan( time(), $this->rows[ self::IP ]['locked_until'], 'Un ataque lento tambien se frena.' );
	}

	public function test_daily_limit_blocks_even_the_correct_password_and_can_be_disabled(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'daily_count' => 4 ) );
		$module                 = $this->make_module(
			self::IP,
			array(
				'max_attempts' => 100,
				'daily_max'    => 4,
			)
		);
		$this->event_log_mock->shouldReceive( 'log' )->once();
		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $this->attempt( $module, new \WP_User() ) ) );

		$this->rows = array();
		$off        = $this->make_module(
			self::IP,
			array(
				'max_attempts' => 100,
				'daily_max'    => 0,
			)
		);
		$this->register_failures( $off, 80 );
		$this->assertSame( 0, $this->rows[ self::IP ]['locked_until'], 'Con 0 no hay limite diario.' );
	}

	// 4 y 5. Contrasenas de aplicacion y REST.

	public function test_application_password_gets_error_when_ip_locked(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 300 ) );
		$module                 = $this->make_module();
		$error                  = new \WP_Error();

		$module->check_app_password( $error, new \WP_User(), array(), 'pass' );

		$this->assertSame( array( 'tsexp_locked' ), $error->get_error_codes() );
	}

	public function test_application_password_gets_no_error_when_ip_not_locked(): void {
		$module = $this->make_module();
		$error  = new \WP_Error();

		$module->check_app_password( $error, new \WP_User(), array(), 'pass' );

		$this->assertSame( array(), $error->get_error_codes() );
	}

	public function test_application_password_failures_count_once_per_request_and_lock(): void {
		$error = new \WP_Error( 'application_passwords_failed', 'x' );

		$request = $this->make_module();
		$request->on_app_password_failed( $error );
		$request->on_app_password_failed( $error );
		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'], 'Una vez por peticion.' );

		$second = $this->make_module();
		$second->on_app_password_failed( $error );
		$third = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once();
		$third->on_app_password_failed( $error );

		$this->assertGreaterThan( time(), $this->rows[ self::IP ]['locked_until'] );
	}

	public function test_basic_auth_from_locked_ip_is_flagged_and_rest_answers_429_uniformly(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$this->with_headers(
			array(
				'PHP_AUTH_USER' => 'admin',
				'PHP_AUTH_PW'   => 'cualquiera',
			)
		);
		$module = $this->make_module();

		$this->assertFalse( $module->filter_determine_user( false ) );
		$result = $module->filter_rest_errors( null );

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
		$this->assertSame( array( 'status' => 429 ), $result->get_error_data( 'tsexp_locked' ) );
	}

	public function test_rest_passes_through_when_not_locked_or_no_basic_auth_or_already_authenticated(): void {
		$module = $this->make_module();

		// Sin credenciales Basic: nada que hacer, aunque la IP este bloqueada.
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$this->assertFalse( $module->filter_determine_user( false ) );
		$this->assertNull( $module->filter_rest_errors( null ) );

		// Con credenciales pero sin bloqueo.
		$this->rows = array();
		$this->with_headers( array( 'PHP_AUTH_USER' => 'admin' ) );
		$free = $this->make_module();
		$this->assertFalse( $free->filter_determine_user( false ) );
		$this->assertTrue( $free->filter_rest_errors( true ), 'Respeta lo que ya decidio otro.' );

		// Sesion ya identificada (cookie): no se toca aunque la IP este bloqueada.
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$open                   = $this->make_module();
		$this->assertSame( 7, $open->filter_determine_user( 7 ) );
		$this->assertNull( $open->filter_rest_errors( null ) );
	}

	public function test_basic_auth_from_allowlisted_ip_is_not_flagged(): void {
		$this->rows[ self::IP ] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$this->with_headers( array( 'PHP_AUTH_USER' => 'admin' ) );
		$module = $this->make_module( self::IP, array( 'allowlist' => array( self::IP ) ) );

		$module->filter_determine_user( false );

		$this->assertNull( $module->filter_rest_errors( null ) );
	}

	// IPv6.

	public function test_addresses_in_the_same_ipv6_64_share_a_counter(): void {
		$first = $this->make_module( self::V6A );
		$this->register_failures( $first, 2 );

		$second = $this->make_module( self::V6B );
		$this->event_log_mock->shouldReceive( 'log' )->once()->with(
			'login-limit',
			'lockout',
			Mockery::type( 'string' ),
			Mockery::on( fn( array $d ): bool => self::V6B === $d['ip'] && '2001:db8:1:2::/64' === $d['bucket'] ),
			'warning'
		);
		$this->register_failures( $second, 1 );

		$this->assertSame( array( '2001:db8:1:2::/64', '2001:db8:1::/48' ), array_keys( $this->rows ), 'Las claves son el /64 (sin pasar por normalize_ip()) y el /48.' );
		$this->assertGreaterThan( time(), $this->rows['2001:db8:1:2::/64']['locked_until'] );
	}

	public function test_different_ipv6_64_networks_do_not_share_a_counter(): void {
		$first = $this->make_module( self::V6A );
		$this->register_failures( $first, 2 );
		$other = $this->make_module( self::V6C );
		$this->register_failures( $other, 2 );

		$this->assertCount( 3, $this->rows, 'Dos /64 y el /48 que comparten.' );
		$this->assertSame( 2, $this->rows['2001:db8:1:3::/64']['attempts'] );
		$this->assertSame( 4, $this->rows['2001:db8:1::/48']['attempts'] );
		$this->assertSame( 0, $this->rows['2001:db8:1:2::/64']['locked_until'] );
		$this->assertSame( 0, $this->rows['2001:db8:1:3::/64']['locked_until'] );
	}

	public function test_allowlist_is_checked_against_the_real_ipv6_address_not_the_bucket(): void {
		$allowed = $this->make_module( self::V6A, array( 'allowlist' => array( self::V6A ) ) );
		$this->register_failures( $allowed, 5 );
		$this->assertSame( array(), $this->rows, 'La direccion exacta de la lista blanca no cuenta.' );

		$neighbour = $this->make_module( self::V6B, array( 'allowlist' => array( self::V6A ) ) );
		$this->register_failures( $neighbour, 1 );
		$this->assertSame( 1, $this->rows['2001:db8:1:2::/64']['attempts'], 'Otra direccion del mismo /64 si cuenta.' );

		$range = $this->make_module( self::V6C, array( 'allowlist' => array( '2001:db8::/32' ) ) );
		$this->register_failures( $range, 5 );
		$this->assertArrayNotHasKey( '2001:db8:1:3::/64', $this->rows );
	}

	public function test_lock_check_uses_the_bucket_key(): void {
		$this->rows['2001:db8:1:2::/64'] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$module                          = $this->make_module( self::V6B );

		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $this->attempt( $module, new \WP_User() ) ) );
	}

	// 9. Sin IP valida.

	public function test_no_valid_ip_neither_counts_nor_locks_and_is_logged_once_a_day(): void {
		$module = $this->make_module( '' );
		$this->event_log_mock->shouldReceive( 'log' )->once()->with( 'login-limit', 'no_client_ip', Mockery::type( 'string' ), array(), 'warning' );

		$user = new \WP_User();
		$this->assertSame( $user, $this->attempt( $module, $user ) );
		$this->register_failures( $module, 20 );
		$module->on_app_password_failed( new \WP_Error( 'x', 'y' ) );
		$error = new \WP_Error();
		$module->check_app_password( $error, null, null, '' );

		$this->assertSame( array(), $this->rows );
		$this->assertSame( array(), $this->queries );
		$this->assertSame( array(), $error->get_error_codes() );
		$this->assertArrayHasKey( 'tsexp_login_limit_noip', $this->ll_transients );
	}

	public function test_no_valid_ip_is_not_logged_again_while_the_transient_lives(): void {
		$this->ll_transients['tsexp_login_limit_noip'] = '1';
		$module                                        = $this->make_module( '' );
		$this->event_log_mock->shouldNotReceive( 'log' );

		$this->register_failures( $module, 3 );

		$this->assertSame( array(), $this->rows );
	}

	// Multisitio (no soportado en la v1): tabla por sitio.

	public function test_table_is_per_site_using_prefix(): void {
		$GLOBALS['wpdb']->prefix = 'wp_2_';
		$module                  = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertStringContainsString( '`wp_2_tsexp_login_attempts`', $this->queries[0] );
		$this->assertSame( 'wp_2_tsexp_login_attempts', Login_Limit::table_name() );
	}

	// 11. Usuario en el registro.

	public function test_logged_username_is_stored_only_if_the_user_exists(): void {
		$module = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once()->with(
			'login-limit',
			'lockout',
			Mockery::type( 'string' ),
			Mockery::on( fn( array $d ): bool => 'admin' === $d['username'] && ! array_key_exists( 'username_length', $d ) ),
			'warning'
		);

		$this->register_failures( $module, 3, 'admin' );
	}

	public function test_logged_email_is_stored_if_it_exists(): void {
		$module = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once()->with(
			'login-limit',
			'lockout',
			Mockery::type( 'string' ),
			Mockery::on( fn( array $d ): bool => 'ana@example.test' === $d['username'] ),
			'warning'
		);

		$this->register_failures( $module, 3, 'ana@example.test' );
	}

	public function test_unknown_username_is_not_stored_in_clear(): void {
		$module = $this->make_module();
		$typed  = 'MiClave-Secreta-1';
		$this->event_log_mock->shouldReceive( 'log' )->once()->with(
			'login-limit',
			'lockout',
			Mockery::type( 'string' ),
			Mockery::on(
				fn( array $d ): bool => 'unknown' === $d['username'] && strlen( $typed ) === $d['username_length']
					&& ! str_contains( (string) wp_json_encode( $d ), $typed )
			),
			'warning'
		);

		$this->register_failures( $module, 3, $typed );
	}

	// Segunda ronda: M1, M2, M4, M5 y M6.

	public function test_cross_site_application_password_failure_is_not_counted(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();

		$module->on_app_password_failed( new \WP_Error( 'incorrect_password', 'x' ) );
		$module->on_app_password_failed( new \WP_Error( 'incorrect_password', 'x' ) );

		$this->assertSame( array(), $this->rows, 'Un fetch no-cors a xmlrpc.php o REST no puede bloquear al administrador.' );
		$this->assertSame( array(), $this->queries );
	}

	public function test_cross_site_origin_application_password_failure_is_not_counted(): void {
		$this->with_headers( array( 'HTTP_ORIGIN' => 'https://evil.example' ) );
		$module = $this->make_module();

		$module->on_app_password_failed( new \WP_Error( 'incorrect_password', 'x' ) );

		$this->assertSame( array(), $this->rows );
	}

	public function test_same_site_application_password_failure_is_counted(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'same-origin' ) );
		$module = $this->make_module();

		$module->on_app_password_failed( new \WP_Error( 'incorrect_password', 'x' ) );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_cross_site_application_password_attempt_gets_an_error(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module();
		$error  = new \WP_Error();

		$module->check_app_password( $error, new \WP_User(), array(), 'correcta' );

		$this->assertSame( array( 'tsexp_cross_site' ), $error->get_error_codes(), 'Ni con la contrasena correcta se prueba "gratis".' );
	}

	public function test_allowlisted_ip_is_checked_before_cross_site(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$module = $this->make_module( self::IP, array( 'allowlist' => array( self::IP ) ) );
		$user   = new \WP_User();
		$error  = new \WP_Error();

		$this->assertSame( $user, $this->attempt( $module, $user ), 'La lista blanca manda sobre la comprobacion cross-site.' );
		$module->check_app_password( $error, $user, array(), 'x' );
		$this->assertSame( array(), $error->get_error_codes() );
	}

	public function test_same_site_with_origin_matching_the_site_is_counted_as_normal(): void {
		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'same-site',
				'HTTP_ORIGIN'         => 'https://example.test',
			)
		);
		$module = $this->make_module();

		$result = $this->register_failures( $module, 1 );

		$this->assertSame( array( 'incorrect_password' ), $this->codes( $result ) );
		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_same_site_with_origin_from_a_sibling_subdomain_is_rejected(): void {
		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'same-site',
				'HTTP_ORIGIN'         => 'https://www.example.test',
			)
		);
		$module = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertSame( array( 'xs|' . self::IP ), array_keys( $this->rows ), 'Un subdominio hermano cuenta como cross-site.' );
	}

	public function test_same_site_without_origin_is_counted(): void {
		$this->with_headers( array( 'HTTP_SEC_FETCH_SITE' => 'same-site' ) );
		$module = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
	}

	public function test_same_origin_fetch_metadata_is_trusted_over_an_opaque_origin(): void {
		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'same-origin',
				'HTTP_ORIGIN'         => 'null',
			)
		);
		$module = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertSame( 1, $this->rows[ self::IP ]['attempts'] );
		$user = new \WP_User();
		$this->assertSame( $user, $this->attempt( $module, $user ) );
	}

	public function test_origin_is_still_compared_when_fetch_metadata_is_missing(): void {
		$this->with_headers( array( 'HTTP_ORIGIN' => 'https://www.example.test' ) );
		$module = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertSame( array( 'xs|' . self::IP ), array_keys( $this->rows ) );
	}

	public function test_short_lockouts_do_not_reset_the_daily_counter(): void {
		$module = $this->make_module(
			self::IP,
			array(
				'long_lockout_after' => 0,
				'daily_max'          => 50,
			)
		);
		$this->event_log_mock->shouldReceive( 'log' )->zeroOrMoreTimes();

		// 16 ciclos de 3 fallos con un bloqueo corto entre cada uno: 48 intentos repartidos.
		for ( $cycle = 0; $cycle < 16; $cycle++ ) {
			$this->register_failures( $module, 3 );
			$this->assertEqualsWithDelta( 1200, $this->rows[ self::IP ]['locked_until'] - time(), 5, 'Bloqueo corto.' );
			$this->rows[ self::IP ]['locked_until'] = time() - 1; // Caduca.
		}
		$this->assertSame( 48, $this->rows[ self::IP ]['daily_count'], 'Un bloqueo corto no reinicia el contador diario.' );

		$this->register_failures( $module, 2 );

		$this->assertEqualsWithDelta( 24 * 3600, $this->rows[ self::IP ]['locked_until'] - time(), 5, 'Los intentos 49 y 50 siguen contando para el tope diario.' );
		$this->assertSame( 0, $this->rows[ self::IP ]['daily_count'], 'Solo el bloqueo causado por el limite diario lo reinicia.' );
	}

	public function test_two_64_networks_inside_the_same_48_are_locked_by_the_coarse_counter(): void {
		// 15 redes /64 distintas del mismo /48, 2 fallos cada una: ninguna llega a 3, pero el /48 llega a 30.
		for ( $i = 1; $i <= 15; $i++ ) {
			$module = $this->make_module( sprintf( '2001:db8:1:%x::5', $i ) );
			$this->event_log_mock->shouldReceive( 'log' )->zeroOrMoreTimes();
			$this->register_failures( $module, 2 );
			$this->assertSame( 0, $this->rows[ sprintf( '2001:db8:1:%x::/64', $i ) ]['locked_until'] );
		}

		$this->assertGreaterThan( time(), $this->rows['2001:db8:1::/48']['locked_until'], 'El fallo 30 del /48 lo bloquea.' );

		$other_64 = $this->make_module( '2001:db8:1:ff::7' );
		$this->assertSame( array( 'tsexp_locked' ), $this->codes( $this->attempt( $other_64, new \WP_User() ) ), 'Otro /64 del mismo /48 queda bloqueado.' );
	}

	public function test_a_different_48_is_not_affected_by_the_coarse_counter(): void {
		for ( $i = 1; $i <= 15; $i++ ) {
			$module = $this->make_module( sprintf( '2001:db8:1:%x::5', $i ) );
			$this->event_log_mock->shouldReceive( 'log' )->zeroOrMoreTimes();
			$this->register_failures( $module, 2 );
		}

		$neighbour = $this->make_module( '2001:db8:2:1::5' );
		$user      = new \WP_User();

		$this->assertSame( $user, $this->attempt( $neighbour, $user ) );
		$this->register_failures( $neighbour, 2 );
		$this->assertSame( 0, $this->rows['2001:db8:2::/48']['locked_until'] );
	}

	public function test_coarse_counter_has_ten_times_the_daily_limit(): void {
		$module = $this->make_module(
			self::V6A,
			array(
				'max_attempts' => 100,
				'daily_max'    => 3,
			)
		);
		$this->event_log_mock->shouldReceive( 'log' )->zeroOrMoreTimes();
		$this->rows['2001:db8:1::/48'] = $this->fresh_row( array( 'daily_count' => 29 ) );

		$this->register_failures( $module, 1 );

		$this->assertGreaterThan( time(), $this->rows['2001:db8:1::/48']['locked_until'], '10 x 3 = 30 intentos en 24 h.' );
	}

	public function test_ipv4_has_no_coarse_counter(): void {
		$module = $this->make_module();

		$this->register_failures( $module, 1 );

		$this->assertSame( array( self::IP ), array_keys( $this->rows ) );
	}

	public function test_refund_gives_the_slot_back_to_both_counters(): void {
		$this->rows['2001:db8:1:2::/64'] = $this->fresh_row( array( 'attempts' => 1 ) );
		$this->rows['2001:db8:1::/48']   = $this->fresh_row( array( 'attempts' => 5 ) );
		$module                          = $this->make_module( self::V6A );
		$user                            = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ) );

		$this->assertSame( 1, $this->rows['2001:db8:1:2::/64']['attempts'] );
		$this->assertSame( 5, $this->rows['2001:db8:1::/48']['attempts'] );
		$refund = array_values( array_filter( $this->queries, fn( $q ) => str_contains( $q, 'GREATEST' ) ) );
		$this->assertCount( 1, $refund );
		$this->assertStringContainsString( "IN ('2001:db8:1:2::/64', '2001:db8:1::/48')", $refund[0] );
	}

	public function test_ipv6_allowlist_skips_both_counters(): void {
		$module = $this->make_module( self::V6A, array( 'allowlist' => array( '2001:db8:1::/48' ) ) );

		$this->register_failures( $module, 20 );

		$this->assertSame( array(), $this->rows );
	}

	public function test_schema_is_upgraded_on_admin_init_when_version_differs(): void {
		$this->capture_hooks( 'admin_init' );
		$this->make_module();
		$this->options['tsexp_login_limit_db_version'] = '1';
		Functions\expect( 'dbDelta' )->once();

		$this->do_captured_action( 'admin_init' );

		$this->assertSame( '3', $this->options['tsexp_login_limit_db_version'] );
	}

	public function test_schema_is_upgraded_on_admin_init_when_version_is_missing(): void {
		$this->capture_hooks( 'admin_init' );
		$this->make_module();
		Functions\expect( 'dbDelta' )->once();

		$this->do_captured_action( 'admin_init' );

		$this->assertSame( '3', $this->options['tsexp_login_limit_db_version'] );
	}

	public function test_schema_is_not_touched_on_admin_init_when_version_matches(): void {
		$this->capture_hooks( 'admin_init' );
		$this->make_module();
		$this->options['tsexp_login_limit_db_version'] = '3';
		Functions\expect( 'dbDelta' )->never();

		$this->do_captured_action( 'admin_init' );

		$this->assertSame( '3', $this->options['tsexp_login_limit_db_version'] );
	}

	public function test_unreadable_row_fails_open_and_logs_db_error_once_an_hour(): void {
		$this->db_unreadable = true;
		$module              = $this->make_module();
		$this->event_log_mock->shouldReceive( 'log' )->once()->with( 'login-limit', 'db_error', Mockery::type( 'string' ), array(), 'warning' );
		$user = new \WP_User();

		$this->assertSame( $user, $this->attempt( $module, $user ) );
		$this->register_failures( $module, 5 );

		$this->assertArrayHasKey( 'tsexp_login_limit_dberr', $this->ll_transients );
	}

	public function test_db_error_is_not_logged_again_while_the_transient_lives(): void {
		$this->ll_transients['tsexp_login_limit_dberr'] = '1';
		$this->db_unreadable                            = true;
		$module = $this->make_module();
		$this->event_log_mock->shouldNotReceive( 'log' );

		$this->register_failures( $module, 2 );
	}

	// Tercera ronda.

	public function test_retry_during_a_coarse_lock_does_not_spend_or_lock_the_own_64(): void {
		$this->rows['2001:db8:1::/48'] = $this->fresh_row( array( 'locked_until' => time() + 600 ) );
		$module                        = $this->make_module( self::V6A );
		$this->event_log_mock->shouldNotReceive( 'log' );

		$results = array();
		for ( $i = 0; $i < 6; $i++ ) {
			$results[] = $this->attempt( $module, new \WP_Error( 'incorrect_password', 'x' ) );
		}

		foreach ( $results as $result ) {
			$this->assertSame( array( 'tsexp_locked' ), $this->codes( $result ) );
		}
		$this->assertArrayNotHasKey( '2001:db8:1:2::/64', $this->rows, 'El /64 propio no se toca.' );
		$this->assertSame( array(), array_filter( $this->queries, fn( $q ) => str_starts_with( $q, 'INSERT' ) ) );
	}

	public function test_description_and_allowlist_help_explain_the_shared_48(): void {
		$module = new Login_Limit();
		ob_start();
		$module->render_settings( array(), 'x[y]' );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( '/48', $module->get_description() );
		$this->assertStringContainsString( '/56', $module->get_description() );
		$this->assertStringContainsString( '/48', $html );
		$this->assertStringContainsString( '/56', $html );
	}

	public function test_cross_site_rest_basic_auth_gets_the_same_error_right_or_wrong(): void {
		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'cross-site',
				'PHP_AUTH_USER'       => 'admin',
				'PHP_AUTH_PW'         => 'cualquiera',
			)
		);
		$module = $this->make_module();

		$wrong = $module->filter_rest_errors( new \WP_Error( 'incorrect_password', 'x' ) );
		$right = $module->filter_rest_errors( null );
		$ok    = $module->filter_rest_errors( true );

		foreach ( array( $wrong, $right, $ok ) as $result ) {
			$this->assertSame( array( 'tsexp_cross_site' ), $this->codes( $result ) );
		}
		$this->assertSame( $wrong->get_error_message(), $right->get_error_message() );
	}

	public function test_same_origin_rest_basic_auth_and_cross_site_without_basic_pass_through(): void {
		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'same-origin',
				'PHP_AUTH_USER'       => 'admin',
			)
		);
		$this->assertNull( $this->make_module()->filter_rest_errors( null ) );

		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'cross-site',
				'PHP_AUTH_USER'       => '',
			)
		);
		$this->assertNull( $this->make_module()->filter_rest_errors( null ), 'Sin credenciales Basic no se toca (la cookie ya la protege el nonce de REST).' );
	}

	public function test_allowlisted_ip_is_not_affected_by_the_cross_site_rest_check(): void {
		$this->with_headers(
			array(
				'HTTP_SEC_FETCH_SITE' => 'cross-site',
				'PHP_AUTH_USER'       => 'admin',
			)
		);
		$module = $this->make_module( self::IP, array( 'allowlist' => array( self::IP ) ) );

		$this->assertNull( $module->filter_rest_errors( null ) );
	}

	public function test_install_does_not_store_the_version_if_the_column_is_missing(): void {
		$this->has_column = false;
		Functions\expect( 'dbDelta' )->once();

		( new Login_Limit() )->install();

		$this->assertArrayNotHasKey( 'tsexp_login_limit_db_version', $this->options );
	}

	public function test_install_stores_the_version_when_the_ip_width_cannot_be_read(): void {
		$this->ip_width = 0;
		Functions\expect( 'dbDelta' )->once();

		( new Login_Limit() )->install();

		$this->assertSame( '3', $this->options['tsexp_login_limit_db_version'], 'Sin anchura legible no se repite install() en cada admin_init.' );
	}

	public function test_install_reads_the_ip_width_with_show_columns(): void {
		Functions\expect( 'dbDelta' )->once();
		$GLOBALS['wpdb']->shouldReceive( 'prepare' )->atLeast()->once()->passthru();

		( new Login_Limit() )->install();

		$this->assertSame( '3', $this->options['tsexp_login_limit_db_version'] );
	}

	public function test_install_does_not_store_the_version_while_the_ip_column_is_narrow(): void {
		$this->ip_width = 45;
		Functions\expect( 'dbDelta' )->once();

		( new Login_Limit() )->install();

		$this->assertArrayNotHasKey( 'tsexp_login_limit_db_version', $this->options );
	}

	public function test_schema_version_2_is_upgraded_on_admin_init(): void {
		$this->capture_hooks( 'admin_init' );
		$this->make_module();
		$this->options['tsexp_login_limit_db_version'] = '2';
		Functions\expect( 'dbDelta' )->once();

		$this->do_captured_action( 'admin_init' );

		$this->assertSame( '3', $this->options['tsexp_login_limit_db_version'] );
	}

	public function test_install_checks_the_column_with_prepare_and_stores_the_version_when_present(): void {
		Functions\expect( 'dbDelta' )->once();
		$GLOBALS['wpdb']->shouldReceive( 'prepare' )->atLeast()->once()->passthru();

		( new Login_Limit() )->install();

		$this->assertSame( '3', $this->options['tsexp_login_limit_db_version'] );
	}

	// Mantenimiento.

	public function test_purge_deletes_only_rows_that_no_longer_matter(): void {
		$now                     = time();
		$this->rows['192.0.2.1'] = $this->row(
			array(
				'first_attempt' => $now - 7200,
				'daily_start'   => $now - 2 * 86400,
			)
		);
		$this->rows['192.0.2.2'] = $this->row( array( 'locked_until' => $now + 600 ) );
		$this->rows['192.0.2.3'] = $this->row(
			array(
				'attempts'      => 2,
				'first_attempt' => $now - 60,
				'daily_start'   => $now - 60,
			)
		);
		$this->rows['192.0.2.4'] = $this->row(
			array(
				'first_attempt' => $now - 7200,
				'lockouts'      => 1,
				'last_lockout'  => $now - 3600,
			)
		);
		$this->rows['192.0.2.5'] = $this->row(
			array(
				'first_attempt' => $now - 7200,
				'daily_start'   => $now - 3600,
				'daily_count'   => 30,
			)
		);
		$module                  = $this->make_module();

		$module->purge_expired();

		$this->assertSame( array( '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5' ), array_keys( $this->rows ) );
	}

	public function test_install_creates_table_with_dbdelta_and_stores_schema_version(): void {
		Functions\expect( 'dbDelta' )->once()->with(
			Mockery::on(
				fn( string $sql ): bool => str_contains( $sql, 'CREATE TABLE wp_tsexp_login_attempts' )
					&& str_contains( $sql, 'ip varchar(64) NOT NULL' )
					&& str_contains( $sql, 'PRIMARY KEY  (ip)' )
					&& str_contains( $sql, 'locked_until' )
					&& str_contains( $sql, 'lockouts' )
					&& str_contains( $sql, 'last_lockout' )
					&& str_contains( $sql, 'daily_count' )
					&& str_contains( $sql, 'daily_start' )
					&& ! str_contains( $sql, 'unsigned' )
			)
		);
		Functions\when( 'update_option' )->alias(
			function ( string $name, $value, $autoload = null ): bool {
				$this->options[ $name ] = array( $value, $autoload );
				return true;
			}
		);

		( new Login_Limit() )->install();

		$this->assertSame( array( '3', false ), $this->options['tsexp_login_limit_db_version'] );
	}

	public function test_uninstall_drops_table_and_deletes_options_and_transients(): void {
		$this->options['tsexp_login_limit_db_version']  = '3';
		$this->ll_transients['tsexp_login_limit_noip']  = '1';
		$this->ll_transients['tsexp_login_limit_dberr'] = '1';

		( new Login_Limit() )->uninstall();

		$this->assertCount( 1, $this->queries );
		$this->assertSame( 'DROP TABLE IF EXISTS `wp_tsexp_login_attempts`', $this->queries[0] );
		$this->assertArrayNotHasKey( 'tsexp_login_limit_db_version', $this->options );
		$this->assertArrayNotHasKey( 'tsexp_login_limit_noip', $this->ll_transients );
		$this->assertArrayNotHasKey( 'tsexp_login_limit_dberr', $this->ll_transients );
	}

	public function test_all_sql_goes_through_prepare(): void {
		$module = $this->make_module();
		$GLOBALS['wpdb']->shouldReceive( 'prepare' )->atLeast()->once()->passthru();

		$this->register_failures( $module, 1 );

		$this->assertStringContainsString( '`wp_tsexp_login_attempts`', $this->queries[0], 'La tabla va como identificador (%i).' );
		$this->assertStringContainsString( "'" . self::IP . "'", $this->queries[0], 'La IP va entrecomillada por prepare().' );
	}

	// Ajustes.

	public function test_sanitize_clamps_ranges(): void {
		$module = new Login_Limit();

		$low  = $module->sanitize_settings(
			array(
				'max_attempts'       => 0,
				'window_minutes'     => -5,
				'lockout_minutes'    => 0,
				'long_lockout_after' => -1,
				'long_lockout_hours' => 0,
				'daily_max'          => -3,
			)
		);
		$high = $module->sanitize_settings(
			array(
				'max_attempts'       => 9999,
				'window_minutes'     => 99999,
				'lockout_minutes'    => 999999,
				'long_lockout_after' => 500,
				'long_lockout_hours' => 5000,
				'daily_max'          => 99999,
			)
		);

		$this->assertSame( 1, $low['max_attempts'] );
		$this->assertSame( 1, $low['window_minutes'] );
		$this->assertSame( 1, $low['lockout_minutes'] );
		$this->assertSame( 0, $low['long_lockout_after'] );
		$this->assertSame( 1, $low['long_lockout_hours'] );
		$this->assertSame( 0, $low['daily_max'] );
		$this->assertSame( 100, $high['max_attempts'] );
		$this->assertSame( 1440, $high['window_minutes'] );
		$this->assertSame( 10080, $high['lockout_minutes'] );
		$this->assertSame( 100, $high['long_lockout_after'] );
		$this->assertSame( 720, $high['long_lockout_hours'] );
		$this->assertSame( 10000, $high['daily_max'] );
	}

	public function test_sanitize_uses_defaults_for_missing_or_garbage_values(): void {
		$module = new Login_Limit();

		$this->assertSame( $module->get_default_settings(), $module->sanitize_settings( array() ) );
		$this->assertSame( 50, $module->get_default_settings()['daily_max'] );
		$out = $module->sanitize_settings(
			array(
				'max_attempts'    => array( 'x' ),
				'window_minutes'  => 'abc',
				'lockout_minutes' => null,
				'daily_max'       => 'mucho',
				'allowlist'       => 42,
			)
		);
		$this->assertSame( $module->get_default_settings(), $out );
	}

	public function test_sanitize_discards_invalid_ips_and_normalizes(): void {
		$module = new Login_Limit();

		$out = $module->sanitize_settings(
			array( 'allowlist' => "203.0.113.5\nno-es-ip\n10.0.0.0/8\n10.0.0.0/99\n<script>alert(1)</script>\n::ffff:192.0.2.1\n203.0.113.5\n2001:db8::/32" )
		);

		$this->assertSame( array( '203.0.113.5', '10.0.0.0/8', '192.0.2.1', '2001:db8::/32' ), $out['allowlist'] );
	}

	public function test_sanitize_rejects_ranges_that_are_too_wide(): void {
		$module = new Login_Limit();

		$out = $module->sanitize_settings(
			array( 'allowlist' => "0.0.0.0/0\n10.0.0.0/7\n128.0.0.0/1\n::/0\n2001:db8::/31\n2001::/16\n10.0.0.0/8\n2001:db8::/32\n192.0.2.9/32\n2001:db8::1/128" )
		);

		$this->assertSame( array( '10.0.0.0/8', '2001:db8::/32', '192.0.2.9/32', '2001:db8::1/128' ), $out['allowlist'] );
	}

	public function test_sanitize_converts_mapped_cidr_to_ipv4(): void {
		$module = new Login_Limit();

		$out = $module->sanitize_settings(
			array( 'allowlist' => "::ffff:192.0.2.0/120\n::ffff:10.0.0.0/104\n::ffff:0.0.0.0/96\n::ffff:10.0.0.0/103" )
		);

		$this->assertSame( array( '192.0.2.0/24', '10.0.0.0/8' ), $out['allowlist'], '/96 y /103 equivalen a /0 y /7 de IPv4 y se descartan.' );
	}

	public function test_sanitize_is_idempotent(): void {
		$module = new Login_Limit();
		$once   = $module->sanitize_settings(
			array(
				'max_attempts' => '7',
				'daily_max'    => '120',
				'allowlist'    => "203.0.113.5\n10.0.0.0/8\n::ffff:192.0.2.0/120\n2001:db8::/32\nbasura\n0.0.0.0/0",
			)
		);

		$this->assertSame( $once, $module->sanitize_settings( $once ) );
		$this->assertSame( $once, $module->sanitize_settings( $module->sanitize_settings( $once ) ) );
		$this->assertSame( 7, $once['max_attempts'] );
		$this->assertSame( 120, $once['daily_max'] );
	}

	public function test_render_settings_is_escaped_read_only_and_labelled(): void {
		$this->rows['<b>9.9.9.9</b>'] = $this->row( array( 'locked_until' => time() + 600 ) );
		$module                       = new Login_Limit();

		ob_start();
		$module->render_settings( array( 'allowlist' => array( '203.0.113.5' ) ), 'tsexp_settings[modules][login-limit][settings]' );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="tsexp_settings[modules][login-limit][settings][max_attempts]"', $html );
		$this->assertStringContainsString( 'name="tsexp_settings[modules][login-limit][settings][daily_max]"', $html );
		$this->assertStringContainsString( 'name="tsexp_settings[modules][login-limit][settings][allowlist]"', $html );
		$this->assertMatchesRegularExpression( '/<label for="([^"]+)">Intentos fallidos permitidos<\/label>.*id="\1"/s', $html );
		$this->assertStringContainsString( '203.0.113.5', $html );
		$this->assertStringContainsString( 'TSEXP_SAFE_MODE', $html );
		$this->assertStringNotContainsString( '<form', $html );
		$this->assertStringNotContainsString( '<script', $html );
		$this->assertStringNotContainsString( '<b>9.9.9.9', $html, 'La IP de la tabla se escapa.' );
		$this->assertStringContainsString( '&lt;b&gt;9.9.9.9', $html );
	}

	public function test_render_settings_shows_cross_site_entries_without_prefix_and_escaped(): void {
		$this->rows['xs|<i>8.8.8.8</i>']  = $this->row( array( 'locked_until' => time() + 600 ) );
		$this->rows['xs|2001:db8:1::/48'] = $this->row( array( 'locked_until' => time() + 300 ) );
		$module                           = new Login_Limit();

		ob_start();
		$module->render_settings( array(), 'x[y]' );
		$html = (string) ob_get_clean();

		$this->assertStringNotContainsString( 'xs|', $html );
		$this->assertStringContainsString( '<code>2001:db8:1::/48</code> (intentos desde otros sitios)', $html );
		$this->assertStringContainsString( '&lt;i&gt;8.8.8.8&lt;/i&gt;', $html );
		$this->assertStringNotContainsString( '<i>8.8.8.8', $html );
	}
}

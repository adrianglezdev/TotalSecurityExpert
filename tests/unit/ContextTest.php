<?php
/**
 * Tests de Context.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

/**
 * Un callback que lanza no propaga; un filtro roto devuelve el valor original.
 */
class ContextTest extends TestCase {

	public function test_action_that_throws_does_not_propagate_and_is_reported_once(): void {
		$context = $this->make_context( 'mi-modulo' );
		$this->capture_hooks( 'init' );

		$context->add_action(
			'init',
			static function () {
				throw new \RuntimeException( 'roto' );
			}
		);

		$this->do_captured_action( 'init' );
		$this->do_captured_action( 'init' );

		$this->assertCount( 1, $this->reported_errors, 'Un error por peticion y modulo, no en bucle.' );
		$this->assertSame( 'mi-modulo', $this->reported_errors[0][0] );
		$this->assertStringContainsString( 'roto', $this->reported_errors[0][1] );
		$this->assertStringContainsString( 'init', $this->reported_errors[0][1] );
	}

	public function test_action_that_works_runs_with_its_arguments(): void {
		$context  = $this->make_context();
		$received = array();
		$this->capture_hooks( 'wp_login_failed' );

		$context->add_action(
			'wp_login_failed',
			static function ( $user, $extra = null ) use ( &$received ) {
				$received = array( $user, $extra );
			},
			10,
			2
		);

		$this->do_captured_action( 'wp_login_failed', 'pepe', 'otro' );

		$this->assertSame( array( 'pepe', 'otro' ), $received );
		$this->assertSame( array(), $this->reported_errors );
	}

	public function test_filter_that_throws_returns_the_first_argument_unchanged(): void {
		$context = $this->make_context();
		$this->capture_hooks( 'authenticate' );

		$context->add_filter(
			'authenticate',
			static function ( $user, $username ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- Firma real del filtro.
				throw new \LogicException( 'filtro roto' );
			},
			10,
			2
		);

		$original = new \stdClass();
		$result   = $this->apply_captured_filter( 'authenticate', $original, 'admin' );

		$this->assertSame( $original, $result );
		$this->assertCount( 1, $this->reported_errors );
	}

	public function test_filter_that_works_changes_the_value(): void {
		$context = $this->make_context();
		$this->capture_hooks( 'the_title' );

		$context->add_filter(
			'the_title',
			static fn( $title ) => strtoupper( $title )
		);

		$this->assertSame( 'HOLA', $this->apply_captured_filter( 'the_title', 'hola' ) );
	}

	public function test_a_php_error_in_a_callback_is_also_contained(): void {
		$context = $this->make_context();
		$this->capture_hooks( 'init' );

		$context->add_action(
			'init',
			static function () {
				return intdiv( 1, 0 );
			}
		);

		$this->do_captured_action( 'init' );

		$this->assertCount( 1, $this->reported_errors );
	}

	public function test_log_adds_the_module_id(): void {
		$context = $this->make_context( 'login-limit' );
		$this->event_log_mock->shouldReceive( 'log' )
			->once()
			->with( 'login-limit', 'blocked', 'Bloqueado', array( 'n' => 1 ), 'warning' );

		$context->log( 'blocked', 'Bloqueado', array( 'n' => 1 ), 'warning' );
	}

	public function test_log_defaults_to_info_and_no_data(): void {
		$context = $this->make_context( 'hardening' );
		$this->event_log_mock->shouldReceive( 'log' )
			->once()
			->with( 'hardening', 'x', 'm', array(), 'info' );

		$context->log( 'x', 'm' );
	}

	public function test_filter_registered_with_zero_args_still_receives_the_value_and_fails_open(): void {
		$context = $this->make_context();
		$this->capture_hooks( 'the_content' );

		$context->add_filter(
			'the_content',
			static function () {
				throw new \LogicException( 'filtro sin argumentos' );
			},
			10,
			0
		);

		// Con 0 argumentos WordPress no pasaria el valor y el filtro devolveria null; se fuerza un minimo de 1.
		$this->assertSame( 'contenido', $this->apply_captured_filter( 'the_content', 'contenido' ) );
		$this->assertCount( 1, $this->reported_errors );
	}

	public function test_add_filter_never_registers_fewer_than_one_argument(): void {
		$context = $this->make_context();
		$seen    = array();
		\Brain\Monkey\Filters\expectAdded( 'the_title' )->twice()->whenHappen(
			function ( $callback, $priority, $args ) use ( &$seen ) {
				$seen[] = $args;
			}
		);

		$context->add_filter( 'the_title', static fn( $v = null ) => $v, 10, 0 );
		$context->add_filter( 'the_title', static fn( ...$params ) => $params[0] ?? null, 10, 2 );

		$this->assertSame( array( 1, 2 ), $seen );
	}

	public function test_reported_error_has_class_hook_and_a_message_cut_to_120_characters(): void {
		$context = $this->make_context( 'mi-modulo' );
		$this->capture_hooks( 'init' );

		$long = str_repeat( 'x', 500 );
		$context->add_action(
			'init',
			static function () use ( $long ) {
				throw new \RuntimeException( $long );  // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Test: no se imprime.
			}
		);
		$this->do_captured_action( 'init' );

		$this->assertSame( 'RuntimeException @ init: ' . str_repeat( 'x', 120 ), $this->reported_errors[0][1] );
	}

	public function test_client_ip_bucket_comes_from_the_request(): void {
		$context = $this->make_context( 'login-limit', '2001:db8:1:2:3:4:5:6' );

		$this->assertSame( '2001:db8:1:2::/64', $context->get_client_ip_bucket() );
		$this->assertSame( '198.51.100.1', $this->make_context( 'login-limit', '198.51.100.1' )->get_client_ip_bucket() );
		$this->assertSame( '', $this->make_context( 'login-limit', '' )->get_client_ip_bucket() );
	}

	public function test_ip_and_module_id(): void {
		$context = $this->make_context( 'admin-alert', '198.51.100.1' );

		$this->assertSame( '198.51.100.1', $context->get_client_ip() );
		$this->assertSame( 'admin-alert', $context->get_module_id() );
	}
}

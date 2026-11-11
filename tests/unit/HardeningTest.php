<?php
/**
 * Tests del modulo hardening.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use Mockery;
use TotalSecurityExpert\Modules\Hardening;

require_once __DIR__ . '/hardening-wp-error-stub.php';
require_once dirname( __DIR__, 2 ) . '/modules/hardening/class-hardening.php';

/**
 * Cada medida: lo que bloquea y lo que deja pasar.
 */
class HardeningTest extends TestCase {

	private const HOOKS = array(
		'xmlrpc_enabled',
		'xmlrpc_methods',
		'pings_open',
		'wp_headers',
		'wp',
		'init',
		'map_meta_cap',
		'request',
		'redirect_canonical',
		'rest_pre_dispatch',
		'rest_request_before_callbacks',
		'wp_sitemaps_add_provider',
		'oembed_response_data',
		'wp_login_errors',
		'rest_authentication_errors',
		'lost_password',
	);

	/**
	 * Variables de query que devuelve el stub de get_query_var().
	 *
	 * @var array<string,mixed>
	 */
	private array $query_var_stub = array();

	/**
	 * Copia de $_POST.
	 *
	 * @var array<string,mixed>
	 */
	private array $post_backup = array();

	/**
	 * Ultimo modulo arrancado por boot_module().
	 *
	 * @var Hardening
	 */
	private $module;

	/**
	 * Copia de $_GET.
	 *
	 * @var array<string,mixed>
	 */
	private array $get_backup = array();

	protected function setUp(): void {
		parent::setUp();
		$this->get_backup  = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Prueba que restaura $_GET, no procesa datos.
		$_GET              = array();
		$this->post_backup = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Prueba que restaura $_POST, no procesa datos.
		Functions\when( 'is_admin' )->justReturn( false );
		Functions\when( 'is_user_logged_in' )->justReturn( false );
		Functions\when( 'get_option' )->alias(
			static function ( $name, $fallback = false ) {
				return 'permalink_structure' === $name ? '/%postname%/' : $fallback;
			}
		);
		Functions\when( 'get_query_var' )->alias( fn( $name ) => $this->query_var_stub[ $name ] ?? '' );
	}

	protected function tearDown(): void {
		$_GET  = $this->get_backup;
		$_POST = $this->post_backup;
		unset( $GLOBALS['wp_query'] );
		parent::tearDown();
	}

	/**
	 * Arranca el modulo con estos ajustes (sobre los de por defecto) capturando los hooks.
	 *
	 * @param array<string,bool> $overrides Ajustes a cambiar.
	 * @return Hardening
	 */
	private function boot_module( array $overrides = array() ): Hardening {
		$module       = new class() extends Hardening {
			/**
			 * Destinos de redireccion pedidos.
			 *
			 * @var array<int,string>
			 */
			public array $redirects = array();

			/**
			 * Cabeceras quitadas.
			 *
			 * @var array<int,string>
			 */
			public array $removed_headers = array();

			/**
			 * Veces que se ha pedido terminar la peticion.
			 *
			 * @var int
			 */
			public int $terminated = 0;

			/**
			 * Simula xmlrpc.php?rsd.
			 *
			 * @var bool
			 */
			public bool $rsd = false;

			/**
			 * Si true, redirect_and_exit() real (con terminate() sustituido).
			 *
			 * @var bool
			 */
			public bool $real_redirect = false;

			protected function redirect_and_exit( string $url ): void {
				if ( $this->real_redirect ) {
					parent::redirect_and_exit( $url );
					return;
				}
				$this->redirects[] = $url;
			}

			protected function remove_header( string $name ): void {
				$this->removed_headers[] = $name;
			}

			protected function terminate(): void {
				++$this->terminated;
			}

			protected function is_rsd_request(): bool {
				return $this->rsd;
			}
		};
		$this->module = $module;
		$this->capture_hooks( 'pre_ping', ...self::HOOKS );
		$module->boot( $this->make_context( 'hardening' ), array_merge( $module->get_default_settings(), $overrides ) );
		return $module;
	}

	private function logged_in( bool $state ): void {
		Functions\when( 'is_user_logged_in' )->justReturn( $state );
	}

	private function rest_request( string $route ) {
		$request = Mockery::mock();
		$request->shouldReceive( 'get_route' )->andReturn( $route );
		return $request;
	}

	private function dispatch( string $route ) {
		return $this->apply_captured_filter( 'rest_pre_dispatch', null, null, $this->rest_request( $route ) );
	}

	// Identidad y ajustes.

	public function test_identity_and_defaults(): void {
		$module = new Hardening();

		$this->assertSame( 'hardening', $module->get_id() );
		$this->assertNotSame( '', $module->get_name() );
		$this->assertNotSame( '', $module->get_description() );
		$this->assertSame(
			array(
				'disable_xmlrpc'         => true,
				'disable_file_editor'    => true,
				'block_user_enumeration' => true,
				'generic_login_errors'   => true,
			),
			$module->get_default_settings()
		);
	}

	public function test_sanitize_treats_missing_as_false(): void {
		$module = new Hardening();

		$this->assertSame(
			array(
				'disable_xmlrpc'         => true,
				'disable_file_editor'    => false,
				'block_user_enumeration' => false,
				'generic_login_errors'   => false,
			),
			$module->sanitize_settings( array( 'disable_xmlrpc' => '1' ) )
		);
		$this->assertSame( array_keys( $module->get_default_settings() ), array_keys( $module->sanitize_settings( array() ) ) );
	}

	public function test_sanitize_is_idempotent_and_ignores_junk(): void {
		$module = new Hardening();
		$first  = $module->sanitize_settings(
			array(
				'disable_xmlrpc'       => 'on',
				'disable_file_editor'  => array( 'x' ),
				'generic_login_errors' => 'false',
				'unknown'              => '1',
			)
		);

		$this->assertSame( $first, $module->sanitize_settings( $first ) );
		$this->assertTrue( $first['disable_xmlrpc'] );
		$this->assertFalse( $first['disable_file_editor'] );
		$this->assertFalse( $first['generic_login_errors'] );
		$this->assertArrayNotHasKey( 'unknown', $first );
	}

	public function test_render_settings_escapes_and_labels_every_field(): void {
		$module = new Hardening();

		ob_start();
		$module->render_settings( array( 'disable_file_editor' => false ), 'tsexp_settings[modules][hardening][settings]' );
		$html = ob_get_clean();

		foreach ( array_keys( $module->get_default_settings() ) as $key ) {
			$this->assertStringContainsString( 'name="tsexp_settings[modules][hardening][settings][' . $key . ']"', $html );
			$this->assertStringContainsString( '<label for="tsexp-hardening-' . $key . '">', $html );
			$this->assertStringContainsString( 'id="tsexp-hardening-' . $key . '"', $html );
		}
		$this->assertSame( 3, substr_count( $html, 'checked="checked"' ) );
		$this->assertStringContainsString( 'Jetpack', $html );
		$this->assertStringNotContainsString( '<form', $html );
		$this->assertStringNotContainsString( '<script', $html );
	}

	// Registro de hooks.

	public function test_all_hooks_registered_by_default(): void {
		$this->boot_module();

		foreach ( self::HOOKS as $hook ) {
			$this->assertNotEmpty( $this->captured_callbacks( $hook ), "Falta el hook $hook" );
		}
	}

	/**
	 * Casilla => hooks que solo ella registra.
	 *
	 * @return array<string,array{0:string,1:array<int,string>}>
	 */
	public static function checkbox_hooks(): array {
		return array(
			'xmlrpc'      => array( 'disable_xmlrpc', array( 'xmlrpc_enabled', 'xmlrpc_methods', 'pings_open', 'wp_headers', 'wp', 'init' ) ),
			'file editor' => array( 'disable_file_editor', array( 'map_meta_cap' ) ),
			'enumeration' => array( 'block_user_enumeration', array( 'request', 'redirect_canonical', 'rest_pre_dispatch', 'rest_request_before_callbacks', 'wp_sitemaps_add_provider', 'oembed_response_data' ) ),
			'login'       => array( 'generic_login_errors', array( 'wp_login_errors', 'rest_authentication_errors', 'lost_password' ) ),
		);
	}

	/**
	 * Apagar una casilla quita solo sus hooks.
	 *
	 * @dataProvider checkbox_hooks
	 *
	 * @param string             $key   Casilla apagada.
	 * @param array<int,string> $hooks Hooks que no deben registrarse.
	 */
	public function test_disabled_checkbox_registers_none_of_its_hooks( string $key, array $hooks ): void {
		$this->boot_module( array( $key => false ) );

		foreach ( $hooks as $hook ) {
			$this->assertSame( array(), $this->captured_callbacks( $hook ), "$key apagado no debe registrar $hook" );
		}
		$others = array_diff( self::HOOKS, $hooks );
		foreach ( $others as $hook ) {
			$this->assertNotEmpty( $this->captured_callbacks( $hook ), "$hook debe seguir activo" );
		}
	}

	// XML-RPC.

	public function test_xmlrpc_disabled_when_checked(): void {
		$this->boot_module();

		$this->assertFalse( $this->apply_captured_filter( 'xmlrpc_enabled', true ) );
		$this->assertSame(
			array(),
			$this->apply_captured_filter(
				'xmlrpc_methods',
				array(
					'pingback.ping'    => 'x',
					'wp.getUsersBlogs' => 'y',
				)
			)
		);
	}

	public function test_xmlrpc_untouched_when_unchecked(): void {
		$this->boot_module( array( 'disable_xmlrpc' => false ) );

		$this->assertTrue( $this->apply_captured_filter( 'xmlrpc_enabled', true ) );
		$this->assertSame( array( 'a' => 'b' ), $this->apply_captured_filter( 'xmlrpc_methods', array( 'a' => 'b' ) ) );
	}

	public function test_pingback_header_removed_case_insensitively_and_others_kept(): void {
		$this->boot_module();

		$headers = $this->apply_captured_filter(
			'wp_headers',
			array(
				'X-Pingback'   => 'http://example.test/xmlrpc.php',
				'x-pingback'   => 'http://example.test/xmlrpc.php',
				'Content-Type' => 'text/html',
			)
		);

		$this->assertSame( array( 'Content-Type' => 'text/html' ), $headers );
	}

	public function test_rsd_link_removed_on_init(): void {
		Actions\expectRemoved( 'wp_head' )->once()->with( 'rsd_link', 10 );
		Functions\expect( 'status_header' )->never();
		$this->boot_module();

		$this->do_captured_action( 'init' );

		$this->assertSame( 0, $this->module->terminated );
	}

	public function test_rsd_request_to_xmlrpc_gets_404_and_ends(): void {
		Actions\expectRemoved( 'wp_head' )->once();
		Functions\expect( 'status_header' )->once()->with( 404 );
		$this->boot_module();
		$this->module->rsd = true;

		$this->do_captured_action( 'init' );

		$this->assertSame( 1, $this->module->terminated );
	}

	public function test_pingback_header_dropped_on_wp_action(): void {
		$this->boot_module();

		$this->do_captured_action( 'wp' );

		$this->assertSame( array( 'X-Pingback' ), $this->module->removed_headers );
	}

	public function test_pings_closed_when_checked_and_open_otherwise(): void {
		$this->boot_module();
		$this->assertFalse( $this->apply_captured_filter( 'pings_open', true, 1 ) );
	}

	public function test_pings_untouched_when_unchecked(): void {
		$this->boot_module( array( 'disable_xmlrpc' => false ) );

		$this->assertTrue( $this->apply_captured_filter( 'pings_open', true, 1 ) );
		$this->do_captured_action( 'init' );
		$this->do_captured_action( 'wp' );
		$this->assertSame( array(), $this->captured_callbacks( 'pre_ping' ) );
		$this->assertSame( array(), $this->module->removed_headers );
	}

	public function test_pre_ping_registered_on_init_and_empties_links_by_reference(): void {
		Actions\expectRemoved( 'wp_head' )->once();
		$this->boot_module();
		$this->assertSame( array(), $this->captured_callbacks( 'pre_ping' ) );

		$this->do_captured_action( 'init' );
		$this->assertCount( 1, $this->captured_callbacks( 'pre_ping' ) );

		$links = array( 'http://a.test/', 'http://b.test/' );
		$this->module->empty_ping_links( $links );
		$this->assertSame( array(), $links );
	}

	// Editor de ficheros.

	public function test_file_editor_caps_denied(): void {
		$this->boot_module();

		foreach ( array( 'edit_files', 'edit_plugins', 'edit_themes' ) as $cap ) {
			$this->assertSame( array( 'do_not_allow' ), $this->apply_captured_filter( 'map_meta_cap', array( 'edit_plugins' ), $cap, 1, array() ), $cap );
		}
	}

	public function test_caps_resolving_to_an_editor_cap_are_denied(): void {
		$this->boot_module();

		$this->assertSame( array( 'do_not_allow' ), $this->apply_captured_filter( 'map_meta_cap', array( 'edit_themes' ), 'otra_cosa', 1, array() ) );
		$this->assertSame( array( 'do_not_allow' ), $this->apply_captured_filter( 'map_meta_cap', array( 'read', 'edit_plugins' ), 'otra_cosa', 1, array() ) );
	}

	public function test_caps_filter_runs_last(): void {
		$this->boot_module();
		$this->assertSame( PHP_INT_MAX, $this->priority_of( 'map_meta_cap' ) );
	}

	public function test_caps_untouched_when_file_editor_checkbox_is_off(): void {
		$this->boot_module( array( 'disable_file_editor' => false ) );
		$this->assertSame( array( 'edit_plugins' ), $this->apply_captured_filter( 'map_meta_cap', array( 'edit_plugins' ), 'edit_plugins', 1, array() ) );
	}

	public function test_other_caps_left_alone(): void {
		$this->boot_module();

		foreach ( array( 'update_plugins', 'install_plugins', 'activate_plugins', 'delete_plugins', 'update_core', 'edit_posts', 'edit_theme_options', 'manage_options' ) as $cap ) {
			$this->assertSame( array( $cap ), $this->apply_captured_filter( 'map_meta_cap', array( $cap ), $cap, 1, array() ), $cap );
		}
	}

	// Enumeracion: ?author=.

	/**
	 * Valores de author que deben cortarse.
	 *
	 * @return array<string,array{0:mixed}>
	 */
	public static function author_values(): array {
		return array(
			'numero'     => array( '1' ),
			'con basura' => array( '1abc' ),
			'texto'      => array( 'admin' ),
			'array'      => array( array( '1' ) ),
			'entero'     => array( 1 ),
		);
	}

	/**
	 * Un visitante con author en la query ya resuelta recibe 404 (y sin feed).
	 *
	 * @dataProvider author_values
	 *
	 * @param mixed $value Valor de author.
	 */
	public function test_author_request_becomes_404_for_guest( $value ): void {
		$this->boot_module();

		$vars = $this->apply_captured_filter(
			'request',
			array(
				'author' => $value,
				'feed'   => 'rss2',
				'paged'  => '2',
			)
		);

		$this->assertSame(
			array(
				'paged' => '2',
				'error' => '404',
			),
			$vars
		);
	}

	public function test_author_from_post_is_blocked_too(): void {
		$_POST = array( 'author' => '1' ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Simula un POST.
		$this->boot_module();

		// WP::parse_request() ya mezcla $_POST en la query antes del filtro.
		$vars = $this->apply_captured_filter( 'request', array( 'author' => '1' ) );

		$this->assertSame( array( 'error' => '404' ), $vars );
	}

	public function test_author_request_allowed_for_logged_in_user_and_in_admin(): void {
		$this->boot_module();
		$vars = array(
			'author' => '1',
			'feed'   => 'rss2',
		);

		$this->logged_in( true );
		$this->assertSame( $vars, $this->apply_captured_filter( 'request', $vars ) );

		$this->logged_in( false );
		Functions\when( 'is_admin' )->justReturn( true );
		$this->assertSame( $vars, $this->apply_captured_filter( 'request', $vars ) );
	}

	public function test_requests_without_author_are_left_alone(): void {
		$this->boot_module();

		foreach ( array( array(), array( 'author' => '' ), array( 'author' => '0' ), array( 'author' => array() ), array( 'author_name' => 'admin' ), array( 's' => 'hola' ) ) as $vars ) {
			$this->assertSame( $vars, $this->apply_captured_filter( 'request', $vars ) );
		}
	}

	public function test_author_not_blocked_with_plain_permalinks(): void {
		Functions\when( 'get_option' )->justReturn( '' );
		$this->boot_module();
		$vars = array( 'author' => '1' );

		$this->assertSame( $vars, $this->apply_captured_filter( 'request', $vars ) );
		$this->query_var_stub = array( 'author' => '1' );
		$this->assertSame( 'u', $this->apply_captured_filter( 'redirect_canonical', 'u' ) );
	}

	public function test_canonical_redirect_to_author_stopped_only_for_guests(): void {
		$this->boot_module();
		$this->query_var_stub = array( 'author' => '1' );

		$this->assertFalse( $this->apply_captured_filter( 'redirect_canonical', 'http://example.test/author/admin/' ) );

		$this->logged_in( true );
		$this->assertSame( 'http://example.test/author/admin/', $this->apply_captured_filter( 'redirect_canonical', 'http://example.test/author/admin/' ) );

		$this->logged_in( false );
		$this->query_var_stub = array();
		$this->assertSame( 'http://example.test/x/', $this->apply_captured_filter( 'redirect_canonical', 'http://example.test/x/' ) );
	}

	public function test_canonical_redirect_kept_on_author_slug_archives(): void {
		$this->boot_module();
		$this->query_var_stub = array(
			'author'      => '1',
			'author_name' => 'admin',
		);

		$this->assertSame( 'http://example.test/author/admin/', $this->apply_captured_filter( 'redirect_canonical', 'http://example.test/author/admin/' ) );
	}

	// Enumeracion: REST.

	public function test_rest_users_blocked_for_guest_with_401(): void {
		$this->boot_module();

		$routes = array(
			'/wp/v2/users',
			'/wp/v2/users/',
			'/wp/v2/users/1',
			'/wp/v2/users/me',
			'/wp/v2/Users',
			'/WP/V2/users/1',
			'/WP/V2/USERS/',
			'/wp/v2/users/1/application-passwords',
			'wp/v2/users',
			"/wp/v2/users\n",
			"/wp/v2/users\r\n",
			"/wp/v2/users/1\n",
			"/wp/v2/users\t ",
			'/wp/v2/users%0A',
			'/wp/v2/users%0a/',
		);
		foreach ( $routes as $route ) {
			$result = $this->dispatch( $route );
			$this->assertInstanceOf( \WP_Error::class, $result, $route );
			$this->assertSame( 401, $result->get_error_data()['status'], $route );
		}
	}

	public function test_rest_other_routes_allowed_for_guest(): void {
		$this->boot_module();

		foreach ( array( '/wp/v2/posts', '/wp/v2/posts/1', '/wp/v2/users-extra', '/wp/v2/usersx', '/wp/v2/types', '/', '/other/v1/users', '/wp/v2' ) as $route ) {
			$this->assertNull( $this->dispatch( $route ), $route );
		}
	}

	public function test_rest_users_allowed_when_logged_in(): void {
		$this->logged_in( true );
		$this->boot_module();

		$this->assertNull( $this->dispatch( '/wp/v2/users' ) );
		$this->assertNull( $this->dispatch( '/wp/v2/Users/1' ) );
	}

	public function test_rest_respects_previous_short_circuit(): void {
		$this->boot_module();
		$previous = array( 'from' => 'other' );

		$this->assertSame( $previous, $this->apply_captured_filter( 'rest_pre_dispatch', $previous, null, $this->rest_request( '/wp/v2/users' ) ) );
	}

	// Enumeracion: sitemaps y oEmbed.

	public function test_users_sitemap_provider_removed_only(): void {
		$this->boot_module();
		$provider = new \stdClass();

		$this->assertFalse( $this->apply_captured_filter( 'wp_sitemaps_add_provider', $provider, 'users' ) );
		$this->assertSame( $provider, $this->apply_captured_filter( 'wp_sitemaps_add_provider', $provider, 'posts' ) );
		$this->assertSame( $provider, $this->apply_captured_filter( 'wp_sitemaps_add_provider', $provider, 'taxonomies' ) );
	}

	public function test_oembed_author_removed_and_rest_kept(): void {
		$this->boot_module();

		$data = $this->apply_captured_filter(
			'oembed_response_data',
			array(
				'title'       => 'Hola',
				'author_name' => 'admin',
				'author_url'  => 'http://example.test/author/admin/',
				'type'        => 'rich',
			)
		);

		$this->assertSame(
			array(
				'title' => 'Hola',
				'type'  => 'rich',
			),
			$data
		);
	}

	public function test_enumeration_off_leaves_everything_untouched(): void {
		$this->boot_module( array( 'block_user_enumeration' => false ) );

		$this->assertSame( array(), $this->captured_callbacks( 'rest_pre_dispatch' ) );
		$this->assertSame( array(), $this->captured_callbacks( 'oembed_response_data' ) );
	}

	// Errores de acceso.

	public function test_leaky_login_errors_replaced_by_one_generic_message(): void {
		$this->boot_module();

		foreach ( array( 'invalid_username', 'invalid_email', 'incorrect_password' ) as $code ) {
			$errors = new \WP_Error( $code, 'El usuario fantasma no existe.' );
			$result = $this->apply_captured_filter( 'wp_login_errors', $errors, '' );

			$this->assertSame( array( 'tsexp_invalid_login' ), $result->get_error_codes(), $code );
			$this->assertStringNotContainsString( 'fantasma', $result->get_error_message() );
		}
	}

	public function test_all_three_leaky_errors_give_a_single_message(): void {
		$this->boot_module();
		$errors = new \WP_Error( 'invalid_username', 'a' );
		$errors->add( 'incorrect_password', 'b' );
		$errors->add( 'invalid_email', 'c' );

		$result = $this->apply_captured_filter( 'wp_login_errors', $errors, '' );

		$this->assertSame( array( 'tsexp_invalid_login' ), $result->get_error_codes() );
		$this->assertCount( 1, $result->errors['tsexp_invalid_login'] );
	}

	public function test_other_login_errors_left_as_they_are(): void {
		$this->boot_module();

		foreach ( array( 'tsexp_locked', 'empty_password', 'empty_username', 'loggedout', 'expired' ) as $code ) {
			$errors = new \WP_Error( $code, 'Mensaje original' );
			$result = $this->apply_captured_filter( 'wp_login_errors', $errors, '' );

			$this->assertSame( array( $code ), $result->get_error_codes(), $code );
			$this->assertSame( 'Mensaje original', $result->get_error_message( $code ) );
		}
	}

	public function test_locked_error_kept_next_to_generic_one(): void {
		$this->boot_module();
		$errors = new \WP_Error( 'tsexp_locked', 'Bloqueado' );
		$errors->add( 'incorrect_password', 'Clave mal' );

		$result = $this->apply_captured_filter( 'wp_login_errors', $errors, '' );

		$this->assertSame( 'Bloqueado', $result->get_error_message( 'tsexp_locked' ) );
		$this->assertContains( 'tsexp_invalid_login', $result->get_error_codes() );
		$this->assertNotContains( 'incorrect_password', $result->get_error_codes() );
	}

	public function test_login_errors_untouched_when_unchecked(): void {
		$this->boot_module( array( 'generic_login_errors' => false ) );

		$this->assertSame( array(), $this->captured_callbacks( 'wp_login_errors' ) );
	}

	public function test_login_filter_ignores_non_wp_error(): void {
		$this->boot_module();

		$this->assertSame( 'texto', $this->apply_captured_filter( 'wp_login_errors', 'texto', '' ) );
	}

	// REST: decidir por el controlador.

	private function handler_for( $controller ): array {
		return array( 'callback' => array( $controller, 'get_items' ) );
	}

	public function test_users_controller_blocked_for_guest_whatever_the_route_text(): void {
		$this->boot_module();

		$result = $this->apply_captured_filter(
			'rest_request_before_callbacks',
			null,
			$this->handler_for( new \WP_REST_Users_Controller() ),
			$this->rest_request( "/wp/v2/users\n" )
		);

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 401, $result->get_error_data()['status'] );
	}

	public function test_users_controller_allowed_when_logged_in(): void {
		$this->logged_in( true );
		$this->boot_module();

		$this->assertNull( $this->apply_captured_filter( 'rest_request_before_callbacks', null, $this->handler_for( new \WP_REST_Users_Controller() ), $this->rest_request( '/wp/v2/users' ) ) );
	}

	public function test_other_handlers_pass_before_callbacks(): void {
		$this->boot_module();
		$request = $this->rest_request( '/wp/v2/posts' );

		$this->assertNull( $this->apply_captured_filter( 'rest_request_before_callbacks', null, $this->handler_for( new \stdClass() ), $request ) );
		$this->assertNull( $this->apply_captured_filter( 'rest_request_before_callbacks', null, array( 'callback' => static fn() => 1 ), $request ) );
		$this->assertNull( $this->apply_captured_filter( 'rest_request_before_callbacks', null, array(), $request ) );
		$this->assertNull( $this->apply_captured_filter( 'rest_request_before_callbacks', null, 'nope', $request ) );
	}

	// REST: errores de contrasenas de aplicacion.

	public function test_rest_auth_leaky_errors_become_one_generic_401(): void {
		$this->boot_module();
		$this->assertGreaterThan( 90, $this->priority_of( 'rest_authentication_errors' ) );

		foreach ( array( 'invalid_username', 'invalid_email', 'incorrect_password' ) as $code ) {
			$result = $this->apply_captured_filter( 'rest_authentication_errors', new \WP_Error( $code, 'fantasma', array( 'status' => 403 ) ) );

			$this->assertSame( array( 'tsexp_invalid_login' ), $result->get_error_codes(), $code );
			$this->assertSame( 401, $result->get_error_data( 'tsexp_invalid_login' )['status'] );
			$this->assertStringNotContainsString( 'fantasma', $result->get_error_message() );
		}
	}

	public function test_rest_auth_application_passwords_disabled_errors_are_generic_too(): void {
		$this->boot_module();

		foreach ( array( 'application_passwords_disabled', 'application_passwords_disabled_for_user' ) as $code ) {
			$result = $this->apply_captured_filter( 'rest_authentication_errors', new \WP_Error( $code, 'Desactivadas', array( 'status' => 501 ) ) );

			$this->assertSame( array( 'tsexp_invalid_login' ), $result->get_error_codes(), $code );
			$this->assertSame( 401, $result->get_error_data( 'tsexp_invalid_login' )['status'] );
		}
	}

	public function test_login_form_keeps_application_passwords_codes(): void {
		$this->boot_module();
		$result = $this->apply_captured_filter( 'wp_login_errors', new \WP_Error( 'application_passwords_disabled', 'x' ), '' );

		$this->assertSame( array( 'application_passwords_disabled' ), $result->get_error_codes() );
	}

	public function test_rest_auth_other_results_untouched(): void {
		$this->boot_module();

		foreach ( array( 'tsexp_locked', 'rest_cannot_x', 'rest_forbidden' ) as $code ) {
			$error  = new \WP_Error( $code, 'Original', array( 'status' => 429 ) );
			$result = $this->apply_captured_filter( 'rest_authentication_errors', $error );

			$this->assertSame( array( $code ), $result->get_error_codes(), $code );
			$this->assertSame( 429, $result->get_error_data( $code )['status'] );
		}
		$this->assertNull( $this->apply_captured_filter( 'rest_authentication_errors', null ) );
		$this->assertTrue( $this->apply_captured_filter( 'rest_authentication_errors', true ) );
	}

	public function test_rest_auth_locked_kept_next_to_generic(): void {
		$this->boot_module();
		$error = new \WP_Error( 'tsexp_locked', 'Bloqueado', array( 'status' => 429 ) );
		$error->add( 'incorrect_password', 'mal' );

		$result = $this->apply_captured_filter( 'rest_authentication_errors', $error );

		$this->assertSame( array( 'tsexp_locked', 'tsexp_invalid_login' ), $result->get_error_codes() );
		$this->assertSame( 429, $result->get_error_data( 'tsexp_locked' )['status'] );
	}

	// Recuperar contrasena.

	private function lostpassword( $errors ): void {
		Functions\when( 'wp_login_url' )->justReturn( 'https://example.test/wp-login.php' );
		Functions\when( 'add_query_arg' )->alias( static fn( $k, $v, $url ) => $url . '?' . $k . '=' . $v );
		$this->do_captured_action( 'lost_password', $errors );
	}

	public function test_lost_password_runs_after_other_plugins(): void {
		$this->boot_module();

		$this->assertGreaterThanOrEqual( 99, $this->priority_of( 'lost_password' ) );
		$this->assertSame( array(), $this->captured_callbacks( 'lostpassword_post' ) );
	}

	public function test_lostpassword_nonexistent_user_redirects_like_success(): void {
		$this->boot_module();

		foreach ( array( 'invalid_email', 'invalidcombo', 'retrieve_password_email_failure' ) as $code ) {
			$this->module->redirects = array();
			$this->lostpassword( new \WP_Error( $code, 'No hay cuenta.' ) );

			$this->assertSame( array( 'https://example.test/wp-login.php?checkemail=confirm' ), $this->module->redirects, $code );
		}
	}

	public function test_lostpassword_all_codes_within_the_list_redirect(): void {
		$this->boot_module();
		$errors = new \WP_Error( 'invalid_email', 'a' );
		$errors->add( 'invalidcombo', 'b' );

		$this->lostpassword( $errors );

		$this->assertCount( 1, $this->module->redirects );
	}

	public function test_lostpassword_other_codes_or_mixed_codes_do_not_redirect(): void {
		$this->boot_module();
		$mixed = new \WP_Error( 'invalidcombo', 'No hay cuenta.' );
		$mixed->add( 'captcha_failed', 'Captcha' );

		$this->lostpassword( new \WP_Error( 'captcha_failed', 'Captcha' ) );
		$this->lostpassword( $mixed );
		$this->lostpassword( new \WP_Error( 'empty_username', 'Falta el usuario.' ) );
		$this->lostpassword( new \WP_Error() );
		$this->lostpassword( 'no-es-error' );
		$this->lostpassword( null );

		$this->assertSame( array(), $this->module->redirects );
	}

	public function test_redirect_and_exit_uses_safe_redirect_then_terminates(): void {
		Functions\expect( 'wp_safe_redirect' )->once()->with( 'https://example.test/x' );
		$this->boot_module();
		$this->module->real_redirect = true;

		$method = new \ReflectionMethod( $this->module, 'redirect_and_exit' );
		$method->invoke( $this->module, 'https://example.test/x' );

		$this->assertSame( 1, $this->module->terminated );
	}

	/**
	 * Prioridad con la que se registro el ultimo callback capturado de un hook.
	 *
	 * @param string $hook Hook.
	 * @return int
	 */
	private function priority_of( string $hook ): int {
		$prop     = new \ReflectionProperty( TestCase::class, 'captured' );
		$captured = $prop->getValue( $this );
		$list     = $captured['filter'][ $hook ] ?? $captured['action'][ $hook ];
		return (int) end( $list )[1];
	}
}

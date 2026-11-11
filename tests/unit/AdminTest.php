<?php
/**
 * Tests de Admin (avisos y permisos).
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey\Functions;
use Mockery;
use TotalSecurityExpert\Admin\Admin;
use TotalSecurityExpert\Event_Log;
use TotalSecurityExpert\Module_Loader;
use TotalSecurityExpert\Settings;

/**
 * Los avisos solo los ve quien tiene manage_options y siempre salen escapados.
 */
class AdminTest extends TestCase {

	/**
	 * Admin con un cargador simulado.
	 *
	 * @param bool                                             $safe_mode Si el modo seguro esta activo.
	 * @param array<string,array{message:string,time:int}>     $errors    Errores guardados.
	 * @return Admin
	 */
	private function make_admin( bool $safe_mode, array $errors ): Admin {
		$loader = Mockery::mock( Module_Loader::class );
		$loader->shouldReceive( 'is_safe_mode' )->andReturn( $safe_mode );
		$loader->shouldReceive( 'get_errors' )->andReturn( $errors );
		return new Admin( Mockery::mock( Settings::class ), $loader, Mockery::mock( Event_Log::class ) );
	}

	public function test_notices_are_hidden_from_users_without_manage_options(): void {
		Functions\expect( 'current_user_can' )->with( 'manage_options' )->andReturn( false );
		$admin = $this->make_admin(
			true,
			array(
				'fake' => array(
					'message' => 'x',
					'time'    => 1,
				),
			)
		);

		ob_start();
		$admin->render_notices();

		$this->assertSame( '', ob_get_clean() );
	}

	public function test_error_notice_is_escaped(): void {
		Functions\expect( 'current_user_can' )->with( 'manage_options' )->andReturn( true );
		$admin = $this->make_admin(
			false,
			array(
				'<img src=x>' => array(
					'message' => '<script>alert(1)</script>',
					'time'    => 1,
				),
			)
		);

		ob_start();
		$admin->render_notices();
		$html = (string) ob_get_clean();

		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringNotContainsString( '<img', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
		$this->assertStringContainsString( 'notice-error', $html );
	}

	public function test_safe_mode_notice_is_shown_to_administrators(): void {
		Functions\expect( 'current_user_can' )->with( 'manage_options' )->andReturn( true );
		$admin = $this->make_admin( true, array() );

		ob_start();
		$admin->render_notices();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'TSEXP_SAFE_MODE', $html );
		$this->assertStringContainsString( 'notice-warning', $html );
	}

	public function test_no_notice_when_all_is_fine(): void {
		Functions\expect( 'current_user_can' )->with( 'manage_options' )->andReturn( true );
		$admin = $this->make_admin( false, array() );

		ob_start();
		$admin->render_notices();

		$this->assertSame( '', ob_get_clean() );
	}

	public function test_settings_and_log_pages_die_without_manage_options(): void {
		Functions\when( 'current_user_can' )->justReturn( false );
		Functions\expect( 'wp_die' )->twice()->andReturnUsing(
			static function () {
				throw new \RuntimeException( 'wp_die' );
			}
		);
		$admin = $this->make_admin( false, array() );

		foreach ( array( 'render_settings_page', 'render_log_page' ) as $method ) {
			try {
				$admin->$method();
				$this->fail( $method . ' debe cortar con wp_die()' );
			} catch ( \RuntimeException $e ) {
				$this->assertSame( 'wp_die', $e->getMessage() );
			}
		}
	}

	/**
	 * Admin con ajustes generales simulados (para los avisos de IP y la pantalla de ajustes).
	 *
	 * @param array<string,mixed> $general   Cambios sobre los ajustes generales por defecto.
	 * @param bool                $safe_mode Si el modo seguro esta activo.
	 * @return Admin
	 */
	private function make_admin_with_general( array $general, bool $safe_mode = false ): Admin {
		$settings = Mockery::mock( Settings::class );
		$settings->shouldReceive( 'get_general' )->andReturn( array_merge( Settings::default_general(), $general ) );
		$loader = Mockery::mock( Module_Loader::class );
		$loader->shouldReceive( 'is_safe_mode' )->andReturn( $safe_mode );
		$loader->shouldReceive( 'get_errors' )->andReturn( array() );
		return new Admin( $settings, $loader, Mockery::mock( Event_Log::class ) );
	}

	public function test_warning_when_a_header_is_chosen_but_there_are_no_trusted_proxies(): void {
		$admin = $this->make_admin_with_general( array( 'ip_source' => 'x_forwarded_for' ) );

		$warnings = $admin->get_ip_config_warnings( array( 'REMOTE_ADDR' => '10.0.0.1' ) );

		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'no hay proxies de confianza', $warnings[0] );
	}

	public function test_no_warning_with_the_default_direct_connection_and_no_proxy_headers(): void {
		$admin = $this->make_admin_with_general( array() );

		$this->assertSame( array(), $admin->get_ip_config_warnings( array( 'REMOTE_ADDR' => '198.51.100.9' ) ) );
	}

	public function test_warning_when_proxy_headers_arrive_and_remote_addr_is_the_source(): void {
		$admin = $this->make_admin_with_general( array() );

		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' ) as $header ) {
			$warnings = $admin->get_ip_config_warnings(
				array(
					'REMOTE_ADDR' => '10.0.0.1',
					$header       => '203.0.113.5',
				)
			);
			$this->assertCount( 1, $warnings, $header );
			$this->assertStringContainsString( 'misma IP', $warnings[0] );
		}
	}

	public function test_warning_when_proxy_headers_arrive_and_remote_addr_is_not_in_the_trusted_list(): void {
		$admin = $this->make_admin_with_general(
			array(
				'ip_source'       => 'x_forwarded_for',
				'trusted_proxies' => array( '10.0.0.0/8' ),
			)
		);

		$warnings = $admin->get_ip_config_warnings(
			array(
				'REMOTE_ADDR'          => '198.51.100.9',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
			)
		);

		$this->assertCount( 1, $warnings );
	}

	public function test_no_warning_when_the_proxy_is_trusted_and_the_header_is_in_use(): void {
		$admin = $this->make_admin_with_general(
			array(
				'ip_source'       => 'x_forwarded_for',
				'trusted_proxies' => array( '10.0.0.0/8' ),
			)
		);

		$warnings = $admin->get_ip_config_warnings(
			array(
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
			)
		);

		$this->assertSame( array(), $warnings );
	}

	public function test_both_warnings_show_when_a_header_is_chosen_without_proxies_and_headers_arrive(): void {
		$admin = $this->make_admin_with_general( array( 'ip_source' => 'cf_connecting_ip' ) );

		$warnings = $admin->get_ip_config_warnings(
			array(
				'REMOTE_ADDR'           => '10.0.0.1',
				'HTTP_CF_CONNECTING_IP' => '203.0.113.5',
			)
		);

		$this->assertCount( 2, $warnings );
	}

	public function test_settings_page_shows_the_safe_mode_notice_and_the_ip_warnings_escaped(): void {
		Functions\when( 'current_user_can' )->justReturn( true );
		Functions\when( 'settings_fields' )->justReturn( null );
		Functions\when( 'do_settings_sections' )->justReturn( null );
		Functions\when( 'submit_button' )->justReturn( null );
		$admin = $this->make_admin_with_general( array( 'ip_source' => 'x_real_ip' ), true );

		ob_start();
		$admin->render_settings_page();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'Modo seguro activo', $html );
		$this->assertStringContainsString( 'TSEXP_SAFE_MODE', $html );
		$this->assertStringContainsString( 'no hay proxies de confianza', $html );
		$this->assertStringNotContainsString( '<script', $html );
	}

	public function test_safe_mode_lists_registry_modules_as_unavailable_without_calling_module_code(): void {
		$settings = Mockery::mock( Settings::class );
		$loader   = Mockery::mock( Module_Loader::class );
		$loader->shouldReceive( 'is_safe_mode' )->andReturn( true );
		$loader->shouldReceive( 'get_registry_ids' )->andReturn( array( 'login-limit', '<b>x</b>' ) );
		$loader->shouldNotReceive( 'get_modules' );
		$loader->shouldNotReceive( 'get_module' );
		$sections = array();
		Functions\when( 'add_settings_field' )->justReturn( null );
		Functions\when( 'add_settings_section' )->alias(
			function ( $id, $title, $callback ) use ( &$sections ) {
				$sections[ $id ] = array( $title, $callback );
			}
		);
		$admin = new Admin( $settings, $loader, Mockery::mock( Event_Log::class ) );

		$admin->register_sections();

		$this->assertArrayHasKey( 'tsexp_module_login-limit', $sections );
		$this->assertArrayHasKey( 'tsexp_module_<b>x</b>', $sections );
		$this->assertStringNotContainsString( '<b>', $sections['tsexp_module_<b>x</b>'][0], 'El titulo va escapado.' );
		ob_start();
		( $sections['tsexp_module_login-limit'][1] )();
		$this->assertStringContainsString( 'No disponible', (string) ob_get_clean() );
	}

	public function test_capability_for_options_php_is_manage_options(): void {
		$this->assertSame( 'manage_options', $this->make_admin( false, array() )->get_capability() );
	}

	/**
	 * Registra el menu con add_menu_page/add_submenu_page simulados y devuelve el Admin.
	 *
	 * @param array<string,string|false> $returns Valor devuelto por pagina (slug => hook suffix o false).
	 * @return Admin
	 */
	private function make_admin_with_menu( array $returns ): Admin {
		Functions\when( 'add_menu_page' )->alias(
			static fn( $title, $menu_title, $cap, $slug ) => $returns[ $slug ]
		);
		Functions\when( 'add_submenu_page' )->alias(
			static fn( $parent_slug, $title, $menu_title, $cap, $slug ) => $returns[ $slug ]
		);
		$admin = $this->make_admin( false, array() );
		$admin->register_menu();
		return $admin;
	}

	public function test_stylesheet_is_enqueued_only_on_the_two_plugin_pages(): void {
		$admin    = $this->make_admin_with_menu(
			array(
				Admin::PAGE_SETTINGS => 'toplevel_page_tsexp-settings',
				Admin::PAGE_LOG      => 'total-security_page_tsexp-log',
			)
		);
		$enqueued = array();
		Functions\when( 'wp_enqueue_style' )->alias(
			static function ( ...$args ) use ( &$enqueued ) {
				$enqueued[] = $args;
			}
		);

		foreach ( array( 'toplevel_page_tsexp-settings', 'total-security_page_tsexp-log' ) as $hook ) {
			$admin->enqueue_assets( $hook );
		}
		$this->assertCount( 2, $enqueued );
		$this->assertSame( TSEXP_URL . 'admin/css/admin.css', $enqueued[0][1] );
		$this->assertSame( TSEXP_VERSION, $enqueued[0][3] );

		foreach ( array( 'index.php', 'plugins.php', 'settings_page_other', 'toplevel_page_tsexp-settings-x', '' ) as $hook ) {
			$admin->enqueue_assets( $hook );
		}
		$this->assertCount( 2, $enqueued, 'No se encola en paginas ajenas.' );
	}

	public function test_stylesheet_is_not_enqueued_when_the_menu_was_not_registered(): void {
		$admin = $this->make_admin_with_menu(
			array(
				Admin::PAGE_SETTINGS => false,
				Admin::PAGE_LOG      => false,
			)
		);
		Functions\expect( 'wp_enqueue_style' )->never();

		$admin->enqueue_assets( 'toplevel_page_tsexp-settings' );
		$admin->enqueue_assets( '' );
	}

	public function test_unknown_severity_falls_back_to_the_neutral_class(): void {
		$admin = $this->make_admin( false, array() );

		foreach ( Event_Log::SEVERITIES as $severity ) {
			$this->assertSame( $severity, $admin->get_severity_class( $severity ) );
		}
		foreach ( array( '', 'fatal', 'CRITICAL', 'critical x" onclick="', '<script>' ) as $severity ) {
			$this->assertSame( 'neutral', $admin->get_severity_class( $severity ), $severity );
		}
	}

	public function test_log_page_renders_severity_labels_with_a_safe_class(): void {
		Functions\when( 'current_user_can' )->justReturn( true );
		Functions\when( 'submit_button' )->justReturn( null );
		Functions\when( 'selected' )->justReturn( '' );
		$loader = Mockery::mock( Module_Loader::class );
		$loader->shouldReceive( 'get_registry_ids' )->andReturn( array() );
		$event_log = Mockery::mock( Event_Log::class );
		$event_log->shouldReceive( 'get_events' )->andReturn(
			array(
				'total' => 3,
				'items' => array(
					array( 'severity' => 'critical' ),
					array( 'severity' => '"><script>x</script>' ),
					array( 'severity' => 'info' ),
				),
			)
		);
		$admin = new Admin( Mockery::mock( Settings::class ), $loader, $event_log );

		ob_start();
		$admin->render_log_page();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'class="wrap tsexp-admin"', $html );
		$this->assertStringContainsString( 'class="tsexp-sev tsexp-sev--critical"', $html );
		$this->assertStringContainsString( 'class="tsexp-sev tsexp-sev--info"', $html );
		$this->assertStringContainsString( 'class="tsexp-sev tsexp-sev--neutral"', $html );
		$this->assertStringContainsString( 'wp-header-end', $html );
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringNotContainsString( 'style=', $html );
	}
}

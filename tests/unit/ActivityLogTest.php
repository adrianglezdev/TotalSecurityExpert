<?php
/**
 * Tests del modulo activity-log.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey\Functions;
use PHPUnit\Framework\Attributes\DataProvider;
use TotalSecurityExpert\Modules\Activity_Log;

require_once dirname( __DIR__, 2 ) . '/modules/activity-log/class-activity-log.php';

/**
 * Lo que registra cada grupo y lo que deja pasar sin apuntar.
 */
class ActivityLogTest extends TestCase {

	private const ALL_HOOKS = array(
		'wp_login',
		'wp_login_failed',
		'wp_logout',
		'user_register',
		'delete_user',
		'set_user_role',
		'profile_update',
		'after_password_reset',
		'activated_plugin',
		'deactivated_plugin',
		'deleted_plugin',
		'upgrader_process_complete',
		'switch_theme',
		'updated_option',
		'transition_post_status',
		'before_delete_post',
		'wp_set_password',
		'add_user_role',
		'remove_user_role',
		'granted_super_admin',
		'revoked_super_admin',
		'wp_create_application_password',
		'wp_delete_application_password',
		'application_password_did_authenticate',
		'application_password_failed_authentication',
		'deleted_theme',
		'added_option',
		'delete_option',
	);

	/**
	 * Llamadas a Event_Log::log() recogidas: lista de array( modulo, evento, mensaje, datos, gravedad ).
	 *
	 * @var array<int,array<int,mixed>>
	 */
	private array $logged = array();

	/**
	 * Usuarios y emails que "existen" para username_exists() y email_exists().
	 *
	 * @var array<int,string>
	 */
	private array $known = array();

	protected function setUp(): void {
		parent::setUp();
		$this->logged = array();
		$this->stub_options();
		$this->known = array();
		Functions\stubs(
			array(
				// Modo no estricto de sanitize_user(): quita etiquetas, %XX y entidades; nada mas.
				'sanitize_user' => static function ( $v ) {
					$v = strip_tags( (string) $v ); // phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- Stub de sanitize_user().
					$v = preg_replace( '|%([a-fA-F0-9][a-fA-F0-9])|', '', $v );
					return trim( preg_replace( '/&.[^;]*;/', '', $v ) );
				},
				'get_bloginfo'  => '7.0',
				'wp_doing_cron' => false,
				'checked'       => static function ( $checked ) {
					echo $checked ? 'checked="checked"' : ''; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Stub de checked().
				},
			)
		);
		Functions\when( 'username_exists' )->alias( fn( $name ) => in_array( $name, $this->known, true ) ? 1 : false );
		Functions\when( 'email_exists' )->alias( fn( $name ) => in_array( $name, $this->known, true ) ? 1 : false );
	}

	/**
	 * Arranca el modulo con estos ajustes (todos los grupos apagados salvo los dados).
	 *
	 * @param array<string,bool> $on Grupos activos.
	 * @param string             $ip IP del cliente.
	 * @return Activity_Log
	 */
	private function boot_module( array $on, string $ip = '203.0.113.7' ): Activity_Log {
		$module  = new Activity_Log();
		$context = $this->make_context( 'activity-log', $ip );
		$this->event_log_mock->shouldReceive( 'log' )->andReturnUsing(
			function ( ...$args ) {
				$this->logged[] = $args;
			}
		);
		$this->capture_hooks( ...self::ALL_HOOKS );

		$settings = array_fill_keys( array_keys( $module->get_default_settings() ), false );
		$module->boot( $context, array_merge( $settings, $on ) );
		return $module;
	}

	public function test_module_identity_and_defaults(): void {
		$module = new Activity_Log();

		$this->assertSame( 'activity-log', $module->get_id() );
		$this->assertTrue( $module->get_default_settings()['log_auth'] );
		$this->assertFalse( $module->get_default_settings()['log_content'], 'El registro de contenido va apagado por defecto.' );
	}

	/**
	 * Grupo => hooks que le corresponden.
	 *
	 * @return array<string,array{0:string,1:array<int,string>}>
	 */
	public static function hook_groups(): array {
		return array(
			'auth'           => array( 'log_auth', array( 'wp_login', 'wp_login_failed', 'wp_logout', 'application_password_did_authenticate', 'application_password_failed_authentication' ) ),
			'users'          => array( 'log_users', array( 'user_register', 'delete_user', 'set_user_role', 'profile_update', 'after_password_reset', 'wp_set_password', 'add_user_role', 'remove_user_role', 'granted_super_admin', 'revoked_super_admin', 'wp_create_application_password', 'wp_delete_application_password' ) ),
			'plugins_themes' => array( 'log_plugins_themes', array( 'activated_plugin', 'deactivated_plugin', 'deleted_plugin', 'upgrader_process_complete', 'switch_theme', 'deleted_theme' ) ),
			'settings'       => array( 'log_settings', array( 'updated_option', 'added_option', 'delete_option' ) ),
			'content'        => array( 'log_content', array( 'transition_post_status', 'before_delete_post' ) ),
		);
	}

	/**
	 * Un grupo registra solo sus hooks.
	 *
	 * @param string             $group Casilla.
	 * @param array<int,string> $hooks Hooks del grupo.
	 */
	#[DataProvider( 'hook_groups' )]
	public function test_each_group_registers_only_its_own_hooks( string $group, array $hooks ): void {
		$this->boot_module( array( $group => true ) );

		foreach ( self::ALL_HOOKS as $hook ) {
			$registered = array() !== $this->captured_callbacks( $hook );
			$this->assertSame( in_array( $hook, $hooks, true ), $registered, "$hook con solo $group activo" );
		}
	}

	public function test_everything_off_registers_nothing(): void {
		$this->boot_module( array() );

		foreach ( self::ALL_HOOKS as $hook ) {
			$this->assertSame( array(), $this->captured_callbacks( $hook ), $hook );
		}
	}

	public function test_content_group_is_off_with_default_settings_merge(): void {
		$module  = new Activity_Log();
		$context = $this->make_context( 'activity-log' );
		$this->capture_hooks( ...self::ALL_HOOKS );

		$module->boot( $context, array() );

		$this->assertSame( array(), $this->captured_callbacks( 'transition_post_status' ) );
		$this->assertNotSame( array(), $this->captured_callbacks( 'wp_login' ) );
	}

	public function test_login_is_logged_as_info(): void {
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_login', 'maria', (object) array( 'ID' => 7 ) );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( 'activity-log', $this->logged[0][0] );
		$this->assertSame( 'login', $this->logged[0][1] );
		$this->assertSame(
			array(
				'login'   => 'maria',
				'user_id' => 7,
			),
			$this->logged[0][3]
		);
		$this->assertSame( 'info', $this->logged[0][4] );
	}

	public function test_failed_login_with_unknown_user_stores_neither_text_nor_length(): void {
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_login_failed', str_repeat( 'a', 500 ), null );

		$this->assertSame( 'warning', $this->logged[0][4] );
		$this->assertSame(
			array(
				'known' => false,
				'login' => 'unknown',
			),
			$this->logged[0][3]
		);
	}

	public function test_failed_login_with_password_like_text_is_not_stored_anywhere(): void {
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_login_failed', 'Tr0ub4dor!#3', null );

		$this->assertSame( 'unknown', $this->logged[0][3]['login'] );
		$this->assertArrayNotHasKey( 'length', $this->logged[0][3] );
		$this->assertStringNotContainsString( 'Tr0ub4dor', wp_json_encode( $this->logged ) );
	}

	public function test_failed_login_message_never_contains_the_username_even_if_it_exists(): void {
		$this->known = array( 'maria' );
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_login_failed', 'maria', null );

		$this->assertStringNotContainsString( 'maria', $this->logged[0][2] );
		$this->assertSame(
			array(
				'known' => true,
				'login' => 'maria',
			),
			$this->logged[0][3]
		);
	}

	public function test_failed_login_with_existing_email_stores_it(): void {
		$this->known = array( 'maria@example.com' );
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_login_failed', 'maria@example.com', null );

		$this->assertTrue( $this->logged[0][3]['known'] );
		$this->assertSame( 'maria@example.com', $this->logged[0][3]['login'] );
	}

	public function test_failed_login_with_html_is_never_stored_raw(): void {
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_login_failed', '<script>alert(1)</script>admin', null );

		$this->assertStringNotContainsString( '<', wp_json_encode( $this->logged ) );
		$this->assertStringNotContainsString( 'script', wp_json_encode( $this->logged ) );
	}

	public function test_failed_login_with_tsexp_locked_error_logs_nothing(): void {
		$this->boot_module( array( 'log_auth' => true ) );
		$error = new class() {
			public function get_error_codes(): array {
				return array( 'tsexp_locked' );
			}
		};

		$this->do_captured_action( 'wp_login_failed', 'maria', $error );
		$this->do_captured_action( 'application_password_failed_authentication', $error );

		$this->assertSame( array(), $this->logged );
		$this->assertSame( array(), $this->transients );
	}

	public function test_failed_logins_from_one_ip_log_ten_then_count_silently(): void {
		$this->boot_module( array( 'log_auth' => true ) );

		for ( $i = 0; $i < 25; $i++ ) {
			$this->do_captured_action( 'wp_login_failed', 'x', null );
		}

		$this->assertCount( 10, $this->logged );
		$state = $this->transients[ 'tsexp_activity_log_fail_' . md5( '203.0.113.7' ) ];
		$this->assertSame( 15, $state['extra'] );
	}

	public function test_a_summary_is_logged_when_the_next_failure_comes_after_the_window(): void {
		$this->boot_module( array( 'log_auth' => true ) );
		$key                      = 'tsexp_activity_log_fail_' . md5( '203.0.113.7' );
		$this->transients[ $key ] = array(
			'start' => time() - 601,
			'count' => 14,
			'extra' => 4,
		);

		$this->do_captured_action( 'wp_login_failed', 'x', null );

		$this->assertSame( array( 'failed_attempts_summary', 'login_failed' ), array_column( $this->logged, 1 ) );
		$this->assertSame( array( 'attempts' => 4 ), $this->logged[0][3] );
		$this->assertStringContainsString( '4', $this->logged[0][2] );
		$this->assertSame( 1, $this->transients[ $key ]['count'], 'Empieza una ventana nueva.' );
		$this->assertSame( 0, $this->transients[ $key ]['extra'] );
	}

	public function test_ipv6_addresses_in_the_same_64_share_one_counter(): void {
		$this->boot_module( array( 'log_auth' => true ), '2001:db8:1:2:aaaa::1' );

		for ( $i = 0; $i < 12; $i++ ) {
			$this->do_captured_action( 'wp_login_failed', 'x', null );
		}
		$same_64 = $this->make_context( 'activity-log', '2001:db8:1:2:bbbb::9' );
		( new Activity_Log() )->boot( $same_64, array( 'log_auth' => true ) );
		$this->event_log_mock->shouldReceive( 'log' )->andReturnUsing(
			function ( ...$args ) {
				$this->logged[] = $args;
			}
		);
		$this->do_captured_action( 'wp_login_failed', 'x', null );

		$this->assertCount( 10, $this->logged, 'La segunda direccion del mismo /64 no abre un contador nuevo.' );
		$keys = array_filter(
			array_keys( $this->transients ),
			static fn( $k ) => 'tsexp_activity_log_fail_global' !== $k
		);
		$this->assertCount( 1, $keys );
	}

	public function test_global_cap_stops_individual_rows_across_ips_and_counts_the_rest(): void {
		$this->boot_module( array( 'log_auth' => true ) );
		$this->transients['tsexp_activity_log_fail_global'] = array(
			'start' => time(),
			'count' => 199,
			'extra' => 0,
		);

		$this->do_captured_action( 'wp_login_failed', 'x', null );
		$this->do_captured_action( 'wp_login_failed', 'x', null );
		$this->do_captured_action( 'wp_login_failed', 'x', null );

		$this->assertCount( 1, $this->logged, 'Solo el 200 entra; el 201 y el 202 se cuentan.' );
		$this->assertSame( 2, $this->transients['tsexp_activity_log_fail_global']['extra'] );
	}

	public function test_global_summary_is_logged_when_the_global_window_closes(): void {
		$this->boot_module( array( 'log_auth' => true ) );
		$this->transients['tsexp_activity_log_fail_global'] = array(
			'start' => time() - 601,
			'count' => 260,
			'extra' => 60,
		);

		$this->do_captured_action( 'wp_login_failed', 'x', null );

		$this->assertSame( array( 'failed_attempts_summary_global', 'login_failed' ), array_column( $this->logged, 1 ) );
		$this->assertSame( array( 'attempts' => 60 ), $this->logged[0][3] );
	}

	public function test_failures_from_different_ips_have_separate_counters(): void {
		$this->boot_module( array( 'log_auth' => true ) );
		$this->transients[ 'tsexp_activity_log_fail_' . md5( '198.51.100.9' ) ] = array(
			'start' => time(),
			'count' => 50,
			'extra' => 40,
		);

		$this->do_captured_action( 'wp_login_failed', 'x', null );

		$this->assertCount( 1, $this->logged );
	}

	public function test_logout_is_logged(): void {
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_logout', 5 );

		$this->assertSame( 'logout', $this->logged[0][1] );
		$this->assertSame( array( 'user_id' => 5 ), $this->logged[0][3] );
	}

	public function test_logout_without_user_logs_nothing(): void {
		$this->boot_module( array( 'log_auth' => true ) );

		$this->do_captured_action( 'wp_logout', 0 );
		$this->do_captured_action( 'wp_logout' );

		$this->assertSame( array(), $this->logged );
	}

	public function test_user_register_and_delete_log_the_login(): void {
		Functions\when( 'get_userdata' )->justReturn( (object) array( 'user_login' => 'nuevo' ) );
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'user_register', 9 );
		$this->do_captured_action( 'delete_user', 9 );

		$this->assertSame( 'user_registered', $this->logged[0][1] );
		$this->assertSame( 'info', $this->logged[0][4] );
		$this->assertSame( 'nuevo', $this->logged[0][3]['login'] );
		$this->assertSame( 'user_deleted', $this->logged[1][1] );
		$this->assertSame( 'warning', $this->logged[1][4] );
		$this->assertSame( 'nuevo', $this->logged[1][3]['login'] );
	}

	public function test_role_change_to_administrator_is_warning(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'set_user_role', 3, 'administrator', array( 'subscriber' ) );

		$this->assertSame( 'warning', $this->logged[0][4] );
		$this->assertSame( 'administrator', $this->logged[0][3]['new_role'] );
		$this->assertSame( array( 'subscriber' ), $this->logged[0][3]['old_roles'] );
	}

	public function test_role_change_to_other_role_is_info(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'set_user_role', 3, 'editor', array( 'subscriber' ) );

		$this->assertSame( 'info', $this->logged[0][4] );
	}

	public function test_profile_update_with_password_change_never_carries_hash_or_password(): void {
		$old = (object) array(
			'user_email'   => 'a@example.com',
			'user_pass'    => '$P$OLDHASHOLDHASHOLDHASH',
			'display_name' => 'Ana',
			'user_url'     => '',
		);
		$new = (object) array(
			'user_email'   => 'a@example.com',
			'user_pass'    => '$P$NEWHASHNEWHASHNEWHASH',
			'display_name' => 'Ana',
			'user_url'     => '',
		);
		Functions\when( 'get_userdata' )->justReturn( $new );
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'profile_update', 4, $old, array( 'user_pass' => 'secreto-en-claro' ) );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( array( 'password' ), $this->logged[0][3]['changed'] );
		$dump = wp_json_encode( $this->logged[0] );
		$this->assertStringNotContainsString( 'NEWHASH', $dump );
		$this->assertStringNotContainsString( 'OLDHASH', $dump );
		$this->assertStringNotContainsString( 'secreto-en-claro', $dump );
	}

	public function test_profile_update_lists_each_changed_field(): void {
		$old = (object) array(
			'user_email'   => 'a@example.com',
			'user_pass'    => 'h',
			'display_name' => 'Ana',
			'user_url'     => '',
		);
		$new = (object) array(
			'user_email'   => 'b@example.com',
			'user_pass'    => 'h',
			'display_name' => 'Ana B',
			'user_url'     => 'https://example.com',
		);
		Functions\when( 'get_userdata' )->justReturn( $new );
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'profile_update', 4, $old );

		$this->assertSame( array( 'email', 'display_name', 'url' ), $this->logged[0][3]['changed'] );
		$this->assertStringNotContainsString( 'example.com', wp_json_encode( $this->logged[0][3] ), 'Solo qué cambia, no los valores.' );
	}

	public function test_profile_update_without_relevant_changes_logs_nothing(): void {
		$user              = (object) array(
			'user_email'   => 'a@example.com',
			'user_pass'    => 'h',
			'display_name' => 'Ana',
			'user_url'     => '',
			'description'  => 'antes',
		);
		$same              = clone $user;
		$same->description = 'despues';
		Functions\when( 'get_userdata' )->justReturn( $same );
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'profile_update', 4, $user );

		$this->assertSame( array(), $this->logged );
	}

	public function test_password_reset_logs_user_but_not_the_new_password(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action(
			'after_password_reset',
			(object) array(
				'ID'         => 8,
				'user_login' => 'luis',
			),
			'clave-nueva-123'
		);

		$this->assertSame( 'password_reset', $this->logged[0][1] );
		$this->assertStringNotContainsString( 'clave-nueva-123', wp_json_encode( $this->logged[0] ) );
	}

	public function test_plugin_events_are_logged(): void {
		$this->boot_module( array( 'log_plugins_themes' => true ) );

		$this->do_captured_action( 'activated_plugin', 'akismet/akismet.php', false );
		$this->do_captured_action( 'deactivated_plugin', 'akismet/akismet.php', false );
		$this->do_captured_action( 'deleted_plugin', 'akismet/akismet.php', true );
		$this->do_captured_action( 'deleted_plugin', 'otro/otro.php', false );

		$this->assertSame( array( 'plugin_activated', 'plugin_deactivated', 'plugin_deleted' ), array_column( $this->logged, 1 ) );
		$this->assertSame( 'akismet/akismet.php', $this->logged[0][3]['plugin'] );
		$this->assertSame( 'warning', $this->logged[2][4] );
	}

	public function test_upgrader_logs_plugin_names_and_core_version(): void {
		$this->boot_module( array( 'log_plugins_themes' => true ) );

		$this->do_captured_action(
			'upgrader_process_complete',
			new \stdClass(),
			array(
				'type'    => 'plugin',
				'action'  => 'update',
				'plugins' => array( 'a/a.php', 'b/b.php' ),
			)
		);
		$this->do_captured_action(
			'upgrader_process_complete',
			new \stdClass(),
			array(
				'type'   => 'core',
				'action' => 'update',
			)
		);
		$this->do_captured_action(
			'upgrader_process_complete',
			new \stdClass(),
			array(
				'type'   => 'translation',
				'action' => 'update',
			)
		);

		$this->assertCount( 2, $this->logged, 'Las traducciones no se registran.' );
		$this->assertSame( array( 'a/a.php', 'b/b.php' ), $this->logged[0][3]['names'] );
		$this->assertSame( '7.0', $this->logged[1][3]['version'] );
	}

	public function test_switch_theme_is_logged(): void {
		$theme = new class() {
			public function get_stylesheet(): string {
				return 'twentytwentyfive';
			}
		};
		$this->boot_module( array( 'log_plugins_themes' => true ) );

		$this->do_captured_action( 'switch_theme', 'Twenty Twenty-Five', $theme, $theme );

		$this->assertSame( 'theme_switched', $this->logged[0][1] );
		$this->assertSame( 'twentytwentyfive', $this->logged[0][3]['new_stylesheet'] );
	}

	public function test_default_role_to_administrator_is_warning(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'default_role', 'subscriber', 'administrator' );

		$this->assertSame( 'warning', $this->logged[0][4] );
		$this->assertSame( 'subscriber', $this->logged[0][3]['old'] );
		$this->assertSame( 'administrator', $this->logged[0][3]['new'] );
	}

	public function test_default_role_to_other_role_is_info(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'default_role', 'editor', 'subscriber' );

		$this->assertSame( 'info', $this->logged[0][4] );
	}

	public function test_siteurl_and_open_registration_are_warnings_but_admin_email_is_not(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'siteurl', 'https://a.test', 'https://b.test' );
		$this->do_captured_action( 'updated_option', 'home', 'https://a.test', 'https://b.test' );
		$this->do_captured_action( 'updated_option', 'users_can_register', '0', '1' );
		$this->do_captured_action( 'updated_option', 'users_can_register', '1', '0' );
		$this->do_captured_action( 'updated_option', 'admin_email', 'a@a.test', 'b@a.test' );
		$this->do_captured_action( 'updated_option', 'blog_public', '1', '0' );

		$this->assertSame(
			array( 'warning', 'warning', 'warning', 'info', 'info', 'info' ),
			array_column( $this->logged, 4 )
		);
	}

	public function test_option_outside_whitelist_logs_nothing(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'blogname', 'Uno', 'Dos' );
		$this->do_captured_action( 'updated_option', '_transient_feed_abc', 'x', 'y' );
		$this->do_captured_action( 'updated_option', 'widget_text', array(), array( 'x' ) );

		$this->assertSame( array(), $this->logged );
	}

	public function test_unchanged_watched_option_logs_nothing(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'default_role', 'editor', 'editor' );
		$this->do_captured_action( 'updated_option', 'blog_public', 1, '1' );

		$this->assertSame( array(), $this->logged );
	}

	public function test_plugin_settings_log_modules_toggled_and_no_values(): void {
		$old = array(
			'general' => array( 'trusted_proxies' => array( '10.9.8.7' ) ),
			'modules' => array(
				'login-limit' => array(
					'enabled'  => true,
					'settings' => array( 'secret_value' => 'VALOR-SECRETO' ),
				),
				'hardening'   => array( 'enabled' => false ),
			),
		);
		$new = array(
			'general' => array( 'trusted_proxies' => array( '10.1.1.1' ) ),
			'modules' => array(
				'login-limit' => array(
					'enabled'  => false,
					'settings' => array( 'secret_value' => 'OTRO-SECRETO' ),
				),
				'hardening'   => array( 'enabled' => true ),
			),
		);
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'tsexp_settings', $old, $new );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( 'plugin_settings_changed', $this->logged[0][1] );
		$this->assertSame( array( 'hardening' ), $this->logged[0][3]['modules_enabled'] );
		$this->assertSame( array( 'login-limit' ), $this->logged[0][3]['modules_disabled'] );
		$this->assertSame(
			array( 'general.trusted_proxies', 'modules.login-limit.enabled', 'modules.login-limit.settings.secret_value', 'modules.hardening.enabled' ),
			$this->logged[0][3]['changed']
		);
		$this->assertSame( 'warning', $this->logged[0][4] );
		$dump = wp_json_encode( $this->logged[0] );
		$this->assertStringNotContainsString( 'SECRETO', $dump );
		$this->assertStringNotContainsString( '10.', $dump );
	}

	public function test_content_publish_and_trash_are_logged_with_trimmed_title(): void {
		$this->boot_module( array( 'log_content' => true ) );
		$post = (object) array(
			'ID'           => 12,
			'post_type'    => 'post',
			'post_title'   => str_repeat( 't', 300 ),
			'post_content' => 'CUERPO-PRIVADO',
		);

		$this->do_captured_action( 'transition_post_status', 'publish', 'draft', $post );
		$this->do_captured_action( 'transition_post_status', 'trash', 'publish', $post );

		$this->assertSame( array( 'post_published', 'post_trashed' ), array_column( $this->logged, 1 ) );
		$this->assertSame( 80, strlen( $this->logged[0][3]['title'] ) );
		$this->assertSame( 12, $this->logged[0][3]['post_id'] );
		$this->assertStringNotContainsString( 'CUERPO-PRIVADO', wp_json_encode( $this->logged ) );
	}

	public function test_content_ignores_other_transitions_revisions_and_other_types(): void {
		$this->boot_module( array( 'log_content' => true ) );
		$post     = (object) array(
			'ID'         => 1,
			'post_type'  => 'post',
			'post_title' => 'x',
		);
		$revision = (object) array(
			'ID'         => 2,
			'post_type'  => 'revision',
			'post_title' => 'x',
		);
		$product  = (object) array(
			'ID'         => 3,
			'post_type'  => 'product',
			'post_title' => 'x',
		);

		$this->do_captured_action( 'transition_post_status', 'draft', 'auto-draft', $post );
		$this->do_captured_action( 'transition_post_status', 'publish', 'publish', $post );
		$this->do_captured_action( 'transition_post_status', 'publish', 'draft', $revision );
		$this->do_captured_action( 'transition_post_status', 'publish', 'draft', $product );
		$this->do_captured_action( 'before_delete_post', 2, $revision );
		$this->do_captured_action( 'before_delete_post', 3, $product );

		$this->assertSame( array(), $this->logged );
	}

	public function test_before_delete_post_logs_posts_and_pages(): void {
		$this->boot_module( array( 'log_content' => true ) );

		$this->do_captured_action(
			'before_delete_post',
			5,
			(object) array(
				'ID'         => 5,
				'post_type'  => 'page',
				'post_title' => 'Inicio',
			)
		);

		$this->assertSame( 'post_deleted', $this->logged[0][1] );
		$this->assertSame( 'warning', $this->logged[0][4] );
		$this->assertSame( 'page', $this->logged[0][3]['post_type'] );
	}

	public function test_user_register_includes_current_roles(): void {
		Functions\when( 'get_userdata' )->justReturn(
			(object) array(
				'user_login' => 'nuevo',
				'roles'      => array( 'editor' ),
			)
		);
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'user_register', 9 );

		$this->assertSame( array( 'editor' ), $this->logged[0][3]['roles'] );
	}

	public function test_add_and_remove_user_role_are_logged_and_administrator_is_warning(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'add_user_role', 3, 'administrator' );
		$this->do_captured_action( 'add_user_role', 3, 'editor' );
		$this->do_captured_action( 'remove_user_role', 3, 'administrator' );
		$this->do_captured_action( 'remove_user_role', 3, 'editor' );

		$this->assertSame( array( 'user_role_added', 'user_role_added', 'user_role_removed', 'user_role_removed' ), array_column( $this->logged, 1 ) );
		$this->assertSame( array( 'warning', 'info', 'warning', 'info' ), array_column( $this->logged, 4 ) );
		$this->assertSame(
			array(
				'user_id' => 3,
				'role'    => 'administrator',
			),
			$this->logged[0][3]
		);
	}

	public function test_super_admin_grant_and_revoke_are_warnings(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'granted_super_admin', 4 );
		$this->do_captured_action( 'revoked_super_admin', 4 );

		$this->assertSame( array( 'super_admin_granted', 'super_admin_revoked' ), array_column( $this->logged, 1 ) );
		$this->assertSame( array( 'warning', 'warning' ), array_column( $this->logged, 4 ) );
	}

	public function test_wp_set_password_logs_only_the_user_id(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action( 'wp_set_password', 'clave-en-claro-999', 6 );

		$this->assertSame( 'password_set', $this->logged[0][1] );
		$this->assertSame( array( 'user_id' => 6 ), $this->logged[0][3] );
		$this->assertStringNotContainsString( 'clave-en-claro-999', wp_json_encode( $this->logged ) );
	}

	public function test_application_password_created_logs_id_uuid_and_name_never_the_password(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action(
			'wp_create_application_password',
			2,
			array(
				'uuid'     => 'abc-123',
				'name'     => 'Mi app',
				'password' => 'HASH-DE-LA-CLAVE',
			),
			'CLAVE-EN-CLARO-XXXX',
			array()
		);

		$this->assertSame( 'warning', $this->logged[0][4] );
		$this->assertSame(
			array(
				'user_id' => 2,
				'uuid'    => 'abc-123',
				'name'    => 'Mi app',
			),
			$this->logged[0][3]
		);
		$dump = wp_json_encode( $this->logged );
		$this->assertStringNotContainsString( 'CLAVE-EN-CLARO', $dump );
		$this->assertStringNotContainsString( 'HASH-DE-LA-CLAVE', $dump );
	}

	public function test_application_password_deleted_is_logged(): void {
		$this->boot_module( array( 'log_users' => true ) );

		$this->do_captured_action(
			'wp_delete_application_password',
			2,
			array(
				'uuid' => 'abc-123',
				'name' => 'Mi app',
			)
		);

		$this->assertSame( 'app_password_deleted', $this->logged[0][1] );
		$this->assertSame( 'abc-123', $this->logged[0][3]['uuid'] );
	}

	public function test_application_password_authentication_is_logged_once_per_user_per_hour(): void {
		$this->boot_module( array( 'log_auth' => true ) );
		$user = (object) array( 'ID' => 5 );
		$item = array(
			'uuid' => 'u-1',
			'name' => 'Sync',
		);

		$this->do_captured_action( 'application_password_did_authenticate', $user, $item );
		$this->do_captured_action( 'application_password_did_authenticate', $user, $item );
		$this->do_captured_action( 'application_password_did_authenticate', (object) array( 'ID' => 6 ), $item );

		$this->assertSame( array( 'app_password_used', 'app_password_used' ), array_column( $this->logged, 1 ) );
		$this->assertSame( 5, $this->logged[0][3]['user_id'] );
		$this->assertSame( 6, $this->logged[1][3]['user_id'] );
	}

	public function test_application_password_failures_are_grouped_by_ip(): void {
		$this->boot_module( array( 'log_auth' => true ) );
		$error = new class() {
			public function get_error_code(): string {
				return 'incorrect_password';
			}
		};

		for ( $i = 0; $i < 14; $i++ ) {
			$this->do_captured_action( 'application_password_failed_authentication', $error );
		}

		$this->assertCount( 10, $this->logged );
		$this->assertSame( 'app_password_failed', $this->logged[0][1] );
		$this->assertSame( 'incorrect_password', $this->logged[0][3]['error_code'] );
	}

	public function test_theme_deleted_is_logged_only_if_deleted(): void {
		$this->boot_module( array( 'log_plugins_themes' => true ) );

		$this->do_captured_action( 'deleted_theme', 'viejo', true );
		$this->do_captured_action( 'deleted_theme', 'otro', false );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( 'theme_deleted', $this->logged[0][1] );
		$this->assertSame( 'viejo', $this->logged[0][3]['stylesheet'] );
	}

	public function test_template_and_stylesheet_options_are_logged(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'template', 'a', 'b' );
		$this->do_captured_action( 'updated_option', 'stylesheet', 'a', 'b' );

		$this->assertSame( array( 'option_changed', 'option_changed' ), array_column( $this->logged, 1 ) );
	}

	public function test_active_plugins_logs_the_diff_of_paths_and_ignores_reordering(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'active_plugins', array( 'a/a.php', 'b/b.php' ), array( 'a/a.php', 'c/c.php' ) );
		$this->do_captured_action( 'updated_option', 'active_plugins', array( 'a/a.php', 'b/b.php' ), array( 'b/b.php', 'a/a.php' ) );

		$this->assertCount( 1, $this->logged );
		$this->assertSame(
			array(
				'activated'   => array( 'c/c.php' ),
				'deactivated' => array( 'b/b.php' ),
			),
			$this->logged[0][3]
		);
	}

	/**
	 * Define $wpdb con get_blog_prefix() para el nombre de la opcion de roles.
	 *
	 * @param string $prefix Prefijo del sitio.
	 * @return void
	 */
	private function set_blog_prefix( string $prefix ): void {
		$GLOBALS['wpdb'] = new class( $prefix ) { // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Simula $wpdb en el test.
			/**
			 * Prefijo.
			 *
			 * @var string
			 */
			public string $prefix;

			/**
			 * Constructor.
			 *
			 * @param string $prefix Prefijo.
			 */
			public function __construct( string $prefix ) {
				$this->prefix = $prefix;
			}

			/**
			 * Prefijo del sitio.
			 *
			 * @return string
			 */
			public function get_blog_prefix(): string {
				return $this->prefix;
			}
		};
	}

	public function test_roles_option_logs_capability_names_only_and_dangerous_ones_are_warning(): void {
		$this->set_blog_prefix( 'wp_2_' );
		$this->boot_module( array( 'log_settings' => true ) );
		$old = array(
			'editor' => array(
				'name'         => 'Editor',
				'capabilities' => array(
					'edit_posts'   => true,
					'read'         => true,
					'delete_posts' => true,
				),
			),
		);
		$new = array(
			'editor' => array(
				'name'         => 'Editor',
				'capabilities' => array(
					'edit_posts'      => true,
					'read'            => true,
					'delete_posts'    => false,
					'unfiltered_html' => true,
				),
			),
		);

		$this->do_captured_action( 'updated_option', 'wp_2_user_roles', $old, $new );

		$this->assertSame( 'roles_changed', $this->logged[0][1] );
		$this->assertSame(
			array(
				'editor' => array(
					'added'   => array( 'unfiltered_html' ),
					'removed' => array( 'delete_posts' ),
				),
			),
			$this->logged[0][3]['roles']
		);
		$this->assertSame( 'warning', $this->logged[0][4] );
	}

	public function test_roles_option_harmless_capability_change_is_info_and_no_change_logs_nothing(): void {
		$this->set_blog_prefix( 'wp_' );
		$this->boot_module( array( 'log_settings' => true ) );
		$old = array( 'author' => array( 'capabilities' => array( 'read' => true ) ) );
		$new = array(
			'author' => array(
				'capabilities' => array(
					'read'         => true,
					'upload_files' => true,
				),
			),
		);

		$this->do_captured_action( 'updated_option', 'wp_user_roles', $old, $new );
		$this->do_captured_action( 'updated_option', 'wp_user_roles', $new, $new );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( 'info', $this->logged[0][4] );
	}

	public function test_roles_option_of_another_blog_prefix_is_ignored(): void {
		$this->set_blog_prefix( 'wp_' );
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'updated_option', 'wp_9_user_roles', array(), array( 'x' => array( 'capabilities' => array( 'manage_options' => true ) ) ) );

		$this->assertSame( array(), $this->logged );
	}

	public function test_plugin_settings_general_change_is_warning_and_lists_only_paths(): void {
		$this->boot_module( array( 'log_settings' => true ) );
		$old = array(
			'general' => array( 'ip_source' => 'remote_addr' ),
			'modules' => array(
				'login-limit' => array(
					'enabled'  => true,
					'settings' => array( 'max_attempts' => 5 ),
				),
			),
		);
		$new = array(
			'general' => array( 'ip_source' => 'x_forwarded_for' ),
			'modules' => array(
				'login-limit' => array(
					'enabled'  => true,
					'settings' => array( 'max_attempts' => '5' ),
				),
			),
		);

		$this->do_captured_action( 'updated_option', 'tsexp_settings', $old, $new );

		$this->assertSame( array( 'general.ip_source' ), $this->logged[0][3]['changed'], '"5" y 5 son el mismo valor.' );
		$this->assertSame( 'warning', $this->logged[0][4] );
		$this->assertStringNotContainsString( 'x_forwarded_for', wp_json_encode( $this->logged ) );
	}

	public function test_plugin_settings_module_setting_change_is_info_and_unchanged_logs_nothing(): void {
		$this->boot_module( array( 'log_settings' => true ) );
		$old = array(
			'modules' => array(
				'login-limit' => array(
					'enabled'  => true,
					'settings' => array( 'max_attempts' => 5 ),
				),
			),
		);
		$new = array(
			'modules' => array(
				'login-limit' => array(
					'enabled'  => true,
					'settings' => array( 'max_attempts' => 8 ),
				),
			),
		);

		$this->do_captured_action( 'updated_option', 'tsexp_settings', $old, $new );
		$this->do_captured_action( 'updated_option', 'tsexp_settings', $new, $new );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( array( 'modules.login-limit.settings.max_attempts' ), $this->logged[0][3]['changed'] );
		$this->assertSame( 'info', $this->logged[0][4] );
	}

	public function test_plugin_settings_added_is_info_without_values(): void {
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action(
			'added_option',
			'tsexp_settings',
			array(
				'general' => array( 'trusted_proxies' => array( '10.0.0.1' ) ),
				'modules' => array( 'hardening' => array( 'enabled' => true ) ),
			)
		);
		$this->do_captured_action( 'added_option', 'otra_opcion', array( 'a' => 1 ) );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( 'plugin_settings_added', $this->logged[0][1] );
		$this->assertSame( 'info', $this->logged[0][4] );
		$this->assertStringNotContainsString( '10.0.0.1', wp_json_encode( $this->logged ) );
	}

	public function test_plugin_settings_deleted_is_warning_and_lists_modules_turned_off(): void {
		$this->options['tsexp_settings'] = array(
			'modules' => array(
				'login-limit' => array( 'enabled' => true ),
				'hardening'   => array( 'enabled' => false ),
			),
		);
		$this->boot_module( array( 'log_settings' => true ) );

		$this->do_captured_action( 'delete_option', 'tsexp_settings' );
		$this->do_captured_action( 'delete_option', 'otra_opcion' );

		$this->assertCount( 1, $this->logged );
		$this->assertSame( 'plugin_settings_deleted', $this->logged[0][1] );
		$this->assertSame( 'warning', $this->logged[0][4] );
		$this->assertSame( array( 'login-limit' ), $this->logged[0][3]['modules_disabled'] );
	}

	public function test_before_delete_post_ignores_auto_drafts(): void {
		$this->boot_module( array( 'log_content' => true ) );

		$this->do_captured_action(
			'before_delete_post',
			8,
			(object) array(
				'ID'          => 8,
				'post_type'   => 'post',
				'post_status' => 'auto-draft',
				'post_title'  => 'Borrador automatico',
			)
		);

		$this->assertSame( array(), $this->logged );
	}

	public function test_before_delete_post_from_cron_is_info_and_from_a_person_is_warning(): void {
		$this->boot_module( array( 'log_content' => true ) );
		$post = (object) array(
			'ID'          => 8,
			'post_type'   => 'post',
			'post_status' => 'trash',
			'post_title'  => 'Vieja',
		);

		$this->do_captured_action( 'before_delete_post', 8, $post );
		Functions\when( 'wp_doing_cron' )->justReturn( true );
		$this->do_captured_action( 'before_delete_post', 8, $post );

		$this->assertSame( array( 'warning', 'info' ), array_column( $this->logged, 4 ) );
	}

	public function test_sanitize_missing_checkbox_is_false_and_all_keys_returned(): void {
		$module = new Activity_Log();

		$clean = $module->sanitize_settings( array( 'log_auth' => '1' ) );

		$this->assertSame( array_keys( $module->get_default_settings() ), array_keys( $clean ) );
		$this->assertTrue( $clean['log_auth'] );
		$this->assertFalse( $clean['log_users'] );
		$this->assertFalse( $clean['log_content'] );
		$this->assertSame( array_fill_keys( array_keys( $clean ), false ), $module->sanitize_settings( array() ) );
	}

	public function test_sanitize_is_idempotent_and_rejects_junk(): void {
		$module = new Activity_Log();

		$once = $module->sanitize_settings(
			array(
				'log_auth'     => 'on',
				'log_users'    => array( 'x' ),
				'log_content'  => '0',
				'log_settings' => 'false',
			)
		);

		$this->assertSame( $once, $module->sanitize_settings( $once ) );
		$this->assertTrue( $once['log_auth'] );
		$this->assertFalse( $once['log_users'] );
		$this->assertFalse( $once['log_content'] );
		$this->assertFalse( $once['log_settings'] );
	}

	public function test_render_settings_prints_escaped_named_checkboxes_with_labels(): void {
		$module = new Activity_Log();

		ob_start();
		$module->render_settings( array( 'log_auth' => true ), 'tsexp_settings[modules][activity-log][settings]' );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="tsexp_settings[modules][activity-log][settings][log_content]"', $html );
		$this->assertSame( 5, substr_count( $html, '<label for=' ) );
		$this->assertStringNotContainsString( '<form', $html );
		$this->assertStringNotContainsString( '<script', $html );
	}
}

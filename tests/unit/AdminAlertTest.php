<?php
/**
 * Tests del modulo admin-alert.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Brain\Monkey\Functions;
use Mockery;
use TotalSecurityExpert\Modules\Admin_Alert;

require_once dirname( __DIR__, 2 ) . '/modules/admin-alert/class-admin-alert.php';

/**
 * Avisa de administradores nuevos y deja pasar el resto.
 */
class AdminAlertTest extends TestCase {

	private const OPT     = 'tsexp_admin_alert_known_admins';
	private const INIT    = 'tsexp_admin_alert_initialized';
	private const PENDING = 'tsexp_admin_alert_pending';
	private const SALT    = 'sal-de-prueba';

	/**
	 * Usuarios simulados por ID.
	 *
	 * @var array<int,object>
	 */
	private array $users = array();

	/**
	 * Correos "enviados".
	 *
	 * @var array<int,array{to:mixed,subject:string,message:string}>
	 */
	private array $mails = array();

	/**
	 * Resultado de wp_mail().
	 *
	 * @var bool
	 */
	private bool $mail_result = true;

	/**
	 * IDs que devolvera get_users().
	 *
	 * @var array<int,int>
	 */
	private array $admin_ids = array();

	/**
	 * Llamadas a log() del contexto de boot_module().
	 *
	 * @var array<int,array<int,mixed>>
	 */
	private array $logs = array();

	protected function setUp(): void {
		parent::setUp();

		$this->users       = array();
		$this->mails       = array();
		$this->mail_result = true;
		$this->admin_ids   = array();
		$this->logs        = array();

		$this->stub_options(
			array(
				'blogname'    => 'Mi sitio',
				'admin_email' => 'admin@example.test',
			)
		);

		Functions\when( 'is_email' )->alias(
			static fn( $e ) => false !== filter_var( $e, FILTER_VALIDATE_EMAIL ) ? $e : false
		);
		Functions\when( 'admin_url' )->alias( static fn( $p = '' ) => 'https://example.test/wp-admin/' . $p );
		Functions\when( 'get_userdata' )->alias( fn( $id ) => $this->users[ (int) $id ] ?? false );
		Functions\when( 'get_users' )->alias( fn() => $this->admin_ids );
		Functions\when( 'wp_salt' )->justReturn( self::SALT );
		Functions\when( 'wp_mail' )->alias(
			function ( ...$args ): bool {
				$this->mails[] = array(
					'to'      => $args[0],
					'subject' => $args[1],
					'message' => $args[2],
					'headers' => $args[3] ?? array(),
				);
				return $this->mail_result;
			}
		);
		// Objeto con get_blog_prefix(), que Wpdb_Stub no tiene (tearDown quita $GLOBALS['wpdb']).
		$GLOBALS['wpdb'] = new class() { // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Simula $wpdb en tests.
			/**
			 * Prefijo de las tablas del sitio.
			 *
			 * @return string
			 */
			public function get_blog_prefix() {
				return 'wp_';
			}
		};
	}

	/**
	 * Guarda una instantanea valida y firmada, y la marca de inicializada.
	 *
	 * @param array<int,int> $ids        IDs.
	 * @param bool           $initialized Si se pone la marca.
	 * @return void
	 */
	private function seed_snapshot( array $ids, bool $initialized = true ): void {
		$sorted = $ids;
		sort( $sorted );
		$this->options[ self::OPT ] = array(
			'ids' => $ids,
			'sig' => hash_hmac( 'sha256', implode( ',', $sorted ), self::SALT ),
		);
		if ( $initialized ) {
			$this->options[ self::INIT ] = '1';
		}
	}

	/**
	 * IDs de la instantanea guardada.
	 *
	 * @return array<int,int>|null
	 */
	private function snapshot_ids(): ?array {
		return $this->options[ self::OPT ]['ids'] ?? null;
	}

	private function add_user( int $id, array $roles, array $extra = array() ): void {
		$this->users[ $id ] = (object) array_merge(
			array(
				'ID'           => $id,
				'user_login'   => 'user' . $id,
				'user_email'   => 'user' . $id . '@example.test',
				'display_name' => 'Usuario ' . $id,
				'roles'        => $roles,
				'user_pass'    => '$P$HASHSECRETO',
			),
			$extra
		);
	}

	private function boot_module( array $settings = array() ): Admin_Alert {
		$context = $this->make_context( 'admin-alert' );
		$this->event_log_mock->shouldReceive( 'log' )->zeroOrMoreTimes()->andReturnUsing(
			function ( ...$args ): void {
				$this->logs[] = $args;
			}
		);
		$this->capture_hooks( 'user_register', 'set_user_role', 'add_user_role', 'granted_super_admin', 'tsexp_hourly', 'added_user_meta', 'updated_user_meta', 'remove_user_role', 'deleted_user', 'admin_init' );
		$module = new Admin_Alert();
		$module->boot( $context, array_merge( $module->get_default_settings(), $settings ) );
		return $module;
	}

	public function test_metadata(): void {
		$module = new Admin_Alert();
		$this->assertSame( 'admin-alert', $module->get_id() );
		$this->assertSame(
			array(
				'recipients'     => array(),
				'include_ip'     => true,
				'periodic_check' => true,
			),
			$module->get_default_settings()
		);
	}

	public function test_registers_expected_hooks(): void {
		$this->boot_module();
		foreach ( array( 'user_register', 'set_user_role', 'add_user_role', 'granted_super_admin', 'tsexp_hourly', 'added_user_meta', 'updated_user_meta', 'remove_user_role', 'deleted_user', 'admin_init' ) as $hook ) {
			$this->assertCount( 1, $this->captured_callbacks( $hook ), $hook );
		}
	}

	public function test_new_user_with_administrator_role_sends_one_mail(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );

		$this->assertCount( 1, $this->mails );
		$this->assertSame( array( 'admin@example.test' ), $this->mails[0]['to'] );
		$this->assertStringContainsString( 'user7', $this->mails[0]['subject'] );
		$this->assertStringContainsString( 'Mi sitio', $this->mails[0]['subject'] );
	}

	public function test_new_subscriber_sends_nothing(): void {
		$this->add_user( 8, array( 'subscriber' ) );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 8, array() );

		$this->assertSame( array(), $this->mails );
	}

	public function test_set_user_role_subscriber_to_administrator_sends_mail(): void {
		$this->add_user( 9, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'set_user_role', 9, 'administrator', array( 'subscriber' ) );

		$this->assertCount( 1, $this->mails );
	}

	public function test_set_user_role_for_someone_who_already_was_administrator_sends_nothing(): void {
		$this->add_user( 9, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'set_user_role', 9, 'administrator', array( 'administrator' ) );

		$this->assertSame( array(), $this->mails );
	}

	public function test_set_user_role_editor_sends_nothing(): void {
		$this->add_user( 9, array( 'editor' ) );
		$this->boot_module();

		$this->do_captured_action( 'set_user_role', 9, 'editor', array( 'subscriber' ) );

		$this->assertSame( array(), $this->mails );
	}

	public function test_add_user_role_administrator_sends_mail_but_editor_does_not(): void {
		$this->add_user( 10, array( 'subscriber', 'administrator' ) );
		$this->add_user( 11, array( 'subscriber', 'editor' ) );
		$this->boot_module();

		$this->do_captured_action( 'add_user_role', 11, 'editor' );
		$this->assertSame( array(), $this->mails );

		$this->do_captured_action( 'add_user_role', 10, 'administrator' );
		$this->assertCount( 1, $this->mails );
	}

	public function test_add_user_role_for_known_administrator_sends_nothing(): void {
		$this->add_user( 10, array( 'administrator' ) );
		$this->seed_snapshot( array( 10 ) );
		$this->boot_module();

		$this->do_captured_action( 'add_user_role', 10, 'administrator' );

		$this->assertSame( array(), $this->mails );
	}

	public function test_granted_super_admin_sends_mail(): void {
		$this->add_user( 12, array( 'editor' ) );
		$this->boot_module();

		$this->do_captured_action( 'granted_super_admin', 12 );

		$this->assertCount( 1, $this->mails );
	}

	public function test_several_hooks_for_the_same_user_send_one_mail(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );
		$this->do_captured_action( 'set_user_role', 7, 'administrator', array() );
		$this->do_captured_action( 'add_user_role', 7, 'administrator' );
		$this->do_captured_action( 'granted_super_admin', 7 );

		$this->assertCount( 1, $this->mails );
	}

	public function test_periodic_check_detects_admin_inserted_without_hooks(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 2, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids = array( '1', '2' );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertCount( 1, $this->mails );
		$this->assertStringContainsString( 'user2', $this->mails[0]['subject'] );
		$this->assertStringContainsString( 'desconocido', $this->mails[0]['message'] );
		$this->assertSame( array( 1, 2 ), $this->snapshot_ids() );

		$this->do_captured_action( 'tsexp_hourly' );
		$this->assertCount( 1, $this->mails, 'La segunda revision no repite el aviso.' );
	}

	public function test_first_periodic_check_creates_snapshot_and_always_mails_the_list(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 2, array( 'administrator' ) );
		$this->admin_ids = array( 1, 2 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertSame( array( 1, 2 ), $this->snapshot_ids() );
		$this->assertCount( 1, $this->mails );
		$this->assertStringContainsString( 'iniciada', $this->mails[0]['subject'] );
		$this->assertStringContainsString( '2 administradores', $this->mails[0]['message'] );
		$this->assertStringContainsString( 'ID 1: user1', $this->mails[0]['message'] );
		$this->assertStringContainsString( 'ID 2: user2', $this->mails[0]['message'] );
		$created = array_values( array_filter( $this->logs, static fn( $l ) => 'snapshot_created' === $l[1] ) );
		$this->assertCount( 1, $created );
		$this->assertSame( 'warning', $created[0][4] );
	}

	public function test_snapshot_is_saved_without_autoload(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->admin_ids = array( 1 );
		$calls           = array();
		Functions\when( 'update_option' )->alias(
			function ( $name, $value, $autoload = null ) use ( &$calls ) {
				$calls[] = array( $name, $value, $autoload );
				return true;
			}
		);
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$by_name = array();
		foreach ( $calls as $call ) {
			$by_name[ $call[0] ] = $call[2];
		}
		$this->assertFalse( $by_name[ self::OPT ] );
		$this->assertFalse( $by_name[ self::INIT ] );
	}

	public function test_immediate_alert_adds_id_to_snapshot_so_periodic_check_does_not_repeat(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 3, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids = array( 1, 3 );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 3, array() );
		$this->assertCount( 1, $this->mails );
		$this->assertSame( array( 1, 3 ), $this->snapshot_ids() );

		// Otra peticion: modulo nuevo, mismo estado guardado.
		$this->boot_module();
		$this->do_captured_action( 'tsexp_hourly' );
		$this->assertCount( 1, $this->mails );
	}

	public function test_administrator_who_loses_role_leaves_the_snapshot(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->seed_snapshot( array( 1, 2 ) );
		$this->admin_ids = array( 1 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertSame( array(), $this->mails );
		$this->assertSame( array( 1 ), $this->snapshot_ids() );
	}

	public function test_periodic_check_off_still_hooks_the_cron_but_skips_the_comparison(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 2, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids = array( 1, 2 );
		$this->boot_module( array( 'periodic_check' => false ) );

		$this->assertCount( 1, $this->captured_callbacks( 'tsexp_hourly' ) );
		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertSame( array(), $this->mails, 'Sin comparacion: el administrador 2 no se detecta.' );
		$this->assertSame( array( 1 ), $this->snapshot_ids() );
	}

	public function test_periodic_check_off_still_retries_failed_mails_until_it_gives_up(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 7, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->mail_result = false;
		$this->boot_module( array( 'periodic_check' => false ) );
		$this->do_captured_action( 'user_register', 7, array() );

		for ( $hour = 0; $hour < 40; $hour++ ) {
			$this->boot_module( array( 'periodic_check' => false ) );
			$this->do_captured_action( 'tsexp_hourly' );
		}

		$events = $this->log_events();
		$this->assertCount( 24, $this->mails );
		$this->assertSame( 1, count( array_filter( $events, static fn( $e ) => 'alert_gave_up' === $e ) ) );
		$this->assertArrayNotHasKey( self::PENDING, $this->options );
	}

	public function test_snapshot_save_failed_is_logged_at_most_once_an_hour(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->admin_ids = array( 1 );
		Functions\when( 'update_option' )->justReturn( true ); // No guarda nada.
		Functions\when( 'current_user_can' )->justReturn( true );
		$this->boot_module();

		$this->do_captured_action( 'admin_init' );
		$this->boot_module();
		$this->do_captured_action( 'admin_init' );
		$this->do_captured_action( 'tsexp_hourly' );

		$failed = array_filter( $this->log_events(), static fn( $e ) => 'snapshot_save_failed' === $e );
		$this->assertCount( 1, $failed );
		$this->assertSame( array(), $this->mails );

		// Pasada la hora (el transient caduca) vuelve a registrarse.
		unset( $this->transients['tsexp_admin_alert_savefail'] );
		$this->boot_module();
		$this->do_captured_action( 'admin_init' );
		$this->assertCount( 2, array_filter( $this->log_events(), static fn( $e ) => 'snapshot_save_failed' === $e ) );
	}

	public function test_invalid_recipients_are_discarded(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$this->boot_module( array( 'recipients' => array( 'uno@example.test', 'no-es-correo', "x@example.test\r\nBcc: y@example.test" ) ) );

		$this->do_captured_action( 'user_register', 7, array() );

		$this->assertSame( array( 'uno@example.test' ), $this->mails[0]['to'] );
	}

	public function test_empty_recipients_fall_back_to_admin_email(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$this->boot_module( array( 'recipients' => array( 'basura' ) ) );

		$this->do_captured_action( 'user_register', 7, array() );

		$this->assertSame( array( 'admin@example.test' ), $this->mails[0]['to'] );
	}

	public function test_subject_has_no_line_breaks_even_with_hostile_login_and_site_name(): void {
		$this->add_user( 7, array( 'administrator' ), array( 'user_login' => "evil\r\nBcc: atacante@example.test" ) );
		$this->options['blogname'] = "Sitio\r\nX-Header: 1&#13;&#10;";
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );

		$subject = $this->mails[0]['subject'];
		$this->assertStringNotContainsString( "\r", $subject );
		$this->assertStringNotContainsString( "\n", $subject );
		$this->assertStringContainsString( 'evil', $subject );
	}

	public function test_body_has_the_data_and_never_the_password_hash(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );

		$body = $this->mails[0]['message'];
		$this->assertStringContainsString( 'user7', $body );
		$this->assertStringContainsString( 'user7@example.test', $body );
		$this->assertStringContainsString( 'Usuario 7', $body );
		$this->assertStringContainsString( 'https://example.test/wp-admin/user-edit.php?user_id=7', $body );
		$this->assertStringNotContainsString( 'HASHSECRETO', $body );
	}

	public function test_body_includes_actor_and_ip_by_default(): void {
		$this->add_user( 7, array( 'administrator' ) );
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'wp_get_current_user' )->justReturn( (object) array( 'user_login' => 'jefe' ) );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );

		$this->assertStringContainsString( 'jefe', $this->mails[0]['message'] );
		$this->assertStringContainsString( '203.0.113.7', $this->mails[0]['message'] );
	}

	public function test_include_ip_off_only_affects_the_mail(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$context = $this->make_context( 'admin-alert' );
		$this->event_log_mock->shouldReceive( 'log' )
			->once()
			->with(
				'admin-alert',
				'new_admin',
				Mockery::type( 'string' ),
				Mockery::on( static fn( $d ) => ! array_key_exists( 'ip', $d ) ),
				'critical'
			);
		$this->capture_hooks( 'user_register' );
		$module = new Admin_Alert();
		$module->boot( $context, array_merge( $module->get_default_settings(), array( 'include_ip' => false ) ) );

		$this->do_captured_action( 'user_register', 7, array() );

		$this->assertCount( 1, $this->mails );
		$this->assertStringNotContainsString( '203.0.113.7', $this->mails[0]['message'] );
	}

	public function test_alert_is_logged_as_critical(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$context = $this->make_context( 'admin-alert' );
		$this->event_log_mock->shouldReceive( 'log' )
			->once()
			->with( 'admin-alert', 'new_admin', Mockery::type( 'string' ), Mockery::type( 'array' ), 'critical' );
		$this->capture_hooks( 'user_register' );
		$module = new Admin_Alert();
		$module->boot( $context, $module->get_default_settings() );

		$this->do_captured_action( 'user_register', 7, array() );
	}

	public function test_mail_failure_logs_mail_failed_warning_and_queues_a_retry(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$this->mail_result = false;
		$context           = $this->make_context( 'admin-alert' );
		$this->event_log_mock->shouldReceive( 'log' )
			->once()
			->with( 'admin-alert', 'new_admin', Mockery::type( 'string' ), Mockery::type( 'array' ), 'critical' );
		$this->event_log_mock->shouldReceive( 'log' )
			->once()
			->with( 'admin-alert', 'mail_failed', Mockery::type( 'string' ), Mockery::type( 'array' ), 'warning' );
		$this->capture_hooks( 'user_register' );
		$module = new Admin_Alert();
		$module->boot( $context, $module->get_default_settings() );

		$this->do_captured_action( 'user_register', 7, array() );

		$this->assertCount( 1, $this->mails );
		$this->assertSame( 1, $this->options[ self::PENDING ][7]['attempts'] );
	}

	public function test_sanitize_is_idempotent_and_complete(): void {
		$module = new Admin_Alert();

		$first = $module->sanitize_settings(
			array(
				'recipients' => "a@example.test\nmala\nb@example.test\na@example.test",
				'include_ip' => '1',
			)
		);

		$this->assertSame( array( 'a@example.test', 'b@example.test' ), $first['recipients'] );
		$this->assertTrue( $first['include_ip'] );
		$this->assertFalse( $first['periodic_check'], 'Casilla ausente = false.' );
		$this->assertSame( array_keys( $module->get_default_settings() ), array_keys( $first ) );
		$this->assertSame( $first, $module->sanitize_settings( $first ) );
	}

	public function test_sanitize_handles_garbage(): void {
		$module = new Admin_Alert();

		$out = $module->sanitize_settings(
			array(
				'recipients'     => 42,
				'include_ip'     => 'no',
				'periodic_check' => array( 'x' ),
			)
		);

		$this->assertSame( array(), $out['recipients'] );
		$this->assertFalse( $out['include_ip'] );
	}

	public function test_render_settings_outputs_escaped_named_fields(): void {
		Functions\when( 'checked' )->alias(
			static function ( $a, $b = true, $display = true ) {
				$r = $a === $b ? " checked='checked'" : '';
				if ( $display ) {
					echo $r; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Stub de test.
				}
				return $r;
			}
		);
		$module = new Admin_Alert();

		ob_start();
		$module->render_settings( array( 'recipients' => array( 'a@example.test' ) ), 'p[x]' );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="p[x][recipients]"', $html );
		$this->assertStringContainsString( 'name="p[x][include_ip]"', $html );
		$this->assertStringContainsString( 'name="p[x][periodic_check]"', $html );
		$this->assertStringContainsString( 'a@example.test', $html );
		$this->assertStringNotContainsString( '<form', $html );
		$this->assertStringNotContainsString( '<script', $html );
	}

	public function test_uninstall_deletes_snapshot(): void {
		$this->seed_snapshot( array( 1, 2 ) );
		$this->options[ self::PENDING ] = array( 7 => array( 'attempts' => 1 ) );

		( new Admin_Alert() )->uninstall();

		$this->assertArrayNotHasKey( self::OPT, $this->options );
		$this->assertArrayNotHasKey( self::INIT, $this->options );
		$this->assertArrayNotHasKey( self::PENDING, $this->options );
	}

	public function test_uninstall_deletes_the_savefail_transient(): void {
		$this->transients['tsexp_admin_alert_savefail'] = '1';

		( new Admin_Alert() )->uninstall();

		$this->assertArrayNotHasKey( 'tsexp_admin_alert_savefail', $this->transients );
	}

	private function log_events(): array {
		return array_column( $this->logs, 1 );
	}

	// Punto 1: instantanea borrada o manipulada.

	public function test_deleted_snapshot_with_marker_alerts_with_full_admin_list_and_recreates_it(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 66, array( 'administrator' ), array( 'user_login' => 'intruso' ) );
		$this->options[ self::INIT ] = '1';
		$this->admin_ids             = array( 1, 66 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertContains( 'snapshot_missing', $this->log_events() );
		$critical = array_filter( $this->logs, static fn( $l ) => 'snapshot_missing' === $l[1] && 'critical' === $l[4] );
		$this->assertCount( 1, $critical );
		$this->assertCount( 1, $this->mails );
		$this->assertStringContainsString( 'user1', $this->mails[0]['message'] );
		$this->assertStringContainsString( 'intruso', $this->mails[0]['message'] );
		$this->assertSame( array( 1, 66 ), $this->snapshot_ids() );
	}

	public function test_non_array_snapshot_is_treated_as_lost(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->options[ self::OPT ]  = 'basura';
		$this->options[ self::INIT ] = '1';
		$this->admin_ids             = array( 1 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertContains( 'snapshot_missing', $this->log_events() );
		$this->assertCount( 1, $this->mails );
	}

	public function test_snapshot_with_invalid_signature_is_treated_as_lost(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 66, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->options[ self::OPT ]['ids'][] = 66; // Alguien anade un ID sin poder firmar.
		$this->admin_ids                     = array( 1, 66 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertContains( 'snapshot_missing', $this->log_events() );
		$this->assertCount( 1, $this->mails );
		$this->assertSame( array( 1, 66 ), $this->snapshot_ids() );
	}

	public function test_snapshot_present_but_invalid_without_marker_is_also_suspicious(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->options[ self::OPT ] = array( 'ids' => array( 1 ) );
		$this->admin_ids            = array( 1 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertContains( 'snapshot_missing', $this->log_events() );
	}

	public function test_lost_snapshot_is_recreated_even_if_the_mail_fails_and_mail_is_retried(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->options[ self::INIT ] = '1';
		$this->admin_ids             = array( 1 );
		$this->mail_result           = false;
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertContains( 'mail_failed', $this->log_events() );
		$this->assertSame( array( 1 ), $this->snapshot_ids(), 'La deteccion no depende del correo.' );
		$this->assertArrayHasKey( 'snapshot', $this->options[ self::PENDING ] );

		$this->mail_result = true;
		$this->boot_module();
		$this->do_captured_action( 'tsexp_hourly' );
		$this->assertCount( 2, $this->mails );
		$this->assertArrayNotHasKey( self::PENDING, $this->options );
	}

	public function test_deleting_both_options_never_recreates_the_snapshot_silently(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 66, array( 'administrator' ), array( 'user_login' => 'intruso' ) );
		$this->admin_ids = array( 1, 66 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertCount( 1, $this->mails );
		$this->assertStringContainsString( 'intruso', $this->mails[0]['message'] );
		$this->assertStringContainsString( 'ID 66', $this->mails[0]['message'] );
		$this->assertContains( 'snapshot_created', $this->log_events() );
	}

	public function test_restart_mail_mentions_salt_rotation(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->options[ self::INIT ] = '1';
		$this->admin_ids             = array( 1 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertStringContainsString( 'salts', $this->mails[0]['message'] );
		$this->assertStringContainsString( 'reiniciado con estos 1 administradores', $this->mails[0]['message'] );
	}

	// Punto 3 (L1): la instantanea se crea tambien con periodic_check apagado, en admin_init.

	public function test_admin_init_creates_the_snapshot_with_mail_even_if_periodic_check_is_off(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->admin_ids = array( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );
		$this->boot_module( array( 'periodic_check' => false ) );

		$this->do_captured_action( 'admin_init' );
		$this->do_captured_action( 'admin_init' );

		$this->assertSame( array( 1 ), $this->snapshot_ids() );
		$this->assertCount( 1, $this->mails );
		$this->assertContains( 'snapshot_created', $this->log_events() );
	}

	public function test_admin_init_does_nothing_without_manage_options_or_with_a_valid_snapshot(): void {
		$this->admin_ids = array( 1 );
		Functions\when( 'current_user_can' )->justReturn( false );
		$this->boot_module();
		$this->do_captured_action( 'admin_init' );
		$this->assertSame( array(), $this->mails );
		$this->assertNull( $this->snapshot_ids() );

		$this->seed_snapshot( array( 1 ) );
		Functions\when( 'current_user_can' )->justReturn( true );
		$this->boot_module();
		$this->do_captured_action( 'admin_init' );
		$this->assertSame( array(), $this->mails );
	}

	public function test_admin_init_detects_a_tampered_snapshot_at_once(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 66, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->options[ self::OPT ]['ids'][] = 66;
		$this->admin_ids                     = array( 1, 66 );
		Functions\when( 'current_user_can' )->justReturn( true );
		$this->boot_module();

		$this->do_captured_action( 'admin_init' );

		$this->assertContains( 'snapshot_missing', $this->log_events() );
		$this->assertCount( 1, $this->mails );
	}

	public function test_valid_snapshot_does_not_raise_snapshot_missing(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids = array( 1 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertNotContains( 'snapshot_missing', $this->log_events() );
		$this->assertSame( array(), $this->mails );
	}

	// Punto 2: capacidades escritas en la meta.

	public function test_capabilities_meta_with_administrator_alerts_for_unknown_user(): void {
		$this->add_user( 20, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->boot_module();

		$this->do_captured_action( 'updated_user_meta', 5, 20, 'wp_capabilities', array( 'administrator' => true ) );

		$this->assertCount( 1, $this->mails );
		$this->assertSame( array( 1, 20 ), $this->snapshot_ids() );
	}

	public function test_added_user_meta_hook_also_alerts(): void {
		$this->add_user( 20, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'added_user_meta', 5, 20, 'wp_capabilities', array( 'administrator' => true ) );

		$this->assertCount( 1, $this->mails );
	}

	public function test_capabilities_meta_ignores_other_keys_roles_and_known_admins(): void {
		$this->add_user( 20, array( 'administrator' ) );
		$this->seed_snapshot( array( 1, 21 ) );
		$this->boot_module();

		$this->do_captured_action( 'updated_user_meta', 5, 20, 'wp_2_capabilities', array( 'administrator' => true ) );
		$this->do_captured_action( 'updated_user_meta', 5, 20, 'nickname', array( 'administrator' => true ) );
		$this->do_captured_action( 'updated_user_meta', 5, 20, 'wp_capabilities', array( 'editor' => true ) );
		$this->do_captured_action( 'updated_user_meta', 5, 20, 'wp_capabilities', 'administrator' );
		$this->do_captured_action( 'updated_user_meta', 5, 21, 'wp_capabilities', array( 'administrator' => true ) );

		$this->assertSame( array(), $this->mails );
	}

	public function test_meta_and_role_hooks_for_the_same_user_send_one_mail(): void {
		$this->add_user( 20, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'updated_user_meta', 5, 20, 'wp_capabilities', array( 'administrator' => true ) );
		$this->do_captured_action( 'set_user_role', 20, 'administrator', array( 'subscriber' ) );

		$this->assertCount( 1, $this->mails );
	}

	// Punto 3: reintento si el correo falla.

	public function test_failed_mail_still_saves_the_id_and_the_cron_retries_it(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 7, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids   = array( 1, 7 );
		$this->mail_result = false;
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );
		$this->do_captured_action( 'set_user_role', 7, 'administrator', array() );
		$this->assertCount( 1, $this->mails, 'Dentro de la misma peticion no se reintenta.' );
		$this->assertContains( 'mail_failed', $this->log_events() );
		$this->assertSame( array( 1, 7 ), $this->snapshot_ids(), 'La deteccion no depende del correo.' );
		$this->assertArrayHasKey( 7, $this->options[ self::PENDING ] );

		// Hora siguiente: otra peticion, ahora el correo sale.
		$this->mail_result = true;
		$this->boot_module();
		$this->do_captured_action( 'tsexp_hourly' );
		$this->assertCount( 2, $this->mails );
		$this->assertArrayNotHasKey( self::PENDING, $this->options );
		$this->assertSame( 1, count( array_filter( $this->log_events(), static fn( $e ) => 'new_admin' === $e ) ), 'new_admin solo la primera vez.' );
	}

	public function test_cron_keeps_only_the_failed_mails_pending(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 2, array( 'administrator' ) );
		$this->add_user( 3, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids = array( 1, 2, 3 );
		$calls           = 0;
		Functions\when( 'wp_mail' )->alias(
			function ( ...$args ) use ( &$calls ): bool {
				$this->mails[] = array( 'subject' => $args[1] );
				return 1 === ++$calls; // Solo el primer aviso sale.
			}
		);
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertSame( array( 1, 2, 3 ), $this->snapshot_ids() );
		$this->assertSame( array( 3 ), array_keys( $this->options[ self::PENDING ] ) );
	}

	public function test_gives_up_after_24_attempts_without_flooding_or_repeating_new_admin(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 7, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids   = array( 1, 7 );
		$this->mail_result = false;
		$this->boot_module();
		$this->do_captured_action( 'user_register', 7, array() );

		for ( $hour = 0; $hour < 40; $hour++ ) {
			$this->boot_module();
			$this->do_captured_action( 'tsexp_hourly' );
		}

		$events = $this->log_events();
		$this->assertCount( 24, $this->mails, 'Exactamente 24 intentos y se para.' );
		$this->assertSame( 1, count( array_filter( $events, static fn( $e ) => 'alert_gave_up' === $e ) ) );
		$this->assertSame( 1, count( array_filter( $events, static fn( $e ) => 'new_admin' === $e ) ) );
		$this->assertSame( 1, count( array_filter( $events, static fn( $e ) => 'mail_failed' === $e ) ), 'mail_failed una vez al dia.' );
		$this->assertArrayNotHasKey( self::PENDING, $this->options );
		$this->assertSame( array( 1, 7 ), $this->snapshot_ids() );
	}

	public function test_mail_failed_is_logged_again_after_a_day(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 7, array( 'administrator' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->admin_ids   = array( 1, 7 );
		$this->mail_result = false;
		$this->boot_module();
		$this->do_captured_action( 'user_register', 7, array() );
		$this->options[ self::PENDING ][7]['mail_failed_at'] = time() - ( 2 * DAY_IN_SECONDS );

		$this->boot_module();
		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertSame( 2, count( array_filter( $this->log_events(), static fn( $e ) => 'mail_failed' === $e ) ) );
	}

	public function test_pending_item_is_dropped_if_the_user_is_no_longer_administrator(): void {
		$this->add_user( 1, array( 'administrator' ) );
		$this->add_user( 7, array( 'subscriber' ) );
		$this->seed_snapshot( array( 1 ) );
		$this->options[ self::PENDING ] = array(
			7 => array(
				'attempts'      => 3,
				'first_attempt' => time(),
			),
		);
		$this->admin_ids                = array( 1 );
		$this->boot_module();

		$this->do_captured_action( 'tsexp_hourly' );

		$this->assertSame( array(), $this->mails );
		$this->assertArrayNotHasKey( self::PENDING, $this->options );
	}

	// Punto 4: cabecera de texto plano.

	public function test_mail_is_sent_as_plain_text_utf8(): void {
		$this->add_user( 7, array( 'administrator' ) );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );

		$this->assertContains( 'Content-Type: text/plain; charset=UTF-8', $this->mails[0]['headers'] );
	}

	// Punto 5: caracteres Unicode de formato.

	public function test_subject_neutralizes_unicode_format_and_separator_characters(): void {
		$hostile = "ad\u{202E}min\u{2066}x\u{2069}\u{200B}y\u{2028}z\u{2029}w";
		$this->add_user( 7, array( 'administrator' ), array( 'user_login' => $hostile ) );
		$this->boot_module();

		$this->do_captured_action( 'user_register', 7, array() );

		$subject = $this->mails[0]['subject'];
		foreach ( array( "\u{202E}", "\u{2066}", "\u{2069}", "\u{200B}", "\u{2028}", "\u{2029}" ) as $char ) {
			$this->assertStringNotContainsString( $char, $subject );
			$this->assertStringNotContainsString( $char, $this->mails[0]['message'] );
		}
		$this->assertStringContainsString( 'ad min x y z w', $subject );
	}

	// Punto 6: remove_user_role y deleted_user.

	public function test_demote_and_promote_again_before_the_cron_alerts_again(): void {
		$this->add_user( 4, array( 'administrator' ) );
		$this->seed_snapshot( array( 1, 4 ) );
		$this->boot_module();

		$this->do_captured_action( 'remove_user_role', 4, 'administrator' );
		$this->assertSame( array( 1 ), $this->snapshot_ids() );

		$this->do_captured_action( 'add_user_role', 4, 'administrator' );
		$this->assertCount( 1, $this->mails );
	}

	public function test_remove_user_role_of_another_role_keeps_the_snapshot(): void {
		$this->seed_snapshot( array( 1, 4 ) );
		$this->boot_module();

		$this->do_captured_action( 'remove_user_role', 4, 'editor' );

		$this->assertSame( array( 1, 4 ), $this->snapshot_ids() );
	}

	public function test_deleted_user_leaves_the_snapshot(): void {
		$this->seed_snapshot( array( 1, 4 ) );
		$this->boot_module();

		$this->do_captured_action( 'deleted_user', 4 );

		$this->assertSame( array( 1 ), $this->snapshot_ids() );
		$this->assertSame( array(), $this->mails );
	}

	public function test_description_only_promises_the_administrator_role(): void {
		$text = ( new Admin_Alert() )->get_description();

		$this->assertStringContainsString( 'con el rol de administrador', $text );
		$this->assertStringContainsString( 'sin ese rol', $text );
	}

	// Punto 7: la etiqueta de include_ip aclara que solo afecta al correo.

	public function test_include_ip_label_says_it_only_affects_the_mail(): void {
		Functions\when( 'checked' )->justReturn( '' );
		ob_start();
		( new Admin_Alert() )->render_settings( array(), 'p' );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'en el correo (el registro de eventos siempre la guarda)', $html );
	}
}

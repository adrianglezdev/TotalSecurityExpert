<?php
/**
 * Modulo admin-alert: aviso por correo cuando aparece un administrador nuevo.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Modules;

defined( 'ABSPATH' ) || exit;

use TotalSecurityExpert\Abstract_Module;
use TotalSecurityExpert\Context;
use TotalSecurityExpert\Settings;

/**
 * Avisa al instante (hooks) y cada hora (comparando con una instantanea).
 */
class Admin_Alert extends Abstract_Module {

	public const OPTION_KNOWN_ADMINS = 'tsexp_admin_alert_known_admins';
	public const OPTION_INITIALIZED  = 'tsexp_admin_alert_initialized';
	public const OPTION_PENDING      = 'tsexp_admin_alert_pending';

	/**
	 * Intentos de envio (el primero incluido) antes de rendirse con un aviso.
	 */
	private const MAX_ATTEMPTS = 24;

	private const TRANSIENT_SAVE_FAIL = 'tsexp_admin_alert_savefail';

	private const ROLE = 'administrator';

	/**
	 * Contexto del modulo (solo existe tras boot()).
	 *
	 * @var Context|null
	 */
	private ?Context $context = null;

	/**
	 * Ajustes validados con los que se arranco.
	 *
	 * @var array<string,mixed>
	 */
	private array $settings = array();

	/**
	 * IDs (o 'snapshot') ya avisados o intentados en esta peticion (evita duplicados entre hooks).
	 *
	 * @var array<int|string,bool>
	 */
	private array $notified = array();

	/**
	 * Id.
	 *
	 * @return string
	 */
	public function get_id(): string {
		return 'admin-alert';
	}

	/**
	 * Nombre.
	 *
	 * @return string
	 */
	public function get_name(): string {
		return __( 'Aviso de nuevo administrador', 'total-security-expert' );
	}

	/**
	 * Descripcion.
	 *
	 * @return string
	 */
	public function get_description(): string {
		return __( 'Envía un correo cuando aparece un usuario con el rol de administrador, incluso si se ha insertado directamente en la base de datos. No detecta usuarios con capacidades de administrador pero sin ese rol.', 'total-security-expert' );
	}

	/**
	 * Ajustes por defecto.
	 *
	 * @return array<string,mixed>
	 */
	public function get_default_settings(): array {
		return array(
			'recipients'     => array(),
			'include_ip'     => true,
			'periodic_check' => true,
		);
	}

	/**
	 * Valida los ajustes (idempotente: acepta su propia salida).
	 *
	 * @param array<string,mixed> $input Datos sin confiar.
	 * @return array<string,mixed>
	 */
	public function sanitize_settings( array $input ): array {
		return array(
			'recipients'     => $this->clean_recipients( $input['recipients'] ?? array() ),
			'include_ip'     => filter_var( $input['include_ip'] ?? false, FILTER_VALIDATE_BOOLEAN ),
			'periodic_check' => filter_var( $input['periodic_check'] ?? false, FILTER_VALIDATE_BOOLEAN ),
		);
	}

	/**
	 * Pinta los campos de ajustes.
	 *
	 * @param array<string,mixed> $settings    Ajustes actuales.
	 * @param string              $name_prefix Prefijo del name de los campos.
	 * @return void
	 */
	public function render_settings( array $settings, string $name_prefix ): void {
		$settings   = array_merge( $this->get_default_settings(), $settings );
		$recipients = implode( "\n", $this->clean_recipients( $settings['recipients'] ) );
		?>
		<p>
			<label for="tsexp-admin-alert-recipients"><?php esc_html_e( 'Destinatarios (un correo por línea)', 'total-security-expert' ); ?></label><br />
			<textarea id="tsexp-admin-alert-recipients" name="<?php echo esc_attr( $name_prefix . '[recipients]' ); ?>" rows="3" cols="40" class="large-text"><?php echo esc_textarea( $recipients ); ?></textarea><br />
			<span class="description"><?php esc_html_e( 'Si lo dejas vacío, se usa el correo del administrador del sitio.', 'total-security-expert' ); ?></span>
		</p>
		<p>
			<input type="checkbox" id="tsexp-admin-alert-include-ip" name="<?php echo esc_attr( $name_prefix . '[include_ip]' ); ?>" value="1" <?php checked( ! empty( $settings['include_ip'] ), true, true ); ?> />
			<label for="tsexp-admin-alert-include-ip"><?php esc_html_e( 'Incluir la IP en el correo (el registro de eventos siempre la guarda)', 'total-security-expert' ); ?></label>
		</p>
		<p>
			<input type="checkbox" id="tsexp-admin-alert-periodic-check" name="<?php echo esc_attr( $name_prefix . '[periodic_check]' ); ?>" value="1" <?php checked( ! empty( $settings['periodic_check'] ), true, true ); ?> />
			<label for="tsexp-admin-alert-periodic-check"><?php esc_html_e( 'Revisar cada hora si hay administradores nuevos creados sin pasar por WordPress', 'total-security-expert' ); ?></label><br />
			<span class="description"><?php esc_html_e( 'El módulo guarda una instantánea firmada de los administradores. Si alguien la borra o la altera, o si cambias las claves de seguridad (salts) en wp-config.php, recibirás el aviso de "instantánea alterada" y se reiniciará con los administradores actuales.', 'total-security-expert' ); ?></span>
		</p>
		<?php
	}

	/**
	 * Registra los hooks.
	 *
	 * @param Context             $context  Contexto.
	 * @param array<string,mixed> $settings Ajustes.
	 * @return void
	 */
	public function boot( Context $context, array $settings ): void {
		$this->context  = $context;
		$this->settings = array_merge( $this->get_default_settings(), $settings );

		$context->add_action( 'user_register', array( $this, 'on_user_register' ), 10, 2 );
		$context->add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
		$context->add_action( 'add_user_role', array( $this, 'on_add_user_role' ), 10, 2 );
		$context->add_action( 'granted_super_admin', array( $this, 'on_granted_super_admin' ), 10, 1 );
		$context->add_action( 'added_user_meta', array( $this, 'on_user_meta' ), 10, 4 );
		$context->add_action( 'updated_user_meta', array( $this, 'on_user_meta' ), 10, 4 );
		$context->add_action( 'remove_user_role', array( $this, 'on_remove_user_role' ), 10, 2 );
		$context->add_action( 'deleted_user', array( $this, 'on_deleted_user' ), 10, 1 );
		$context->add_action( 'admin_init', array( $this, 'on_admin_init' ) );

		// Siempre: los reintentos de correo no dependen del ajuste; solo la comparacion de administradores.
		$context->add_action( 'tsexp_hourly', array( $this, 'on_hourly' ) );
	}

	/**
	 * Cron horario: reintenta los avisos pendientes y, si el ajuste lo permite, compara administradores.
	 *
	 * @return void
	 */
	public function on_hourly(): void {
		if ( ! empty( $this->settings['periodic_check'] ) ) {
			$this->run_periodic_check();
			return;
		}
		$this->retry_pending();
	}

	/**
	 * Borra la instantanea.
	 *
	 * @return void
	 */
	public function uninstall(): void {
		delete_option( self::OPTION_KNOWN_ADMINS );
		delete_option( self::OPTION_INITIALIZED );
		delete_option( self::OPTION_PENDING );
		delete_transient( self::TRANSIENT_SAVE_FAIL );
	}

	/**
	 * Usuario nuevo: avisa si ya nace administrador.
	 *
	 * @param int   $user_id  ID.
	 * @param mixed $userdata Datos de alta (no se usan).
	 * @return void
	 */
	public function on_user_register( $user_id, $userdata = null ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Firma real de la accion.
		$user_id = (int) $user_id;
		$user    = get_userdata( $user_id );
		if ( $user && $this->has_admin_role( $user ) ) {
			$this->alert( $user_id, 'user_register' );
		}
	}

	/**
	 * Cambio de rol: avisa si pasa a administrador y no lo era.
	 *
	 * @param int    $user_id   ID.
	 * @param string $role      Rol nuevo.
	 * @param mixed  $old_roles Roles anteriores.
	 * @return void
	 */
	public function on_set_user_role( $user_id, $role, $old_roles = array() ): void {
		$user_id = (int) $user_id;
		if ( self::ROLE !== $role ) {
			$this->forget( $user_id );
			return;
		}
		if ( in_array( self::ROLE, (array) $old_roles, true ) ) {
			return;
		}
		$this->alert( $user_id, 'set_user_role' );
	}

	/**
	 * Rol anadido: avisa si es administrador y no estaba ya en la instantanea.
	 *
	 * WordPress lanza esta accion con el rol ya puesto, asi que "no lo tenia" se
	 * decide con la instantanea de administradores conocidos.
	 *
	 * @param int    $user_id ID.
	 * @param string $role    Rol anadido.
	 * @return void
	 */
	public function on_add_user_role( $user_id, $role ): void {
		$user_id = (int) $user_id;
		if ( self::ROLE !== $role ) {
			return;
		}
		$known = $this->get_snapshot();
		if ( null !== $known && in_array( $user_id, $known, true ) ) {
			return;
		}
		$this->alert( $user_id, 'add_user_role' );
	}

	/**
	 * Super administrador concedido (multisitio).
	 *
	 * @param int $user_id ID.
	 * @return void
	 */
	public function on_granted_super_admin( $user_id ): void {
		$this->alert( (int) $user_id, 'granted_super_admin' );
	}

	/**
	 * Revision horaria: compara los administradores actuales con la instantanea.
	 *
	 * @return void
	 */
	public function run_periodic_check(): void {
		$current = array();
		$found   = get_users(
			array(
				'role'   => self::ROLE,
				'fields' => 'ID',
			)
		);
		foreach ( (array) $found as $id ) {
			$current[] = (int) $id;
		}
		$current = array_values( array_unique( $current ) );

		$known = $this->get_snapshot();
		if ( null === $known ) {
			// Nunca se crea en silencio: start_monitoring() avisa por correo y lo registra.
			$this->start_monitoring( $current );
			$this->retry_pending();
			return;
		}

		$kept = array_values( array_intersect( $known, $current ) );
		if ( $kept !== $known ) {
			$this->save_snapshot( $kept );
		}

		// alert() guarda cada ID en la instantanea aunque el correo falle; los correos fallidos quedan pendientes.
		foreach ( array_diff( $current, $known ) as $user_id ) {
			$this->alert( $user_id, 'periodic_check' );
		}
		$this->retry_pending();
	}

	/**
	 * Capacidades escritas directamente en la meta del usuario (sin hooks de rol).
	 *
	 * @param mixed $meta_id    ID de la meta (no se usa).
	 * @param int   $user_id    ID del usuario.
	 * @param mixed $meta_key   Clave de la meta.
	 * @param mixed $meta_value Valor nuevo.
	 * @return void
	 */
	public function on_user_meta( $meta_id, $user_id, $meta_key, $meta_value ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Firma real de la accion.
		global $wpdb;
		if ( ! is_array( $meta_value ) || empty( $meta_value[ self::ROLE ] ) ) {
			return;
		}
		if ( ! is_object( $wpdb ) || $wpdb->get_blog_prefix() . 'capabilities' !== $meta_key ) {
			return;
		}
		$user_id = (int) $user_id;
		$known   = $this->get_snapshot();
		if ( null !== $known && in_array( $user_id, $known, true ) ) {
			return;
		}
		$this->alert( $user_id, 'user_meta' );
	}

	/**
	 * Rol quitado: si era administrador, sale de la instantanea.
	 *
	 * @param int    $user_id ID.
	 * @param string $role    Rol quitado.
	 * @return void
	 */
	public function on_remove_user_role( $user_id, $role ): void {
		if ( self::ROLE === $role ) {
			$this->forget( (int) $user_id );
		}
	}

	/**
	 * Usuario borrado: sale de la instantanea.
	 *
	 * @param int $user_id ID.
	 * @return void
	 */
	public function on_deleted_user( $user_id ): void {
		$this->forget( (int) $user_id );
	}

	/**
	 * Primera visita al administrador con el modulo activo: crea la instantanea si falta.
	 *
	 * Se hace aqui y no en cada hook porque en user_register el nuevo administrador
	 * ya existe y saldria dentro de la lista inicial sin su propio aviso. Si
	 * periodic_check esta apagado, es la unica via para crearla.
	 *
	 * @return void
	 */
	public function on_admin_init(): void {
		if ( ! current_user_can( 'manage_options' ) || null !== $this->get_snapshot() ) {
			return;
		}
		$this->start_monitoring( $this->get_current_admin_ids() );
	}

	/**
	 * IDs de los usuarios con rol administrador.
	 *
	 * @return array<int,int>
	 */
	private function get_current_admin_ids(): array {
		$ids   = array();
		$found = get_users(
			array(
				'role'   => self::ROLE,
				'fields' => 'ID',
			)
		);
		foreach ( (array) $found as $id ) {
			$ids[] = (int) $id;
		}
		return array_values( array_unique( $ids ) );
	}

	/**
	 * Crea (o recrea) la instantanea y avisa siempre por correo. Nunca en silencio.
	 *
	 * La instantanea se guarda aunque el correo falle; el correo se reintenta desde la lista de pendientes.
	 *
	 * @param array<int,int> $current Administradores actuales.
	 * @return void
	 */
	private function start_monitoring( array $current ): void {
		if ( null === $this->context || isset( $this->notified['snapshot'] ) ) {
			return;
		}
		$restarted = $this->snapshot_expected();
		$this->save_snapshot( $current );
		if ( null === $this->get_snapshot() ) {
			// No se puede guardar: ni correo en bucle ni registro en cada peticion (una vez por hora).
			if ( false === get_transient( self::TRANSIENT_SAVE_FAIL ) ) {
				set_transient( self::TRANSIENT_SAVE_FAIL, '1', HOUR_IN_SECONDS );
				$this->context->log(
					'snapshot_save_failed',
					__( 'No se pudo guardar la instantánea de administradores.', 'total-security-expert' ),
					array( 'admin_ids' => $current ),
					'critical'
				);
			}
			return;
		}
		$this->notified['snapshot'] = true;

		$this->context->log(
			'snapshot_created',
			$restarted
				? __( 'Se ha recreado la instantánea de administradores.', 'total-security-expert' )
				: __( 'Se ha creado la instantánea de administradores.', 'total-security-expert' ),
			array(
				'admin_ids' => $current,
				'restarted' => $restarted,
			),
			'warning'
		);
		if ( $restarted ) {
			$this->context->log(
				'snapshot_missing',
				__( 'La instantánea de administradores faltaba o no era válida; puede haberse manipulado.', 'total-security-expert' ),
				array( 'admin_ids' => $current ),
				'critical'
			);
		}

		$this->deliver(
			'snapshot',
			array(
				'first_attempt' => time(),
				'ids'           => $current,
				'restarted'     => $restarted,
			)
		);
	}

	/**
	 * Avisa de un administrador nuevo (una vez por usuario y peticion).
	 *
	 * @param int    $user_id ID.
	 * @param string $source  Hook o revision que lo detecto.
	 * @return void
	 */
	private function alert( int $user_id, string $source ): void {
		if ( null === $this->context || $user_id <= 0 || isset( $this->notified[ $user_id ] ) ) {
			return;
		}
		$this->notified[ $user_id ] = true;

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		// La deteccion no depende del correo: el ID entra en la instantanea ya.
		$this->remember( $user_id );

		$periodic = 'periodic_check' === $source;
		$unknown  = __( 'desconocido', 'total-security-expert' );
		$actor    = $unknown;
		if ( ! $periodic && get_current_user_id() > 0 ) {
			$current = wp_get_current_user();
			$actor   = '' !== (string) ( $current->user_login ?? '' ) ? (string) $current->user_login : $unknown;
		}
		// En la revision periodica la IP seria la de quien disparo el cron, no la del autor.
		$ip = ( ! $periodic && ! empty( $this->settings['include_ip'] ) ) ? $this->context->get_client_ip() : '';

		$data = array(
			'user_id' => $user_id,
			'login'   => $this->one_line( $user->user_login ),
			'email'   => $this->one_line( $user->user_email ),
			'actor'   => $this->one_line( $actor ),
			'source'  => $source,
		);
		if ( '' !== $ip ) {
			$data['ip'] = $ip;
		}

		// new_admin se registra solo esta primera vez; los reintentos no lo repiten.
		$this->context->log(
			'new_admin',
			/* translators: %s: nombre de usuario del nuevo administrador. */
			sprintf( __( 'Nuevo administrador: %s', 'total-security-expert' ), $data['login'] ),
			$data,
			'critical'
		);

		$this->deliver(
			$user_id,
			array(
				'first_attempt' => time(),
				'source'        => $source,
				'actor'         => $data['actor'],
				'ip'            => $ip,
			)
		);
	}

	/**
	 * Un intento de envio. Si falla, el aviso queda pendiente (hasta MAX_ATTEMPTS intentos).
	 *
	 * @param int|string          $key   ID de usuario, o 'snapshot'.
	 * @param array<string,mixed> $entry Datos del aviso.
	 * @return void
	 */
	private function deliver( $key, array $entry ): void {
		if ( null === $this->context ) {
			return;
		}
		$pending = $this->get_pending();
		$mail    = 'snapshot' === $key ? $this->build_snapshot_mail( $entry ) : $this->build_admin_mail( (int) $key, $entry );
		if ( null === $mail ) { // El usuario ya no existe o ya no es administrador.
			unset( $pending[ $key ] );
			$this->save_pending( $pending );
			return;
		}

		$entry['attempts'] = (int) ( $entry['attempts'] ?? 0 ) + 1;
		if ( $this->send_mail( $mail['subject'], $mail['lines'] ) ) {
			unset( $pending[ $key ] );
			$this->save_pending( $pending );
			return;
		}

		if ( $entry['attempts'] >= self::MAX_ATTEMPTS ) {
			$this->context->log(
				'alert_gave_up',
				__( 'No se pudo enviar el aviso tras varios intentos; se deja de reintentar.', 'total-security-expert' ),
				array(
					'key'      => (string) $key,
					'attempts' => $entry['attempts'],
				),
				'critical'
			);
			unset( $pending[ $key ] );
			$this->save_pending( $pending );
			return;
		}

		// mail_failed, como mucho una vez al dia por aviso pendiente.
		$now = time();
		if ( $now - (int) ( $entry['mail_failed_at'] ?? 0 ) >= DAY_IN_SECONDS ) {
			$this->context->log(
				'mail_failed',
				__( 'No se pudo enviar el aviso de administradores; se reintentará.', 'total-security-expert' ),
				array(
					'key'      => (string) $key,
					'attempts' => $entry['attempts'],
				),
				'warning'
			);
			$entry['mail_failed_at'] = $now;
		}
		$pending[ $key ] = $entry;
		$this->save_pending( $pending );
	}

	/**
	 * Reintenta los avisos pendientes (salvo los ya intentados en esta peticion).
	 *
	 * @return void
	 */
	private function retry_pending(): void {
		foreach ( $this->get_pending() as $key => $entry ) {
			if ( isset( $this->notified[ $key ] ) ) {
				continue;
			}
			$this->notified[ $key ] = true;
			$this->deliver( $key, $entry );
		}
	}

	/**
	 * Correo de nuevo administrador, o null si el usuario ya no es administrador.
	 *
	 * @param int                 $user_id ID.
	 * @param array<string,mixed> $entry   Datos del aviso.
	 * @return array{subject:string,lines:array<int,string>}|null
	 */
	private function build_admin_mail( int $user_id, array $entry ): ?array {
		$user = get_userdata( $user_id );
		if ( ! $user || ( ! $this->has_admin_role( $user ) && 'granted_super_admin' !== ( $entry['source'] ?? '' ) ) ) {
			return null;
		}
		$login = $this->one_line( $user->user_login );
		$site  = $this->site_name();
		$actor = '' !== (string) ( $entry['actor'] ?? '' ) ? (string) $entry['actor'] : __( 'desconocido', 'total-security-expert' );
		$ip    = (string) ( $entry['ip'] ?? '' );
		$when  = (int) ( $entry['first_attempt'] ?? time() );

		$lines = array(
			/* translators: %s: nombre del sitio. */
			sprintf( __( 'Se ha detectado un nuevo administrador en %s.', 'total-security-expert' ), $site ),
			'',
			/* translators: %s: nombre de usuario. */
			sprintf( __( 'Usuario: %s', 'total-security-expert' ), $login ),
			/* translators: %s: correo del usuario. */
			sprintf( __( 'Correo: %s', 'total-security-expert' ), $this->one_line( $user->user_email ) ),
			/* translators: %s: nombre visible del usuario. */
			sprintf( __( 'Nombre visible: %s', 'total-security-expert' ), $this->one_line( $user->display_name ) ),
			/* translators: %d: ID del usuario. */
			sprintf( __( 'ID: %d', 'total-security-expert' ), $user_id ),
			/* translators: %s: nombre de usuario de quien lo hizo. */
			sprintf( __( 'Creado o promovido por: %s', 'total-security-expert' ), $actor ),
		);
		if ( '' !== $ip ) {
			/* translators: %s: direccion IP. */
			$lines[] = sprintf( __( 'IP: %s', 'total-security-expert' ), $this->one_line( $ip ) );
		}
		/* translators: %s: fecha y hora en UTC. */
		$lines[] = sprintf( __( 'Fecha: %s', 'total-security-expert' ), gmdate( 'Y-m-d H:i:s', $when ) . ' UTC' );
		/* translators: %s: URL de edicion del usuario. */
		$lines[] = sprintf( __( 'Revisar usuario: %s', 'total-security-expert' ), admin_url( 'user-edit.php?user_id=' . $user_id ) );
		$lines[] = '';
		$lines[] = __( 'Si no esperabas este administrador, revisa la cuenta cuanto antes.', 'total-security-expert' );

		return array(
			'subject' => $this->one_line(
				sprintf(
					/* translators: 1: nombre del sitio, 2: nombre de usuario del nuevo administrador. */
					__( '[%1$s] Nuevo administrador: %2$s', 'total-security-expert' ),
					$site,
					$login
				)
			),
			'lines'   => $lines,
		);
	}

	/**
	 * Correo de monitorizacion iniciada o reiniciada, con la lista completa de administradores.
	 *
	 * @param array<string,mixed> $entry Datos del aviso.
	 * @return array{subject:string,lines:array<int,string>}
	 */
	private function build_snapshot_mail( array $entry ): array {
		$site = $this->site_name();
		$ids  = array_map( 'intval', (array) ( $entry['ids'] ?? array() ) );

		if ( ! empty( $entry['restarted'] ) ) {
			$subject = sprintf(
				/* translators: %s: nombre del sitio. */
				__( '[%s] Instantánea de administradores alterada', 'total-security-expert' ),
				$site
			);
			$lines = array(
				/* translators: %s: nombre del sitio. */
				sprintf( __( 'La instantánea de administradores de %s faltaba o no era válida.', 'total-security-expert' ), $site ),
				__( 'Puede que alguien la haya borrado o alterado. También ocurre si has cambiado las claves de seguridad (salts) en wp-config.php.', 'total-security-expert' ),
				'',
				/* translators: %d: numero de administradores. */
				sprintf( __( 'La monitorización se ha reiniciado con estos %d administradores:', 'total-security-expert' ), count( $ids ) ),
			);
		} else {
			$subject = sprintf(
				/* translators: %s: nombre del sitio. */
				__( '[%s] Monitorización de administradores iniciada', 'total-security-expert' ),
				$site
			);
			$lines = array(
				/* translators: %s: nombre del sitio. */
				sprintf( __( 'Se ha iniciado la monitorización de administradores de %s.', 'total-security-expert' ), $site ),
				'',
				/* translators: %d: numero de administradores. */
				sprintf( __( 'Estos son los %d administradores actuales:', 'total-security-expert' ), count( $ids ) ),
			);
		}

		foreach ( $ids as $id ) {
			$user = get_userdata( $id );
			if ( $user ) {
				/* translators: 1: ID, 2: nombre de usuario. */
				$lines[] = sprintf( __( '- ID %1$d: %2$s', 'total-security-expert' ), $id, $this->one_line( $user->user_login ) );
			} else {
				/* translators: %d: ID del usuario. */
				$lines[] = sprintf( __( '- ID %d', 'total-security-expert' ), $id );
			}
		}
		$lines[] = '';
		$lines[] = __( 'Si alguno no es legítimo, revísalo cuanto antes.', 'total-security-expert' );

		return array(
			'subject' => $this->one_line( $subject ),
			'lines'   => $lines,
		);
	}

	/**
	 * Nombre del sitio, en una sola linea y sin entidades HTML.
	 *
	 * @return string
	 */
	private function site_name(): string {
		return $this->one_line( html_entity_decode( (string) get_option( 'blogname', '' ), ENT_QUOTES, 'UTF-8' ) );
	}

	/**
	 * Envia el correo en texto plano.
	 *
	 * @param string            $subject Asunto (ya sin saltos de linea).
	 * @param array<int,string> $lines   Lineas del cuerpo.
	 * @return bool
	 */
	private function send_mail( string $subject, array $lines ): bool {
		return (bool) wp_mail(
			$this->get_recipients(),
			$subject,
			implode( "\n", $lines ),
			array( 'Content-Type: text/plain; charset=UTF-8' )
		);
	}

	/**
	 * Si el usuario tiene el rol administrador.
	 *
	 * @param object $user Usuario.
	 * @return bool
	 */
	private function has_admin_role( $user ): bool {
		return in_array( self::ROLE, (array) ( $user->roles ?? array() ), true );
	}

	/**
	 * Destinatarios del aviso: los ajustes (re-validados) o el correo del sitio.
	 *
	 * @return array<int,string>
	 */
	private function get_recipients(): array {
		$list = $this->clean_recipients( $this->settings['recipients'] ?? array() );
		if ( array() === $list ) {
			$list = $this->clean_recipients( (string) get_option( 'admin_email', '' ) );
		}
		return $list;
	}

	/**
	 * Lista de correos validados y sin repetir.
	 *
	 * @param mixed $value Texto (uno por linea) o array.
	 * @return array<int,string>
	 */
	private function clean_recipients( $value ): array {
		$out = array();
		foreach ( Settings::parse_list( $value ) as $email ) {
			$valid = is_email( $email );
			if ( $valid ) {
				$out[] = $valid;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Quita saltos de linea y caracteres de control (asunto, cabeceras, lineas del cuerpo).
	 *
	 * @param mixed $value Valor.
	 * @return string
	 */
	private function one_line( $value ): string {
		$value = (string) $value;
		$clean = preg_replace( '/[\p{Cc}\p{Cf}\x{2028}\x{2029}]+/u', ' ', $value );
		if ( null === $clean ) { // UTF-8 invalido.
			$clean = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $value );
		}
		return trim( (string) $clean );
	}

	/**
	 * Instantanea guardada, o null si todavia no existe.
	 *
	 * @return array<int,int>|null
	 */
	private function get_snapshot(): ?array {
		$stored = get_option( self::OPTION_KNOWN_ADMINS, false );
		if ( ! is_array( $stored ) || ! is_array( $stored['ids'] ?? null ) || ! is_string( $stored['sig'] ?? null ) ) {
			return null;
		}
		$ids = array();
		foreach ( $stored['ids'] as $id ) {
			if ( ! is_int( $id ) && ! ( is_string( $id ) && ctype_digit( $id ) ) ) {
				return null;
			}
			$ids[] = (int) $id;
		}
		if ( ! hash_equals( $this->sign( $ids ), $stored['sig'] ) ) {
			return null;
		}
		return $ids;
	}

	/**
	 * Si ya hubo una instantanea (marca o valor presente), de modo que su falta es sospechosa.
	 *
	 * @return bool
	 */
	private function snapshot_expected(): bool {
		return false !== get_option( self::OPTION_INITIALIZED, false )
			|| false !== get_option( self::OPTION_KNOWN_ADMINS, false );
	}

	/**
	 * Firma HMAC de una lista de IDs (independiente del orden).
	 *
	 * @param array<int,int> $ids IDs.
	 * @return string
	 */
	private function sign( array $ids ): string {
		$ids = array_values( array_unique( array_map( 'intval', $ids ) ) );
		sort( $ids );
		return hash_hmac( 'sha256', implode( ',', $ids ), wp_salt( 'auth' ) );
	}

	/**
	 * Guarda la instantanea firmada y la marca de inicializada (sin autoload).
	 *
	 * @param array<int,int> $ids IDs de administradores.
	 * @return void
	 */
	private function save_snapshot( array $ids ): void {
		$ids = array_values( array_unique( array_map( 'intval', $ids ) ) );
		update_option(
			self::OPTION_KNOWN_ADMINS,
			array(
				'ids' => $ids,
				'sig' => $this->sign( $ids ),
			),
			false
		);
		update_option( self::OPTION_INITIALIZED, '1', false );
	}

	/**
	 * Anade un ID a la instantanea si esta existe (si no, la revision periodica la creara completa).
	 *
	 * @param int $user_id ID.
	 * @return void
	 */
	private function remember( int $user_id ): void {
		$known = $this->get_snapshot();
		if ( null !== $known && ! in_array( $user_id, $known, true ) ) {
			$known[] = $user_id;
			$this->save_snapshot( $known );
		}
	}

	/**
	 * Saca un ID de la instantanea (pierde el rol).
	 *
	 * @param int $user_id ID.
	 * @return void
	 */
	private function forget( int $user_id ): void {
		$known = $this->get_snapshot();
		if ( null !== $known && in_array( $user_id, $known, true ) ) {
			$this->save_snapshot( array_values( array_diff( $known, array( $user_id ) ) ) );
		}
	}

	/**
	 * Avisos pendientes de enviar, saneados: clave (ID o 'snapshot') => datos.
	 *
	 * @return array<int|string,array<string,mixed>>
	 */
	private function get_pending(): array {
		$stored = get_option( self::OPTION_PENDING, array() );
		$out    = array();
		if ( ! is_array( $stored ) ) {
			return $out;
		}
		foreach ( $stored as $key => $entry ) {
			if ( ! is_array( $entry ) || ( 'snapshot' !== $key && ! is_int( $key ) ) ) {
				continue;
			}
			$out[ $key ] = array(
				'attempts'       => (int) ( $entry['attempts'] ?? 0 ),
				'first_attempt'  => (int) ( $entry['first_attempt'] ?? time() ),
				'mail_failed_at' => (int) ( $entry['mail_failed_at'] ?? 0 ),
				'source'         => is_string( $entry['source'] ?? null ) ? $entry['source'] : '',
				'actor'          => is_string( $entry['actor'] ?? null ) ? $entry['actor'] : '',
				'ip'             => is_string( $entry['ip'] ?? null ) ? $entry['ip'] : '',
				'ids'            => array_map( 'intval', (array) ( $entry['ids'] ?? array() ) ),
				'restarted'      => ! empty( $entry['restarted'] ),
			);
		}
		return $out;
	}

	/**
	 * Guarda la lista de pendientes (sin autoload); vacia, borra la opcion.
	 *
	 * @param array<int|string,array<string,mixed>> $pending Pendientes.
	 * @return void
	 */
	private function save_pending( array $pending ): void {
		if ( array() === $pending ) {
			delete_option( self::OPTION_PENDING );
			return;
		}
		update_option( self::OPTION_PENDING, $pending, false );
	}
}

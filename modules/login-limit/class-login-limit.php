<?php
/**
 * Modulo de limite de intentos de acceso.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Modules;

use TotalSecurityExpert\Abstract_Module;
use TotalSecurityExpert\Context;
use TotalSecurityExpert\Request;
use TotalSecurityExpert\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Cuenta los intentos de acceso por IP (por red /64 en IPv6) y bloquea la IP al pasar el limite.
 *
 * Modelo de "reserva": en `authenticate` cada intento incrementa de forma atomica
 * el contador de la IP ANTES de saber si la contrasena es correcta. Si se pasa del
 * limite, se bloquea aunque la contrasena sea buena; si no, y el acceso es valido,
 * se devuelve solo esa plaza. Un acceso correcto nunca reinicia el contador: asi un
 * atacante con cuenta propia no puede "limpiar" sus fallos entrando con ella.
 *
 * Se cuenta por IP y nunca por usuario. Todo falla abierto: sin IP, con la IP en la
 * lista blanca o ante un error de base de datos, no se bloquea.
 *
 * Intentos "cross-site" (el formulario de wp-login.php enviado desde otra web, por ejemplo
 * el boton "Acceder a WordPress" de cPanel o Plesk): no se rechazan de entrada, pero se
 * cuentan en un contador propio (claves con el prefijo CROSS_PREFIX) con los mismos limites,
 * ventana, escalada y limite diario. Un bloqueo de CUALQUIERA de los dos contadores bloquea
 * los intentos cross-site; un bloqueo del contador cross-site NUNCA bloquea el login normal,
 * y los fallos cross-site nunca tocan el contador normal. Asi no hace falta configurar nada
 * ni confiar en ningun origen, y una web ajena no puede bloquear a un tercero en su acceso
 * normal. Ver is_cross_site() para los compromisos aceptados.
 */
class Login_Limit extends Abstract_Module {

	public const TABLE_SUFFIX    = 'tsexp_login_attempts';
	public const VERSION_OPTION  = 'tsexp_login_limit_db_version';
	public const NOIP_TRANSIENT  = 'tsexp_login_limit_noip';
	public const DBERR_TRANSIENT = 'tsexp_login_limit_dberr';
	public const SCHEMA_VERSION  = '3';

	/**
	 * Segundos en un minuto.
	 */
	private const MINUTE = 60;

	/**
	 * Segundos en una hora.
	 */
	private const HOUR = 3600;

	/**
	 * Segundos en un dia (ventana del contador diario y de la escalada).
	 */
	private const DAY = 86400;

	/**
	 * Prefijo de las claves del contador de intentos cross-site.
	 */
	private const CROSS_PREFIX = 'xs|';

	/**
	 * Anchura de la columna ip (cabe el prefijo mas una red IPv6 con su /48 o /64).
	 */
	private const IP_COLUMN_WIDTH = 64;

	/**
	 * Cuantas IPs bloqueadas se listan en los ajustes.
	 */
	private const LIST_LIMIT = 10;

	/**
	 * El contador grueso (/48 en IPv6) admite este multiplo de los limites del /64.
	 */
	private const COARSE_FACTOR = 10;

	/**
	 * Contexto del modulo.
	 *
	 * @var Context|null
	 */
	private ?Context $context = null;

	/**
	 * Ajustes validados.
	 *
	 * @var array<string,mixed>
	 */
	private array $settings = array();

	/**
	 * Hay una plaza reservada en esta peticion por un fallo de contrasena de aplicacion
	 * (aun no se sabe si otro metodo de acceso de la misma peticion tendra exito).
	 *
	 * @var bool
	 */
	private bool $held = false;

	/**
	 * Hash usuario+contrasena del intento Basic que fallo como contrasena de aplicacion
	 * (null = no se conoce, por ejemplo en XML-RPC). Solo vale para un intento.
	 *
	 * @var string|null
	 */
	private ?string $held_hash = null;

	/**
	 * Intentos (hash de usuario y contrasena, solo en memoria) ya contados como fallo en esta peticion.
	 *
	 * @var array<string,bool>
	 */
	private array $failed_keys = array();

	/**
	 * Resultado de la comprobacion de bloqueo REST en esta peticion (null = sin comprobar).
	 *
	 * @var bool|null
	 */
	private ?bool $rest_locked = null;

	/**
	 * Id del modulo.
	 *
	 * @return string
	 */
	public function get_id(): string {
		return 'login-limit';
	}

	/**
	 * Nombre.
	 *
	 * @return string
	 */
	public function get_name(): string {
		return __( 'Límite de intentos de acceso', 'total-security-expert' );
	}

	/**
	 * Descripcion.
	 *
	 * @return string
	 */
	public function get_description(): string {
		return __( 'Bloquea durante un tiempo a la IP que falla demasiadas veces al iniciar sesión, también por XML-RPC y contraseñas de aplicación. Detrás de un proxy o CDN todos los visitantes comparten IP: configura antes la fuente de la IP en los ajustes generales o se bloquearía a todos a la vez. Una sesión ya abierta no se ve afectada por un bloqueo. En IPv6 el bloqueo puede alcanzar a toda una red /48 compartida con otros usuarios; añadir tu propio /48 o /56 a la lista blanca lo evita.', 'total-security-expert' );
	}

	/**
	 * Valores por defecto.
	 *
	 * @return array<string,mixed>
	 */
	public function get_default_settings(): array {
		return array(
			'max_attempts'       => 5,
			'window_minutes'     => 15,
			'lockout_minutes'    => 20,
			'long_lockout_after' => 4,
			'long_lockout_hours' => 24,
			'daily_max'          => 50,
			'allowlist'          => array(),
		);
	}

	/**
	 * Valida los ajustes; acepta su propia salida (idempotente).
	 *
	 * @param array<string,mixed> $input Datos sin confiar.
	 * @return array<string,mixed>
	 */
	public function sanitize_settings( array $input ): array {
		$defaults = $this->get_default_settings();

		$allowlist = array();
		foreach ( Settings::parse_list( $input['allowlist'] ?? array() ) as $entry ) {
			$entry = $this->sanitize_allowlist_entry( sanitize_text_field( $entry ) );
			if ( '' !== $entry ) {
				$allowlist[] = $entry;
			}
		}

		return array(
			'max_attempts'       => $this->clamp_int( $input['max_attempts'] ?? null, 1, 100, $defaults['max_attempts'] ),
			'window_minutes'     => $this->clamp_int( $input['window_minutes'] ?? null, 1, 1440, $defaults['window_minutes'] ),
			'lockout_minutes'    => $this->clamp_int( $input['lockout_minutes'] ?? null, 1, 10080, $defaults['lockout_minutes'] ),
			'long_lockout_after' => $this->clamp_int( $input['long_lockout_after'] ?? null, 0, 100, $defaults['long_lockout_after'] ),
			'long_lockout_hours' => $this->clamp_int( $input['long_lockout_hours'] ?? null, 1, 720, $defaults['long_lockout_hours'] ),
			'daily_max'          => $this->clamp_int( $input['daily_max'] ?? null, 0, 10000, $defaults['daily_max'] ),
			'allowlist'          => array_values( array_unique( $allowlist ) ),
		);
	}

	/**
	 * Pinta los campos (sin form, nonce ni boton).
	 *
	 * @param array<string,mixed> $settings    Ajustes actuales.
	 * @param string              $name_prefix Prefijo del name de los campos.
	 * @return void
	 */
	public function render_settings( array $settings, string $name_prefix ): void {
		$settings = $this->sanitize_settings( $settings );
		$base_id  = 'tsexp-ll-' . trim( (string) preg_replace( '/[^A-Za-z0-9_-]+/', '-', $name_prefix ), '-' );

		$numbers = array(
			'max_attempts'       => __( 'Intentos fallidos permitidos', 'total-security-expert' ),
			'window_minutes'     => __( 'Ventana de recuento (minutos)', 'total-security-expert' ),
			'lockout_minutes'    => __( 'Duración del bloqueo (minutos)', 'total-security-expert' ),
			'long_lockout_after' => __( 'Bloqueos en 24 h para pasar al bloqueo largo (0 = desactivado)', 'total-security-expert' ),
			'long_lockout_hours' => __( 'Duración del bloqueo largo (horas)', 'total-security-expert' ),
			'daily_max'          => __( 'Intentos máximos en 24 h antes del bloqueo largo (0 = desactivado)', 'total-security-expert' ),
		);
		$limits  = array(
			'max_attempts'       => array( 1, 100 ),
			'window_minutes'     => array( 1, 1440 ),
			'lockout_minutes'    => array( 1, 10080 ),
			'long_lockout_after' => array( 0, 100 ),
			'long_lockout_hours' => array( 1, 720 ),
			'daily_max'          => array( 0, 10000 ),
		);

		echo '<table class="form-table" role="presentation"><tbody>';
		foreach ( $numbers as $key => $label ) {
			printf(
				'<tr><th scope="row"><label for="%1$s">%2$s</label></th><td><input type="number" id="%1$s" name="%3$s" value="%4$s" min="%5$s" max="%6$s" step="1" class="small-text" /></td></tr>',
				esc_attr( $base_id . '-' . $key ),
				esc_html( $label ),
				esc_attr( $name_prefix . '[' . $key . ']' ),
				esc_attr( (string) $settings[ $key ] ),
				esc_attr( (string) $limits[ $key ][0] ),
				esc_attr( (string) $limits[ $key ][1] )
			);
		}

		printf(
			'<tr><th scope="row"><label for="%1$s">%2$s</label></th><td><textarea id="%1$s" name="%3$s" rows="4" cols="40" class="large-text code">%4$s</textarea><p class="description">%5$s</p></td></tr>',
			esc_attr( $base_id . '-allowlist' ),
			esc_html__( 'Lista blanca de IP', 'total-security-expert' ),
			esc_attr( $name_prefix . '[allowlist]' ),
			esc_textarea( implode( "\n", $settings['allowlist'] ) ),
			esc_html__( 'Una IP o rango CIDR por línea (IPv4 desde /8, IPv6 desde /32). Estas IP nunca se cuentan ni se bloquean. Si te bloqueas a ti mismo, añade tu IP aquí o define TSEXP_SAFE_MODE como true en wp-config.php. En IPv6 el bloqueo puede afectar a toda una red /48 compartida con otros usuarios: añadir tu propio /48 o /56 (por ejemplo 2001:db8:1::/48) a la lista evita que te alcance.', 'total-security-expert' )
		);

		$locked = $this->get_locked_overview();
		echo '<tr><th scope="row">' . esc_html__( 'IP bloqueadas ahora', 'total-security-expert' ) . '</th><td>';
		echo '<p>' . esc_html( (string) $locked['count'] ) . '</p>';
		if ( array() !== $locked['rows'] ) {
			echo '<ul>';
			foreach ( $locked['rows'] as $row ) {
				echo '<li><code>' . esc_html( $row['ip'] ) . '</code> ';
				if ( $row['cross'] ) {
					echo esc_html__( '(intentos desde otros sitios)', 'total-security-expert' ) . ' ';
				}
				echo esc_html(
					sprintf(
						/* translators: %s: fecha y hora en que acaba el bloqueo. */
						__( 'hasta %s', 'total-security-expert' ),
						gmdate( 'Y-m-d H:i:s', $row['until'] ) . ' UTC'
					)
				);
				echo '</li>';
			}
			echo '</ul>';
		}
		echo '</td></tr></tbody></table>';
	}

	/**
	 * Registra los hooks.
	 *
	 * @param Context             $context  Contexto del modulo.
	 * @param array<string,mixed> $settings Ajustes guardados.
	 * @return void
	 */
	public function boot( Context $context, array $settings ): void {
		$this->context  = $context;
		$this->settings = $this->sanitize_settings( $settings );

		$context->add_filter( 'authenticate', array( $this, 'filter_authenticate' ), 99, 3 );
		$context->add_filter( 'determine_current_user', array( $this, 'filter_determine_user' ), 19, 1 );
		$context->add_filter( 'rest_authentication_errors', array( $this, 'filter_rest_errors' ), 5, 1 );
		$context->add_action( 'application_password_failed_authentication', array( $this, 'on_app_password_failed' ), 10, 1 );
		$context->add_action( 'wp_authenticate_application_password_errors', array( $this, 'check_app_password' ), 10, 4 );
		$context->add_action( 'admin_init', array( $this, 'maybe_upgrade_schema' ), 10, 0 );
		$context->add_action( 'tsexp_hourly', array( $this, 'purge_expired' ), 10, 0 );
	}

	/**
	 * Crea la tabla (idempotente).
	 *
	 * @return void
	 */
	public function install(): void {
		global $wpdb;
		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}

		$table   = self::table_name();
		$charset = $wpdb->get_charset_collate();

		// La columna ip guarda el grupo de IP: la IPv4 tal cual o la red /64 en IPv6 (con el prefijo
		// "xs|" en el contador cross-site; por eso son 64 caracteres).
		// last_lockout es el FIN del ultimo bloqueo. Contadores con signo para que GREATEST(x - 1, 0) no desborde.
		dbDelta(
			"CREATE TABLE {$table} (
	ip varchar(64) NOT NULL,
	attempts int(11) NOT NULL DEFAULT 0,
	first_attempt bigint(20) NOT NULL DEFAULT 0,
	locked_until bigint(20) NOT NULL DEFAULT 0,
	lockouts int(11) NOT NULL DEFAULT 0,
	last_lockout bigint(20) NOT NULL DEFAULT 0,
	daily_count int(11) NOT NULL DEFAULT 0,
	daily_start bigint(20) NOT NULL DEFAULT 0,
	PRIMARY KEY  (ip),
	KEY locked_until (locked_until)
) {$charset};"
		);

		// Solo se da el esquema por actualizado si la tabla existe con la columna daily_count y con
		// la columna ip ya ensanchada. Si la anchura no se puede leer (motor que no devuelve
		// varchar(N), como SQLite en Playground) no se puede comprobar nada mas: se da por
		// actualizado para no repetir install() en cada admin_init.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Comprobacion del esquema de la tabla propia.
		$column = $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM %i LIKE %s', $table, 'daily_count' ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Comprobacion del esquema de la tabla propia.
		$ip_column = $wpdb->get_row( $wpdb->prepare( 'SHOW COLUMNS FROM %i LIKE %s', $table, 'ip' ), ARRAY_A );
		$type      = is_array( $ip_column ) && isset( $ip_column['Type'] ) && is_string( $ip_column['Type'] ) ? $ip_column['Type'] : '';
		$width     = 1 === preg_match( '/varchar\((\d+)\)/i', $type, $found ) ? (int) $found[1] : null;
		if ( is_string( $column ) && '' !== $column && ( null === $width || $width >= self::IP_COLUMN_WIDTH ) ) {
			update_option( self::VERSION_OPTION, self::SCHEMA_VERSION, false );
		}
	}

	/**
	 * Borra la tabla, las opciones y los transients del modulo.
	 *
	 * @return void
	 */
	public function uninstall(): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Borrado de la tabla propia al desinstalar.
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', self::table_name() ) );
		delete_option( self::VERSION_OPTION );
		delete_transient( self::NOIP_TRANSIENT );
		delete_transient( self::DBERR_TRANSIENT );
	}

	/**
	 * Nombre completo de la tabla (una por sitio).
	 *
	 * Multisitio no esta soportado en la v1: la tabla es por sitio ($wpdb->prefix) para que los
	 * limites y bloqueos del administrador de un sitio no afecten a las IP de toda la red.
	 *
	 * @return string
	 */
	public static function table_name(): string {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_SUFFIX;
	}

	/**
	 * Crea o actualiza la tabla si la version del esquema guardada no es la actual (el nucleo solo
	 * compara su propia version, asi que una tabla antigua se quedaria sin las columnas nuevas).
	 *
	 * @return void
	 */
	public function maybe_upgrade_schema(): void {
		if ( get_option( self::VERSION_OPTION ) !== self::SCHEMA_VERSION ) {
			$this->install();
		}
	}

	/**
	 * Filtro authenticate: reserva una plaza del contador de la IP y decide.
	 *
	 * @param mixed $user     WP_User, WP_Error o null.
	 * @param mixed $username Usuario.
	 * @param mixed $password Contrasena (solo se usa para distinguir intentos, nunca se guarda).
	 * @return mixed
	 */
	public function filter_authenticate( $user, $username = '', $password = '' ) {
		$username = is_string( $username ) ? $username : '';
		$password = is_string( $password ) ? $password : '';

		if ( '' === $username || '' === $password ) {
			// No es un intento de acceso (campos vacios): solo se mira si la IP esta bloqueada.
			return $this->locked_error_or( $user, $this->get_remaining_lock( $this->get_keys( false ) ) );
		}

		if ( $this->is_allowlisted() ) {
			return $user;
		}

		$normal = $this->get_keys( true );
		if ( array() === $normal ) {
			return $user;
		}

		// Intento cross-site: se cuenta en su propio contador (claves con prefijo) y le bloquea
		// un bloqueo de cualquiera de los dos; el contador normal nunca se toca.
		$cross     = $this->is_cross_site();
		$keys      = $cross ? $this->cross_keys( $normal ) : $normal;
		$lock_keys = $cross ? array_merge( $keys, $normal ) : $normal;

		$valid    = $user instanceof \WP_User;
		$attempt  = hash( 'sha256', $username . "\0" . $password );
		$counted  = isset( $this->failed_keys[ $attempt ] );
		$has_slot = false;

		if ( $this->held ) {
			// La plaza retenida vale para UN solo intento y se consume siempre. Un fallo la usa si
			// es el mismo intento (mismas credenciales, o credenciales desconocidas); un acceso
			// valido solo la recupera si las credenciales coinciden con las del fallo. Si no
			// coincide, el intento va por reserve() como cualquier otro.
			$has_slot        = $valid
				? null !== $this->held_hash && hash_equals( $this->held_hash, $attempt )
				: null === $this->held_hash || hash_equals( $this->held_hash, $attempt );
			$this->held      = false;
			$this->held_hash = null;
		}

		if ( $has_slot || ( $counted && ! $valid ) ) {
			// Este mismo intento ya esta contado (fallo de contrasena de aplicacion o segunda
			// llamada a authenticate con las mismas credenciales): no se cuenta dos veces.
			if ( $has_slot && $valid ) {
				// La plaza retenida viene de una contrasena de aplicacion: siempre es del contador normal.
				$this->refund( $normal );
			}
			if ( ! $valid ) {
				$this->failed_keys[ $attempt ] = true;
			}
			return $this->locked_error_or( $user, $this->get_remaining_lock( $lock_keys ), $cross ? $normal : array() );
		}

		$result = $this->reserve( $keys, $username, $valid, $lock_keys );
		if ( ! $valid && $result['counted'] ) {
			$this->failed_keys[ $attempt ] = true;
		}
		if ( $result['blocked'] ) {
			return $this->locked_error_or( $user, max( 1, $result['remaining'] ), $cross ? $normal : array() );
		}
		return $user;
	}

	/**
	 * Filtro determine_current_user (19): con credenciales Basic y la IP bloqueada, no se identifica a nadie.
	 *
	 * @param mixed $user_id Id de usuario ya determinado, o false.
	 * @return mixed
	 */
	public function filter_determine_user( $user_id ) {
		if ( $user_id || ! isset( $_SERVER['PHP_AUTH_USER'] ) || ! is_string( $_SERVER['PHP_AUTH_USER'] ) || '' === $_SERVER['PHP_AUTH_USER'] ) {
			return $user_id;
		}
		if ( null === $this->rest_locked ) {
			$this->rest_locked = $this->get_remaining_lock( $this->get_keys( false ) ) > 0;
		}
		return $this->rest_locked ? false : $user_id;
	}

	/**
	 * Filtro rest_authentication_errors (5): respuesta uniforme 429 si la IP esta bloqueada.
	 *
	 * @param mixed $result Resultado previo.
	 * @return mixed
	 */
	public function filter_rest_errors( $result ) {
		if ( isset( $_SERVER['PHP_AUTH_USER'] ) && is_string( $_SERVER['PHP_AUTH_USER'] ) && '' !== $_SERVER['PHP_AUTH_USER']
			&& ! $this->is_allowlisted() && $this->is_cross_site() ) {
			// Mismo error acierte o no la contrasena: no se puede probar credenciales desde otro sitio.
			return new \WP_Error( 'tsexp_cross_site', __( 'No se ha podido completar la solicitud.', 'total-security-expert' ), array( 'status' => 403 ) );
		}
		if ( true !== $this->rest_locked ) {
			return $result;
		}
		$remaining = $this->get_remaining_lock( $this->get_keys( false ) );
		return new \WP_Error( 'tsexp_locked', $this->locked_message( max( 1, $remaining ) ), array( 'status' => 429 ) );
	}

	/**
	 * Accion application_password_failed_authentication: cuenta el fallo (una vez por peticion).
	 *
	 * @param mixed $error Error (sin usar).
	 * @return void
	 */
	public function on_app_password_failed( $error = null ): void {
		unset( $error );
		if ( $this->held ) {
			return;
		}
		// Antes de contar: la lista blanca manda y una peticion de otro sitio (fetch no-cors a
		// xmlrpc.php o a REST con Basic) no puede servir para bloquear la IP del administrador.
		if ( $this->is_allowlisted() || $this->is_cross_site() ) {
			return;
		}
		$keys = $this->get_keys( true );
		if ( array() === $keys ) {
			return;
		}
		$result = $this->reserve( $keys, '', false );
		if ( $result['counted'] ) {
			$this->held      = true;
			$this->held_hash = null;
			if ( isset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ) && is_string( $_SERVER['PHP_AUTH_USER'] ) && is_string( $_SERVER['PHP_AUTH_PW'] ) ) {
				// Igual que el nucleo: las credenciales del intento Basic que ha fallado.
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- El nucleo tampoco las desescapa: solo se hashea para comparar, no se guarda ni se muestra; sanear la contrasena la alteraria.
				$this->held_hash = hash( 'sha256', $_SERVER['PHP_AUTH_USER'] . "\0" . $_SERVER['PHP_AUTH_PW'] );
			}
		}
	}

	/**
	 * Accion wp_authenticate_application_password_errors: anade un error si la IP esta bloqueada.
	 *
	 * @param mixed $error    WP_Error al que anadir.
	 * @param mixed $user     Usuario (sin usar).
	 * @param mixed $item     Contrasena de aplicacion (sin usar).
	 * @param mixed $password Contrasena (sin usar).
	 * @return void
	 */
	public function check_app_password( $error = null, $user = null, $item = null, $password = null ): void {
		unset( $user, $item, $password );
		if ( ! $error instanceof \WP_Error ) {
			return;
		}
		if ( $this->is_allowlisted() ) {
			return;
		}
		if ( $this->is_cross_site() ) {
			// Nadie puede usar estas cabeceras para probar contrasenas de aplicacion "gratis".
			$error->add( 'tsexp_cross_site', __( 'No se ha podido completar la solicitud.', 'total-security-expert' ) );
			return;
		}
		$remaining = $this->get_remaining_lock( $this->get_keys( false ) );
		if ( $remaining > 0 ) {
			$error->add( 'tsexp_locked', $this->locked_message( $remaining ) );
		}
	}

	/**
	 * Cron horario: borra las filas que ya no aportan nada.
	 *
	 * @return void
	 */
	public function purge_expired(): void {
		global $wpdb;
		$settings = array() === $this->settings ? $this->get_default_settings() : $this->settings;
		$now      = $this->now();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Limpieza de la tabla propia.
		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE locked_until <= %d AND first_attempt < %d AND last_lockout < %d AND daily_start < %d',
				self::table_name(),
				$now,
				$now - ( (int) $settings['window_minutes'] * self::MINUTE ),
				$now - self::DAY,
				$now - self::DAY
			)
		);
	}

	/**
	 * Reserva una plaza en cada contador de la IP (/64 en IPv6 y, ademas, /48; IPv4 solo uno),
	 * lee los valores resultantes y bloquea o devuelve las plazas.
	 *
	 * @param array<int,string> $keys      Claves donde se cuenta: la primera es el grupo fino, la segunda (opcional) el grueso.
	 * @param string            $username  Usuario del intento (solo para el registro, saneado).
	 * @param bool              $valid     Si el acceso es valido (WP_User) y por tanto las plazas se devuelven.
	 * @param array<int,string> $lock_keys Claves cuyo bloqueo impide el intento (vacio = las mismas que $keys).
	 * @return array{blocked:bool,remaining:int,counted:bool}
	 */
	private function reserve( array $keys, string $username, bool $valid, array $lock_keys = array() ): array {
		// Si ya hay un bloqueo en cualquier contador (por ejemplo el /48), se devuelve sin contar
		// nada: quien reintenta durante un bloqueo ajeno no gasta ni bloquea su propio /64.
		$locked = $this->get_remaining_lock( array() === $lock_keys ? $keys : $lock_keys );
		if ( $locked > 0 ) {
			return array(
				'blocked'   => true,
				'remaining' => $locked,
				'counted'   => false,
			);
		}

		$final = null;
		foreach ( array_values( $keys ) as $i => $key ) {
			$factor = 0 === $i ? 1 : self::COARSE_FACTOR;
			$result = $this->count_one(
				$key,
				(int) $this->settings['max_attempts'] * $factor,
				(int) $this->settings['daily_max'] * $factor,
				$valid,
				$username
			);
			if ( null === $result ) {
				continue;
			}
			if ( $result['blocked'] ) {
				return $result;
			}
			$final = $final ?? $result;
		}
		if ( null !== $final ) {
			return $final;
		}
		if ( $valid ) {
			$this->refund( $keys );
			return array(
				'blocked'   => false,
				'remaining' => 0,
				'counted'   => false,
			);
		}
		return array(
			'blocked'   => false,
			'remaining' => 0,
			'counted'   => true,
		);
	}

	/**
	 * Reserva atomica en un contador y decide si hay que bloquear.
	 *
	 * @param string $key      Clave del contador.
	 * @param int    $max      Intentos maximos en la ventana para este contador.
	 * @param int    $dmax     Intentos maximos en 24 h (0 = sin limite diario).
	 * @param bool   $valid    Si el acceso es valido.
	 * @param string $username Usuario del intento.
	 * @return array{blocked:bool,remaining:int,counted:bool}|null Null si no hay nada que hacer (o no se pudo leer).
	 */
	private function count_one( string $key, int $max, int $dmax, bool $valid, string $username ): ?array {
		global $wpdb;
		$table = self::table_name();
		$now   = $this->now();
		$cut   = $now - ( (int) $this->settings['window_minutes'] * self::MINUTE );
		$dcut  = $now - self::DAY;

		// Reserva atomica: la ventana (y la diaria) se reinicia en el propio SQL y mientras
		// la IP esta bloqueada no se cuenta nada. Las asignaciones de MySQL se evaluan de
		// izquierda a derecha con los valores ya asignados, por eso cada condicion usa
		// columnas aun sin tocar y locked_until va la ultima.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia; el contador no se puede cachear.
		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (ip, attempts, first_attempt, locked_until, lockouts, last_lockout, daily_count, daily_start) VALUES (%s, 1, %d, 0, 0, 0, 1, %d)
				ON DUPLICATE KEY UPDATE
				attempts = IF(locked_until > %d, attempts, IF(first_attempt < %d OR (locked_until > 0 AND locked_until <= %d), 1, attempts + 1)),
				first_attempt = IF(locked_until > %d, first_attempt, IF(first_attempt < %d OR (locked_until > 0 AND locked_until <= %d), %d, first_attempt)),
				daily_count = IF(locked_until > %d, daily_count, IF(daily_start < %d, 1, daily_count + 1)),
				daily_start = IF(locked_until > %d, daily_start, IF(daily_start < %d, %d, daily_start)),
				locked_until = IF(locked_until > 0 AND locked_until <= %d, 0, locked_until)',
				$table,
				$key,
				$now,
				$now,
				$now,
				$cut,
				$now,
				$now,
				$cut,
				$now,
				$now,
				$now,
				$dcut,
				$now,
				$dcut,
				$now,
				$now
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia.
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT attempts, locked_until, lockouts, last_lockout, daily_count FROM %i WHERE ip = %s', $table, $key ),
			ARRAY_A
		);
		if ( ! is_array( $rows ) || ! isset( $rows[0] ) ) {
			$this->log_db_error_once();
			return null; // Falla abierto.
		}
		$row      = $rows[0];
		$attempts = (int) $row['attempts'];
		$daily    = (int) $row['daily_count'];

		if ( (int) $row['locked_until'] > $now ) {
			return array(
				'blocked'   => true,
				'remaining' => (int) $row['locked_until'] - $now,
				'counted'   => false,
			);
		}

		// "Se pasa" si el valor supera el limite; si lo iguala y el acceso falla, tambien se
		// bloquea ya (el fallo numero max). Con acceso valido y valor == max, entra.
		$over_attempts = $attempts > $max || ( $attempts === $max && ! $valid );
		$over_daily    = $dmax > 0 && ( $daily > $dmax || ( $daily === $dmax && ! $valid ) );
		$exceeds       = $attempts > $max || ( $dmax > 0 && $daily > $dmax );

		if ( $over_attempts || $over_daily ) {
			$remaining = $this->apply_lock( $key, $row, $attempts, $over_daily, $username, $max, $dmax );
			return array(
				'blocked'   => $exceeds && $remaining > 0,
				'remaining' => $remaining,
				'counted'   => true,
			);
		}
		return null;
	}

	/**
	 * Devuelve SOLO las plazas reservadas (no reinicia nada) en todos los contadores de la IP.
	 *
	 * @param array<int,string> $keys Claves de los contadores.
	 * @return void
	 */
	private function refund( array $keys ): void {
		global $wpdb;
		if ( array() === $keys ) {
			return;
		}
		$keys = array_values( array_unique( $keys ) );
		// Un %s por clave: la cadena de marcadores no lleva ningun dato, los valores van por prepare().
		$placeholders = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Lista IN de marcadores %s generada; los valores van por prepare().
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET attempts = GREATEST(attempts - 1, 0), daily_count = GREATEST(daily_count - 1, 0) WHERE ip IN ({$placeholders}) AND locked_until <= %d",
				array_merge( array( self::table_name() ), $keys, array( $this->now() ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
	}

	/**
	 * Aplica el bloqueo (solo una peticion concurrente lo consigue) y lo registra.
	 *
	 * Escalada: los bloqueos se acumulan mientras el ultimo acabo hace menos de 24 h (last_lockout
	 * guarda el FIN del bloqueo), asi funciona aunque lockout_minutes sea de 1440 o mas.
	 * El contador diario solo se reinicia si el bloqueo lo causo el propio limite diario: un
	 * bloqueo corto no da un cupo diario nuevo.
	 *
	 * @param string              $key        Clave del contador.
	 * @param array<string,mixed> $row        Fila leida.
	 * @param int                 $attempts   Valor del contador.
	 * @param bool                $over_daily Si el motivo es el limite diario.
	 * @param string              $username   Usuario del intento.
	 * @param int                 $max        Limite de la ventana de este contador.
	 * @param int                 $dmax       Limite diario de este contador (0 = ninguno).
	 * @return int Segundos de bloqueo que quedan (0 si no hay bloqueo).
	 */
	private function apply_lock( string $key, array $row, int $attempts, bool $over_daily, string $username, int $max, int $dmax ): int {
		global $wpdb;
		$table = self::table_name();
		$now   = $this->now();

		$lockouts = (int) $row['lockouts'];
		if ( (int) $row['last_lockout'] < $now - self::DAY ) {
			$lockouts = 0;
		}
		++$lockouts;

		$long_after = (int) $this->settings['long_lockout_after'];
		$is_long    = $over_daily || ( $long_after > 0 && $lockouts >= $long_after );
		$duration   = $is_long
			? (int) $this->settings['long_lockout_hours'] * self::HOUR
			: (int) $this->settings['lockout_minutes'] * self::MINUTE;
		$end        = $now + $duration;

		// El WHERE hace que solo una peticion concurrente aplique el bloqueo.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia.
		$changed = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET attempts = 0, daily_count = IF(%d = 1, 0, daily_count), locked_until = %d, lockouts = %d, last_lockout = %d WHERE ip = %s AND locked_until <= %d AND (attempts >= %d OR daily_count >= %d)',
				$table,
				$over_daily ? 1 : 0,
				$end,
				$lockouts,
				$end,
				$key,
				$now,
				$max,
				$dmax > 0 ? $dmax : 2147483647
			)
		);
		if ( (int) $changed < 1 ) {
			return $this->get_remaining_lock( array( $key ) );
		}

		$this->context->log(
			'lockout',
			sprintf(
				/* translators: 1: IP, 2: minutos de bloqueo, 3: intentos. */
				__( 'IP %1$s bloqueada %2$d minutos tras %3$d intentos de acceso.', 'total-security-expert' ),
				$this->context->get_client_ip(),
				(int) round( $duration / self::MINUTE ),
				$attempts
			),
			array_merge(
				array(
					'ip'       => $this->context->get_client_ip(),
					'bucket'   => $key,
					'attempts' => $attempts,
					'duration' => $duration,
					'lockouts' => $lockouts,
					'long'     => $is_long,
					'daily'    => $over_daily,
				),
				$this->loggable_username( $username )
			),
			'warning'
		);
		return $duration;
	}

	/**
	 * Apunta, como mucho una vez por hora, que no se ha podido leer el contador.
	 *
	 * @return void
	 */
	private function log_db_error_once(): void {
		if ( null === $this->context || false !== get_transient( self::DBERR_TRANSIENT ) ) {
			return;
		}
		set_transient( self::DBERR_TRANSIENT, '1', self::HOUR );
		$this->context->log(
			'db_error',
			__( 'No se ha podido leer el contador de intentos de acceso (¿falta la tabla o una columna?). El límite no se aplica hasta que se arregle.', 'total-security-expert' ),
			array(),
			'warning'
		);
	}

	/**
	 * Usuario para el registro: el texto solo si es un usuario o correo que existe; si no,
	 * "unknown" y su longitud (quien escribe su contrasena en el campo de usuario no la deja en el registro).
	 *
	 * @param string $username Texto sin confiar.
	 * @return array<string,mixed>
	 */
	private function loggable_username( string $username ): array {
		$text = sanitize_text_field( $username );
		if ( '' !== $text && $text === $username && mb_strlen( $text ) <= 100 && ( username_exists( $text ) || email_exists( $text ) ) ) {
			return array( 'username' => $text );
		}
		return array(
			'username'        => 'unknown',
			'username_length' => mb_strlen( $username ),
		);
	}

	/**
	 * Segundos que le quedan de bloqueo a la IP (el mayor de sus contadores; 0 si no esta
	 * bloqueada o no se puede saber).
	 *
	 * @param array<int,string> $keys Claves de los contadores.
	 * @return int
	 */
	private function get_remaining_lock( array $keys ): int {
		if ( array() === $keys ) {
			return 0;
		}
		$keys = array_values( array_unique( $keys ) );
		global $wpdb;
		// Un %s por clave: la cadena de marcadores no lleva ningun dato, los valores van por prepare().
		$placeholders = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Lista IN de marcadores %s generada; los valores van por prepare().
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia.
		$until = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT MAX(locked_until) FROM %i WHERE ip IN ({$placeholders})",
				array_merge( array( self::table_name() ), $keys )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
		if ( ! is_numeric( $until ) ) {
			return 0;
		}
		return max( 0, (int) $until - $this->now() );
	}

	/**
	 * Error de bloqueo si quedan segundos; si no, el valor tal cual.
	 *
	 * Si se pasan $normal_keys (intento cross-site) y el contador normal NO esta bloqueado, el
	 * mensaje avisa de que se puede entrar directamente desde la pagina de acceso de la web.
	 *
	 * @param mixed             $user        Valor de authenticate.
	 * @param int               $remaining   Segundos de bloqueo.
	 * @param array<int,string> $normal_keys Claves del contador normal, solo en intentos cross-site.
	 * @return mixed
	 */
	private function locked_error_or( $user, int $remaining, array $normal_keys = array() ) {
		if ( $remaining <= 0 ) {
			return $user;
		}
		$cross_only = array() !== $normal_keys && 0 === $this->get_remaining_lock( $normal_keys );
		return new \WP_Error( 'tsexp_locked', $cross_only ? $this->cross_locked_message( $remaining ) : $this->locked_message( $remaining ) );
	}

	/**
	 * Claves del contador cross-site: las normales con el prefijo.
	 *
	 * @param array<int,string> $keys Claves normales.
	 * @return array<int,string>
	 */
	private function cross_keys( array $keys ): array {
		return array_map( static fn( $key ): string => self::CROSS_PREFIX . $key, array_values( $keys ) );
	}

	/**
	 * Claves de contador de la IP actual: el grupo fino (IPv4 tal cual, IPv6 su /64) y, solo en
	 * IPv6, el grueso (/48). Vacio si no hay IP valida o esta en la lista blanca.
	 *
	 * @param bool $is_attempt Si es un intento que cuenta (entonces se avisa una vez al dia si no hay IP).
	 * @return array<int,string>
	 */
	private function get_keys( bool $is_attempt ): array {
		if ( null === $this->context ) {
			return array();
		}
		$bucket = $this->context->get_client_ip_bucket();
		if ( '' === $bucket ) {
			if ( $is_attempt ) {
				$this->log_no_ip_once();
			}
			return array();
		}
		if ( $this->is_allowlisted() ) {
			return array();
		}
		$keys   = array( $bucket );
		$coarse = $this->coarse_key();
		if ( '' !== $coarse ) {
			$keys[] = $coarse;
		}
		return $keys;
	}

	/**
	 * Si la IP real (no el grupo) esta en la lista blanca.
	 *
	 * @return bool
	 */
	private function is_allowlisted(): bool {
		if ( null === $this->context ) {
			return false;
		}
		$real = Request::normalize_ip( $this->context->get_client_ip() );
		if ( '' === $real ) {
			return false;
		}
		foreach ( (array) ( $this->settings['allowlist'] ?? array() ) as $entry ) {
			if ( is_string( $entry ) && Request::ip_matches( $real, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Clave del contador grueso: la red /48 de la IP real en IPv6 ('' en IPv4 o sin IP).
	 *
	 * @return string
	 */
	private function coarse_key(): string {
		if ( null === $this->context ) {
			return '';
		}
		$real = Request::normalize_ip( $this->context->get_client_ip() );
		if ( '' === $real || ! str_contains( $real, ':' ) ) {
			return '';
		}
		$packed = inet_pton( $real );
		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return '';
		}
		$network = inet_ntop( substr( $packed, 0, 6 ) . str_repeat( "\0", 10 ) );
		return false === $network ? '' : $network . '/48';
	}

	/**
	 * Apunta, como mucho una vez al dia, que no hay una IP valida (el limite no funciona sin ella).
	 *
	 * @return void
	 */
	private function log_no_ip_once(): void {
		if ( false !== get_transient( self::NOIP_TRANSIENT ) ) {
			return;
		}
		set_transient( self::NOIP_TRANSIENT, '1', self::DAY );
		$this->context->log(
			'no_client_ip',
			__( 'No se ha podido determinar una IP válida del cliente: el límite de intentos no se aplica a estas peticiones.', 'total-security-expert' ),
			array(),
			'warning'
		);
	}

	/**
	 * Si la peticion viene de otro sitio: Sec-Fetch-Site cross-site. Si esa cabecera dice
	 * same-origin o none se confia en ella; en cualquier otro caso (incluido same-site, que
	 * admite subdominios hermanos) se compara Origin: su host debe ser el de home_url() o
	 * site_url() (un Origin "null" u opaco cuenta como otro sitio). Sin esas cabeceras (clientes
	 * que no son navegadores) no es cross-site.
	 *
	 * Uso: en el login de formulario (authenticate) un intento cross-site NO se rechaza, sino que
	 * se cuenta en su propio contador (ver la clase): asi funcionan sin configurar nada los botones
	 * de acceso de paneles como cPanel o Plesk. Se descartaron una lista de origenes de confianza
	 * (exige configurar), fiarse de puertos o nombres de panel (un atacante sirve una pagina en
	 * :2083) y dejar pasar sin contar los cross-site validos (un cliente que no es un navegador
	 * elige sus cabeceras: seria un bypass total del limite y un oraculo de exito). Siguen siendo
	 * estrictos, sin contador, REST con Basic y las contrasenas de aplicacion.
	 *
	 * Compromisos aceptados: el login CSRF vuelve a ser posible en el formulario, como en el
	 * nucleo de WordPress; y un atacante con un script, que controla sus cabeceras, tiene
	 * aproximadamente el doble de intentos por IP al alternar los dos contadores.
	 *
	 * @return bool
	 */
	private function is_cross_site(): bool {
		if ( isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) && is_string( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ) {
			$site = strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ) );
			if ( 'cross-site' === $site ) {
				return true;
			}
			if ( in_array( $site, array( 'same-origin', 'none' ), true ) ) {
				return false; // El navegador lo garantiza: no se compara el host de Origin.
			}
			// same-site incluye subdominios hermanos: se sigue comparando el host de Origin.
		}
		if ( ! isset( $_SERVER['HTTP_ORIGIN'] ) || ! is_string( $_SERVER['HTTP_ORIGIN'] ) ) {
			return false;
		}
		$origin = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_ORIGIN'] ) ) );
		if ( '' === $origin ) {
			return false;
		}
		$origin_host = wp_parse_url( $origin, PHP_URL_HOST );
		if ( ! is_string( $origin_host ) || '' === $origin_host ) {
			return true; // Por ejemplo "null".
		}
		$allowed = array();
		foreach ( array( home_url(), site_url() ) as $url ) {
			$host = wp_parse_url( (string) $url, PHP_URL_HOST );
			if ( is_string( $host ) && '' !== $host ) {
				$allowed[] = strtolower( $host );
			}
		}
		return ! in_array( strtolower( $origin_host ), $allowed, true );
	}

	/**
	 * Valida una entrada de la lista blanca: IP o CIDR; descarta /0 y prefijos menores que
	 * /8 (IPv4) o /32 (IPv6); convierte los CIDR de IPv4 mapeada en IPv6 a IPv4.
	 *
	 * @param string $entry Entrada sin confiar.
	 * @return string Entrada canonica o '' si no vale.
	 */
	private function sanitize_allowlist_entry( string $entry ): string {
		if ( ! Request::is_valid_ip_or_cidr( $entry ) ) {
			return '';
		}
		if ( ! str_contains( $entry, '/' ) ) {
			return Request::normalize_ip( $entry );
		}

		list( $net, $bits ) = explode( '/', trim( $entry ), 2 );
		$bits               = (int) $bits;
		$packed             = inet_pton( trim( $net ) );
		if ( false === $packed ) {
			return '';
		}
		if ( 16 === strlen( $packed ) && str_starts_with( $packed, str_repeat( "\0", 10 ) . "\xff\xff" ) && $bits >= 96 ) {
			$packed = substr( $packed, 12 );
			$bits  -= 96;
		}
		$min = 4 === strlen( $packed ) ? 8 : 32;
		if ( $bits < $min ) {
			return '';
		}
		$network = inet_ntop( $packed );
		return false === $network ? '' : $network . '/' . $bits;
	}

	/**
	 * Mensaje generico con los minutos que faltan.
	 *
	 * @param int $remaining Segundos restantes.
	 * @return string
	 */
	private function locked_message( int $remaining ): string {
		$minutes = max( 1, (int) ceil( $remaining / self::MINUTE ) );
		return sprintf(
			/* translators: %d: minutos que faltan para poder volver a intentarlo. */
			_n(
				'Demasiados intentos fallidos. Inténtalo de nuevo en %d minuto.',
				'Demasiados intentos fallidos. Inténtalo de nuevo en %d minutos.',
				$minutes,
				'total-security-expert'
			),
			$minutes
		);
	}

	/**
	 * Mensaje del bloqueo de un intento cross-site: ademas del tiempo, indica que se puede entrar
	 * directamente desde la pagina de acceso de la web.
	 *
	 * @param int $remaining Segundos restantes.
	 * @return string
	 */
	private function cross_locked_message( int $remaining ): string {
		$minutes = max( 1, (int) ceil( $remaining / self::MINUTE ) );
		return sprintf(
			/* translators: %d: minutos que faltan para poder volver a intentarlo. */
			_n(
				'Demasiados intentos desde otro sitio. Accede directamente desde la página de inicio de sesión de esta web o inténtalo de nuevo en %d minuto.',
				'Demasiados intentos desde otro sitio. Accede directamente desde la página de inicio de sesión de esta web o inténtalo de nuevo en %d minutos.',
				$minutes,
				'total-security-expert'
			),
			$minutes
		);
	}

	/**
	 * IPs bloqueadas ahora: total y unas pocas para mostrar.
	 *
	 * @return array{count:int,rows:array<int,array{ip:string,until:int,cross:bool}>}
	 */
	private function get_locked_overview(): array {
		global $wpdb;
		$table = self::table_name();
		$now   = $this->now();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia; solo lectura para la pantalla de ajustes.
		$count = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE locked_until > %d', $table, $now ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia; solo lectura para la pantalla de ajustes.
		$found = $wpdb->get_results(
			$wpdb->prepare( 'SELECT ip, locked_until FROM %i WHERE locked_until > %d ORDER BY locked_until DESC LIMIT %d', $table, $now, self::LIST_LIMIT ),
			ARRAY_A
		);

		$rows = array();
		foreach ( is_array( $found ) ? $found : array() as $row ) {
			$ip     = (string) ( $row['ip'] ?? '' );
			$cross  = str_starts_with( $ip, self::CROSS_PREFIX );
			$rows[] = array(
				'ip'    => $cross ? substr( $ip, strlen( self::CROSS_PREFIX ) ) : $ip,
				'until' => (int) ( $row['locked_until'] ?? 0 ),
				'cross' => $cross,
			);
		}
		return array(
			'count' => is_numeric( $count ) ? (int) $count : 0,
			'rows'  => $rows,
		);
	}

	/**
	 * Entero acotado; si no es numerico, el valor por defecto.
	 *
	 * @param mixed $value    Valor sin confiar.
	 * @param int   $min      Minimo.
	 * @param int   $max      Maximo.
	 * @param int   $fallback Valor por defecto.
	 * @return int
	 */
	private function clamp_int( $value, int $min, int $max, int $fallback ): int {
		if ( ! is_numeric( $value ) ) {
			return $fallback;
		}
		return max( $min, min( $max, (int) $value ) );
	}

	/**
	 * Hora actual (unix).
	 *
	 * @return int
	 */
	protected function now(): int {
		return time();
	}
}

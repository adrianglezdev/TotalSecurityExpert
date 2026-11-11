<?php
/**
 * Modulo: registro de actividad.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Modules;

use TotalSecurityExpert\Abstract_Module;
use TotalSecurityExpert\Context;

defined( 'ABSPATH' ) || exit;

/**
 * Apunta en el registro del plugin lo que ocurre en el sitio: accesos, usuarios,
 * plugins y temas, ajustes sensibles y (opcional) contenido. No tiene pantalla propia.
 */
class Activity_Log extends Abstract_Module {

	/**
	 * Opciones de WordPress vigiladas (lista blanca).
	 *
	 * @var array<int,string>
	 */
	private const WATCHED_OPTIONS = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'blog_public', 'template', 'stylesheet' );

	/**
	 * Capacidades cuyo cambio en un rol es grave.
	 *
	 * @var array<int,string>
	 */
	private const DANGEROUS_CAPS = array( 'manage_options', 'promote_users', 'edit_users', 'activate_plugins', 'install_plugins', 'edit_plugins', 'unfiltered_html' );

	/**
	 * Fallos por IP que se registran uno a uno en cada ventana.
	 *
	 * @var int
	 */
	private const FAIL_LIMIT = 10;

	/**
	 * Duracion de la ventana de fallos, en segundos.
	 *
	 * @var int
	 */
	private const FAIL_WINDOW = 600;

	/**
	 * Fallos que se registran uno a uno en cada ventana entre todas las IP del sitio.
	 *
	 * @var int
	 */
	private const FAIL_GLOBAL_LIMIT = 200;

	/**
	 * Vida del contador en el transient, en segundos (mas que la ventana, para poder resumir).
	 *
	 * @var int
	 */
	private const FAIL_TTL = 3600;

	/**
	 * Tipos de contenido que se registran.
	 *
	 * @var array<int,string>
	 */
	private const POST_TYPES = array( 'post', 'page' );

	/**
	 * Contexto recibido en boot().
	 *
	 * @var Context|null
	 */
	private ?Context $context = null;

	/**
	 * Id del modulo.
	 *
	 * @return string
	 */
	public function get_id(): string {
		return 'activity-log';
	}

	/**
	 * Nombre.
	 *
	 * @return string
	 */
	public function get_name(): string {
		return __( 'Registro de actividad', 'total-security-expert' );
	}

	/**
	 * Descripcion.
	 *
	 * @return string
	 */
	public function get_description(): string {
		return __( 'Apunta en el registro los accesos, los cambios de usuarios, plugins, temas y ajustes sensibles.', 'total-security-expert' );
	}

	/**
	 * Ajustes por defecto: una casilla por grupo.
	 *
	 * @return array<string,bool>
	 */
	public function get_default_settings(): array {
		return array(
			'log_auth'           => true,
			'log_users'          => true,
			'log_plugins_themes' => true,
			'log_settings'       => true,
			'log_content'        => false,
		);
	}

	/**
	 * Casilla ausente o invalida = false. Idempotente.
	 *
	 * @param array<string,mixed> $input Datos sin confiar.
	 * @return array<string,bool>
	 */
	public function sanitize_settings( array $input ): array {
		$clean = array();
		foreach ( array_keys( $this->get_default_settings() ) as $key ) {
			$clean[ $key ] = isset( $input[ $key ] )
				&& is_scalar( $input[ $key ] )
				&& filter_var( $input[ $key ], FILTER_VALIDATE_BOOLEAN );
		}
		return $clean;
	}

	/**
	 * Pinta una casilla por grupo.
	 *
	 * @param array<string,mixed> $settings    Ajustes actuales.
	 * @param string              $name_prefix Prefijo del name de los campos.
	 * @return void
	 */
	public function render_settings( array $settings, string $name_prefix ): void {
		$settings = array_merge( $this->get_default_settings(), $settings );
		$labels   = array(
			'log_auth'           => __( 'Accesos: entradas correctas, intentos fallidos y salidas.', 'total-security-expert' ),
			'log_users'          => __( 'Usuarios: altas, bajas, cambios de rol y de perfil, restablecimiento de contraseña.', 'total-security-expert' ),
			'log_plugins_themes' => __( 'Plugins y temas: activación, desactivación, borrado, instalación y actualización.', 'total-security-expert' ),
			'log_settings'       => __( 'Ajustes sensibles de WordPress y activación de módulos de este plugin.', 'total-security-expert' ),
			'log_content'        => __( 'Contenido: entradas y páginas publicadas, enviadas a la papelera o borradas.', 'total-security-expert' ),
		);

		foreach ( $labels as $key => $label ) {
			$name = $name_prefix . '[' . $key . ']';
			$id   = $name_prefix . '_' . $key;
			?>
			<p>
				<input type="checkbox" id="<?php echo esc_attr( $id ); ?>" name="<?php echo esc_attr( $name ); ?>" value="1" <?php checked( ! empty( $settings[ $key ] ) ); ?> />
				<label for="<?php echo esc_attr( $id ); ?>"><?php echo esc_html( $label ); ?></label>
			</p>
			<?php
		}
	}

	/**
	 * Registra solo los hooks de los grupos activos.
	 *
	 * @param Context             $context  Contexto.
	 * @param array<string,mixed> $settings Ajustes.
	 * @return void
	 */
	public function boot( Context $context, array $settings ): void {
		$this->context = $context;
		$settings      = array_merge( $this->get_default_settings(), $settings );

		if ( ! empty( $settings['log_auth'] ) ) {
			$context->add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
			$context->add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 2 );
			$context->add_action( 'wp_logout', array( $this, 'on_logout' ), 10, 1 );
			$context->add_action( 'application_password_did_authenticate', array( $this, 'on_app_password_authenticated' ), 10, 2 );
			$context->add_action( 'application_password_failed_authentication', array( $this, 'on_app_password_failed' ), 10, 1 );
		}

		if ( ! empty( $settings['log_users'] ) ) {
			$context->add_action( 'user_register', array( $this, 'on_user_register' ), 10, 1 );
			$context->add_action( 'delete_user', array( $this, 'on_delete_user' ), 10, 1 );
			$context->add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
			$context->add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );
			$context->add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 1 );
			$context->add_action( 'wp_set_password', array( $this, 'on_set_password' ), 10, 2 );
			$context->add_action( 'add_user_role', array( $this, 'on_add_user_role' ), 10, 2 );
			$context->add_action( 'remove_user_role', array( $this, 'on_remove_user_role' ), 10, 2 );
			$context->add_action( 'granted_super_admin', array( $this, 'on_granted_super_admin' ), 10, 1 );
			$context->add_action( 'revoked_super_admin', array( $this, 'on_revoked_super_admin' ), 10, 1 );
			$context->add_action( 'wp_create_application_password', array( $this, 'on_app_password_created' ), 10, 2 );
			$context->add_action( 'wp_delete_application_password', array( $this, 'on_app_password_deleted' ), 10, 2 );
		}

		if ( ! empty( $settings['log_plugins_themes'] ) ) {
			$context->add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ), 10, 2 );
			$context->add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ), 10, 2 );
			$context->add_action( 'deleted_plugin', array( $this, 'on_plugin_deleted' ), 10, 2 );
			$context->add_action( 'upgrader_process_complete', array( $this, 'on_upgrader_complete' ), 10, 2 );
			$context->add_action( 'switch_theme', array( $this, 'on_switch_theme' ), 10, 3 );
			$context->add_action( 'deleted_theme', array( $this, 'on_theme_deleted' ), 10, 2 );
		}

		if ( ! empty( $settings['log_settings'] ) ) {
			$context->add_action( 'updated_option', array( $this, 'on_updated_option' ), 10, 3 );
			$context->add_action( 'added_option', array( $this, 'on_added_option' ), 10, 2 );
			$context->add_action( 'delete_option', array( $this, 'on_delete_option' ), 10, 1 );
		}

		if ( ! empty( $settings['log_content'] ) ) {
			$context->add_action( 'transition_post_status', array( $this, 'on_transition_post_status' ), 10, 3 );
			$context->add_action( 'before_delete_post', array( $this, 'on_before_delete_post' ), 10, 2 );
		}
	}

	/**
	 * Acceso correcto.
	 *
	 * @param mixed $user_login Login.
	 * @param mixed $user       Objeto WP_User.
	 * @return void
	 */
	public function on_login( $user_login, $user = null ): void {
		$login = $this->clean( $user_login, 60 );
		$this->log(
			'login',
			/* translators: %s: login del usuario. */
			sprintf( __( 'Acceso correcto del usuario %s.', 'total-security-expert' ), $login ),
			array(
				'login'   => $login,
				'user_id' => is_object( $user ) ? absint( $user->ID ?? 0 ) : 0,
			)
		);
	}

	/**
	 * Acceso fallido. El texto escrito solo se guarda si es un usuario o email que existe:
	 * si no, podria ser una contrasena puesta en el campo de usuario.
	 *
	 * @param mixed $username Usuario intentado.
	 * @param mixed $error    Objeto WP_Error del fallo.
	 * @return void
	 */
	public function on_login_failed( $username, $error = null ): void {
		if ( $this->is_locked_error( $error ) ) {
			return;
		}

		$raw       = is_scalar( $username ) ? (string) $username : '';
		$candidate = $this->clean_user( $raw, 60 );
		$known     = '' !== $candidate && mb_strlen( $candidate ) <= 100
			&& ( (bool) username_exists( $candidate ) || (bool) email_exists( $candidate ) );

		if ( $known ) {
			$data = array(
				'known' => true,
				'login' => $candidate,
			);
		} else {
			$data = array(
				'known' => false,
				'login' => 'unknown',
			);
		}

		$this->log_failure( 'login_failed', __( 'Acceso fallido.', 'total-security-expert' ), $data );
	}

	/**
	 * Salida del usuario (sin usuario, nada que registrar).
	 *
	 * @param mixed $user_id ID del usuario (WordPress 5.5+).
	 * @return void
	 */
	public function on_logout( $user_id = 0 ): void {
		$id = absint( $user_id );
		if ( 0 === $id ) {
			return;
		}
		$this->log(
			'logout',
			/* translators: %d: ID del usuario. */
			sprintf( __( 'El usuario %d ha cerrado sesión.', 'total-security-expert' ), $id ),
			array( 'user_id' => $id )
		);
	}

	/**
	 * Alta de usuario, con los roles que tiene en este momento.
	 *
	 * @param mixed $user_id ID.
	 * @return void
	 */
	public function on_user_register( $user_id ): void {
		$id    = absint( $user_id );
		$user  = get_userdata( $id );
		$roles = array();
		if ( is_object( $user ) && is_array( $user->roles ?? null ) ) {
			$roles = $this->to_list( $user->roles );
		}
		$this->log(
			'user_registered',
			/* translators: %d: ID del usuario. */
			sprintf( __( 'Nuevo usuario creado (ID %d).', 'total-security-expert' ), $id ),
			array(
				'user_id' => $id,
				'login'   => is_object( $user ) ? $this->clean( $user->user_login ?? '', 60 ) : '',
				'roles'   => $roles,
			)
		);
	}

	/**
	 * Borrado de usuario (antes de borrar, para conservar el login).
	 *
	 * @param mixed $user_id ID.
	 * @return void
	 */
	public function on_delete_user( $user_id ): void {
		$id   = absint( $user_id );
		$user = get_userdata( $id );
		$this->log(
			'user_deleted',
			/* translators: %d: ID del usuario. */
			sprintf( __( 'Usuario borrado (ID %d).', 'total-security-expert' ), $id ),
			array(
				'user_id' => $id,
				'login'   => is_object( $user ) ? $this->clean( $user->user_login ?? '', 60 ) : '',
			),
			'warning'
		);
	}

	/**
	 * Cambio de rol; aviso si el nuevo es administrador.
	 *
	 * @param mixed $user_id   ID.
	 * @param mixed $role      Rol nuevo.
	 * @param mixed $old_roles Roles anteriores.
	 * @return void
	 */
	public function on_set_user_role( $user_id, $role = '', $old_roles = array() ): void {
		$id    = absint( $user_id );
		$new   = $this->clean( $role, 60 );
		$old   = array();
		$items = is_array( $old_roles ) ? array_slice( $old_roles, 0, 10 ) : array();
		foreach ( $items as $item ) {
			$old[] = $this->clean( $item, 60 );
		}
		$this->log(
			'user_role_changed',
			/* translators: 1: ID del usuario, 2: rol nuevo. */
			sprintf( __( 'Rol del usuario %1$d cambiado a %2$s.', 'total-security-expert' ), $id, $new ),
			array(
				'user_id'   => $id,
				'old_roles' => $old,
				'new_role'  => $new,
			),
			'administrator' === $new ? 'warning' : 'info'
		);
	}

	/**
	 * Cambio de perfil: solo que han cambiado email, contrasena, nombre visible o URL.
	 *
	 * @param mixed $user_id       ID.
	 * @param mixed $old_user_data Datos anteriores (WP_User).
	 * @return void
	 */
	public function on_profile_update( $user_id, $old_user_data = null ): void {
		$id  = absint( $user_id );
		$new = get_userdata( $id );
		if ( ! is_object( $old_user_data ) || ! is_object( $new ) ) {
			return;
		}

		$fields  = array(
			'email'        => 'user_email',
			'password'     => 'user_pass',
			'display_name' => 'display_name',
			'url'          => 'user_url',
		);
		$changed = array();
		foreach ( $fields as $label => $property ) {
			if ( (string) ( $old_user_data->$property ?? '' ) !== (string) ( $new->$property ?? '' ) ) {
				$changed[] = $label;
			}
		}
		if ( array() === $changed ) {
			return;
		}

		$this->log(
			'user_updated',
			/* translators: 1: ID del usuario, 2: lista de campos cambiados. */
			sprintf( __( 'Perfil del usuario %1$d actualizado (cambia: %2$s).', 'total-security-expert' ), $id, implode( ', ', $changed ) ),
			array(
				'user_id' => $id,
				'changed' => $changed,
			)
		);
	}

	/**
	 * Restablecimiento de contrasena (nunca se toca la nueva).
	 *
	 * @param mixed $user Objeto WP_User.
	 * @return void
	 */
	public function on_password_reset( $user ): void {
		$this->log(
			'password_reset',
			__( 'Contraseña restablecida mediante el enlace de recuperación.', 'total-security-expert' ),
			array(
				'user_id' => is_object( $user ) ? absint( $user->ID ?? 0 ) : 0,
				'login'   => is_object( $user ) ? $this->clean( $user->user_login ?? '', 60 ) : '',
			)
		);
	}

	/**
	 * Contrasena cambiada con wp_set_password(). El primer argumento es la contrasena
	 * en claro: no se lee. Solo se registra el ID.
	 *
	 * @param mixed ...$args Argumentos del hook ( contrasena, ID, datos anteriores ).
	 * @return void
	 */
	public function on_set_password( ...$args ): void {
		$id = absint( $args[1] ?? 0 );
		$this->log(
			'password_set',
			/* translators: %d: ID del usuario. */
			sprintf( __( 'Contraseña del usuario %d cambiada.', 'total-security-expert' ), $id ),
			array( 'user_id' => $id )
		);
	}

	/**
	 * Rol anadido a un usuario.
	 *
	 * @param mixed $user_id ID.
	 * @param mixed $role    Rol.
	 * @return void
	 */
	public function on_add_user_role( $user_id, $role = '' ): void {
		$this->log_role_event( 'user_role_added', $user_id, $role );
	}

	/**
	 * Rol quitado a un usuario.
	 *
	 * @param mixed $user_id ID.
	 * @param mixed $role    Rol.
	 * @return void
	 */
	public function on_remove_user_role( $user_id, $role = '' ): void {
		$this->log_role_event( 'user_role_removed', $user_id, $role );
	}

	/**
	 * Super administrador concedido.
	 *
	 * @param mixed $user_id ID.
	 * @return void
	 */
	public function on_granted_super_admin( $user_id ): void {
		$id = absint( $user_id );
		$this->log(
			'super_admin_granted',
			/* translators: %d: ID del usuario. */
			sprintf( __( 'Super administrador concedido al usuario %d.', 'total-security-expert' ), $id ),
			array( 'user_id' => $id ),
			'warning'
		);
	}

	/**
	 * Super administrador retirado.
	 *
	 * @param mixed $user_id ID.
	 * @return void
	 */
	public function on_revoked_super_admin( $user_id ): void {
		$id = absint( $user_id );
		$this->log(
			'super_admin_revoked',
			/* translators: %d: ID del usuario. */
			sprintf( __( 'Super administrador retirado al usuario %d.', 'total-security-expert' ), $id ),
			array( 'user_id' => $id ),
			'warning'
		);
	}

	/**
	 * Contrasena de aplicacion creada. El 2.o argumento del hook es $new_item (incluye el hash)
	 * y el 3.o es la contrasena en claro. Del 2.o solo se leen uuid y name; el 3.o no se recibe.
	 *
	 * @param mixed $user_id ID del usuario.
	 * @param mixed $item    Datos de la contrasena (uuid, name...).
	 * @return void
	 */
	public function on_app_password_created( $user_id, $item = array() ): void {
		$this->log( 'app_password_created', __( 'Contraseña de aplicación creada.', 'total-security-expert' ), $this->app_password_data( $user_id, $item ), 'warning' );
	}

	/**
	 * Contrasena de aplicacion borrada.
	 *
	 * @param mixed $user_id ID del usuario.
	 * @param mixed $item    Datos de la contrasena.
	 * @return void
	 */
	public function on_app_password_deleted( $user_id, $item = array() ): void {
		$this->log( 'app_password_deleted', __( 'Contraseña de aplicación borrada.', 'total-security-expert' ), $this->app_password_data( $user_id, $item ) );
	}

	/**
	 * Acceso correcto con contrasena de aplicacion: como mucho una vez por usuario y hora.
	 *
	 * @param mixed $user Objeto WP_User.
	 * @param mixed $item Datos de la contrasena.
	 * @return void
	 */
	public function on_app_password_authenticated( $user, $item = array() ): void {
		$id = is_object( $user ) ? absint( $user->ID ?? 0 ) : 0;
		if ( 0 === $id ) {
			return;
		}
		$key = 'tsexp_activity_log_appauth_' . $id;
		if ( false !== get_transient( $key ) ) {
			return;
		}
		set_transient( $key, 1, self::FAIL_TTL );
		$this->log( 'app_password_used', __( 'Acceso con contraseña de aplicación.', 'total-security-expert' ), $this->app_password_data( $id, $item ) );
	}

	/**
	 * Acceso fallido con contrasena de aplicacion (agrupado por IP como los accesos fallidos).
	 *
	 * @param mixed $error Objeto WP_Error.
	 * @return void
	 */
	public function on_app_password_failed( $error = null ): void {
		if ( $this->is_locked_error( $error ) ) {
			return;
		}
		$code = '';
		if ( is_object( $error ) && method_exists( $error, 'get_error_code' ) ) {
			$code = $this->clean( $error->get_error_code(), 60 );
		}
		$this->log_failure( 'app_password_failed', __( 'Autenticación fallida con contraseña de aplicación.', 'total-security-expert' ), array( 'error_code' => $code ) );
	}

	/**
	 * Plugin activado.
	 *
	 * @param mixed $plugin       Ruta del plugin.
	 * @param mixed $network_wide Si es en toda la red.
	 * @return void
	 */
	public function on_plugin_activated( $plugin, $network_wide = false ): void {
		/* translators: %s: ruta del plugin. */
		$this->log_plugin( 'plugin_activated', __( 'Plugin activado: %s.', 'total-security-expert' ), $plugin, $network_wide );
	}

	/**
	 * Plugin desactivado.
	 *
	 * @param mixed $plugin       Ruta del plugin.
	 * @param mixed $network_wide Si es en toda la red.
	 * @return void
	 */
	public function on_plugin_deactivated( $plugin, $network_wide = false ): void {
		/* translators: %s: ruta del plugin. */
		$this->log_plugin( 'plugin_deactivated', __( 'Plugin desactivado: %s.', 'total-security-expert' ), $plugin, $network_wide );
	}

	/**
	 * Plugin borrado (solo si el borrado ha funcionado).
	 *
	 * @param mixed $plugin  Ruta del plugin.
	 * @param mixed $deleted Si se borro.
	 * @return void
	 */
	public function on_plugin_deleted( $plugin, $deleted = true ): void {
		if ( ! $deleted ) {
			return;
		}
		/* translators: %s: ruta del plugin. */
		$this->log_plugin( 'plugin_deleted', __( 'Plugin borrado: %s.', 'total-security-expert' ), $plugin, false, 'warning' );
	}

	/**
	 * Instalacion o actualizacion de plugins, temas o del nucleo.
	 *
	 * @param mixed $upgrader   Objeto WP_Upgrader.
	 * @param mixed $hook_extra Datos del proceso.
	 * @return void
	 */
	public function on_upgrader_complete( $upgrader, $hook_extra = array() ): void {
		if ( ! is_array( $hook_extra ) ) {
			return;
		}
		$type   = $this->clean( $hook_extra['type'] ?? '', 20 );
		$action = $this->clean( $hook_extra['action'] ?? '', 20 );
		if ( ! in_array( $type, array( 'plugin', 'theme', 'core' ), true ) ) {
			return;
		}

		$names = array();
		if ( 'plugin' === $type ) {
			$names = $this->to_list( $hook_extra['plugins'] ?? ( $hook_extra['plugin'] ?? array() ) );
			if ( array() === $names && is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) ) {
				$names = $this->to_list( $upgrader->plugin_info() );
			}
		} elseif ( 'theme' === $type ) {
			$names = $this->to_list( $hook_extra['themes'] ?? ( $hook_extra['theme'] ?? array() ) );
			if ( array() === $names && is_object( $upgrader ) && method_exists( $upgrader, 'theme_info' ) ) {
				$names = $this->to_list( $this->stylesheet_of( $upgrader->theme_info() ) );
			}
		}

		$data = array(
			'type'   => $type,
			'action' => $action,
		);
		if ( 'core' === $type ) {
			$data['version'] = $this->clean( get_bloginfo( 'version' ), 20 );
		} else {
			$data['names'] = $names;
		}

		$this->log(
			'upgrader_complete',
			/* translators: 1: tipo (plugin, theme o core), 2: accion (install o update). */
			sprintf( __( 'Proceso de WordPress completado: %1$s, %2$s.', 'total-security-expert' ), $type, $action ),
			$data
		);
	}

	/**
	 * Cambio de tema.
	 *
	 * @param mixed $new_name  Nombre del tema nuevo.
	 * @param mixed $new_theme Objeto WP_Theme nuevo.
	 * @param mixed $old_theme Objeto WP_Theme anterior.
	 * @return void
	 */
	public function on_switch_theme( $new_name, $new_theme = null, $old_theme = null ): void {
		$new = $this->clean( $new_name, 100 );
		$this->log(
			'theme_switched',
			/* translators: %s: nombre del tema. */
			sprintf( __( 'Tema cambiado a %s.', 'total-security-expert' ), $new ),
			array(
				'new_theme'      => $new,
				'new_stylesheet' => $this->stylesheet_of( $new_theme ),
				'old_stylesheet' => $this->stylesheet_of( $old_theme ),
			)
		);
	}

	/**
	 * Tema borrado.
	 *
	 * @param mixed $stylesheet Carpeta del tema.
	 * @param mixed $deleted    Si se borro.
	 * @return void
	 */
	public function on_theme_deleted( $stylesheet, $deleted = true ): void {
		if ( ! $deleted ) {
			return;
		}
		$name = $this->clean( $stylesheet, 100 );
		$this->log(
			'theme_deleted',
			/* translators: %s: carpeta del tema. */
			sprintf( __( 'Tema borrado: %s.', 'total-security-expert' ), $name ),
			array( 'stylesheet' => $name ),
			'warning'
		);
	}

	/**
	 * Cambio de una opcion vigilada o de los ajustes de este plugin.
	 *
	 * @param mixed $option    Nombre de la opcion.
	 * @param mixed $old_value Valor anterior.
	 * @param mixed $value     Valor nuevo.
	 * @return void
	 */
	public function on_updated_option( $option, $old_value = null, $value = null ): void {
		if ( ! is_string( $option ) ) {
			return;
		}

		if ( 'tsexp_settings' === $option ) {
			$this->log_plugin_settings_change( $old_value, $value, 'plugin_settings_changed', true );
			return;
		}

		if ( $option === $this->roles_option_name() ) {
			$this->log_roles_change( $old_value, $value );
			return;
		}

		if ( 'active_plugins' === $option ) {
			$this->log_active_plugins_change( $old_value, $value );
			return;
		}

		if ( ! in_array( $option, self::WATCHED_OPTIONS, true ) || $old_value === $value ) {
			return;
		}

		$old = $this->clean( $old_value, 200 );
		$new = $this->clean( $value, 200 );
		if ( $old === $new ) {
			return;
		}

		$warning = in_array( $option, array( 'siteurl', 'home' ), true )
			|| ( 'users_can_register' === $option && '1' === $new )
			|| ( 'default_role' === $option && 'administrator' === $new );

		$this->log(
			'option_changed',
			/* translators: %s: nombre de la opcion de WordPress. */
			sprintf( __( 'Ajuste de WordPress cambiado: %s.', 'total-security-expert' ), $option ),
			array(
				'option' => $option,
				'old'    => $old,
				'new'    => $new,
			),
			$warning ? 'warning' : 'info'
		);
	}

	/**
	 * Ajustes del plugin creados por primera vez.
	 *
	 * @param mixed $option Nombre de la opcion.
	 * @param mixed $value  Valor.
	 * @return void
	 */
	public function on_added_option( $option, $value = null ): void {
		if ( 'tsexp_settings' === $option ) {
			$this->log_plugin_settings_change( array(), $value, 'plugin_settings_added', false );
		}
	}

	/**
	 * Ajustes del plugin a punto de borrarse: todos los modulos quedan apagados.
	 *
	 * @param mixed $option Nombre de la opcion.
	 * @return void
	 */
	public function on_delete_option( $option ): void {
		if ( 'tsexp_settings' !== $option ) {
			return;
		}
		$this->log(
			'plugin_settings_deleted',
			__( 'Se han borrado los ajustes de Total Security Expert: todos los módulos quedan apagados.', 'total-security-expert' ),
			array( 'modules_disabled' => $this->enabled_modules( get_option( 'tsexp_settings', array() ) ) ),
			'warning'
		);
	}

	/**
	 * Entrada o pagina que pasa a publicada o a la papelera.
	 *
	 * @param mixed $new_status Estado nuevo.
	 * @param mixed $old_status Estado anterior.
	 * @param mixed $post       Objeto WP_Post.
	 * @return void
	 */
	public function on_transition_post_status( $new_status, $old_status = '', $post = null ): void {
		if ( ! is_object( $post ) || $new_status === $old_status || ! in_array( $new_status, array( 'publish', 'trash' ), true ) ) {
			return;
		}
		if ( ! in_array( $post->post_type ?? '', self::POST_TYPES, true ) ) {
			return;
		}

		$id = absint( $post->ID ?? 0 );
		if ( 'publish' === $new_status ) {
			$event = 'post_published';
			/* translators: %d: ID del contenido. */
			$message = sprintf( __( 'Contenido publicado (ID %d).', 'total-security-expert' ), $id );
		} else {
			$event = 'post_trashed';
			/* translators: %d: ID del contenido. */
			$message = sprintf( __( 'Contenido enviado a la papelera (ID %d).', 'total-security-expert' ), $id );
		}
		$this->log( $event, $message, $this->post_data( $post ) );
	}

	/**
	 * Borrado definitivo de una entrada o pagina.
	 *
	 * @param mixed $post_id ID.
	 * @param mixed $post    Objeto WP_Post (WordPress 5.5+).
	 * @return void
	 */
	public function on_before_delete_post( $post_id, $post = null ): void {
		if ( ! is_object( $post ) ) {
			$post = get_post( absint( $post_id ) );
		}
		if ( ! is_object( $post ) || ! in_array( $post->post_type ?? '', self::POST_TYPES, true ) || 'auto-draft' === ( $post->post_status ?? '' ) ) {
			return;
		}

		$this->log(
			'post_deleted',
			/* translators: %d: ID del contenido. */
			sprintf( __( 'Contenido borrado definitivamente (ID %d).', 'total-security-expert' ), absint( $post_id ) ),
			$this->post_data( $post ),
			wp_doing_cron() ? 'info' : 'warning'
		);
	}

	/**
	 * Registra el cambio de los ajustes del plugin: rutas de las claves que cambian (sin valores)
	 * y modulos que se activan o desactivan.
	 *
	 * @param mixed  $old_value Valor anterior.
	 * @param mixed  $value     Valor nuevo.
	 * @param string $event     Id del evento.
	 * @param bool   $escalate  Si un cambio en general.* o apagar un modulo es warning.
	 * @return void
	 */
	private function log_plugin_settings_change( $old_value, $value, string $event, bool $escalate ): void {
		$paths = $this->changed_paths( $old_value, $value );
		if ( array() === $paths ) {
			return;
		}
		$before   = $this->enabled_modules( $old_value );
		$after    = $this->enabled_modules( $value );
		$disabled = array_values( array_diff( $before, $after ) );

		$warning = false;
		foreach ( $paths as $path ) {
			if ( str_starts_with( $path, 'general.' ) ) {
				$warning = true;
			}
		}

		$this->log(
			$event,
			__( 'Se han cambiado los ajustes de Total Security Expert.', 'total-security-expert' ),
			array(
				'changed'          => $paths,
				'modules_enabled'  => array_values( array_diff( $after, $before ) ),
				'modules_disabled' => $disabled,
			),
			$escalate && ( $warning || array() !== $disabled ) ? 'warning' : 'info'
		);
	}

	/**
	 * Rutas (a.b.c) de las claves de dos ajustes que cambian. Nunca devuelve valores.
	 *
	 * @param mixed $old_value Valor anterior.
	 * @param mixed $value     Valor nuevo.
	 * @return array<int,string>
	 */
	private function changed_paths( $old_value, $value ): array {
		$old = array();
		$new = array();
		$this->flatten( $old_value, '', $old );
		$this->flatten( $value, '', $new );

		$paths = array();
		foreach ( array_unique( array_merge( array_keys( $old ), array_keys( $new ) ) ) as $path ) {
			if ( ! array_key_exists( $path, $old ) || ! array_key_exists( $path, $new ) || ! $this->same_value( $old[ $path ], $new[ $path ] ) ) {
				$paths[] = mb_substr( (string) $path, 0, 150 );
			}
		}
		return array_slice( $paths, 0, 60 );
	}

	/**
	 * Aplana un array en hojas con ruta; las listas y los valores simples son hojas.
	 *
	 * @param mixed               $value  Valor.
	 * @param string              $prefix Ruta hasta aqui.
	 * @param array<string,mixed> $out    Hojas (por referencia).
	 * @return void
	 */
	private function flatten( $value, string $prefix, array &$out ): void {
		if ( is_array( $value ) && array() !== $value && ! array_is_list( $value ) ) {
			foreach ( $value as $key => $item ) {
				$name = $this->clean( $key, 64 );
				$this->flatten( $item, '' === $prefix ? $name : $prefix . '.' . $name, $out );
			}
			return;
		}
		if ( '' !== $prefix ) {
			$out[ $prefix ] = $value;
		}
	}

	/**
	 * Compara dos hojas; "5" y 5 cuentan como iguales.
	 *
	 * @param mixed $a Valor.
	 * @param mixed $b Valor.
	 * @return bool
	 */
	private function same_value( $a, $b ): bool {
		if ( is_scalar( $a ) && is_scalar( $b ) ) {
			return $this->clean( $a, 100000 ) === $this->clean( $b, 100000 );
		}
		return $a === $b;
	}

	/**
	 * Nombre de la opcion de roles de este sitio.
	 *
	 * @return string
	 */
	private function roles_option_name(): string {
		global $wpdb;
		if ( is_object( $wpdb ) && method_exists( $wpdb, 'get_blog_prefix' ) ) {
			return $wpdb->get_blog_prefix() . 'user_roles';
		}
		return ( is_object( $wpdb ) ? (string) $wpdb->prefix : 'wp_' ) . 'user_roles';
	}

	/**
	 * Registra que capacidades se anaden o quitan a cada rol (solo nombres).
	 *
	 * @param mixed $old_value Roles anteriores.
	 * @param mixed $value     Roles nuevos.
	 * @return void
	 */
	private function log_roles_change( $old_value, $value ): void {
		$old = $this->role_caps( $old_value );
		$new = $this->role_caps( $value );

		$changes   = array();
		$dangerous = false;
		foreach ( array_unique( array_merge( array_keys( $old ), array_keys( $new ) ) ) as $role ) {
			$before  = $old[ $role ] ?? array();
			$after   = $new[ $role ] ?? array();
			$added   = array_values( array_diff( $after, $before ) );
			$removed = array_values( array_diff( $before, $after ) );
			if ( array() === $added && array() === $removed ) {
				continue;
			}
			if ( array() !== array_intersect( self::DANGEROUS_CAPS, array_merge( $added, $removed ) ) ) {
				$dangerous = true;
			}
			$changes[ (string) $role ] = array(
				'added'   => array_slice( $added, 0, 60 ),
				'removed' => array_slice( $removed, 0, 60 ),
			);
		}
		if ( array() === $changes ) {
			return;
		}

		$this->log(
			'roles_changed',
			__( 'Se han cambiado las capacidades de los roles.', 'total-security-expert' ),
			array( 'roles' => $changes ),
			$dangerous ? 'warning' : 'info'
		);
	}

	/**
	 * Capacidades concedidas por rol, a partir del valor de la opcion de roles.
	 *
	 * @param mixed $roles Valor de la opcion.
	 * @return array<string,array<int,string>>
	 */
	private function role_caps( $roles ): array {
		$out = array();
		if ( ! is_array( $roles ) ) {
			return $out;
		}
		foreach ( $roles as $role => $definition ) {
			$caps = array();
			if ( is_array( $definition ) && is_array( $definition['capabilities'] ?? null ) ) {
				foreach ( $definition['capabilities'] as $cap => $granted ) {
					if ( $granted ) {
						$caps[] = $this->clean( $cap, 64 );
					}
				}
			}
			$out[ $this->clean( $role, 64 ) ] = $caps;
		}
		return $out;
	}

	/**
	 * Registra los plugins que entran o salen de active_plugins (rutas).
	 *
	 * @param mixed $old_value Lista anterior.
	 * @param mixed $value     Lista nueva.
	 * @return void
	 */
	private function log_active_plugins_change( $old_value, $value ): void {
		$old       = is_array( $old_value ) ? $this->to_list( array_values( $old_value ) ) : array();
		$new       = is_array( $value ) ? $this->to_list( array_values( $value ) ) : array();
		$activated = array_values( array_diff( $new, $old ) );
		$disabled  = array_values( array_diff( $old, $new ) );
		if ( array() === $activated && array() === $disabled ) {
			return;
		}
		$this->log(
			'active_plugins_changed',
			__( 'Ha cambiado la lista de plugins activos.', 'total-security-expert' ),
			array(
				'activated'   => $activated,
				'deactivated' => $disabled,
			)
		);
	}

	/**
	 * Registra un cambio de rol de un usuario (anadir o quitar).
	 *
	 * @param string $event   Id del evento.
	 * @param mixed  $user_id ID.
	 * @param mixed  $role    Rol.
	 * @return void
	 */
	private function log_role_event( string $event, $user_id, $role ): void {
		$id   = absint( $user_id );
		$name = $this->clean( $role, 60 );
		if ( 'user_role_added' === $event ) {
			/* translators: 1: rol, 2: ID del usuario. */
			$message = sprintf( __( 'Rol %1$s añadido al usuario %2$d.', 'total-security-expert' ), $name, $id );
		} else {
			/* translators: 1: rol, 2: ID del usuario. */
			$message = sprintf( __( 'Rol %1$s quitado al usuario %2$d.', 'total-security-expert' ), $name, $id );
		}
		$this->log(
			$event,
			$message,
			array(
				'user_id' => $id,
				'role'    => $name,
			),
			'administrator' === $name ? 'warning' : 'info'
		);
	}

	/**
	 * Datos de una contrasena de aplicacion: usuario, uuid y nombre.
	 *
	 * @param mixed $user_id ID.
	 * @param mixed $item    Datos de la contrasena.
	 * @return array<string,mixed>
	 */
	private function app_password_data( $user_id, $item ): array {
		$item = is_array( $item ) ? $item : array();
		return array(
			'user_id' => absint( $user_id ),
			'uuid'    => $this->clean( $item['uuid'] ?? '', 40 ),
			'name'    => $this->clean( $item['name'] ?? '', 100 ),
		);
	}

	/**
	 * Si el error es del bloqueo de este plugin (ya lo apunta el modulo de bloqueo).
	 *
	 * @param mixed $error Objeto WP_Error.
	 * @return bool
	 */
	private function is_locked_error( $error ): bool {
		if ( is_object( $error ) && method_exists( $error, 'get_error_codes' ) ) {
			return in_array( 'tsexp_locked', (array) $error->get_error_codes(), true );
		}
		return is_object( $error ) && method_exists( $error, 'get_error_code' ) && 'tsexp_locked' === $error->get_error_code();
	}

	/**
	 * Registra un fallo de autenticacion con dos limites: por IP (las IPv6 se agrupan por su /64)
	 * y global. En cada ventana de 10 minutos van uno a uno los 10 primeros fallos de cada
	 * grupo de IP y, entre todos, los 200 primeros del sitio; el resto solo se cuenta y se
	 * resume en un evento cuando llega el primer fallo despues de cerrarse la ventana (si ese
	 * fallo no llega en una hora, el contador caduca y el resumen se pierde: no hay cron).
	 *
	 * @param string              $event   Id del evento.
	 * @param string              $message Mensaje.
	 * @param array<string,mixed> $data    Datos.
	 * @return void
	 */
	private function log_failure( string $event, string $message, array $data ): void {
		$bucket = null !== $this->context ? $this->context->get_client_ip_bucket() : '';

		$per_ip = $this->take_slot( 'tsexp_activity_log_fail_' . md5( $bucket ), self::FAIL_LIMIT, false );
		if ( $per_ip && $this->take_slot( 'tsexp_activity_log_fail_global', self::FAIL_GLOBAL_LIMIT, true ) ) {
			$this->log( $event, $message, $data, 'warning' );
		}
	}

	/**
	 * Cuenta un fallo en su ventana y dice si toca registrarlo uno a uno. Al abrirse una ventana
	 * nueva, resume los fallos no registrados de la anterior.
	 *
	 * @param string $key    Nombre del transient.
	 * @param int    $limit  Fallos individuales por ventana.
	 * @param bool   $site_wide Si es el contador de todo el sitio.
	 * @return bool
	 */
	private function take_slot( string $key, int $limit, bool $site_wide ): bool {
		$now   = time();
		$fresh = array(
			'start' => $now,
			'count' => 0,
			'extra' => 0,
		);
		$state = get_transient( $key );
		if ( ! is_array( $state ) || ! isset( $state['start'], $state['count'], $state['extra'] ) ) {
			$state = $fresh;
		}

		if ( $now - (int) $state['start'] >= self::FAIL_WINDOW ) {
			if ( (int) $state['extra'] > 0 ) {
				$this->log_summary( (int) $state['extra'], $site_wide );
			}
			$state = $fresh;
		}

		++$state['count'];
		$allowed = $state['count'] <= $limit;
		if ( ! $allowed ) {
			++$state['extra'];
		}
		set_transient( $key, $state, self::FAIL_TTL );
		return $allowed;
	}

	/**
	 * Evento resumen de fallos no registrados uno a uno.
	 *
	 * @param int  $extra  Numero de fallos.
	 * @param bool $site_wide Si es el resumen de todo el sitio.
	 * @return void
	 */
	private function log_summary( int $extra, bool $site_wide ): void {
		if ( $site_wide ) {
			/* translators: %d: numero de intentos fallidos que no se registraron uno a uno. */
			$message = sprintf( __( '%d intentos fallidos más en todo el sitio.', 'total-security-expert' ), $extra );
		} else {
			/* translators: %d: numero de intentos fallidos que no se registraron uno a uno. */
			$message = sprintf( __( '%d intentos fallidos más desde esta IP.', 'total-security-expert' ), $extra );
		}
		$this->log(
			$site_wide ? 'failed_attempts_summary_global' : 'failed_attempts_summary',
			$message,
			array( 'attempts' => $extra ),
			'warning'
		);
	}

	/**
	 * Ids de los modulos activados en un valor de tsexp_settings.
	 *
	 * @param mixed $settings Valor de la opcion.
	 * @return array<int,string>
	 */
	private function enabled_modules( $settings ): array {
		$out = array();
		if ( ! is_array( $settings ) || ! is_array( $settings['modules'] ?? null ) ) {
			return $out;
		}
		foreach ( $settings['modules'] as $id => $module ) {
			if ( is_array( $module ) && ! empty( $module['enabled'] ) ) {
				$out[] = $this->clean( $id, 64 );
			}
		}
		return $out;
	}

	/**
	 * Registra un evento de plugin.
	 *
	 * @param string $event        Id del evento.
	 * @param string $message      Mensaje ya traducido con %s para el plugin.
	 * @param mixed  $plugin       Ruta del plugin.
	 * @param mixed  $network_wide Si es en red.
	 * @param string $severity     Gravedad.
	 * @return void
	 */
	private function log_plugin( string $event, string $message, $plugin, $network_wide = false, string $severity = 'info' ): void {
		$plugin = $this->clean( $plugin, 150 );
		$this->log(
			$event,
			sprintf( $message, $plugin ),
			array(
				'plugin'       => $plugin,
				'network_wide' => (bool) $network_wide,
			),
			$severity
		);
	}

	/**
	 * Datos comunes de un contenido: ID, tipo y titulo recortado (nunca el cuerpo).
	 *
	 * @param object $post Objeto WP_Post.
	 * @return array<string,mixed>
	 */
	private function post_data( object $post ): array {
		return array(
			'post_id'   => absint( $post->ID ?? 0 ),
			'post_type' => $this->clean( $post->post_type ?? '', 20 ),
			'title'     => $this->clean( $post->post_title ?? '', 80 ),
		);
	}

	/**
	 * Stylesheet de un WP_Theme, o ''.
	 *
	 * @param mixed $theme Objeto WP_Theme.
	 * @return string
	 */
	private function stylesheet_of( $theme ): string {
		if ( is_object( $theme ) && method_exists( $theme, 'get_stylesheet' ) ) {
			return $this->clean( $theme->get_stylesheet(), 100 );
		}
		return '';
	}

	/**
	 * Convierte un valor en lista corta de cadenas limpias.
	 *
	 * @param mixed $value Cadena o lista.
	 * @return array<int,string>
	 */
	private function to_list( $value ): array {
		$items = is_array( $value ) ? $value : array( $value );
		$out   = array();
		foreach ( array_slice( $items, 0, 20 ) as $item ) {
			$text = $this->clean( $item, 100 );
			if ( '' !== $text ) {
				$out[] = $text;
			}
		}
		return $out;
	}

	/**
	 * Cadena escalar saneada y recortada; lo que no sea escalar queda vacio.
	 *
	 * @param mixed $value  Valor.
	 * @param int   $length Longitud maxima.
	 * @return string
	 */
	private function clean( $value, int $length ): string {
		if ( is_bool( $value ) ) {
			$value = $value ? '1' : '0';
		}
		if ( ! is_scalar( $value ) ) {
			return '';
		}
		return mb_substr( sanitize_text_field( (string) $value ), 0, $length );
	}

	/**
	 * Nombre de usuario saneado con sanitize_user() y recortado.
	 *
	 * @param mixed $value  Valor.
	 * @param int   $length Longitud maxima.
	 * @return string
	 */
	private function clean_user( $value, int $length ): string {
		if ( ! is_scalar( $value ) ) {
			return '';
		}
		return mb_substr( sanitize_text_field( sanitize_user( (string) $value ) ), 0, $length );
	}

	/**
	 * Escribe el evento si hay contexto.
	 *
	 * @param string              $event    Id del evento.
	 * @param string              $message  Mensaje.
	 * @param array<string,mixed> $data     Datos.
	 * @param string              $severity Gravedad.
	 * @return void
	 */
	private function log( string $event, string $message, array $data = array(), string $severity = 'info' ): void {
		if ( null !== $this->context ) {
			$this->context->log( $event, $message, $data, $severity );
		}
	}
}

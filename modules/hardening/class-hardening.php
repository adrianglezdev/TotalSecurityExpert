<?php
/**
 * Modulo de endurecimiento.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Modules;

use TotalSecurityExpert\Abstract_Module;
use TotalSecurityExpert\Context;

defined( 'ABSPATH' ) || exit;

/**
 * Cuatro medidas independientes: XML-RPC, editor de ficheros, enumeracion de
 * usuarios y errores de acceso genericos. Todas fallan abiertas: si algo lanza,
 * el Context devuelve el valor original del filtro.
 */
class Hardening extends Abstract_Module {

	/**
	 * Capacidades que se deniegan con disable_file_editor (y solo estas).
	 *
	 * @var array<int,string>
	 */
	private const FILE_EDITOR_CAPS = array( 'edit_files', 'edit_plugins', 'edit_themes' );

	/**
	 * Codigos de error de acceso que revelan si el usuario existe.
	 *
	 * @var array<int,string>
	 */
	private const LEAKY_LOGIN_CODES = array( 'invalid_username', 'invalid_email', 'incorrect_password' );

	/**
	 * Codigos que delatan al usuario en la REST (ademas de los del formulario de acceso).
	 *
	 * @var array<int,string>
	 */
	private const LEAKY_REST_CODES = array( 'invalid_username', 'invalid_email', 'incorrect_password', 'application_passwords_disabled', 'application_passwords_disabled_for_user' );

	/**
	 * Codigos con los que termina la recuperacion de contrasena de un usuario inexistente.
	 *
	 * @var array<int,string>
	 */
	private const LOST_PASSWORD_CODES = array( 'invalid_email', 'invalidcombo', 'retrieve_password_email_failure' );

	/**
	 * Id del modulo.
	 *
	 * @return string
	 */
	public function get_id(): string {
		return 'hardening';
	}

	/**
	 * Nombre.
	 *
	 * @return string
	 */
	public function get_name(): string {
		return __( 'Endurecimiento', 'total-security-expert' );
	}

	/**
	 * Descripcion.
	 *
	 * @return string
	 */
	public function get_description(): string {
		return __( 'Cierra puertas habituales de ataque: XML-RPC, editor de ficheros, enumeracion de usuarios y mensajes de acceso que delatan si un usuario existe.', 'total-security-expert' );
	}

	/**
	 * Todas las medidas activas por defecto.
	 *
	 * @return array<string,bool>
	 */
	public function get_default_settings(): array {
		return array(
			'disable_xmlrpc'         => true,
			'disable_file_editor'    => true,
			'block_user_enumeration' => true,
			'generic_login_errors'   => true,
		);
	}

	/**
	 * Casillas: ausente es false (un checkbox desmarcado no llega en el POST).
	 * Idempotente: acepta tanto el POST como su propio resultado.
	 *
	 * @param array<string,mixed> $input Datos sin confiar.
	 * @return array<string,bool>
	 */
	public function sanitize_settings( array $input ): array {
		$clean = array();
		foreach ( array_keys( $this->get_default_settings() ) as $key ) {
			$value         = $input[ $key ] ?? false;
			$clean[ $key ] = is_scalar( $value ) && filter_var( $value, FILTER_VALIDATE_BOOLEAN );
		}
		return $clean;
	}

	/**
	 * Pinta una casilla por medida.
	 *
	 * @param array<string,mixed> $settings    Ajustes actuales.
	 * @param string              $name_prefix Prefijo del name de los campos.
	 * @return void
	 */
	public function render_settings( array $settings, string $name_prefix ): void {
		$settings = array_merge( $this->get_default_settings(), $settings );

		foreach ( $this->get_fields() as $key => $field ) {
			$id = 'tsexp-hardening-' . $key;
			echo '<p>';
			printf(
				'<input type="checkbox" id="%1$s" name="%2$s" value="1"%3$s /> <label for="%1$s"><strong>%4$s</strong></label>',
				esc_attr( $id ),
				esc_attr( $name_prefix . '[' . $key . ']' ),
				empty( $settings[ $key ] ) ? '' : ' checked="checked"',
				esc_html( $field['label'] )
			);
			echo '<br /><span class="description">' . esc_html( $field['description'] ) . '</span>';
			echo '</p>';
		}
	}

	/**
	 * Registra los hooks de las medidas activas.
	 *
	 * @param Context             $context  Contexto.
	 * @param array<string,mixed> $settings Ajustes (el nucleo ya mezcla los valores por defecto).
	 * @return void
	 */
	public function boot( Context $context, array $settings ): void {
		$settings = array_merge( $this->get_default_settings(), $settings );

		if ( ! empty( $settings['disable_xmlrpc'] ) ) {
			$context->add_filter( 'xmlrpc_enabled', static fn() => false );
			$context->add_filter( 'xmlrpc_methods', static fn() => array() );
			$context->add_filter( 'pings_open', static fn() => false );
			$context->add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
			$context->add_action( 'wp', array( $this, 'drop_pingback_header' ) );
			$context->add_action( 'init', array( $this, 'on_init_xmlrpc' ) );
		}

		if ( ! empty( $settings['disable_file_editor'] ) ) {
			// Ultima prioridad para que otro plugin no devuelva la capacidad despues.
			$context->add_filter( 'map_meta_cap', array( $this, 'deny_file_editor_caps' ), PHP_INT_MAX, 2 );
		}

		if ( ! empty( $settings['block_user_enumeration'] ) ) {
			$context->add_filter( 'request', array( $this, 'block_author_request' ) );
			$context->add_filter( 'redirect_canonical', array( $this, 'stop_author_redirect' ) );
			$context->add_filter( 'rest_pre_dispatch', array( $this, 'block_rest_users' ), 10, 3 );
			$context->add_filter( 'rest_request_before_callbacks', array( $this, 'block_users_controller' ), 10, 3 );
			$context->add_filter( 'wp_sitemaps_add_provider', array( $this, 'remove_users_sitemap' ), 10, 2 );
			$context->add_filter( 'oembed_response_data', array( $this, 'strip_oembed_author' ) );
		}

		if ( ! empty( $settings['generic_login_errors'] ) ) {
			// wp_login_errors recibe el WP_Error con codigos; login_errors ya recibe HTML y no permite distinguir un codigo de otro.
			$context->add_filter( 'wp_login_errors', array( $this, 'genericize_login_errors' ) );
			// Las contrasenas de aplicacion (REST) filtran lo mismo; el nucleo las comprueba en prioridad 90.
			$context->add_filter( 'rest_authentication_errors', array( $this, 'genericize_rest_auth_errors' ), 99 );
			// lost_password solo se ejecuta en wp-login.php, ya con todos los errores (captcha, limite de intentos...) puestos por otros plugins.
			$context->add_action( 'lost_password', array( $this, 'hide_unknown_lostpassword_user' ), 99 );
		}
	}

	/**
	 * Quita la cabecera X-Pingback (sin distinguir mayusculas).
	 *
	 * @param mixed $headers Cabeceras.
	 * @return mixed
	 */
	public function remove_pingback_header( $headers ) {
		if ( ! is_array( $headers ) ) {
			return $headers;
		}
		foreach ( array_keys( $headers ) as $name ) {
			if ( 0 === strcasecmp( (string) $name, 'X-Pingback' ) ) {
				unset( $headers[ $name ] );
			}
		}
		return $headers;
	}

	/**
	 * Quita la cabecera X-Pingback ya enviada por WP::send_headers().
	 *
	 * @return void
	 */
	public function drop_pingback_header(): void {
		$this->remove_header( 'X-Pingback' );
	}

	/**
	 * En init: quita el enlace RSD, vacia los pingbacks salientes y corta xmlrpc.php?rsd.
	 *
	 * @return void
	 */
	public function on_init_xmlrpc(): void {
		remove_action( 'wp_head', 'rsd_link', 10 );
		// pre_ping pasa sus listas por referencia; el Context no puede reenviarlas, asi que este callback sencillo se registra directo.
		add_action(
			'pre_ping',
			function ( &$links ) {
				$this->empty_ping_links( $links );
			}
		);

		if ( $this->is_rsd_request() ) {
			status_header( 404 );
			$this->terminate();
		}
	}

	/**
	 * Vacia la lista de enlaces a los que WordPress enviaria pingbacks.
	 *
	 * @param mixed $links Enlaces (por referencia).
	 * @return void
	 */
	public function empty_ping_links( &$links ): void {
		$links = array();
	}

	/**
	 * Deniega solo las capacidades del editor de ficheros.
	 *
	 * @param mixed $caps Capacidades primitivas.
	 * @param mixed $cap  Capacidad que se comprueba.
	 * @return mixed
	 */
	public function deny_file_editor_caps( $caps, $cap = '' ) {
		if ( is_string( $cap ) && in_array( $cap, self::FILE_EDITOR_CAPS, true ) ) {
			return array( 'do_not_allow' );
		}
		// Otra capacidad que se resuelva a una del editor tambien se niega.
		if ( is_array( $caps ) && array() !== array_intersect( $caps, self::FILE_EDITOR_CAPS ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * Con la query ya resuelta (GET, POST y reglas de reescritura), un visitante
	 * con "author" recibe 404. Sin author ni feed, WordPress no llega al archivo del autor.
	 *
	 * @param mixed $query_vars Variables de la query.
	 * @return mixed
	 */
	public function block_author_request( $query_vars ) {
		if ( ! is_array( $query_vars ) || empty( $query_vars['author'] ) || ! $this->is_guest_on_front() || $this->has_plain_permalinks() ) {
			return $query_vars;
		}
		unset( $query_vars['author'], $query_vars['feed'] );
		$query_vars['error'] = '404';
		return $query_vars;
	}

	/**
	 * Segunda barrera: impide que redirect_canonical lleve ?author=N a /author/<slug>/.
	 *
	 * @param mixed $redirect_url URL de destino.
	 * @return mixed
	 */
	public function stop_author_redirect( $redirect_url ) {
		// En /author/<slug>/ (author_name) la redireccion canonica sigue activa.
		if ( $this->is_guest_on_front() && ! $this->has_plain_permalinks() && ! empty( get_query_var( 'author' ) ) && empty( get_query_var( 'author_name' ) ) ) {
			return false;
		}
		return $redirect_url;
	}

	/**
	 * Devuelve 401 en /wp/v2/users (y debajo) a quien no tiene sesion.
	 *
	 * @param mixed $result  Resultado previo (null si nadie ha cortocircuitado).
	 * @param mixed $server  Servidor REST.
	 * @param mixed $request Peticion REST.
	 * @return mixed
	 */
	public function block_rest_users( $result, $server = null, $request = null ) {
		if ( null !== $result || ! is_object( $request ) || ! is_callable( array( $request, 'get_route' ) ) || is_user_logged_in() ) {
			return $result;
		}

		// WordPress compara las rutas sin distinguir mayusculas: se normaliza igual.
		// Tambien con saltos de linea o caracteres de control al final (el "$" de su regex los admite).
		$route = '/' . trim( strtolower( rawurldecode( (string) $request->get_route() ) ), "\x00..\x20/" );
		if ( '/wp/v2/users' !== $route && ! str_starts_with( $route, '/wp/v2/users/' ) ) {
			return $result;
		}

		return $this->unauthorized_error();
	}

	/**
	 * Decide por el controlador, no por el texto de la ruta: cualquier ruta que
	 * WordPress resuelva al controlador de usuarios se niega a quien no tiene sesion.
	 *
	 * @param mixed $response Respuesta previa.
	 * @param mixed $handler  Manejador de la ruta.
	 * @return mixed
	 */
	public function block_users_controller( $response, $handler = null ) {
		if ( is_user_logged_in() || ! is_array( $handler ) || ! isset( $handler['callback'] ) ) {
			return $response;
		}
		$callback = $handler['callback'];
		if ( is_array( $callback ) && isset( $callback[0] ) && $callback[0] instanceof \WP_REST_Users_Controller ) {
			return $this->unauthorized_error();
		}
		return $response;
	}

	/**
	 * Quita el proveedor de sitemap de usuarios.
	 *
	 * @param mixed $provider Proveedor.
	 * @param mixed $name     Nombre del proveedor.
	 * @return mixed
	 */
	public function remove_users_sitemap( $provider, $name = '' ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Quita autor de la respuesta oEmbed.
	 *
	 * @param mixed $data Datos de la respuesta.
	 * @return mixed
	 */
	public function strip_oembed_author( $data ) {
		if ( is_array( $data ) ) {
			unset( $data['author_name'], $data['author_url'] );
		}
		return $data;
	}

	/**
	 * Sustituye los errores que delatan al usuario por un solo mensaje generico.
	 * El resto de errores (tsexp_locked, empty_password...) se dejan como estan.
	 *
	 * @param mixed $errors WP_Error del formulario de acceso.
	 * @return mixed
	 */
	public function genericize_login_errors( $errors ) {
		if ( ! $errors instanceof \WP_Error ) {
			return $errors;
		}
		$this->replace_leaky_codes( $errors, array(), self::LEAKY_LOGIN_CODES );
		return $errors;
	}

	/**
	 * Igual que el formulario de acceso, para las contrasenas de aplicacion de la REST.
	 * Si solo habia errores que delatan al usuario, queda un unico 401 generico.
	 *
	 * @param mixed $result Resultado de la autenticacion REST.
	 * @return mixed
	 */
	public function genericize_rest_auth_errors( $result ) {
		if ( ! $result instanceof \WP_Error ) {
			return $result;
		}
		$this->replace_leaky_codes( $result, array( 'status' => 401 ), self::LEAKY_REST_CODES );
		return $result;
	}

	/**
	 * Recuperar contrasena (accion lost_password de wp-login.php, que recibe el WP_Error
	 * con lo que dejo retrieve_password()): si todos los errores son de usuario inexistente,
	 * responde igual que si existiera (redireccion a "revisa tu correo"). Con cualquier otro
	 * codigo (captcha, limite de intentos...) no hace nada.
	 *
	 * @param mixed $errors WP_Error del formulario.
	 * @return void
	 */
	public function hide_unknown_lostpassword_user( $errors = null ): void {
		if ( ! $errors instanceof \WP_Error ) {
			return;
		}
		$codes = $errors->get_error_codes();
		if ( array() === $codes || array() !== array_diff( $codes, self::LOST_PASSWORD_CODES ) ) {
			return;
		}
		$this->redirect_and_exit( add_query_arg( 'checkemail', 'confirm', wp_login_url() ) );
	}

	/**
	 * Quita de un WP_Error los codigos que delatan al usuario y pone uno generico.
	 *
	 * @param \WP_Error           $errors Errores (se modifica).
	 * @param array<string,mixed> $data   Datos del error generico.
	 * @param array<int,string>   $codes  Codigos a sustituir.
	 * @return void
	 */
	private function replace_leaky_codes( \WP_Error $errors, array $data, array $codes ): void {
		$found = false;
		foreach ( $codes as $code ) {
			if ( in_array( $code, $errors->get_error_codes(), true ) ) {
				$errors->remove( $code );
				$found = true;
			}
		}
		if ( $found ) {
			$errors->add(
				'tsexp_invalid_login',
				__( '<strong>Error:</strong> los datos de acceso no son correctos.', 'total-security-expert' ),
				array() === $data ? '' : $data
			);
		}
	}

	/**
	 * Error 401 de la REST.
	 *
	 * @return \WP_Error
	 */
	private function unauthorized_error(): \WP_Error {
		return new \WP_Error(
			'rest_not_logged_in',
			__( 'Tienes que iniciar sesion para ver esta informacion.', 'total-security-expert' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * Quita una cabecera HTTP. Separado para poder sustituirlo en los tests.
	 *
	 * @param string $name Cabecera.
	 * @return void
	 */
	protected function remove_header( string $name ): void {
		if ( ! headers_sent() ) {
			header_remove( $name );
		}
	}

	/**
	 * Redirige y termina. Separado para poder sustituirlo en los tests.
	 *
	 * @param string $url Destino.
	 * @return void
	 */
	protected function redirect_and_exit( string $url ): void {
		wp_safe_redirect( $url );
		$this->terminate();
	}

	/**
	 * Termina la peticion. Los tests lo sustituyen.
	 *
	 * @return void
	 */
	protected function terminate(): void {
		exit;
	}

	/**
	 * Si es xmlrpc.php?rsd (xmlrpc.php define XMLRPC_REQUEST antes de cargar WordPress).
	 *
	 * @return bool
	 */
	protected function is_rsd_request(): bool {
		return defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && isset( $_GET['rsd'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Solo comprueba si existe el parametro.
	}

	/**
	 * Visitante sin sesion fuera del escritorio.
	 *
	 * @return bool
	 */
	private function is_guest_on_front(): bool {
		return ! is_admin() && ! is_user_logged_in();
	}

	/**
	 * Enlaces permanentes simples (?p=123): ahi los enlaces de autor del tema usan ?author=.
	 *
	 * @return bool
	 */
	private function has_plain_permalinks(): bool {
		return '' === (string) get_option( 'permalink_structure', '' );
	}

	/**
	 * Etiquetas y descripciones de las casillas.
	 *
	 * @return array<string,array{label:string,description:string}>
	 */
	private function get_fields(): array {
		return array(
			'disable_xmlrpc'         => array(
				'label'       => __( 'Desactivar XML-RPC', 'total-security-expert' ),
				'description' => __( 'Apaga XML-RPC y los pingbacks, y quita la cabecera X-Pingback, el enlace RSD y xmlrpc.php?rsd. Aviso: rompe las aplicaciones que usan XML-RPC, como Jetpack o algunas aplicaciones moviles antiguas.', 'total-security-expert' ),
			),
			'disable_file_editor'    => array(
				'label'       => __( 'Desactivar el editor de ficheros', 'total-security-expert' ),
				'description' => __( 'Impide editar el codigo de plugins y temas desde el escritorio. No afecta a instalar, actualizar ni activar.', 'total-security-expert' ),
			),
			'block_user_enumeration' => array(
				'label'       => __( 'Bloquear la enumeracion de usuarios', 'total-security-expert' ),
				'description' => __( 'Para visitantes sin sesion: bloquea ?author=N, la lista de usuarios de la API REST, el mapa del sitio de usuarios y el autor en oEmbed. Aviso: los sitios headless o que leen /wp/v2/users o _embed=author sin iniciar sesion dejaran de mostrar los autores. Con enlaces permanentes simples (?p=123) no se bloquea ?author=, porque los enlaces de autor del tema dejarian de funcionar.', 'total-security-expert' ),
			),
			'generic_login_errors'   => array(
				'label'       => __( 'Errores de acceso genericos', 'total-security-expert' ),
				'description' => __( 'Muestra el mismo mensaje tanto si el usuario no existe como si la contrasena es incorrecta (acceso, REST con contrasenas de aplicacion y recuperar contrasena).', 'total-security-expert' ),
			),
		);
	}
}

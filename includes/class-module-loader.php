<?php
/**
 * Registro fijo, carga y aislamiento de modulos.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

defined( 'ABSPATH' ) || exit;

/**
 * Carga los modulos del registro fijo y arranca solo los activos.
 * Nada de lo que haga un modulo puede salir de aqui como excepcion.
 */
class Module_Loader {

	public const ERRORS_OPTION = 'tsexp_module_errors';
	public const LOCK_PREFIX   = 'tsexp_err_lock_';
	public const LOCK_SECONDS  = 600;
	public const MESSAGE_MAX   = 120;

	/**
	 * Registro fijo: id => clase y fichero (relativo a la carpeta del plugin).
	 *
	 * @var array<string,array{class:string,file:string}>
	 */
	public const REGISTRY = array(
		'login-limit'  => array(
			'class' => 'TotalSecurityExpert\Modules\Login_Limit',
			'file'  => 'modules/login-limit/class-login-limit.php',
		),
		'hardening'    => array(
			'class' => 'TotalSecurityExpert\Modules\Hardening',
			'file'  => 'modules/hardening/class-hardening.php',
		),
		'admin-alert'  => array(
			'class' => 'TotalSecurityExpert\Modules\Admin_Alert',
			'file'  => 'modules/admin-alert/class-admin-alert.php',
		),
		'activity-log' => array(
			'class' => 'TotalSecurityExpert\Modules\Activity_Log',
			'file'  => 'modules/activity-log/class-activity-log.php',
		),
	);

	/**
	 * Carpeta base (con barra final) contra la que se resuelven los ficheros.
	 *
	 * @var string
	 */
	private string $base_path;

	/**
	 * Registro en uso (el fijo, salvo en tests).
	 *
	 * @var array<string,array{class:string,file:string}>
	 */
	private array $registry;

	/**
	 * Modulos instanciados, por id.
	 *
	 * @var array<string,Module>
	 */
	private array $modules = array();

	/**
	 * Si ya se cargaron los ficheros.
	 *
	 * @var bool
	 */
	private bool $loaded = false;

	/**
	 * Constructor sin efectos.
	 *
	 * @param string                                             $base_path Carpeta base; por defecto la del plugin.
	 * @param array<string,array{class:string,file:string}>|null $registry  Registro alternativo (tests).
	 */
	public function __construct( string $base_path = '', ?array $registry = null ) {
		$this->base_path = '' !== $base_path ? rtrim( $base_path, '/\\' ) . '/' : dirname( __DIR__ ) . '/';
		$this->registry  = $registry ?? self::REGISTRY;
	}

	/**
	 * Carga los ficheros de los modulos e instancia los validos. Idempotente.
	 * Un fichero ausente se ignora; cualquier otro fallo se apunta y se sigue.
	 * En modo seguro no se hace require de ningun fichero de modulo.
	 *
	 * @return void
	 */
	public function load(): void {
		if ( $this->loaded ) {
			return;
		}
		$this->loaded = true;

		if ( $this->is_safe_mode() ) {
			return;
		}

		foreach ( $this->registry as $id => $entry ) {
			$file = $this->base_path . $entry['file'];
			if ( ! is_readable( $file ) ) {
				continue;
			}
			try {
				require_once $file;
				$module = $this->instantiate( $id, $entry['class'] );
			} catch ( \Throwable $e ) {
				$this->record_error( $id, self::format_error( $e, 'load' ) );
				continue;
			}
			if ( null !== $module ) {
				$this->modules[ $id ] = $module;
			}
		}
	}

	/**
	 * Modulos cargados, por id.
	 *
	 * @return array<string,Module>
	 */
	public function get_modules(): array {
		$this->load();
		return $this->modules;
	}

	/**
	 * Ids del registro (esten o no cargados). No ejecuta codigo de ningun modulo.
	 *
	 * @return array<int,string>
	 */
	public function get_registry_ids(): array {
		return array_map( 'strval', array_keys( $this->registry ) );
	}

	/**
	 * Un modulo cargado.
	 *
	 * @param string $id Id del modulo.
	 * @return Module|null
	 */
	public function get_module( string $id ): ?Module {
		return $this->get_modules()[ $id ] ?? null;
	}

	/**
	 * Si TSEXP_SAFE_MODE esta definida y es true (salida para un administrador bloqueado).
	 *
	 * @return bool
	 */
	public function is_safe_mode(): bool {
		return defined( 'TSEXP_SAFE_MODE' ) && self::is_truthy( TSEXP_SAFE_MODE );
	}

	/**
	 * Si el valor de TSEXP_SAFE_MODE activa el modo seguro: true, 1, '1', 'true' (y equivalentes de FILTER_VALIDATE_BOOLEAN).
	 *
	 * @param mixed $value Valor de la constante.
	 * @return bool
	 */
	public static function is_truthy( $value ): bool {
		return is_scalar( $value ) && filter_var( $value, FILTER_VALIDATE_BOOLEAN );
	}

	/**
	 * Texto corto para guardar un fallo: clase de la excepcion, hook y mensaje recortado.
	 * No incluye ficheros, lineas ni traza.
	 *
	 * @param \Throwable $e    Fallo.
	 * @param string     $hook Hook o fase donde ocurrio.
	 * @return string
	 */
	public static function format_error( \Throwable $e, string $hook = '' ): string {
		$message = mb_substr( preg_replace( '/\s+/', ' ', $e->getMessage() ) ?? '', 0, self::MESSAGE_MAX );
		return get_class( $e ) . ( '' !== $hook ? ' @ ' . $hook : '' ) . ': ' . $message;
	}

	/**
	 * Arranca los modulos activos, cada uno aislado. No hace nada en modo seguro.
	 *
	 * @param Settings  $settings  Ajustes.
	 * @param Event_Log $event_log Registro de eventos.
	 * @param Request   $request   Resolutor de IP.
	 * @return void
	 */
	public function boot_modules( Settings $settings, Event_Log $event_log, Request $request ): void {
		if ( $this->is_safe_mode() ) {
			return;
		}
		foreach ( $this->get_modules() as $id => $module ) {
			try {
				if ( ! $settings->is_module_enabled( $id ) ) {
					continue;
				}
				$context = new Context( $id, $event_log, $request, $this->record_error( ... ) );
				$module->boot( $context, $settings->get_module_settings( $id ) );
			} catch ( \Throwable $e ) {
				$this->record_error( $id, self::format_error( $e, 'boot' ) );
			}
		}
	}

	/**
	 * Apunta un error de un modulo en la opcion tsexp_module_errors (nunca lanza).
	 * No escribe en la BD si el mensaje es el mismo que ya estaba guardado, ni mas de una vez
	 * cada 10 minutos por modulo (transient tsexp_err_lock_<id>), aunque el mensaje cambie.
	 *
	 * @param string $id      Id del modulo.
	 * @param string $message Mensaje.
	 * @return void
	 */
	public function record_error( string $id, string $message ): void {
		try {
			$id      = sanitize_key( $id );
			$message = mb_substr( sanitize_text_field( $message ), 0, 255 );
			$errors  = $this->get_errors();
			if ( isset( $errors[ $id ] ) && $errors[ $id ]['message'] === $message ) {
				return;
			}
			if ( false !== get_transient( self::LOCK_PREFIX . $id ) ) {
				return;
			}
			$errors[ $id ] = array(
				'message' => $message,
				'time'    => time(),
			);
			update_option( self::ERRORS_OPTION, $errors, false );
			set_transient( self::LOCK_PREFIX . $id, 1, self::LOCK_SECONDS );
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Errores guardados: id => array( message, time ).
	 *
	 * @return array<string,array{message:string,time:int}>
	 */
	public function get_errors(): array {
		$stored = get_option( self::ERRORS_OPTION, array() );
		if ( ! is_array( $stored ) ) {
			return array();
		}
		$out = array();
		foreach ( $stored as $id => $item ) {
			if ( is_array( $item ) && isset( $item['message'] ) && is_string( $item['message'] ) ) {
				$out[ (string) $id ] = array(
					'message' => $item['message'],
					'time'    => isset( $item['time'] ) ? (int) $item['time'] : 0,
				);
			}
		}
		return $out;
	}

	/**
	 * Borra los errores guardados (p. ej. al guardar los ajustes).
	 *
	 * @return void
	 */
	public function clear_errors(): void {
		delete_option( self::ERRORS_OPTION );
		foreach ( $this->get_registry_ids() as $id ) {
			delete_transient( self::LOCK_PREFIX . sanitize_key( $id ) );
		}
	}

	/**
	 * Crea el modulo si la clase existe e implementa Module con el id esperado.
	 *
	 * @param string $id    Id del registro.
	 * @param string $class_name Clase completa.
	 * @return Module|null
	 */
	private function instantiate( string $id, string $class_name ): ?Module {
		if ( ! class_exists( $class_name, false ) ) {
			$this->record_error( $id, 'La clase del módulo no existe.' );
			return null;
		}
		if ( ! is_subclass_of( $class_name, Module::class ) ) {
			$this->record_error( $id, 'La clase del módulo no implementa Module.' );
			return null;
		}
		$module = new $class_name();
		if ( $module->get_id() !== $id ) {
			$this->record_error( $id, 'El id del módulo no coincide con el del registro.' );
			return null;
		}
		return $module;
	}
}

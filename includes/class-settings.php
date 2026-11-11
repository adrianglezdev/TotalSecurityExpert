<?php
/**
 * Ajustes del plugin (opcion tsexp_settings).
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

defined( 'ABSPATH' ) || exit;

/**
 * Lectura con valores por defecto y saneado de la opcion unica de ajustes.
 */
class Settings {

	public const OPTION = 'tsexp_settings';
	public const GROUP  = 'tsexp_settings';

	public const IP_SOURCES = array( 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip' );

	public const LOG_MAX_ROWS_DEFAULT = 50000;
	public const LOG_MAX_ROWS_MIN     = 1000;
	public const LOG_MAX_ROWS_MAX     = 1000000;

	/**
	 * Cargador de modulos (de ahi salen los modulos conocidos y sus valores por defecto).
	 *
	 * @var Module_Loader
	 */
	private Module_Loader $loader;

	/**
	 * Constructor.
	 *
	 * @param Module_Loader $loader Cargador de modulos.
	 */
	public function __construct( Module_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Ajustes generales por defecto.
	 *
	 * @return array{ip_source:string,trusted_proxies:array<int,string>,log_retention_days:int,log_max_rows:int}
	 */
	public static function default_general(): array {
		return array(
			'ip_source'          => 'remote_addr',
			'trusted_proxies'    => array(),
			'log_retention_days' => 30,
			'log_max_rows'       => self::LOG_MAX_ROWS_DEFAULT,
		);
	}

	/**
	 * Registra la opcion en la Settings API (llamar en admin_init).
	 *
	 * @return void
	 */
	public function register(): void {
		register_setting(
			self::GROUP,
			self::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize' ),
				'show_in_rest'      => false,
			)
		);
	}

	/**
	 * Ajustes completos: general validado y todos los modulos registrados con sus valores por defecto.
	 *
	 * @return array{general:array<string,mixed>,modules:array<string,array{enabled:bool,settings:array<string,mixed>}>}
	 */
	public function get_all(): array {
		$out = array(
			'general' => $this->get_general(),
			'modules' => array(),
		);
		foreach ( array_keys( $this->loader->get_modules() ) as $id ) {
			$out['modules'][ $id ] = array(
				'enabled'  => $this->is_module_enabled( $id ),
				'settings' => $this->get_module_settings( $id ),
			);
		}
		return $out;
	}

	/**
	 * Ajustes generales, validados y con los valores por defecto mezclados.
	 *
	 * @return array{ip_source:string,trusted_proxies:array<int,string>,log_retention_days:int,log_max_rows:int}
	 */
	public function get_general(): array {
		$stored = $this->get_stored();
		return $this->sanitize_general( is_array( $stored['general'] ?? null ) ? $stored['general'] : array() );
	}

	/**
	 * Ajustes de un modulo con los valores por defecto mezclados.
	 *
	 * @param string $id Id del modulo.
	 * @return array<string,mixed> Vacio si el modulo no esta registrado.
	 */
	public function get_module_settings( string $id ): array {
		$module = $this->loader->get_module( $id );
		if ( null === $module ) {
			return array();
		}
		try {
			$defaults = $module->get_default_settings();
		} catch ( \Throwable $e ) {
			$defaults = array();
		}
		$stored = $this->get_stored();
		$mine   = $stored['modules'][ $id ]['settings'] ?? array();
		return array_merge( $defaults, is_array( $mine ) ? $mine : array() );
	}

	/**
	 * Si el modulo esta activado (por defecto no).
	 *
	 * @param string $id Id del modulo.
	 * @return bool
	 */
	public function is_module_enabled( string $id ): bool {
		$stored = $this->get_stored();
		return filter_var( $stored['modules'][ $id ]['enabled'] ?? false, FILTER_VALIDATE_BOOLEAN );
	}

	/**
	 * Sanea lo que llega del formulario (sanitize_callback de la opcion).
	 *
	 * Ojo: WordPress puede llamar a este callback dos veces con el mismo valor
	 * la primera vez que se guarda la opcion, asi que sanitize_settings() de
	 * cada modulo debe ser idempotente (aceptar su propia salida).
	 *
	 * @param mixed $input Datos sin confiar.
	 * @return array{general:array<string,mixed>,modules:array<string,array{enabled:bool,settings:array<string,mixed>}>}
	 */
	public function sanitize( $input ): array {
		$input   = is_array( $input ) ? $input : array();
		$general = is_array( $input['general'] ?? null ) ? $input['general'] : array();
		$raw_mod = is_array( $input['modules'] ?? null ) ? $input['modules'] : array();
		$dropped = array();
		$out     = array(
			'general' => $this->sanitize_general( $general, $dropped ),
			'modules' => array(),
		);
		$this->report_dropped_proxies( $dropped );

		$loaded = $this->loader->get_modules();
		foreach ( $this->loader->get_registry_ids() as $id ) {
			$module = $loaded[ $id ] ?? null;
			if ( null === $module ) {
				// Modulo sin cargar (fichero roto o modo seguro): se conserva su bloque guardado tal cual.
				$stored = $this->get_stored();
				if ( is_array( $stored['modules'][ $id ] ?? null ) ) {
					$out['modules'][ $id ] = $stored['modules'][ $id ];
				}
				continue;
			}
			$raw      = is_array( $raw_mod[ $id ] ?? null ) ? $raw_mod[ $id ] : array();
			$raw_set  = is_array( $raw['settings'] ?? null ) ? $raw['settings'] : array();
			$enabled  = filter_var( $raw['enabled'] ?? false, FILTER_VALIDATE_BOOLEAN );
			$settings = null;

			try {
				$settings = $module->sanitize_settings( $raw_set );
			} catch ( \Throwable $e ) {
				$settings = $this->get_module_settings( $id );
				$this->loader->record_error( $id, Module_Loader::format_error( $e, 'sanitize_settings' ) );
				if ( function_exists( 'add_settings_error' ) ) {
					add_settings_error(
						self::GROUP,
						'tsexp_sanitize_' . $id,
						sprintf(
							/* translators: %s: id del modulo. */
							__( 'No se han podido guardar los ajustes del módulo «%s»; se conservan los anteriores.', 'total-security-expert' ),
							$id
						),
						'error'
					);
				}
			}

			$out['modules'][ $id ] = array(
				'enabled'  => (bool) $enabled,
				'settings' => $settings,
			);
		}

		return $out;
	}

	/**
	 * Valida los ajustes generales.
	 *
	 * @param array<string,mixed>    $input   Datos sin confiar.
	 * @param array<int,string>|null $dropped Si se pasa, recibe las entradas de proxies descartadas.
	 * @return array{ip_source:string,trusted_proxies:array<int,string>,log_retention_days:int,log_max_rows:int}
	 */
	public function sanitize_general( array $input, ?array &$dropped = null ): array {
		$defaults = self::default_general();

		$source = $input['ip_source'] ?? '';
		$source = is_string( $source ) && in_array( $source, self::IP_SOURCES, true ) ? $source : $defaults['ip_source'];

		$proxies = array();
		$dropped = is_array( $dropped ) ? $dropped : array();
		foreach ( self::parse_list( $input['trusted_proxies'] ?? array() ) as $entry ) {
			$entry = sanitize_text_field( $entry );
			$clean = Request::normalize_trusted_proxy( $entry );
			if ( '' !== $clean ) {
				$proxies[] = $clean;
			} else {
				$dropped[] = $entry;
			}
		}

		$days = $input['log_retention_days'] ?? null;
		$days = is_numeric( $days ) ? max( 1, min( 365, (int) $days ) ) : $defaults['log_retention_days'];

		$rows = $input['log_max_rows'] ?? null;
		$rows = is_numeric( $rows ) ? max( self::LOG_MAX_ROWS_MIN, min( self::LOG_MAX_ROWS_MAX, (int) $rows ) ) : $defaults['log_max_rows'];

		return array(
			'ip_source'          => $source,
			'trusted_proxies'    => array_values( array_unique( $proxies ) ),
			'log_retention_days' => $days,
			'log_max_rows'       => $rows,
		);
	}

	/**
	 * Avisa en la pantalla de ajustes de las entradas de proxies de confianza que se han descartado.
	 *
	 * @param array<int,string> $dropped Entradas descartadas (ya con sanitize_text_field).
	 * @return void
	 */
	private function report_dropped_proxies( array $dropped ): void {
		if ( array() === $dropped || ! function_exists( 'add_settings_error' ) ) {
			return;
		}
		$shown = array();
		foreach ( array_slice( array_unique( $dropped ), 0, 10 ) as $entry ) {
			$shown[] = esc_html( mb_substr( $entry, 0, 60 ) );
		}
		add_settings_error(
			self::GROUP,
			'tsexp_trusted_proxies_dropped',
			sprintf(
				/* translators: %s: lista de entradas descartadas. */
				__( 'Se han descartado estas entradas de proxies de confianza (no son una IP o un rango CIDR válido, o el rango es demasiado ancho: mínimo /8 en IPv4 y /32 en IPv6): %s', 'total-security-expert' ),
				implode( ', ', $shown )
			),
			'warning'
		);
	}

	/**
	 * Convierte una lista (texto con una entrada por linea, o array) en array de cadenas.
	 *
	 * @param mixed $value Texto o array.
	 * @return array<int,string>
	 */
	public static function parse_list( $value ): array {
		if ( is_string( $value ) ) {
			$value = preg_split( '/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( ! is_array( $value ) ) {
			return array();
		}
		$out = array();
		foreach ( $value as $item ) {
			if ( is_string( $item ) && '' !== trim( $item ) ) {
				$out[] = trim( $item );
			}
		}
		return $out;
	}

	/**
	 * Opcion tal como esta guardada.
	 *
	 * @return array<string,mixed>
	 */
	private function get_stored(): array {
		$stored = get_option( self::OPTION, array() );
		return is_array( $stored ) ? $stored : array();
	}
}

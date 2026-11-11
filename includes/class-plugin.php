<?php
/**
 * Arranque, activacion, crons y desinstalacion.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

use TotalSecurityExpert\Admin\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Punto de entrada del plugin.
 */
final class Plugin {

	public const CRON_HOURLY = 'tsexp_hourly';
	public const CRON_DAILY  = 'tsexp_daily';
	public const DB_VERSION  = 'tsexp_db_version';

	/**
	 * Instancia unica.
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $instance = null;

	/**
	 * Cargador de modulos.
	 *
	 * @var Module_Loader
	 */
	private Module_Loader $loader;

	/**
	 * Ajustes.
	 *
	 * @var Settings
	 */
	private Settings $settings;

	/**
	 * Resolutor de IP.
	 *
	 * @var Request
	 */
	private Request $request;

	/**
	 * Registro de eventos.
	 *
	 * @var Event_Log
	 */
	private Event_Log $event_log;

	/**
	 * Construye los servicios; ninguno tiene efectos al construirse.
	 */
	private function __construct() {
		$this->loader    = new Module_Loader();
		$this->settings  = new Settings( $this->loader );
		$this->request   = new Request( $this->settings );
		$this->event_log = new Event_Log( $this->request );
	}

	/**
	 * Instancia unica.
	 *
	 * @return Plugin
	 */
	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Engancha todo (en plugins_loaded).
	 *
	 * @return void
	 */
	public function run(): void {
		add_action( 'init', array( $this, 'load_textdomain' ) );
		add_action( 'init', array( $this, 'ensure_crons' ) );
		add_action( 'admin_init', array( $this->settings, 'register' ) );
		add_action( 'admin_init', array( $this, 'maybe_upgrade' ) );
		add_action( self::CRON_DAILY, array( $this, 'purge_logs' ) );
		add_action( self::CRON_HOURLY, array( $this, 'trim_logs' ) );
		add_action( 'update_option_' . Settings::OPTION, array( $this->loader, 'clear_errors' ) );

		$this->loader->load();

		if ( is_admin() ) {
			( new Admin( $this->settings, $this->loader, $this->event_log ) )->init();
		}

		$this->loader->boot_modules( $this->settings, $this->event_log, $this->request );
	}

	/**
	 * Carga las traducciones.
	 *
	 * @return void
	 */
	public function load_textdomain(): void {
		load_plugin_textdomain( 'total-security-expert', false, dirname( plugin_basename( TSEXP_FILE ) ) . '/languages' );
	}

	/**
	 * Reprograma los crons si faltan.
	 *
	 * @return void
	 */
	public function ensure_crons(): void {
		if ( ! wp_next_scheduled( self::CRON_HOURLY ) ) {
			wp_schedule_event( time(), 'hourly', self::CRON_HOURLY );
		}
		if ( ! wp_next_scheduled( self::CRON_DAILY ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_DAILY );
		}
	}

	/**
	 * Purga el registro segun la retencion configurada (cron diario).
	 *
	 * @return void
	 */
	public function purge_logs(): void {
		$general = $this->settings->get_general();
		$this->event_log->purge( $general['log_retention_days'] );
	}

	/**
	 * Recorta el registro al maximo de filas configurado, borrando las mas antiguas (cron cada hora).
	 *
	 * @return void
	 */
	public function trim_logs(): void {
		$general = $this->settings->get_general();
		$this->event_log->trim_to_max_rows( $general['log_max_rows'] );
	}

	/**
	 * Si la version de BD guardada no es la actual (p. ej. tras actualizar), vuelve a instalar.
	 *
	 * @return void
	 */
	public function maybe_upgrade(): void {
		if ( get_option( self::DB_VERSION ) !== TSEXP_DB_VERSION ) {
			$this->install_all();
		}
	}

	/**
	 * Crea la tabla del nucleo y las de todos los modulos, guarda la version de BD y programa crons.
	 * El fallo de un modulo se apunta y no impide el resto.
	 *
	 * @return void
	 */
	public function install_all(): void {
		$this->event_log->install();
		foreach ( $this->loader->get_modules() as $id => $module ) {
			try {
				$module->install();
			} catch ( \Throwable $e ) {
				$this->loader->record_error( $id, Module_Loader::format_error( $e, 'install' ) );
			}
		}
		update_option( self::DB_VERSION, TSEXP_DB_VERSION );
		$this->ensure_crons();
	}

	/**
	 * Activacion del plugin.
	 *
	 * @return void
	 */
	public static function activate(): void {
		self::instance()->install_all();
	}

	/**
	 * Desactivacion: quita los crons y no borra datos.
	 *
	 * @return void
	 */
	public static function deactivate(): void {
		wp_clear_scheduled_hook( self::CRON_HOURLY );
		wp_clear_scheduled_hook( self::CRON_DAILY );
	}

	/**
	 * Desinstalacion: modulos, tabla, opciones tsexp_*, transients y crons.
	 * En modo seguro no se carga ningun modulo; por eso, ademas, se borran todas las tablas tsexp_* sin depender de ellos.
	 *
	 * @param Module_Loader|null $loader Cargador de modulos; por defecto el real (solo lo cambian los tests).
	 * @return void
	 */
	public static function uninstall( ?Module_Loader $loader = null ): void {
		global $wpdb;

		$loader ??= new Module_Loader();
		foreach ( $loader->get_modules() as $module ) {
			try {
				$module->uninstall();
			} catch ( \Throwable $e ) {
				continue;
			}
		}

		self::deactivate();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Desinstalacion: borra la tabla propia del plugin.
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', Event_Log::table_name() ) );
		self::drop_tsexp_tables();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Desinstalacion: borra solo opciones tsexp_* (la cache se limpia debajo).
		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s',
				$wpdb->options,
				$wpdb->esc_like( 'tsexp_' ) . '%',
				$wpdb->esc_like( '_transient_tsexp_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_tsexp_' ) . '%',
				$wpdb->esc_like( '_site_transient_tsexp_' ) . '%',
				$wpdb->esc_like( '_site_transient_timeout_tsexp_' ) . '%'
			)
		);
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}

	/**
	 * Red de seguridad de la desinstalacion: borra toda tabla `{prefix}tsexp_*` y `{base_prefix}tsexp_*`
	 * sin cargar codigo de modulos (en modo seguro no se carga ninguno y sus tablas se quedarian).
	 *
	 * @return void
	 */
	private static function drop_tsexp_tables(): void {
		global $wpdb;

		$prefixes = array_unique( array( $wpdb->prefix . 'tsexp_', $wpdb->base_prefix . 'tsexp_' ) );
		foreach ( $prefixes as $prefix ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Desinstalacion: lista las tablas propias del plugin.
			$tables = $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $prefix ) . '%' ) );
			foreach ( (array) $tables as $table ) {
				// Doble comprobacion: solo nombres que empiezan exactamente por el prefijo (el `_` del LIKE no es comodin aqui).
				if ( ! is_string( $table ) || ! str_starts_with( $table, $prefix ) ) {
					continue;
				}
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching -- Desinstalacion: borra tablas propias del plugin.
				$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $table ) );
			}
		}
	}
}

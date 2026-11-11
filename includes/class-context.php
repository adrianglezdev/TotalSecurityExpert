<?php
/**
 * Lo que recibe cada modulo al arrancar.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

defined( 'ABSPATH' ) || exit;

/**
 * Registro de hooks aislado, log e IP del cliente para un modulo.
 */
final class Context {

	/**
	 * Id del modulo dueño del contexto.
	 *
	 * @var string
	 */
	private string $module_id;

	/**
	 * Registro de eventos.
	 *
	 * @var Event_Log
	 */
	private Event_Log $event_log;

	/**
	 * Resolutor de la IP del cliente.
	 *
	 * @var Request
	 */
	private Request $request;

	/**
	 * Callback (id, mensaje) para apuntar errores del modulo.
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $error_reporter;

	/**
	 * Si ya se apunto un error en esta peticion (una vez por peticion y modulo).
	 *
	 * @var bool
	 */
	private bool $error_reported = false;

	/**
	 * Constructor.
	 *
	 * @param string        $module_id      Id del modulo.
	 * @param Event_Log     $event_log      Registro de eventos.
	 * @param Request       $request        Resolutor de IP.
	 * @param \Closure|null $error_reporter Callback( string $module_id, string $message ).
	 */
	public function __construct( string $module_id, Event_Log $event_log, Request $request, ?\Closure $error_reporter = null ) {
		$this->module_id      = $module_id;
		$this->event_log      = $event_log;
		$this->request        = $request;
		$this->error_reporter = $error_reporter;
	}

	/**
	 * Registra una accion; si el callback lanza, no se propaga.
	 *
	 * @param string   $hook     Nombre del hook.
	 * @param callable $cb       Callback.
	 * @param int      $priority Prioridad.
	 * @param int      $args     Numero de argumentos aceptados.
	 * @return void
	 */
	public function add_action( string $hook, callable $cb, int $priority = 10, int $args = 1 ): void {
		try {
			add_action(
				$hook,
				function ( ...$params ) use ( $cb, $hook ) {
					try {
						return $cb( ...$params );
					} catch ( \Throwable $e ) {
						$this->report( $hook, $e );
						return null;
					}
				},
				$priority,
				$args
			);
		} catch ( \Throwable $e ) {
			$this->report( $hook, $e );
		}
	}

	/**
	 * Registra un filtro; si el callback lanza, devuelve el primer argumento sin cambiar.
	 * Acepta como minimo 1 argumento: con 0, WordPress no pasaria el valor y un fallo devolveria null.
	 *
	 * @param string   $hook     Nombre del hook.
	 * @param callable $cb       Callback.
	 * @param int      $priority Prioridad.
	 * @param int      $args     Numero de argumentos aceptados.
	 * @return void
	 */
	public function add_filter( string $hook, callable $cb, int $priority = 10, int $args = 1 ): void {
		try {
			add_filter(
				$hook,
				function ( ...$params ) use ( $cb, $hook ) {
					try {
						return $cb( ...$params );
					} catch ( \Throwable $e ) {
						$this->report( $hook, $e );
						return $params[0] ?? null;
					}
				},
				$priority,
				max( 1, $args )
			);
		} catch ( \Throwable $e ) {
			$this->report( $hook, $e );
		}
	}

	/**
	 * Escribe un evento en el registro con el id del modulo ya puesto.
	 *
	 * @param string              $event    Id corto del evento.
	 * @param string              $message  Mensaje.
	 * @param array<string,mixed> $data     Datos extra (sin contrasenas ni tokens).
	 * @param string              $severity info|warning|critical.
	 * @return void
	 */
	public function log( string $event, string $message, array $data = array(), string $severity = 'info' ): void {
		$this->event_log->log( $this->module_id, $event, $message, $data, $severity );
	}

	/**
	 * IP del cliente, o '' si no hay una valida.
	 *
	 * @return string
	 */
	public function get_client_ip(): string {
		return $this->request->get_client_ip();
	}

	/**
	 * Grupo de la IP del cliente para contar intentos: la IP en IPv4 y la red /64 (CIDR) en IPv6.
	 * Un limite de intentos debe contar por este valor y no por get_client_ip().
	 *
	 * @return string '' si no hay IP valida.
	 */
	public function get_client_ip_bucket(): string {
		return $this->request->get_client_ip_bucket();
	}

	/**
	 * Id del modulo.
	 *
	 * @return string
	 */
	public function get_module_id(): string {
		return $this->module_id;
	}

	/**
	 * Apunta el error del callback, una sola vez por peticion y modulo.
	 *
	 * @param string     $hook Hook donde fallo.
	 * @param \Throwable $e    Error.
	 * @return void
	 */
	private function report( string $hook, \Throwable $e ): void {
		if ( $this->error_reported || null === $this->error_reporter ) {
			return;
		}
		$this->error_reported = true;
		try {
			( $this->error_reporter )(
				$this->module_id,
				Module_Loader::format_error( $e, $hook )
			);
		} catch ( \Throwable $inner ) {
			return;
		}
	}
}

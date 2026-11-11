<?php
/**
 * Modulos falsos para probar el nucleo.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Fixtures;

use TotalSecurityExpert\Abstract_Module;
use TotalSecurityExpert\Context;

/**
 * Modulo que funciona: cuenta cuantas veces se arranca y sanea un numero.
 */
class Fake_Module extends Abstract_Module {

	/**
	 * Veces que se ha llamado a boot().
	 *
	 * @var int
	 */
	public static int $boot_calls = 0;

	/**
	 * Veces que se ha llamado a uninstall().
	 *
	 * @var int
	 */
	public static int $uninstall_calls = 0;

	/**
	 * Ajustes recibidos en el ultimo boot().
	 *
	 * @var array<string,mixed>
	 */
	public static array $last_settings = array();

	/**
	 * Pone los contadores a cero.
	 *
	 * @return void
	 */
	public static function reset(): void {
		self::$boot_calls      = 0;
		self::$uninstall_calls = 0;
		self::$last_settings   = array();
	}

	/**
	 * Id.
	 *
	 * @return string
	 */
	public function get_id(): string {
		return 'fake';
	}

	/**
	 * Nombre.
	 *
	 * @return string
	 */
	public function get_name(): string {
		return 'Fake';
	}

	/**
	 * Descripcion.
	 *
	 * @return string
	 */
	public function get_description(): string {
		return 'Modulo de prueba.';
	}

	/**
	 * Ajustes por defecto.
	 *
	 * @return array<string,mixed>
	 */
	public function get_default_settings(): array {
		return array( 'limit' => 5 );
	}

	/**
	 * Convierte limit en entero positivo.
	 *
	 * @param array<string,mixed> $input Datos sin confiar.
	 * @return array<string,mixed>
	 */
	public function sanitize_settings( array $input ): array {
		return array( 'limit' => max( 1, (int) ( $input['limit'] ?? 5 ) ) );
	}

	/**
	 * Cuenta la llamada.
	 *
	 * @param Context             $context  Contexto.
	 * @param array<string,mixed> $settings Ajustes.
	 * @return void
	 */
	public function boot( Context $context, array $settings ): void {
		++self::$boot_calls;
		self::$last_settings = $settings;
	}

	/**
	 * Cuenta la llamada.
	 *
	 * @return void
	 */
	public function uninstall(): void {
		++self::$uninstall_calls;
	}
}

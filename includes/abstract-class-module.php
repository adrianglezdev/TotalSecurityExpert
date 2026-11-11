<?php
/**
 * Base opcional para modulos.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

defined( 'ABSPATH' ) || exit;

/**
 * Implementa lo que casi todo modulo deja vacio.
 */
abstract class Abstract_Module implements Module {

	/**
	 * Devuelve los valores por defecto (los modulos sobrescriben si necesitan sanear).
	 *
	 * @param array<string,mixed> $input Datos sin confiar (ignorados).
	 * @return array<string,mixed>
	 */
	public function sanitize_settings( array $input ): array {
		return $this->get_default_settings();
	}

	/**
	 * No pinta nada.
	 *
	 * @param array<string,mixed> $settings    Ajustes actuales.
	 * @param string              $name_prefix Prefijo del name de los campos.
	 * @return void
	 */
	public function render_settings( array $settings, string $name_prefix ): void {
	}

	/**
	 * Sin tablas que crear.
	 *
	 * @return void
	 */
	public function install(): void {
	}

	/**
	 * Sin datos que borrar.
	 *
	 * @return void
	 */
	public function uninstall(): void {
	}
}

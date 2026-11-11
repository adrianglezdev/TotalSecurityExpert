<?php
/**
 * Interfaz que implementa todo modulo de Total Security Expert.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

defined( 'ABSPATH' ) || exit;

/**
 * Contrato de un modulo. Ver docs/ARQUITECTURA.md.
 */
interface Module {

	/**
	 * Id del modulo; igual que en el registro de Module_Loader.
	 *
	 * @return string
	 */
	public function get_id(): string;

	/**
	 * Nombre traducible.
	 *
	 * @return string
	 */
	public function get_name(): string;

	/**
	 * Descripcion traducible.
	 *
	 * @return string
	 */
	public function get_description(): string;

	/**
	 * Ajustes por defecto del modulo.
	 *
	 * @return array<string,mixed>
	 */
	public function get_default_settings(): array;

	/**
	 * Sanea datos sin confiar y devuelve ajustes limpios y completos.
	 *
	 * @param array<string,mixed> $input Datos sin confiar.
	 * @return array<string,mixed>
	 */
	public function sanitize_settings( array $input ): array;

	/**
	 * Pinta los campos de ajustes (sin form, nonce ni boton). Todo escapado.
	 *
	 * @param array<string,mixed> $settings    Ajustes actuales.
	 * @param string              $name_prefix Prefijo del atributo name de cada campo.
	 * @return void
	 */
	public function render_settings( array $settings, string $name_prefix ): void;

	/**
	 * Registra hooks a traves de Context. Solo se llama si el modulo esta activo.
	 *
	 * @param Context             $context  Contexto del modulo.
	 * @param array<string,mixed> $settings Ajustes del modulo.
	 * @return void
	 */
	public function boot( Context $context, array $settings ): void;

	/**
	 * Crea sus tablas (idempotente, con dbDelta).
	 *
	 * @return void
	 */
	public function install(): void;

	/**
	 * Borra sus tablas, opciones y transients.
	 *
	 * @return void
	 */
	public function uninstall(): void;
}

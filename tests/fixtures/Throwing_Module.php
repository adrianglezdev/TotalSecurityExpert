<?php
/**
 * Modulo que falla en todo.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Fixtures;

use TotalSecurityExpert\Abstract_Module;
use TotalSecurityExpert\Context;

/**
 * Su sanitize_settings(), boot() e install() lanzan.
 */
class Throwing_Module extends Abstract_Module {

	/**
	 * Id.
	 *
	 * @return string
	 */
	public function get_id(): string {
		return 'throwing';
	}

	/**
	 * Nombre.
	 *
	 * @return string
	 */
	public function get_name(): string {
		return 'Throwing';
	}

	/**
	 * Descripcion.
	 *
	 * @return string
	 */
	public function get_description(): string {
		return 'Modulo de prueba que lanza.';
	}

	/**
	 * Ajustes por defecto.
	 *
	 * @return array<string,mixed>
	 */
	public function get_default_settings(): array {
		return array( 'flag' => true );
	}

	/**
	 * Lanza siempre.
	 *
	 * @param array<string,mixed> $input Datos sin confiar.
	 * @return array<string,mixed>
	 */
	public function sanitize_settings( array $input ): array {
		throw new \RuntimeException( 'sanitize roto' );
	}

	/**
	 * Lanza siempre.
	 *
	 * @param Context             $context  Contexto.
	 * @param array<string,mixed> $settings Ajustes.
	 * @return void
	 */
	public function boot( Context $context, array $settings ): void {
		throw new \RuntimeException( 'boot roto' );
	}

	/**
	 * Lanza siempre.
	 *
	 * @return void
	 */
	public function install(): void {
		throw new \RuntimeException( 'install roto' );
	}
}

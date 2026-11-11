<?php
/**
 * Module_Loader con el modo seguro forzado.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Fixtures;

use TotalSecurityExpert\Module_Loader;

/**
 * Para probar el modo seguro sin definir la constante (que no se puede deshacer en el mismo proceso).
 */
class Safe_Mode_Loader extends Module_Loader {

	/**
	 * Modo seguro forzado.
	 *
	 * @return bool
	 */
	public function is_safe_mode(): bool {
		return true;
	}
}

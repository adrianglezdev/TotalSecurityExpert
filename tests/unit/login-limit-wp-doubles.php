<?php
/**
 * Doble minimo de WP_User para los tests de login-limit (solo si no existe). WP_Error lo registra tests/bootstrap.php.
 *
 * @package TotalSecurityExpert
 */

// phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedClassFound -- Dobles de clases de WordPress.

if ( ! class_exists( 'WP_User' ) ) {
	/**
	 * Doble minimo de WP_User.
	 */
	class WP_User {
		/**
		 * Id.
		 *
		 * @var int
		 */
		public int $ID = 1;
	}
}

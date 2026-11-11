<?php
/**
 * Dobles minimos de clases de WordPress para los tests del modulo hardening (WordPress no se carga).
 * WP_Error no se define aqui: lo registra tests/bootstrap.php (tests/fixtures/Wp_Error_Double.php).
 *
 * @package TotalSecurityExpert
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals, Generic.Files.OneObjectStructurePerFile, Universal.Files.SeparateFunctionsFromOO, WordPress.Files.FileName, Squiz.Commenting

if ( ! class_exists( 'WP_REST_Users_Controller', false ) ) {
	class WP_REST_Users_Controller {

		public function get_items() {
			return null;
		}
	}
}

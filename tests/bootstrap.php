<?php
/**
 * Bootstrap de PHPUnit: Composer, constantes minimas y ficheros del nucleo.
 *
 * Los tests no cargan WordPress. Las funciones de WordPress se simulan con
 * Brain Monkey (ver tests/unit/TestCase.php).
 *
 * @package TotalSecurityExpert
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Define constantes de WordPress (ABSPATH, ARRAY_A...) para simular el entorno.

$tsexp_root = dirname( __DIR__ );

require_once $tsexp_root . '/vendor/autoload.php';

define( 'ABSPATH', $tsexp_root . '/' );

// Constantes de WordPress que usa el codigo del plugin.
define( 'ARRAY_A', 'ARRAY_A' );
define( 'DAY_IN_SECONDS', 86400 );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );

// Constantes del plugin (las mismas que define total-security-expert.php).
define( 'TSEXP_VERSION', '0.1.1' );
define( 'TSEXP_DB_VERSION', '1' );
define( 'TSEXP_FILE', $tsexp_root . '/total-security-expert.php' );
define( 'TSEXP_PATH', $tsexp_root . '/' );
define( 'TSEXP_URL', 'http://example.test/wp-content/plugins/total-security-expert/' );

// Nucleo, en el mismo orden que total-security-expert.php. Sin autoloader en produccion.
require_once TSEXP_PATH . 'includes/interface-module.php';
require_once TSEXP_PATH . 'includes/abstract-class-module.php';
require_once TSEXP_PATH . 'includes/class-request.php';
require_once TSEXP_PATH . 'includes/class-settings.php';
require_once TSEXP_PATH . 'includes/class-event-log.php';
require_once TSEXP_PATH . 'includes/class-context.php';
require_once TSEXP_PATH . 'includes/class-module-loader.php';
require_once TSEXP_PATH . 'includes/class-plugin.php';
require_once TSEXP_PATH . 'admin/class-admin.php';

unset( $tsexp_root );

// WP_Error minimo (WordPress no se carga). Es la unica definicion para los tests; se registra como alias.
if ( ! class_exists( 'WP_Error', false ) ) {
	class_alias( 'TotalSecurityExpert\Tests\Fixtures\Wp_Error_Double', 'WP_Error' );
}

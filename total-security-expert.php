<?php
/**
 * Plugin Name:       Total Security Expert
 * Description:       Plugin de seguridad ligero, por módulos que se activan por separado.
 * Version:           0.1.1
 * Requires at least: 7.0
 * Requires PHP:      8.1
 * Author:            Total Security Expert
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       total-security-expert
 * Domain Path:       /languages
 *
 * @package TotalSecurityExpert
 */

defined( 'ABSPATH' ) || exit;

defined( 'TSEXP_VERSION' ) || define( 'TSEXP_VERSION', '0.1.1' );
defined( 'TSEXP_DB_VERSION' ) || define( 'TSEXP_DB_VERSION', '1' );
defined( 'TSEXP_FILE' ) || define( 'TSEXP_FILE', __FILE__ );
defined( 'TSEXP_PATH' ) || define( 'TSEXP_PATH', plugin_dir_path( __FILE__ ) );
defined( 'TSEXP_URL' ) || define( 'TSEXP_URL', plugin_dir_url( __FILE__ ) );

require_once TSEXP_PATH . 'includes/interface-module.php';
require_once TSEXP_PATH . 'includes/abstract-class-module.php';
require_once TSEXP_PATH . 'includes/class-request.php';
require_once TSEXP_PATH . 'includes/class-settings.php';
require_once TSEXP_PATH . 'includes/class-event-log.php';
require_once TSEXP_PATH . 'includes/class-context.php';
require_once TSEXP_PATH . 'includes/class-module-loader.php';
require_once TSEXP_PATH . 'includes/class-plugin.php';
require_once TSEXP_PATH . 'admin/class-admin.php';

register_activation_hook( TSEXP_FILE, array( \TotalSecurityExpert\Plugin::class, 'activate' ) );
register_deactivation_hook( TSEXP_FILE, array( \TotalSecurityExpert\Plugin::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( \TotalSecurityExpert\Plugin::instance(), 'run' ) );

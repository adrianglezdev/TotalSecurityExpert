<?php
/**
 * Desinstalacion: borra modulos, tabla, opciones, transients y crons.
 *
 * @package TotalSecurityExpert
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Los modulos pueden usar estas constantes en su uninstall().
defined( 'TSEXP_FILE' ) || define( 'TSEXP_FILE', __DIR__ . '/total-security-expert.php' );
defined( 'TSEXP_PATH' ) || define( 'TSEXP_PATH', plugin_dir_path( TSEXP_FILE ) );
defined( 'TSEXP_URL' ) || define( 'TSEXP_URL', plugin_dir_url( TSEXP_FILE ) );

require_once TSEXP_PATH . 'includes/interface-module.php';
require_once TSEXP_PATH . 'includes/abstract-class-module.php';
require_once TSEXP_PATH . 'includes/class-request.php';
require_once TSEXP_PATH . 'includes/class-settings.php';
require_once TSEXP_PATH . 'includes/class-event-log.php';
require_once TSEXP_PATH . 'includes/class-context.php';
require_once TSEXP_PATH . 'includes/class-module-loader.php';
require_once TSEXP_PATH . 'includes/class-plugin.php';

\TotalSecurityExpert\Plugin::uninstall();

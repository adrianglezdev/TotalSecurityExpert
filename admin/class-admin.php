<?php
/**
 * Pantallas de administracion: ajustes y registro.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Admin;

use TotalSecurityExpert\Event_Log;
use TotalSecurityExpert\Module;
use TotalSecurityExpert\Module_Loader;
use TotalSecurityExpert\Request;
use TotalSecurityExpert\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Menu "Total Security", pagina de ajustes (Settings API) y visor del registro.
 * Todo exige manage_options.
 */
class Admin {

	public const CAPABILITY    = 'manage_options';
	public const PAGE_SETTINGS = 'tsexp-settings';
	public const PAGE_LOG      = 'tsexp-log';
	private const PER_PAGE     = 50;
	private const STYLE_HANDLE = 'tsexp-admin';

	/**
	 * Ajustes.
	 *
	 * @var Settings
	 */
	private Settings $settings;

	/**
	 * Cargador de modulos.
	 *
	 * @var Module_Loader
	 */
	private Module_Loader $loader;

	/**
	 * Registro de eventos.
	 *
	 * @var Event_Log
	 */
	private Event_Log $event_log;

	/**
	 * Hook suffixes de las paginas del plugin (los que devuelven add_menu_page y add_submenu_page).
	 *
	 * @var array<int,string>
	 */
	private array $page_hooks = array();

	/**
	 * Constructor sin efectos.
	 *
	 * @param Settings      $settings  Ajustes.
	 * @param Module_Loader $loader    Cargador de modulos.
	 * @param Event_Log     $event_log Registro de eventos.
	 */
	public function __construct( Settings $settings, Module_Loader $loader, Event_Log $event_log ) {
		$this->settings  = $settings;
		$this->loader    = $loader;
		$this->event_log = $event_log;
	}

	/**
	 * Engancha la administracion.
	 *
	 * @return void
	 */
	public function init(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_sections' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_notices', array( $this, 'render_notices' ) );
		add_filter( 'option_page_capability_' . Settings::GROUP, array( $this, 'get_capability' ) );
	}

	/**
	 * Capacidad exigida para guardar los ajustes en options.php.
	 *
	 * @return string
	 */
	public function get_capability(): string {
		return self::CAPABILITY;
	}

	/**
	 * Menu y submenus.
	 *
	 * @return void
	 */
	public function register_menu(): void {
		$hooks   = array();
		$hooks[] = add_menu_page(
			__( 'Total Security', 'total-security-expert' ),
			__( 'Total Security', 'total-security-expert' ),
			self::CAPABILITY,
			self::PAGE_SETTINGS,
			array( $this, 'render_settings_page' ),
			esc_url( TSEXP_URL . 'assets/images/menu-icon.png' ),
			80
		);
		$hooks[] = add_submenu_page(
			self::PAGE_SETTINGS,
			__( 'Ajustes', 'total-security-expert' ),
			__( 'Ajustes', 'total-security-expert' ),
			self::CAPABILITY,
			self::PAGE_SETTINGS,
			array( $this, 'render_settings_page' )
		);
		$hooks[] = add_submenu_page(
			self::PAGE_SETTINGS,
			__( 'Registro', 'total-security-expert' ),
			__( 'Registro', 'total-security-expert' ),
			self::CAPABILITY,
			self::PAGE_LOG,
			array( $this, 'render_log_page' )
		);

		// add_*_page() devuelve false si el usuario no tiene permiso: se descartan.
		$this->page_hooks = array_values( array_unique( array_filter( $hooks, 'is_string' ) ) );
	}

	/**
	 * Encola la hoja de estilos solo en las paginas del plugin.
	 *
	 * @param mixed $hook_suffix Pagina de administracion actual.
	 * @return void
	 */
	public function enqueue_assets( $hook_suffix ): void {
		if ( ! is_string( $hook_suffix ) || ! in_array( $hook_suffix, $this->page_hooks, true ) ) {
			return;
		}
		wp_enqueue_style( self::STYLE_HANDLE, TSEXP_URL . 'admin/css/admin.css', array(), TSEXP_VERSION );
	}

	/**
	 * Cabecera de marca de las pantallas del plugin. El hr.wp-header-end hace que WordPress
	 * coloque los avisos (.notice) debajo de la cabecera y no dentro de ella.
	 *
	 * @param string $title Titulo ya traducido (se escapa aqui).
	 * @return void
	 */
	private function render_header( string $title ): void {
		?>
		<div class="tsexp-header">
			<img class="tsexp-header__logo" src="<?php echo esc_url( TSEXP_URL . 'assets/images/logo.png' ); ?>" alt="<?php echo esc_attr__( 'Logotipo de Total Security Expert', 'total-security-expert' ); ?>" width="96" height="129" />
			<h1><?php echo esc_html( $title ); ?></h1>
		</div>
		<hr class="wp-header-end" />
		<?php
	}

	/**
	 * Argumentos de add_settings_section() para pintar la seccion como tarjeta.
	 *
	 * @param bool $enabled Si es un modulo activado.
	 * @return array<string,string>
	 */
	private function card_args( bool $enabled = false ): array {
		return array(
			'before_section' => '<div class="%s">',
			'after_section'  => '</div>',
			'section_class'  => $enabled ? 'tsexp-card tsexp-card--on' : 'tsexp-card',
		);
	}

	/**
	 * Clase CSS de una gravedad: solo las de la lista blanca; el resto, la neutra.
	 *
	 * @param string $severity Gravedad leida del registro.
	 * @return string
	 */
	public function get_severity_class( string $severity ): string {
		return in_array( $severity, Event_Log::SEVERITIES, true ) ? $severity : 'neutral';
	}

	/**
	 * Secciones y campos de la Settings API: una general y una por modulo.
	 *
	 * @return void
	 */
	public function register_sections(): void {
		add_settings_section( 'tsexp_general', esc_html__( 'General', 'total-security-expert' ), '__return_false', self::PAGE_SETTINGS, $this->card_args() );
		add_settings_field(
			'tsexp_ip_source',
			__( 'Origen de la IP del cliente', 'total-security-expert' ),
			array( $this, 'render_field_ip_source' ),
			self::PAGE_SETTINGS,
			'tsexp_general',
			array( 'label_for' => 'tsexp-ip-source' )
		);
		add_settings_field(
			'tsexp_trusted_proxies',
			__( 'Proxies de confianza', 'total-security-expert' ),
			array( $this, 'render_field_trusted_proxies' ),
			self::PAGE_SETTINGS,
			'tsexp_general',
			array( 'label_for' => 'tsexp-trusted-proxies' )
		);
		add_settings_field(
			'tsexp_log_retention_days',
			__( 'Días que se conserva el registro', 'total-security-expert' ),
			array( $this, 'render_field_retention' ),
			self::PAGE_SETTINGS,
			'tsexp_general',
			array( 'label_for' => 'tsexp-log-retention-days' )
		);
		add_settings_field(
			'tsexp_log_max_rows',
			__( 'Máximo de eventos en el registro', 'total-security-expert' ),
			array( $this, 'render_field_max_rows' ),
			self::PAGE_SETTINGS,
			'tsexp_general',
			array( 'label_for' => 'tsexp-log-max-rows' )
		);

		if ( $this->loader->is_safe_mode() ) {
			// Modo seguro: no se ha cargado ningun modulo; se listan los del registro sin llamar a su codigo.
			foreach ( $this->loader->get_registry_ids() as $id ) {
				add_settings_section(
					'tsexp_module_' . $id,
					esc_html( $id ),
					function () {
						echo '<p>' . esc_html__( 'No disponible: el modo seguro está activo y este módulo no se carga. Sus ajustes guardados se conservan.', 'total-security-expert' ) . '</p>';
					},
					self::PAGE_SETTINGS,
					$this->card_args()
				);
			}
			return;
		}

		foreach ( $this->loader->get_modules() as $id => $module ) {
			add_settings_section(
				'tsexp_module_' . $id,
				esc_html( $this->module_name( $module ) ),
				function () use ( $module ) {
					$this->render_module_section( $module );
				},
				self::PAGE_SETTINGS,
				$this->card_args( $this->settings->is_module_enabled( $id ) )
			);
		}
	}

	/**
	 * Pagina de ajustes: un unico formulario a options.php.
	 *
	 * @return void
	 */
	public function render_settings_page(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'No tienes permisos para ver esta página.', 'total-security-expert' ), '', array( 'response' => 403 ) );
		}
		?>
		<div class="wrap tsexp-admin">
			<?php $this->render_header( __( 'Total Security: ajustes', 'total-security-expert' ) ); ?>
			<?php if ( $this->loader->is_safe_mode() ) : ?>
				<div class="notice notice-warning inline"><p><?php echo esc_html__( 'Modo seguro activo (TSEXP_SAFE_MODE): ningún módulo se carga ni se ejecuta y todos aparecen como no disponibles. Para volver a la normalidad quita la constante de wp-config.php.', 'total-security-expert' ); ?></p></div>
			<?php endif; ?>
			<?php foreach ( $this->get_ip_config_warnings() as $warning ) : ?>
				<div class="notice notice-warning inline"><p><?php echo esc_html( $warning ); ?></p></div>
			<?php endforeach; ?>
			<form method="post" action="options.php">
				<?php
				settings_fields( Settings::GROUP );
				do_settings_sections( self::PAGE_SETTINGS );
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Campo: origen de la IP.
	 *
	 * @return void
	 */
	public function render_field_ip_source(): void {
		$general = $this->settings->get_general();
		$labels  = array(
			'remote_addr'      => __( 'Conexión directa (REMOTE_ADDR)', 'total-security-expert' ),
			'x_forwarded_for'  => 'X-Forwarded-For',
			'x_real_ip'        => 'X-Real-IP',
			'cf_connecting_ip' => 'CF-Connecting-IP',
		);
		?>
		<select id="tsexp-ip-source" name="<?php echo esc_attr( Settings::OPTION . '[general][ip_source]' ); ?>">
			<?php foreach ( $labels as $value => $label ) : ?>
				<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $general['ip_source'], $value ); ?>><?php echo esc_html( $label ); ?></option>
			<?php endforeach; ?>
		</select>
		<p class="description"><?php echo esc_html__( 'Las cabeceras solo se usan si la conexión llega desde un proxy de confianza.', 'total-security-expert' ); ?></p>
		<?php
	}

	/**
	 * Campo: proxies de confianza.
	 *
	 * @return void
	 */
	public function render_field_trusted_proxies(): void {
		$general = $this->settings->get_general();
		?>
		<textarea id="tsexp-trusted-proxies" class="large-text code" rows="4" name="<?php echo esc_attr( Settings::OPTION . '[general][trusted_proxies]' ); ?>"><?php echo esc_textarea( implode( "\n", $general['trusted_proxies'] ) ); ?></textarea>
		<p class="description"><?php echo esc_html__( 'Una IP o rango CIDR (IPv4 o IPv6) por línea.', 'total-security-expert' ); ?></p>
		<?php
	}

	/**
	 * Avisos de configuracion de la IP del cliente (texto plano; quien los pinta los escapa).
	 *
	 * 1. Se eligio una cabecera como origen pero no hay proxies de confianza: la cabecera no se usara nunca.
	 * 2. Llegan cabeceras de proxy y se usa REMOTE_ADDR, o REMOTE_ADDR no es un proxy de confianza: si la web
	 *    esta tras un proxy, todos los visitantes compartiran IP (y el limite de intentos los bloqueara a todos).
	 *
	 * @param array<string,mixed>|null $server Datos tipo $_SERVER; por defecto el real.
	 * @return array<int,string>
	 */
	public function get_ip_config_warnings( ?array $server = null ): array {
		$server   = $server ?? $_SERVER;
		$general  = $this->settings->get_general();
		$warnings = array();

		if ( 'remote_addr' !== $general['ip_source'] && array() === $general['trusted_proxies'] ) {
			$warnings[] = __( 'Has elegido una cabecera como origen de la IP pero no hay proxies de confianza: la cabecera se ignora y se usa la IP de la conexión directa (REMOTE_ADDR). Añade la IP de tu proxy a la lista.', 'total-security-expert' );
		}

		$has_proxy_header = false;
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' ) as $key ) {
			if ( isset( $server[ $key ] ) && is_string( $server[ $key ] ) && '' !== trim( $server[ $key ] ) ) {
				$has_proxy_header = true;
				break;
			}
		}
		if ( $has_proxy_header ) {
			$remote = isset( $server['REMOTE_ADDR'] ) && is_string( $server['REMOTE_ADDR'] ) ? Request::normalize_ip( sanitize_text_field( wp_unslash( $server['REMOTE_ADDR'] ) ) ) : '';
			if ( 'remote_addr' === $general['ip_source'] || '' === $remote || ! Request::is_trusted( $remote, $general['trusted_proxies'] ) ) {
				$warnings[] = __( 'Esta petición trae cabeceras de proxy (X-Forwarded-For, X-Real-IP o CF-Connecting-IP) pero no se están usando: si la web está detrás de un proxy o CDN, todos los visitantes compartirán la misma IP. Elige el origen de la IP y añade la IP del proxy a la lista de confianza.', 'total-security-expert' );
			}
		}

		return $warnings;
	}

	/**
	 * Campo: maximo de filas del registro.
	 *
	 * @return void
	 */
	public function render_field_max_rows(): void {
		$general = $this->settings->get_general();
		?>
		<input type="number" id="tsexp-log-max-rows" min="<?php echo esc_attr( (string) Settings::LOG_MAX_ROWS_MIN ); ?>" max="<?php echo esc_attr( (string) Settings::LOG_MAX_ROWS_MAX ); ?>" step="1" class="small-text" name="<?php echo esc_attr( Settings::OPTION . '[general][log_max_rows]' ); ?>" value="<?php echo esc_attr( (string) $general['log_max_rows'] ); ?>" />
		<p class="description"><?php echo esc_html__( 'Cada hora se borran los eventos más antiguos que pasen de este número.', 'total-security-expert' ); ?></p>
		<?php
	}

	/**
	 * Campo: dias de retencion del registro.
	 *
	 * @return void
	 */
	public function render_field_retention(): void {
		$general = $this->settings->get_general();
		?>
		<input type="number" id="tsexp-log-retention-days" min="1" max="365" step="1" class="small-text" name="<?php echo esc_attr( Settings::OPTION . '[general][log_retention_days]' ); ?>" value="<?php echo esc_attr( (string) $general['log_retention_days'] ); ?>" />
		<?php
	}

	/**
	 * Contenido de la seccion de un modulo: casilla de activar y sus campos.
	 *
	 * @param Module $module Modulo.
	 * @return void
	 */
	private function render_module_section( Module $module ): void {
		$id     = $module->get_id();
		$prefix = Settings::OPTION . '[modules][' . $id . ']';

		try {
			$description = $module->get_description();
		} catch ( \Throwable $e ) {
			$description = '';
		}
		?>
		<p><?php echo esc_html( $description ); ?></p>
		<p>
			<label>
				<input type="checkbox" name="<?php echo esc_attr( $prefix . '[enabled]' ); ?>" value="1" <?php checked( $this->settings->is_module_enabled( $id ) ); ?> />
				<?php echo esc_html__( 'Activar este módulo', 'total-security-expert' ); ?>
			</label>
		</p>
		<?php
		ob_start();
		try {
			$module->render_settings( $this->settings->get_module_settings( $id ), $prefix . '[settings]' );
			$html = (string) ob_get_clean();
			echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Lo pinta el modulo y es responsable de escapar (contrato).
		} catch ( \Throwable $e ) {
			ob_end_clean();
			$this->loader->record_error( $id, Module_Loader::format_error( $e, 'render_settings' ) );
			echo '<p>' . esc_html__( 'No se han podido mostrar los ajustes de este módulo.', 'total-security-expert' ) . '</p>';
		}
	}

	/**
	 * Pagina del registro: tabla paginada con filtros en lista blanca.
	 *
	 * @return void
	 */
	public function render_log_page(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'No tienes permisos para ver esta página.', 'total-security-expert' ), '', array( 'response' => 403 ) );
		}

		$module_ids = $this->loader->get_registry_ids();
		$filters    = $this->read_log_filters( $module_ids );
		$result     = $this->event_log->get_events(
			array(
				'module'   => $filters['module'],
				'severity' => $filters['severity'],
				'page'     => $filters['paged'],
				'per_page' => self::PER_PAGE,
			)
		);
		$pages      = max( 1, (int) ceil( $result['total'] / self::PER_PAGE ) );
		?>
		<div class="wrap tsexp-admin">
			<?php $this->render_header( __( 'Total Security: registro', 'total-security-expert' ) ); ?>

			<form method="get">
				<input type="hidden" name="page" value="<?php echo esc_attr( self::PAGE_LOG ); ?>" />
				<select name="module">
					<option value=""><?php echo esc_html__( 'Todos los módulos', 'total-security-expert' ); ?></option>
					<?php foreach ( $module_ids as $module_id ) : ?>
						<option value="<?php echo esc_attr( $module_id ); ?>" <?php selected( $filters['module'], $module_id ); ?>><?php echo esc_html( $module_id ); ?></option>
					<?php endforeach; ?>
				</select>
				<select name="severity">
					<option value=""><?php echo esc_html__( 'Todas las gravedades', 'total-security-expert' ); ?></option>
					<?php foreach ( Event_Log::SEVERITIES as $severity ) : ?>
						<option value="<?php echo esc_attr( $severity ); ?>" <?php selected( $filters['severity'], $severity ); ?>><?php echo esc_html( $severity ); ?></option>
					<?php endforeach; ?>
				</select>
				<?php submit_button( __( 'Filtrar', 'total-security-expert' ), 'secondary', '', false ); ?>
			</form>

			<table class="widefat striped tsexp-log-table">
				<thead>
					<tr>
						<th><?php echo esc_html__( 'Fecha (UTC)', 'total-security-expert' ); ?></th>
						<th><?php echo esc_html__( 'Módulo', 'total-security-expert' ); ?></th>
						<th><?php echo esc_html__( 'Evento', 'total-security-expert' ); ?></th>
						<th><?php echo esc_html__( 'Gravedad', 'total-security-expert' ); ?></th>
						<th><?php echo esc_html__( 'Usuario', 'total-security-expert' ); ?></th>
						<th><?php echo esc_html__( 'IP', 'total-security-expert' ); ?></th>
						<th><?php echo esc_html__( 'Mensaje', 'total-security-expert' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( empty( $result['items'] ) ) : ?>
					<tr><td colspan="7"><?php echo esc_html__( 'No hay eventos.', 'total-security-expert' ); ?></td></tr>
				<?php endif; ?>
				<?php foreach ( $result['items'] as $row ) : ?>
					<tr>
						<td><?php echo esc_html( (string) ( $row['created_at'] ?? '' ) ); ?></td>
						<td><?php echo esc_html( (string) ( $row['module'] ?? '' ) ); ?></td>
						<td><?php echo esc_html( (string) ( $row['event'] ?? '' ) ); ?></td>
						<?php $row_severity = (string) ( $row['severity'] ?? '' ); ?>
						<td><span class="tsexp-sev tsexp-sev--<?php echo esc_attr( $this->get_severity_class( $row_severity ) ); ?>"><?php echo esc_html( $row_severity ); ?></span></td>
						<td><?php echo esc_html( (string) absint( $row['user_id'] ?? 0 ) ); ?></td>
						<td><?php echo esc_html( (string) ( $row['ip'] ?? '' ) ); ?></td>
						<td>
							<?php echo esc_html( (string) ( $row['message'] ?? '' ) ); ?>
							<?php if ( ! empty( $row['data'] ) && '[]' !== $row['data'] && '{}' !== $row['data'] ) : ?>
								<details><summary><?php echo esc_html__( 'Datos', 'total-security-expert' ); ?></summary><code><?php echo esc_html( (string) $row['data'] ); ?></code></details>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) : ?>
				<div class="tablenav"><div class="tablenav-pages">
					<?php
					echo wp_kses_post(
						(string) paginate_links(
							array(
								'base'      => add_query_arg( 'paged', '%#%' ),
								'format'    => '',
								'current'   => $filters['paged'],
								'total'     => $pages,
								'prev_text' => '&laquo;',
								'next_text' => '&raquo;',
							)
						)
					);
					?>
				</div></div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Avisos de administracion: modo seguro y errores de modulos. Solo para manage_options.
	 *
	 * @return void
	 */
	public function render_notices(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}

		if ( $this->loader->is_safe_mode() ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Total Security Expert: el modo seguro (TSEXP_SAFE_MODE) está activo y ningún módulo se está ejecutando.', 'total-security-expert' ) . '</p></div>';
		}

		foreach ( $this->loader->get_errors() as $id => $error ) {
			echo '<div class="notice notice-error"><p>' . esc_html(
				sprintf(
					/* translators: 1: id del modulo, 2: mensaje de error. */
					__( 'Total Security Expert: el módulo «%1$s» ha fallado: %2$s', 'total-security-expert' ),
					$id,
					$error['message']
				)
			) . '</p></div>';
		}
	}

	/**
	 * Lee y valida (lista blanca) los filtros de la URL del visor. Solo lectura.
	 *
	 * @param array<int,string> $module_ids Ids de modulo permitidos.
	 * @return array{module:string,severity:string,paged:int}
	 */
	private function read_log_filters( array $module_ids ): array {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Filtros de solo lectura, validados contra lista blanca.
		$module   = isset( $_GET['module'] ) && is_string( $_GET['module'] ) ? sanitize_key( wp_unslash( $_GET['module'] ) ) : '';
		$severity = isset( $_GET['severity'] ) && is_string( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '';
		$paged    = isset( $_GET['paged'] ) && is_scalar( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		return array(
			'module'   => in_array( $module, $module_ids, true ) ? $module : '',
			'severity' => in_array( $severity, Event_Log::SEVERITIES, true ) ? $severity : '',
			'paged'    => max( 1, $paged ),
		);
	}

	/**
	 * Nombre del modulo sin que un fallo suyo rompa la pantalla.
	 *
	 * @param Module $module Modulo.
	 * @return string
	 */
	private function module_name( Module $module ): string {
		try {
			$name = $module->get_name();
			return '' !== $name ? $name : $module->get_id();
		} catch ( \Throwable $e ) {
			return $module->get_id();
		}
	}
}

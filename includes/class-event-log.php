<?php
/**
 * Registro de eventos de seguridad (tabla tsexp_events).
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

defined( 'ABSPATH' ) || exit;

/**
 * Escritura que nunca lanza, purga y lectura paginada del registro.
 */
class Event_Log {

	public const TABLE_SUFFIX = 'tsexp_events';
	public const SEVERITIES   = array( 'info', 'warning', 'critical' );

	/**
	 * Fragmentos de nombre de clave cuyo valor nunca se guarda (coincidencia por subcadena).
	 *
	 * @var array<int,string>
	 */
	private const SENSITIVE_KEYS = array( 'pass', 'pwd', 'cookie', 'nonce', 'token', 'secret', 'authoriz' );

	/**
	 * Palabras sensibles que se comparan por segmentos del nombre (api_key, apiKey, session-id),
	 * no por subcadena, para no ocultar claves legitimas como "monkey", "author" o "footprint".
	 * Tambien se acepta el plural (keys, codes, hashes, credentials).
	 *
	 * @var array<int,string>
	 */
	private const SENSITIVE_WORDS = array( 'key', 'auth', 'session', 'otp', 'code', 'hash', 'salt', 'credential', 'apikey' );

	/**
	 * Resolutor de IP.
	 *
	 * @var Request
	 */
	private Request $request;

	/**
	 * Constructor sin efectos.
	 *
	 * @param Request $request Resolutor de IP.
	 */
	public function __construct( Request $request ) {
		$this->request = $request;
	}

	/**
	 * Nombre completo de la tabla.
	 *
	 * @return string
	 */
	public static function table_name(): string {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_SUFFIX;
	}

	/**
	 * Crea o actualiza la tabla con dbDelta (idempotente).
	 *
	 * @return void
	 */
	public function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table   = self::table_name();
		$charset = $wpdb->get_charset_collate();

		dbDelta(
			"CREATE TABLE {$table} (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	created_at datetime NOT NULL,
	module varchar(64) NOT NULL DEFAULT '',
	event varchar(64) NOT NULL DEFAULT '',
	severity varchar(16) NOT NULL DEFAULT 'info',
	user_id bigint(20) unsigned NOT NULL DEFAULT 0,
	ip varchar(45) NOT NULL DEFAULT '',
	message text NOT NULL,
	data longtext NOT NULL,
	PRIMARY KEY  (id),
	KEY created_at (created_at),
	KEY module (module),
	KEY event (event)
) {$charset};"
		);
	}

	/**
	 * Guarda un evento. Sanea todo y nunca lanza: un fallo de BD no rompe la peticion.
	 *
	 * @param string              $module   Id del modulo.
	 * @param string              $event    Id corto del evento.
	 * @param string              $message  Mensaje.
	 * @param array<string,mixed> $data     Datos extra (se descartan claves sensibles).
	 * @param string              $severity info|warning|critical.
	 * @return void
	 */
	public function log( string $module, string $event, string $message, array $data = array(), string $severity = 'info' ): void {
		try {
			global $wpdb;
			if ( ! is_object( $wpdb ) ) {
				return;
			}

			$severity = in_array( $severity, self::SEVERITIES, true ) ? $severity : 'info';
			$json     = wp_json_encode( $this->scrub( $data ) );
			if ( ! is_string( $json ) || strlen( $json ) > 10000 ) {
				$json = '{"truncated":true}';
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Tabla propia del plugin; escribir un evento no se cachea.
			$wpdb->insert(
				self::table_name(),
				array(
					'created_at' => gmdate( 'Y-m-d H:i:s' ),
					'module'     => mb_substr( sanitize_key( $module ), 0, 64 ),
					'event'      => mb_substr( sanitize_key( $event ), 0, 64 ),
					'severity'   => $severity,
					'user_id'    => absint( get_current_user_id() ),
					'ip'         => $this->request->get_client_ip(),
					'message'    => mb_substr( sanitize_text_field( $message ), 0, 1000 ),
					'data'       => $json,
				),
				array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
			);
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Borra los eventos mas antiguos que $days dias.
	 *
	 * @param int $days Dias de retencion (minimo 1).
	 * @return void
	 */
	public function purge( int $days ): void {
		try {
			global $wpdb;
			$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( max( 1, $days ) * DAY_IN_SECONDS ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Purga de la tabla propia del plugin.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created_at < %s', self::table_name(), $cutoff ) );
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Recorta la tabla a un maximo de filas borrando las mas antiguas (por id).
	 *
	 * @param int $max Filas a conservar; se limita a 1 000 - 1 000 000.
	 * @return void
	 */
	public function trim_to_max_rows( int $max ): void {
		try {
			global $wpdb;
			$max   = max( Settings::LOG_MAX_ROWS_MIN, min( Settings::LOG_MAX_ROWS_MAX, $max ) );
			$table = self::table_name();
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Tabla propia del plugin; hay que leer el valor fresco.
			$edge = $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i ORDER BY id DESC LIMIT 1 OFFSET %d', $table, $max - 1 ) );
			if ( null === $edge || false === $edge || '' === $edge ) {
				return; // Hay menos filas que el maximo.
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Recorte de la tabla propia del plugin.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE id < %d', $table, (int) $edge ) );
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Lectura paginada para el visor.
	 *
	 * @param array{module?:string,severity?:string,page?:int,per_page?:int} $args Filtros; module y severity se validan.
	 * @return array{items:array<int,array<string,mixed>>,total:int}
	 */
	public function get_events( array $args = array() ): array {
		$empty = array(
			'items' => array(),
			'total' => 0,
		);
		try {
			global $wpdb;

			$page     = max( 1, (int) ( $args['page'] ?? 1 ) );
			$per_page = max( 1, min( 200, (int) ( $args['per_page'] ?? 50 ) ) );
			$module   = isset( $args['module'] ) && is_string( $args['module'] ) ? sanitize_key( $args['module'] ) : '';
			$severity = isset( $args['severity'] ) && is_string( $args['severity'] ) ? $args['severity'] : '';

			$where  = array();
			$params = array();
			if ( '' !== $module ) {
				$where[]  = 'module = %s';
				$params[] = $module;
			}
			if ( in_array( $severity, self::SEVERITIES, true ) ) {
				$where[]  = 'severity = %s';
				$params[] = $severity;
			}
			$where_sql = $where ? ' WHERE ' . implode( ' AND ', $where ) : '';
			$table     = self::table_name();

			// $where_sql solo contiene literales fijos con marcadores; los valores van en $params. Tabla propia: el visor lee siempre datos frescos.
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
			$total = (int) $wpdb->get_var(
				$wpdb->prepare( 'SELECT COUNT(*) FROM %i' . $where_sql, array_merge( array( $table ), $params ) )
			);
			$items = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT * FROM %i' . $where_sql . ' ORDER BY id DESC LIMIT %d OFFSET %d',
					array_merge( array( $table ), $params, array( $per_page, ( $page - 1 ) * $per_page ) )
				),
				ARRAY_A
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber

			return array(
				'items' => is_array( $items ) ? $items : array(),
				'total' => $total,
			);
		} catch ( \Throwable $e ) {
			return $empty;
		}
	}

	/**
	 * Sustituye por [redacted] el valor de las claves sensibles (recursivo, con limite de profundidad).
	 *
	 * @param array<mixed> $data  Datos.
	 * @param int          $depth Profundidad actual.
	 * @return array<mixed>
	 */
	private function scrub( array $data, int $depth = 0 ): array {
		$out = array();
		foreach ( $data as $key => $value ) {
			if ( self::is_sensitive_key( (string) $key ) ) {
				$out[ $key ] = '[redacted]';
				continue;
			}
			if ( is_array( $value ) ) {
				$out[ $key ] = $depth < 4 ? $this->scrub( $value, $depth + 1 ) : '[omitted]';
			} elseif ( is_scalar( $value ) || null === $value ) {
				$out[ $key ] = $value;
			} else {
				$out[ $key ] = '[omitted]';
			}
		}
		return $out;
	}

	/**
	 * Si el nombre de una clave de datos es sensible: contiene un fragmento de SENSITIVE_KEYS o
	 * alguno de sus segmentos (separados por _, -, espacios o mayusculas) es una palabra de SENSITIVE_WORDS.
	 *
	 * @param string $key Nombre de la clave.
	 * @return bool
	 */
	private static function is_sensitive_key( string $key ): bool {
		$name = strtolower( $key );
		foreach ( self::SENSITIVE_KEYS as $fragment ) {
			if ( str_contains( $name, $fragment ) ) {
				return true;
			}
		}
		$spaced   = preg_replace( '/([a-z0-9])([A-Z])/', '$1 $2', $key ) ?? $key;
		$segments = preg_split( '/[^a-z0-9]+/', strtolower( $spaced ), -1, PREG_SPLIT_NO_EMPTY );
		foreach ( false === $segments ? array() : $segments as $segment ) {
			foreach ( self::SENSITIVE_WORDS as $word ) {
				if ( $segment === $word || $segment === $word . 's' || $segment === $word . 'es' ) {
					return true;
				}
			}
		}
		return false;
	}
}

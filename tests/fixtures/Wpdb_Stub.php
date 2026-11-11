<?php
/**
 * Sustituto minimo de $wpdb para los tests (sin BD real).
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Fixtures;

// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter -- Las firmas imitan a wpdb; los metodos vacios se esperan con Mockery.

/**
 * Tiene las propiedades y metodos de wpdb que usa el plugin. prepare() y
 * esc_like() funcionan de verdad (para poder comprobar el SQL); el resto no
 * hace nada y se espera con Mockery: $this->mock_wpdb()->shouldReceive( 'insert' ).
 */
class Wpdb_Stub {

	/**
	 * Prefijo de tablas.
	 *
	 * @var string
	 */
	public string $prefix = 'wp_';

	/**
	 * Prefijo base de tablas (el de la red en multisitio).
	 *
	 * @var string
	 */
	public string $base_prefix = 'wp_';

	/**
	 * Tabla de opciones.
	 *
	 * @var string
	 */
	public string $options = 'wp_options';

	/**
	 * Ultimo id insertado.
	 *
	 * @var int
	 */
	public int $insert_id = 0;

	/**
	 * Como wpdb::prepare(): %s, %d y %i (identificador); acepta los valores sueltos o en un array.
	 *
	 * @param string $query   SQL con marcadores.
	 * @param mixed  ...$args Valores.
	 * @return string
	 */
	public function prepare( $query, ...$args ) {
		if ( 1 === count( $args ) && is_array( $args[0] ) ) {
			$args = $args[0];
		}
		$args = array_values( $args );
		$i    = 0;
		return preg_replace_callback(
			'/%([sdi])/',
			static function ( array $m ) use ( &$i, $args ) {
				$value = $args[ $i++ ] ?? '';
				if ( 'd' === $m[1] ) {
					return (string) (int) $value;
				}
				if ( 'i' === $m[1] ) {
					return '`' . str_replace( '`', '``', (string) $value ) . '`';
				}
				return "'" . addslashes( (string) $value ) . "'";
			},
			$query
		);
	}

	/**
	 * Como wpdb::esc_like().
	 *
	 * @param string $text Texto.
	 * @return string
	 */
	public function esc_like( $text ) {
		return addcslashes( $text, '_%\\' );
	}

	/**
	 * Collation de la tabla.
	 *
	 * @return string
	 */
	public function get_charset_collate() {
		return 'DEFAULT CHARACTER SET utf8mb4';
	}

	/**
	 * Sin efecto (esperar con Mockery).
	 *
	 * @param string $table  Tabla.
	 * @param array  $data   Datos.
	 * @param array  $format Formatos.
	 * @return int|false
	 */
	public function insert( $table, $data, $format = null ) {
		return false;
	}

	/**
	 * Sin efecto (esperar con Mockery).
	 *
	 * @param string $query SQL.
	 * @return int|bool
	 */
	public function query( $query ) {
		return false;
	}

	/**
	 * Sin efecto (esperar con Mockery).
	 *
	 * @param string $query SQL.
	 * @return string|null
	 */
	public function get_var( $query ) {
		return null;
	}

	/**
	 * Sin efecto (esperar con Mockery).
	 *
	 * @param string $query  SQL.
	 * @param string $output Formato.
	 * @return array|null
	 */
	public function get_row( $query, $output = 'OBJECT' ) {
		return null;
	}

	/**
	 * Sin efecto (esperar con Mockery).
	 *
	 * @param string $query SQL.
	 * @return array
	 */
	public function get_col( $query ) {
		return array();
	}

	/**
	 * Sin efecto (esperar con Mockery).
	 *
	 * @param string $query  SQL.
	 * @param string $output Formato.
	 * @return array|null
	 */
	public function get_results( $query, $output = 'OBJECT' ) {
		return null;
	}
}

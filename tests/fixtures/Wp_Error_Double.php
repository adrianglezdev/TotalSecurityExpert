<?php
/**
 * WP_Error minimo para los tests (WordPress no se carga).
 *
 * El bootstrap de los tests lo registra como alias de WP_Error si ninguna otra definicion existe. Es compatible
 * con lo que usan los tests de hardening: codigos, mensajes y datos por codigo.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Fixtures;

// phpcs:disable Squiz.Commenting.FunctionComment, Squiz.Commenting.FunctionCommentThrowTag, Universal.NamingConventions.NoReservedKeywordParameterNames -- Imita la API de WP_Error.

/**
 * Subconjunto de WP_Error: add, remove, has_errors, get_error_code(s), get_error_message(s), get_error_data.
 */
class Wp_Error_Double {

	/**
	 * Mensajes por codigo.
	 *
	 * @var array<string,array<int,string>>
	 */
	public $errors = array();

	/**
	 * Datos por codigo.
	 *
	 * @var array<string,mixed>
	 */
	public $error_data = array();

	public function __construct( $code = '', $message = '', $data = '' ) {
		if ( '' !== $code ) {
			$this->add( $code, $message, $data );
		}
	}

	public function add( $code, $message, $data = '' ) {
		$this->errors[ $code ][] = $message;
		if ( '' !== $data ) {
			$this->error_data[ $code ] = $data;
		}
	}

	public function has_errors() {
		return ! empty( $this->errors );
	}

	public function remove( $code ) {
		unset( $this->errors[ $code ], $this->error_data[ $code ] );
	}

	public function get_error_codes() {
		return array_keys( $this->errors );
	}

	public function get_error_code() {
		return $this->get_error_codes()[0] ?? '';
	}

	public function get_error_messages( $code = '' ) {
		if ( '' === $code ) {
			return array_merge( array(), ...array_values( $this->errors ) );
		}
		return $this->errors[ $code ] ?? array();
	}

	public function get_error_message( $code = '' ) {
		if ( '' === $code ) {
			$code = $this->get_error_code();
		}
		return $this->errors[ $code ][0] ?? '';
	}

	public function get_error_data( $code = '' ) {
		if ( '' === $code ) {
			$code = $this->get_error_code();
		}
		return $this->error_data[ $code ] ?? null;
	}
}

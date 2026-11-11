<?php
/**
 * IP del cliente.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert;

defined( 'ABSPATH' ) || exit;

/**
 * Resuelve la IP del cliente sin fiarse de cabeceras que pueda falsear cualquiera.
 */
class Request {

	/**
	 * Prefijo minimo aceptado en un CIDR de proxies de confianza (IPv4 / IPv6).
	 */
	public const MIN_PREFIX_V4 = 8;
	public const MIN_PREFIX_V6 = 32;

	/**
	 * Cabecera $_SERVER de cada fuente de IP.
	 *
	 * @var array<string,string>
	 */
	private const HEADER_KEYS = array(
		'x_forwarded_for'  => 'HTTP_X_FORWARDED_FOR',
		'x_real_ip'        => 'HTTP_X_REAL_IP',
		'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP',
	);

	/**
	 * Ajustes.
	 *
	 * @var Settings
	 */
	private Settings $settings;

	/**
	 * Constructor.
	 *
	 * @param Settings $settings Ajustes del plugin.
	 */
	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * IP del cliente segun los ajustes, o '' si no hay una valida.
	 *
	 * @return string
	 */
	public function get_client_ip(): string {
		$general = $this->settings->get_general();
		$server  = array();
		$keys    = array_merge( array( 'REMOTE_ADDR' ), array_values( self::HEADER_KEYS ) );
		foreach ( $keys as $key ) {
			if ( isset( $_SERVER[ $key ] ) && is_string( $_SERVER[ $key ] ) ) {
				$server[ $key ] = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
			}
		}
		return self::resolve_ip( $server, $general['ip_source'], $general['trusted_proxies'] );
	}

	/**
	 * Valor por el que agrupar al cliente (limite de intentos, bloqueos): la IP en IPv4 y la red /64 en IPv6.
	 *
	 * @return string IPv4 tal cual, IPv6 como "2001:db8:1:2::/64", o '' si no hay IP valida.
	 */
	public function get_client_ip_bucket(): string {
		return self::ip_bucket( $this->get_client_ip() );
	}

	/**
	 * Agrupa una IP: IPv4 tal cual (normalizada) e IPv6 como su red /64 en CIDR canonico.
	 * Un atacante con IPv6 controla al menos un /64, asi que contar por IP exacta no limita nada.
	 * Cabe siempre en 45 caracteres.
	 *
	 * @param string $ip IP sin confiar.
	 * @return string Grupo o '' si no es una IP valida.
	 */
	public static function ip_bucket( string $ip ): string {
		$ip = self::normalize_ip( $ip );
		if ( '' === $ip || ! str_contains( $ip, ':' ) ) {
			return $ip;
		}
		$packed = inet_pton( $ip );
		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return '';
		}
		$network = inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) );
		return false === $network ? '' : $network . '/64';
	}

	/**
	 * Calcula la IP a partir de los datos del servidor (funcion pura, facil de probar).
	 *
	 * @param array<string,string> $server          Datos tipo $_SERVER.
	 * @param string               $ip_source       remote_addr|x_forwarded_for|x_real_ip|cf_connecting_ip.
	 * @param array<int,string>    $trusted_proxies IPs o CIDR de proxies de confianza.
	 * @return string IP valida o ''.
	 */
	public static function resolve_ip( array $server, string $ip_source, array $trusted_proxies ): string {
		$remote = self::normalize_ip( (string) ( $server['REMOTE_ADDR'] ?? '' ) );
		if ( '' === $remote || ! isset( self::HEADER_KEYS[ $ip_source ] ) || ! self::is_trusted( $remote, $trusted_proxies ) ) {
			return $remote;
		}

		$header = (string) ( $server[ self::HEADER_KEYS[ $ip_source ] ] ?? '' );
		if ( '' === trim( $header ) ) {
			return $remote;
		}

		if ( 'x_forwarded_for' !== $ip_source ) {
			$candidate = self::normalize_header_ip( $header );
			return '' === $candidate ? $remote : $candidate;
		}

		// X-Forwarded-For: la mas a la derecha que no sea un proxy de confianza.
		foreach ( array_reverse( explode( ',', $header ) ) as $part ) {
			$candidate = self::normalize_header_ip( $part );
			if ( '' === $candidate ) {
				return $remote; // Cabecera mal formada: no se fia.
			}
			if ( ! self::is_trusted( $candidate, $trusted_proxies ) ) {
				return $candidate;
			}
		}
		return $remote;
	}

	/**
	 * Valida una IP y la devuelve en forma canonica (IPv4 mapeada en IPv6 pasa a IPv4).
	 *
	 * @param string $ip IP sin confiar.
	 * @return string IP canonica o '' si no es valida.
	 */
	public static function normalize_ip( string $ip ): string {
		$ip = trim( $ip );
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$packed = inet_pton( $ip );
		if ( false === $packed ) {
			return '';
		}
		if ( 16 === strlen( $packed ) && str_starts_with( $packed, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$packed = substr( $packed, 12 );
		}
		$canonical = inet_ntop( $packed );
		return false === $canonical ? '' : $canonical;
	}

	/**
	 * Como normalize_ip() pero para el valor de una cabecera: quita el puerto y los corchetes
	 * ("1.2.3.4:5678", "[2001:db8::1]:443", "[2001:db8::1]") antes de validar.
	 *
	 * @param string $value Valor de la cabecera (una sola IP) sin confiar.
	 * @return string IP canonica o '' si no es valida.
	 */
	public static function normalize_header_ip( string $value ): string {
		$value = trim( $value );
		if ( str_starts_with( $value, '[' ) ) {
			$end = strpos( $value, ']' );
			if ( false === $end ) {
				return '';
			}
			$rest = substr( $value, $end + 1 );
			if ( '' !== $rest && ! self::is_port_suffix( $rest ) ) {
				return '';
			}
			return self::normalize_ip( substr( $value, 1, $end - 1 ) );
		}
		// IPv4 con puerto: un solo ':' y puntos. Una IPv6 sin corchetes tiene varios ':'.
		if ( 1 === substr_count( $value, ':' ) && str_contains( $value, '.' ) ) {
			list( $host, $port ) = explode( ':', $value, 2 );
			if ( ! self::is_port_suffix( ':' . $port ) ) {
				return '';
			}
			return self::normalize_ip( $host );
		}
		return self::normalize_ip( $value );
	}

	/**
	 * Si el texto es ":puerto" con un puerto numerico valido.
	 *
	 * @param string $text Texto tras la IP.
	 * @return bool
	 */
	private static function is_port_suffix( string $text ): bool {
		return 1 === preg_match( '/^:[0-9]{1,5}$/', $text ) && (int) substr( $text, 1 ) <= 65535;
	}

	/**
	 * Valida y normaliza una entrada de la lista de proxies de confianza (IP o CIDR).
	 *
	 * - Una IP suelta se devuelve tal cual (recortada).
	 * - Un CIDR mas ancho que /8 (IPv4) o /32 (IPv6) se rechaza: dos /1 ya cubren todo IPv4 y permitirian fijar la IP
	 *   con una cabecera. Los rangos de Cloudflare caben.
	 * - Un CIDR IPv4 mapeado en IPv6 (::ffff:10.0.0.0/104) pasa a IPv4 (10.0.0.0/8); si el prefijo es
	 *   menor de /96 abarcaria mas que IPv4 y se rechaza.
	 *
	 * @param string $entry Entrada sin confiar.
	 * @return string Entrada canonica o '' si se descarta.
	 */
	public static function normalize_trusted_proxy( string $entry ): string {
		$entry = trim( $entry );
		if ( ! str_contains( $entry, '/' ) ) {
			return false !== filter_var( $entry, FILTER_VALIDATE_IP ) ? $entry : '';
		}
		if ( ! self::is_valid_ip_or_cidr( $entry ) ) {
			return '';
		}
		list( $net, $bits ) = explode( '/', $entry, 2 );
		$bits               = (int) $bits;
		if ( $bits < ( str_contains( $net, ':' ) ? self::MIN_PREFIX_V6 : self::MIN_PREFIX_V4 ) ) {
			return '';
		}
		$packed = inet_pton( $net );
		if ( false !== $packed && 16 === strlen( $packed ) && str_starts_with( $packed, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			if ( $bits < 97 ) {
				return ''; // Cubriria mas que el espacio IPv4 mapeado (y /96 daria 0.0.0.0/0).
			}
			$v4 = inet_ntop( substr( $packed, 12 ) );
			return false === $v4 || $bits - 96 < self::MIN_PREFIX_V4 ? '' : $v4 . '/' . ( $bits - 96 );
		}
		return $entry;
	}

	/**
	 * Si el texto es una IP o un CIDR valido (IPv4 o IPv6).
	 *
	 * @param string $value Texto.
	 * @return bool
	 */
	public static function is_valid_ip_or_cidr( string $value ): bool {
		$value = trim( $value );
		if ( ! str_contains( $value, '/' ) ) {
			return false !== filter_var( $value, FILTER_VALIDATE_IP );
		}
		list( $net, $bits ) = explode( '/', $value, 2 );
		if ( false === filter_var( $net, FILTER_VALIDATE_IP ) || ! ctype_digit( $bits ) ) {
			return false;
		}
		$max = str_contains( $net, ':' ) ? 128 : 32;
		return (int) $bits <= $max;
	}

	/**
	 * Si la IP coincide con una entrada (IP o CIDR).
	 *
	 * @param string $ip    IP ya normalizada.
	 * @param string $entry IP o CIDR.
	 * @return bool
	 */
	public static function ip_matches( string $ip, string $entry ): bool {
		$entry = trim( $entry );
		if ( ! self::is_valid_ip_or_cidr( $entry ) ) {
			return false;
		}
		if ( ! str_contains( $entry, '/' ) ) {
			return self::normalize_ip( $entry ) === $ip;
		}

		list( $net, $bits ) = explode( '/', $entry, 2 );
		$bits               = (int) $bits;
		$ip_bin             = inet_pton( $ip );
		$net_bin            = inet_pton( $net );
		if ( false === $ip_bin || false === $net_bin || strlen( $ip_bin ) !== strlen( $net_bin ) ) {
			return false;
		}

		$full = intdiv( $bits, 8 );
		$rest = $bits % 8;
		if ( substr( $ip_bin, 0, $full ) !== substr( $net_bin, 0, $full ) ) {
			return false;
		}
		if ( 0 === $rest ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;
		return ( ord( $ip_bin[ $full ] ) & $mask ) === ( ord( $net_bin[ $full ] ) & $mask );
	}

	/**
	 * Si la IP esta en la lista de proxies de confianza (ignora entradas /0 y normaliza las IPv4 mapeadas).
	 *
	 * @param string            $ip      IP normalizada.
	 * @param array<int,string> $proxies IPs o CIDR.
	 * @return bool
	 */
	public static function is_trusted( string $ip, array $proxies ): bool {
		foreach ( $proxies as $entry ) {
			if ( ! is_string( $entry ) ) {
				continue;
			}
			// Igual que al guardar: un /0 guardado antiguo no confia en nadie y un CIDR mapeado se lee como IPv4.
			$entry = self::normalize_trusted_proxy( $entry );
			if ( '' !== $entry && self::ip_matches( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}
}

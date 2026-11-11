<?php
/**
 * Genera dist/total-security-expert-<version>.zip con el plugin listo para instalar.
 *
 * Uso: php bin/build-zip.php
 *
 * No forma parte del plugin (esta en .distignore) y no depende de WordPress.
 *
 * @package TotalSecurityExpert
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.Security.EscapeOutput, WordPress.PHP.DiscouragedPHPFunctions

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

const TSEXP_BUILD_SLUG = 'total-security-expert';

/**
 * Termina con error: mensaje por STDERR y codigo distinto de 0.
 *
 * @param string $message Mensaje.
 */
function tsexp_build_fail( string $message ): never {
	fwrite( STDERR, "ERROR: {$message}\n" );
	exit( 1 );
}

/**
 * Lee la version de la cabecera "Version:" del fichero principal.
 *
 * @param string $main_file Ruta del fichero principal del plugin.
 * @return string
 */
function tsexp_build_version( string $main_file ): string {
	$head = file_get_contents( $main_file, false, null, 0, 8192 );
	if ( false === $head || 1 !== preg_match( '/^[ \t\/*#@]*Version:[ \t]*(\S+)[ \t]*$/mi', $head, $match ) ) {
		tsexp_build_fail( 'No se encuentra la cabecera Version: en total-security-expert.php.' );
	}
	if ( 1 !== preg_match( '/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/', $match[1] ) ) {
		tsexp_build_fail( "La version '{$match[1]}' no tiene formato X.Y.Z." );
	}
	return $match[1];
}

/**
 * Lee las entradas de .distignore: directorios (acaban en "/") y patrones de fichero.
 *
 * @param string $file Ruta de .distignore.
 * @return array{dirs: string[], patterns: string[]}
 */
function tsexp_build_ignore_rules( string $file ): array {
	$rules = array(
		'dirs'     => array(),
		'patterns' => array(),
	);
	if ( ! is_file( $file ) ) {
		return $rules;
	}
	$lines = file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
	if ( false === $lines ) {
		tsexp_build_fail( 'No se puede leer .distignore.' );
	}
	foreach ( $lines as $line ) {
		$line = trim( $line );
		if ( '' === $line || '#' === $line[0] ) {
			continue;
		}
		$line = ltrim( $line, '/' );
		if ( str_ends_with( $line, '/' ) ) {
			$rules['dirs'][] = rtrim( $line, '/' );
		} else {
			$rules['patterns'][] = $line;
		}
	}
	return $rules;
}

/**
 * Indica si una ruta relativa (con "/") queda fuera del zip.
 *
 * @param string                                    $rel     Ruta relativa a la raiz del plugin.
 * @param bool                                      $is_dir  Si es un directorio.
 * @param array{dirs: string[], patterns: string[]} $rules   Reglas de .distignore.
 * @return bool
 */
function tsexp_build_is_ignored( string $rel, bool $is_dir, array $rules ): bool {
	$top = explode( '/', $rel, 2 )[0];

	// Cualquier cosa que empiece por punto en la raiz, y bin/.
	if ( str_starts_with( $top, '.' ) || 'bin' === $top ) {
		return true;
	}
	// Directorios de .distignore, solo desde la raiz.
	if ( in_array( $top, $rules['dirs'], true ) && ( $is_dir || $top !== $rel ) ) {
		return true;
	}
	// Ficheros o patrones: sin "/" valen a cualquier profundidad (nombre); con "/" desde la raiz.
	foreach ( $rules['patterns'] as $pattern ) {
		$subject = str_contains( $pattern, '/' ) ? $rel : basename( $rel );
		if ( fnmatch( $pattern, $subject ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Recorre el plugin y devuelve las rutas relativas de los ficheros a incluir.
 *
 * @param string                                    $root  Raiz del plugin.
 * @param string                                    $rel   Subdirectorio actual ('' = raiz).
 * @param array{dirs: string[], patterns: string[]} $rules Reglas de .distignore.
 * @return string[]
 */
function tsexp_build_collect( string $root, string $rel, array $rules ): array {
	$dir     = '' === $rel ? $root : $root . '/' . $rel;
	$entries = scandir( $dir );
	if ( false === $entries ) {
		tsexp_build_fail( "No se puede leer el directorio {$dir}." );
	}
	sort( $entries, SORT_STRING );

	$files = array();
	foreach ( $entries as $entry ) {
		if ( '.' === $entry || '..' === $entry ) {
			continue;
		}
		$entry_rel = '' === $rel ? $entry : $rel . '/' . $entry;
		$abs       = $root . '/' . $entry_rel;
		if ( is_link( $abs ) ) {
			continue;
		}
		$is_dir = is_dir( $abs );
		if ( tsexp_build_is_ignored( $entry_rel, $is_dir, $rules ) ) {
			continue;
		}
		if ( $is_dir ) {
			$files = array_merge( $files, tsexp_build_collect( $root, $entry_rel, $rules ) );
		} elseif ( is_file( $abs ) ) {
			$files[] = $entry_rel;
		}
	}
	return $files;
}

/**
 * Programa principal.
 */
function tsexp_build_main(): void {
	if ( ! class_exists( 'ZipArchive' ) ) {
		tsexp_build_fail( 'Falta la extension zip de PHP (ZipArchive).' );
	}

	$root = str_replace( '\\', '/', dirname( __DIR__ ) );
	$main = $root . '/total-security-expert.php';
	if ( ! is_file( $main ) ) {
		tsexp_build_fail( 'No se encuentra total-security-expert.php.' );
	}

	$version = tsexp_build_version( $main );
	$rules   = tsexp_build_ignore_rules( $root . '/.distignore' );
	$files   = tsexp_build_collect( $root, '', $rules );
	if ( ! in_array( 'total-security-expert.php', $files, true ) ) {
		tsexp_build_fail( 'El fichero principal ha quedado fuera del zip.' );
	}

	$dist = $root . '/dist';
	if ( ! is_dir( $dist ) && ! mkdir( $dist, 0755, true ) && ! is_dir( $dist ) ) {
		tsexp_build_fail( 'No se puede crear dist/.' );
	}

	$target = $dist . '/' . TSEXP_BUILD_SLUG . '-' . $version . '.zip';
	$tmp    = $target . '.tmp';
	if ( file_exists( $tmp ) ) {
		unlink( $tmp );
	}

	$zip    = new ZipArchive();
	$opened = $zip->open( $tmp, ZipArchive::CREATE | ZipArchive::OVERWRITE );
	if ( true !== $opened ) {
		tsexp_build_fail( "No se puede crear el zip temporal (codigo {$opened})." );
	}
	foreach ( $files as $rel ) {
		if ( ! $zip->addFile( $root . '/' . $rel, TSEXP_BUILD_SLUG . '/' . $rel ) ) {
			$zip->close();
			unlink( $tmp );
			tsexp_build_fail( "No se puede anadir {$rel} al zip." );
		}
	}
	if ( ! $zip->close() ) {
		if ( file_exists( $tmp ) ) {
			unlink( $tmp );
		}
		tsexp_build_fail( 'No se puede escribir el zip.' );
	}
	if ( ! rename( $tmp, $target ) ) {
		unlink( $tmp );
		tsexp_build_fail( 'No se puede renombrar el zip temporal.' );
	}

	echo "Zip: {$target}\n";
	echo 'Ficheros incluidos (' . count( $files ) . "):\n";
	foreach ( $files as $rel ) {
		echo '  ' . TSEXP_BUILD_SLUG . '/' . $rel . "\n";
	}
}

tsexp_build_main();

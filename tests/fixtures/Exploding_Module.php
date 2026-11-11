<?php
/**
 * Fichero de modulo que falla en cuanto se carga.
 *
 * Los tests de modo seguro comprueban que este fichero NUNCA se carga con TSEXP_SAFE_MODE activo.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Fixtures;

throw new \RuntimeException( 'Exploding_Module: el fichero se ha cargado.' );

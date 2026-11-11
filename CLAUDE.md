# Plugin de seguridad para WordPress

## Qué es

Plugin de seguridad ligero, por módulos que se activan por separado. Versión
inicial, sin instalaciones todavía.

Vamos a llamarlo Total Security Expert, el slug será total-security-expert.
Prefijo: `tsexp_` (constantes `TSEXP_`, namespace `TotalSecurityExpert`).

## Tecnología

- PHP 8.1 o superior. Sin dependencias en producción.
- Desarrollo: Composer, PHPUnit, PHPCS con WordPress Coding Standards.
- Pruebas manuales en WordPress Playground, nunca en una web real.
- Wordpress 7+

## Comandos

- Instalar herramientas de desarrollo: `composer install`
- Tests (PHPUnit + Brain Monkey): `composer test`
- Un solo fichero de tests: `composer test -- tests/unit/SettingsTest.php`
- Estilo (PHPCS + WordPress Coding Standards): `composer lint`
- Corregir estilo automáticamente: `composer lint:fix`
- Generar el zip del plugin en `dist/` (local; el release lo hace el workflow al subir un tag `vX.Y.Z`): `composer build`
- Sintaxis PHP de un fichero: `php -l ruta/fichero.php`
- Modo seguro (administrador bloqueado): `define( 'TSEXP_SAFE_MODE', true );` en `wp-config.php`

## Estructura

- `total-security-expert.php`: cabecera y arranque
- `docs/ARQUITECTURA.md`: interfaz de módulo y contrato del núcleo
- `includes/`: núcleo (cargador de módulos, ajustes, registro de eventos)
- `modules/<nombre>/`: un módulo por carpeta, todos con la misma interfaz
- `admin/`: pantalla de ajustes
- `tests/`: un fichero de tests por módulo

## Qué significa "terminado"

- Los tests y el linter pasan.
- El módulo se ha probado activado y desactivado en Playground.
- El plugin entero se activa y se desactiva sin errores ni avisos de PHP.
- El revisor de seguridad no deja ningún hallazgo grave abierto.

## Qué no se toca

- Ningún servidor ni web real. Todo se prueba en local.
- Nada fuera de esta carpeta.

## Convenciones

- Prefijo único en funciones, clases, opciones y hooks.
- Toda entrada saneada y toda salida escapada.
- Nonce y `current_user_can()` en cada acción; `permission_callback` en REST.
- SQL siempre con `$wpdb->prepare()`.
- Comprobación de `ABSPATH` al principio de cada fichero PHP.
- Un fallo de un módulo no puede tumbar la web ni dejar al administrador fuera.
- Ninguna llamada a servicios externos sin una opción para apagarla.
- Textos preparados para traducir, con el text domain del plugin.
- Al desinstalar, el plugin borra sus opciones y sus tablas.

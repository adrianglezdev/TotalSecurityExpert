# Arquitectura de Total Security Expert

Contrato común entre el núcleo y los módulos. Todo el que escriba código del
plugin trabaja contra este documento.

## Identidad

- Nombre: Total Security Expert. Slug y text domain: `total-security-expert`.
- Fichero principal: `total-security-expert.php`.
- Prefijo: `tsexp_` en funciones, opciones, hooks, transients, crons y tablas
  (`{$wpdb->prefix}tsexp_*`). Constantes `TSEXP_*`. Clases en el namespace
  `TotalSecurityExpert` (módulos en `TotalSecurityExpert\Modules`).
- PHP 8.1+, WordPress 7.0+. Sin dependencias en producción (Composer solo para
  desarrollo; el plugin no carga `vendor/`).
- Cada fichero PHP empieza con `defined( 'ABSPATH' ) || exit;` (salvo
  `uninstall.php`, que comprueba `WP_UNINSTALL_PLUGIN`).

## Ficheros

```
total-security-expert.php          cabecera, constantes, require de includes/, hooks de activación
uninstall.php                      borra opciones, tablas, crons y transients
includes/interface-module.php      TotalSecurityExpert\Module
includes/abstract-class-module.php TotalSecurityExpert\Abstract_Module
includes/class-plugin.php          TotalSecurityExpert\Plugin (arranque, activación, crons)
includes/class-module-loader.php   TotalSecurityExpert\Module_Loader (registro fijo, carga, aislamiento)
includes/class-context.php         TotalSecurityExpert\Context (lo que recibe cada módulo)
includes/class-settings.php        TotalSecurityExpert\Settings (opción tsexp_settings)
includes/class-event-log.php       TotalSecurityExpert\Event_Log (tabla tsexp_events)
includes/class-request.php         TotalSecurityExpert\Request (IP del cliente)
admin/class-admin.php              TotalSecurityExpert\Admin\Admin (menú, ajustes, visor del registro)
modules/<id>/class-<id>.php        un módulo por carpeta
tests/unit/                        PHPUnit + Brain Monkey; un *Test.php por módulo y uno del núcleo
```

## Registro de módulos

Lista fija en `Module_Loader` (no se escanean carpetas):

| id              | clase                                   | fichero                                         |
| --------------- | --------------------------------------- | ----------------------------------------------- |
| `login-limit`   | `Modules\Login_Limit`                   | `modules/login-limit/class-login-limit.php`     |
| `hardening`     | `Modules\Hardening`                     | `modules/hardening/class-hardening.php`         |
| `admin-alert`   | `Modules\Admin_Alert`                   | `modules/admin-alert/class-admin-alert.php`     |
| `activity-log`  | `Modules\Activity_Log`                  | `modules/activity-log/class-activity-log.php`   |

Si el fichero no existe, la clase no existe o no implementa `Module`, el
módulo se ignora y se apunta el error; el resto sigue.

## Interfaz de módulo

```php
namespace TotalSecurityExpert;

interface Module {
	public function get_id(): string;                 // igual que en el registro
	public function get_name(): string;               // traducible
	public function get_description(): string;        // traducible
	public function get_default_settings(): array;
	public function sanitize_settings( array $input ): array;   // devuelve ajustes limpios y completos
	public function render_settings( array $settings, string $name_prefix ): void; // pinta campos, todo escapado
	public function boot( Context $context, array $settings ): void;  // registra hooks; solo si está activo
	public function install(): void;                  // idempotente: crea sus tablas (dbDelta)
	public function uninstall(): void;                // borra sus tablas, opciones y transients
}
```

- El constructor no tiene efectos (no registra hooks, no toca la BD): el
  núcleo instancia todos los módulos para pintar y sanear sus ajustes aunque
  estén apagados.
- `boot()` solo registra hooks, y siempre a través de `$context->add_action()`
  / `$context->add_filter()`, nunca con `add_action()` directo.
- `render_settings()` recibe `$name_prefix` (por ejemplo
  `tsexp_settings[modules][login-limit][settings]`) y nombra cada campo
  `$name_prefix . '[clave]'`. No pinta `<form>`, nonce ni botón: eso es del
  núcleo. Nada de JavaScript inline.
- `sanitize_settings()` recibe datos sin confiar (pueden faltar claves o venir
  de otro tipo) y devuelve siempre todas las claves de
  `get_default_settings()`, con valores validados. Las listas (IP, correos)
  llegan como texto con una entrada por línea.
- `Abstract_Module` implementa `install()`, `uninstall()` vacíos,
  `render_settings()` vacío y `sanitize_settings()` que devuelve los valores
  por defecto; los módulos sobrescriben lo que necesiten.

## Context

```php
final class Context {
	public function add_action( string $hook, callable $cb, int $priority = 10, int $args = 1 ): void;
	public function add_filter( string $hook, callable $cb, int $priority = 10, int $args = 1 ): void;
	public function log( string $event, string $message, array $data = array(), string $severity = 'info' ): void;
	public function get_client_ip(): string;          // '' si no hay IP válida
	public function get_client_ip_bucket(): string;   // IPv4: la IP; IPv6: la red /64 en CIDR; '' si no hay IP
	public function get_module_id(): string;
}
```

- `add_action` / `add_filter` envuelven el callback en `try { } catch ( \Throwable )`.
  Si un callback lanza, se apunta el error (sin repetirlo en bucle: una vez
  por petición y módulo) y, si era un filtro, se devuelve el primer argumento
  sin cambiar. Así un módulo roto falla abierto y no tumba la web.
- `add_filter()` fuerza `$args` a 1 como mínimo: con 0, WordPress no pasa el
  valor y un filtro que lanzase devolvería `null` en vez del valor original.
- `log()` escribe en `Event_Log` con el id del módulo ya puesto.
- **Límite de intentos: contar por `get_client_ip_bucket()`, no por
  `get_client_ip()`.** Con IPv6 un atacante controla como mínimo un /64 (2^64
  direcciones) y rotando la IP exacta esquivaría cualquier contador. El bucket
  es la IP tal cual en IPv4 (una IPv4 mapeada en IPv6 cuenta como IPv4) y la red
  /64 en notación CIDR normalizada en IPv6 (`2001:db8:1:2::/64`); `''` si no hay
  IP. Cabe siempre en 45 caracteres (`varchar(45)`). `get_client_ip()` sigue
  sirviendo para mostrar y registrar la IP exacta.
- Los errores que un callback hace aflorar se guardan como
  `Clase @ hook: mensaje` con el mensaje recortado a 120 caracteres (sin
  ficheros, líneas ni traza).

## Event_Log

Tabla `{$wpdb->prefix}tsexp_events`:

`id` bigint unsigned auto, `created_at` datetime (UTC), `module` varchar(64),
`event` varchar(64), `severity` varchar(16) (`info`|`warning`|`critical`),
`user_id` bigint unsigned, `ip` varchar(45), `message` text, `data` longtext
(JSON). Índices en `created_at`, `module`, `event`.

- `Event_Log::log( string $module, string $event, string $message, array $data = array(), string $severity = 'info' ): void`
  sanea todo, recorta longitudes, guarda `data` con `wp_json_encode` y nunca
  lanza (un fallo de BD no puede romper la petición).
- Nunca se registran contraseñas, cookies, nonces ni tokens. Se redacta
  (`[redacted]`, también en datos anidados) toda clave de `data` que contenga
  `pass`, `pwd`, `cookie`, `nonce`, `token`, `secret` o `authoriz`, o que tenga
  como segmento (separado por `_`, `-`, espacio o mayúscula: `api_key`,
  `apiKey`; también en plural) alguna de `key`, `auth`, `session`, `otp`,
  `code`, `hash`, `salt`, `credential`, `apikey`. Las segundas no son por
  subcadena para no ocultar claves legítimas (`monkey`, `author`, `footprint`).
  Las claves que usan hoy los módulos (`user_login`, `ip`, `role`, `option`,
  `old`, `new`, `count`, `user_id`...) no se redactan; **un módulo no debe
  poner datos en claves con esos nombres.**
- Purga diaria (cron `tsexp_daily`) de lo que pase de
  `general.log_retention_days` (por defecto 30, 1–365).
- Tope de filas: el cron `tsexp_hourly` recorta la tabla a
  `general.log_max_rows` (por defecto 50 000, entre 1 000 y 1 000 000) con
  `Event_Log::trim_to_max_rows()`, borrando las más antiguas (por `id`) con
  `$wpdb->prepare()`.
- Lectura paginada para el visor, siempre con `$wpdb->prepare()`.

## Request / IP del cliente

- Por defecto, solo `REMOTE_ADDR`.
- Ajuste `general.ip_source`: `remote_addr` | `x_forwarded_for` |
  `x_real_ip` | `cf_connecting_ip`. La cabecera solo se usa si `REMOTE_ADDR`
  está en `general.trusted_proxies` (IPs o CIDR, IPv4 e IPv6). En
  `X-Forwarded-For` se toma la IP más a la derecha que no sea un proxy de
  confianza. Todo se valida con `FILTER_VALIDATE_IP`.
- Antes de validar una IP de cabecera se quitan el puerto y los corchetes
  (`1.2.3.4:5678`, `[2001:db8::1]:443`, `[2001:db8::1]`); un puerto no
  numérico o mayor de 65535 invalida la cabecera.
- `trusted_proxies` se sanea con `Request::normalize_trusted_proxy()`: se
  rechazan los rangos más anchos que `/8` (IPv4) o `/32` (IPv6) (`0.0.0.0/0`, `::/0`, y también `0.0.0.0/1` + `128.0.0.0/1`, que juntos cubren todo IPv4 y dejarían fijar la IP con una cabecera; los rangos de Cloudflare caben) y
  un CIDR IPv4 mapeado en IPv6 se pasa a IPv4 (`::ffff:10.0.0.0/104` →
  `10.0.0.0/8`; con prefijo menor de /97 se rechaza). Las entradas descartadas
  se avisan con `add_settings_error()`. Al comparar, las entradas guardadas se
  normalizan igual (un rango demasiado ancho guardado a mano no confía en nadie).
- La pantalla de ajustes avisa si `ip_source` no es `remote_addr` y no hay
  proxies de confianza, y si llegan cabeceras `X-Forwarded-For`, `X-Real-IP` o
  `CF-Connecting-IP` y `ip_source` es `remote_addr` o `REMOTE_ADDR` no está en la
  lista (tras un proxy sin configurar todos los visitantes compartirían IP).
- `Request::ip_matches()` / `is_valid_ip_or_cidr()` no cambian y aceptan `/0`
  (las usan listas de permitidos de los módulos); el rechazo del `/0` es solo de
  la lista de proxies de confianza.

## Ajustes

Una sola opción `tsexp_settings` (Settings API, grupo `tsexp_settings`,
capacidad `manage_options`):

```php
array(
	'general' => array( 'ip_source' => 'remote_addr', 'trusted_proxies' => array(), 'log_retention_days' => 30, 'log_max_rows' => 50000 ),
	'modules' => array( '<id>' => array( 'enabled' => false, 'settings' => array( /* del módulo */ ) ) ),
)
```

- Todos los módulos vienen apagados al activar.
- `Settings::sanitize()` valida `general`, descarta ids desconocidos y llama a
  `sanitize_settings()` de cada módulo dentro de `try/catch`.
- Si un id del registro no tiene módulo cargado (fichero roto, clase inválida o
  modo seguro), `sanitize()` conserva sin tocar el bloque guardado de ese id (no
  se pierde al guardar); si no había bloque guardado, no se crea.
- Lectura con valores por defecto mezclados: `Settings::get_module_settings( $id )`.

## Aislamiento y recuperación

- Si `TSEXP_SAFE_MODE` está definida y vale `true`, `1`, `'1'` o `'true'` (en
  `wp-config.php`; se evalúa con `FILTER_VALIDATE_BOOLEAN`), no se hace `require`
  de ningún fichero de módulo ni en el front, ni en el admin, ni al activar, ni
  al desinstalar: `Module_Loader::load()` no carga nada, `get_modules()` está
  vacío y no arranca ningún módulo. `get_registry_ids()` da los ids del registro
  sin ejecutar código de módulos. La pantalla de ajustes muestra un aviso de modo
  seguro y los módulos como no disponibles. Es la salida para un administrador
  bloqueado. Desinstalar en modo seguro no llama a `uninstall()` de los módulos,
  pero sí borra sus tablas gracias al barrido por prefijo (ver "Desinstalar").
- La carga de cada fichero de módulo y su `boot()` van dentro de
  `try/catch ( \Throwable )`. Los errores se guardan en la opción
  `tsexp_module_errors` (id → mensaje corto y fecha) y se avisan en el
  escritorio a quien tenga `manage_options`.
- Solo se guarda clase de la excepción + hook + mensaje recortado a 120
  caracteres (`Module_Loader::format_error()`). La opción no se escribe más de
  una vez por módulo cada 10 minutos (transient `tsexp_err_lock_<id>`), aunque
  el mensaje cambie; guardar los ajustes borra los errores y los bloqueos.

## Crons

El núcleo programa `tsexp_hourly` (recorta el registro a `log_max_rows`) y
`tsexp_daily` (purga por días) al activar, los reprograma si faltan y los quita
al desactivar. Los módulos se cuelgan de ellos con
`$context->add_action()`.

## Activación, desactivación y desinstalación

- Activar: crea `tsexp_events`, llama a `install()` de todos los módulos
  registrados (estén activos o no), guarda `tsexp_db_version`, programa crons.
- Desactivar: quita crons. No borra datos.
- Desinstalar: `Plugin::uninstall( ?Module_Loader $loader = null )` (los tests
  inyectan un cargador; en producción se usa el real y se llama a `uninstall()`
  de cada módulo cargado, dentro de `try/catch`), borra `tsexp_events`, las
  opciones `tsexp_*` y los transients `_transient_tsexp_*` /
  `_transient_timeout_tsexp_*` (y sus equivalentes `_site_transient_`). Los
  patrones `LIKE` pasan por `$wpdb->esc_like()`, así que `_` no es comodín.
- Red de seguridad, sin cargar código de módulos (necesaria en modo seguro):
  `Plugin::drop_tsexp_tables()` busca con
  `SHOW TABLES LIKE '<esc_like($wpdb->prefix . "tsexp_")>%'` y lo mismo con
  `$wpdb->base_prefix` (todas las tablas usan `$wpdb->prefix`; el barrido de
  `base_prefix` es solo por seguridad; si coinciden, una sola consulta;
  multisitio no está soportado en la v1) y borra cada tabla con `DROP TABLE IF EXISTS %i` (vía
  `prepare()`). Solo se borran nombres que empiezan exactamente por el prefijo
  más `tsexp_`: `wp_tsexpfoo` o `wp_other_tsexp_x` no se tocan.

## Administración

Menú propio "Total Security" con dos páginas:

1. Ajustes: sección general y una sección por módulo (casilla de activar más
   los campos de `render_settings()`), un solo formulario a `options.php`. En
   modo seguro, aviso y cada módulo del registro como "no disponible".
2. Registro: tabla paginada de `tsexp_events`, filtro por módulo y gravedad
   (valores en lista blanca), todo escapado. Solo `manage_options`.

## Tests

- PHPUnit + Brain Monkey (sin BD real; `$wpdb` simulado cuando haga falta).
- Cada módulo tiene `tests/unit/<Modulo>Test.php` con tests de lo que bloquea
  y de lo que deja pasar.
- `composer test` y `composer lint` deben pasar.

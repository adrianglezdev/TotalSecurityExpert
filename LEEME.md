# Plugin de seguridad para WordPress: proyecto con orquestador

Proyecto de Claude Code preparado para desarrollar un plugin de seguridad con
un agente principal que reparte el trabajo, subagentes más baratos que lo
hacen y un revisor que comprueba la seguridad de cada módulo.

Esta carpeta solo tiene la configuración. El código del plugin lo escribe el
propio proyecto a partir del primer mensaje.

## Qué hay

| Fichero | Para qué |
| --- | --- |
| `.claude/settings.json` | Modelo principal, agente de arranque, advisor y un solo nivel de delegación |
| `.claude/agents/orquestador.md` | Agente principal (Fable): reparte, comprueba y junta |
| `.claude/agents/explorador.md` | Búsqueda en solo lectura (Haiku) |
| `.claude/agents/implementador.md` | Escribe código y ejecuta tests (Sonnet) |
| `.claude/agents/revisor-seguridad.md` | Revisa cada módulo en solo lectura (Opus) |
| `CLAUDE.md` | Datos y convenciones del plugin |

## Puesta en marcha

1. Decide el nombre, el slug y el prefijo del plugin y ponlos en `CLAUDE.md`.
2. Abre esta carpeta como proyecto en Claude Code. La configuración solo se
   aplica a las sesiones abiertas aquí.
3. Escribe `/advisor` para ver si el advisor está activo. Si no lo está,
   actívalo con `/advisor fable`.
4. Pega el primer mensaje.

## Primer mensaje

```
Objetivo: primera versión de un plugin de seguridad para WordPress con cuatro
módulos independientes: límite de intentos de acceso, endurecimiento (XML-RPC,
editor de ficheros, enumeración de usuarios), aviso por correo cuando aparece
un administrador nuevo y registro de actividad.
Terminado cuando: se cumple lo que dice CLAUDE.md para cada módulo y el plugin
se activa sin errores en Playground.
No tocar: nada fuera de esta carpeta.
Contexto: empieza por composer.json con los scripts de tests y linter, el
núcleo y la interfaz de módulo; después un módulo por subagente.
```

## Qué mirar en la primera prueba

- Que el núcleo se haga antes y los cuatro módulos se repartan en paralelo.
- Que cada módulo pase por `revisor-seguridad` y los hallazgos graves vuelvan
  al implementador.
- Que el orquestador consulte al advisor para el diseño de la interfaz y antes
  de dar la tarea por terminada.
- Que el informe final distinga lo comprobado de lo que no se ha comprobado.

## Ajustes que puedes cambiar

- **Modelo de un agente**: el campo `model:` de su fichero (`haiku`, `sonnet`,
  `opus`, `fable` o `inherit`).
- **Más agentes**: un fichero nuevo en `.claude/agents/`. El orquestador elige
  por el campo `description`, que debe decir cuándo usarlo.
- **Skills precargadas**: el frontmatter admite un campo `skills`. Si tienes
  instalada `wp-plugin-development`, al implementador le vendría bien; la
  sintaxis exacta está en la documentación de subagentes.
- **Niveles de delegación**: `CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH` (aquí `1`).
- **Volver al Claude Code normal**: quita la línea `"agent": "orquestador"` de
  `settings.json`.

## A tener en cuenta

- El advisor es una función experimental y necesita Claude Code 2.1.260 o
  superior.
- `advisorModel` está puesto en los ajustes del proyecto. La documentación lo
  describe como ajuste de usuario; si aquí no surte efecto, usa `/advisor fable`.
- La revisión del agente no sustituye a una revisión humana antes de instalar
  el plugin en una web con datos reales.
- Esta configuración no se ha probado todavía en una sesión real.

## Publicar una versión (release en GitHub)

El repositorio es `adrianglezdev/TotalSecurityExpert`. Cada versión se publica
como un release con el zip del plugin adjunto; lo crea el workflow
`.github/workflows/release.yml` al subir un tag `v*`.

1. Sube la versión en los dos sitios de `total-security-expert.php`: la
   cabecera `Version:` y la constante `TSEXP_VERSION` (y en
   `tests/bootstrap.php`). El workflow falla si el tag no coincide con ambas.
2. Anota los cambios en `CHANGELOG.md`.
3. `composer test && composer lint`
4. Haz commit.
5. `git tag vX.Y.Z && git push origin main --tags`
6. El workflow ejecuta tests y lint, comprueba las versiones, construye el zip
   y crea el release con el zip adjunto y las notas generadas.

`composer build` genera el zip en local (`dist/total-security-expert-<versión>.zip`)
con lo que dejan pasar `.distignore`, los ficheros que empiezan por punto en la
raíz y `bin/`. Sirve para probarlo antes de subir el tag.
## Documentación

- Advisor: https://code.claude.com/docs/en/advisor
- Subagentes: https://code.claude.com/docs/en/sub-agents
- Modelos: https://code.claude.com/docs/en/model-config

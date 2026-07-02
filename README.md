# pci-dss-vulnerable-demo

Repo de práctica con fallas de seguridad **intencionales**, mapeadas a **PCI-DSS v4.0**, para usar como target de prueba de IONIX Sentinel: código para el Analizador Estático (Fase 1) y logs de producción para el Analizador de Logs (Fase 2, stretch goal).

Stack: Node.js + TypeScript + Next.js + React + Postgres — el mismo stack de la solución real, para que el analizador la pruebe contra código representativo.

**No desplegar ni usar como base de un proyecto real.** Las credenciales, keys y datos de tarjeta son ficticios pero el patrón de la falla es real.

## Cómo usarlo con Sentinel

1. Apuntar el Analizador Estático a este repo (o a una PR sobre él).
2. Comparar los hallazgos que emite Sentinel contra `findings-expected.json` (ground truth) para medir precisión y recall antes de la demo.
3. `findings-expected.json` tiene dos listas: `real_violations` (debe detectarlas) y `negative_controls` (NO debe marcarlas como violación — sirven para probar que el motor de reglas no genera falsos positivos, ej. la validación de Luhn).

## Catálogo de vulnerabilidades reales (12 escenarios)

Algunos escenarios abarcan más de una línea vulnerable (ej. VULN-003 tiene 4 sub-hallazgos en el mismo archivo); por eso `findings-expected.json` lista 18 entradas individuales en `real_violations` bajo estos 12 IDs base.

| ID | Archivo | Requisito PCI-DSS v4 | Descripción |
|---|---|---|---|
| VULN-001 | `lib/db.ts` | 8.6.2 | Password de la cuenta de aplicación hardcodeada en el código |
| VULN-002 | `migrations/001_init.sql` | 3.5.1 / 3.3.2 / 3.3.3 | Tabla `cardholders` guarda PAN, CVV y track2 en texto plano |
| VULN-003 | `pages/api/payments/charge.ts` | 3.4.1 / 6.2.4 / 3.3.2 | PAN+CVV en logs, SQL injection, y persistencia de SAD (CVV/track2) |
| VULN-004 | `lib/crypto.ts` | 3.6.1 | Clave de cifrado hardcodeada + AES-128-ECB (modo débil) |
| VULN-005 | `lib/auth.ts` | 8.6.2 | Secreto JWT hardcodeado, tokens sin expiración |
| VULN-006 | `pages/api/payments/[id].ts` | 7.2.1 | Endpoint sin auth que expone PAN/CVV/track2 completos |
| VULN-007 | `pages/api/payments/refund.ts` | 4.2.1 | PAN viaja como query param en GET |
| VULN-008 | `components/CheckoutForm.tsx` | 3.3 / 3.4.1 | PAN+CVV en `localStorage` y en `console.log` del navegador |
| VULN-009 | `pages/api/webhooks/stripe.ts` | 8.6.2 | API key de Stripe hardcodeada |
| VULN-010 | `components/AdminReconciliation.tsx` | 3.4.1 | PAN mostrado completo sin enmascarar en la UI |
| VULN-011 | `lib/db.ts` | 4.2.1 | Conexión a Postgres sin TLS (`ssl: false`) |
| VULN-012 | `pages/api/auth/login.ts` | 6.2.4 | Stack trace y error crudo devueltos al cliente |
| VULN-013 | `lib/db.ts` | 8.6.2 | Password de DB en texto plano logueada ante error del pool |
| VULN-014 | `lib/auth.ts` | 8.6.2 | Secreto JWT logueado en cada fallo de verificación |
| VULN-015 | `pages/api/auth/login.ts` | 6.2.4 | Log de intento fallido con mensaje fijo + stack trace logueado en servidor |
| VULN-016 | `pages/api/payments/refund.ts` | 3.4.1 | PAN completo logueado al procesar un refund |
| VULN-017 | `pages/api/payments/[id].ts` | 3.3.2 | Registro completo del cardholder (PAN/CVV/track2) logueado en cada consulta |

Cada archivo tiene el hallazgo comentado inline con el prefijo `VULN-XXX` y el requisito PCI-DSS correspondiente — útil tanto para que el LLM del Motor de Razonamiento tenga contexto, como para auditar manualmente los resultados.

Los VULN-013 a VULN-017 son los que además generan logs de producción reutilizables para la Fase 2 (ver sección siguiente): son las funciones que loguean el dato sensible, no solo lo persisten o lo devuelven en la respuesta HTTP.

## Controles negativos / trampas de falso positivo (3)

Para probar que el motor de reglas determinístico no dispara falsos positivos (uno de los "gotchas" del proyecto: regex de PAN sin Luhn genera ruido masivo):

- **`lib/testCards.ts`** — números de 16 dígitos que fallan el checksum de Luhn. No son PAN reales y no deberían marcarse como hallazgo.
- **`lib/mask.ts`** — implementación correcta de enmascaramiento de PAN (primeros 6 + últimos 4). No debería marcarse.
- **`lib/crypto.ts` → `encryptPanStrong`** — AES-256-GCM con clave desde variable de entorno e IV aleatorio: ejemplo de cifrado fuerte correctamente implementado. No debería marcarse como violación.

## Fase 2 — Logs de producción (stretch goal)

`logs/production-sample.log` es un log de aplicación en formato NDJSON (una línea = un JSON), generado por `scripts/generate-production-logs.js`, que simula el tráfico que el propio producto demo emitiría en producción: cargos, refunds, webhooks, consultas de conciliación y logins.

Correr `node scripts/generate-production-logs.js > logs/production-sample.log` regenera el archivo de forma determinística.

### Cómo correr el análisis contra este fixture

El Analizador de Logs necesita dos rutas: dónde está el log y dónde está el código para la correlación (HU-B4.2). En este repo ambas cosas son la **misma carpeta raíz**, porque `logs/` vive a propósito junto al código. Ejemplo de invocación:

```bash
sentinel analyze-logs --log <ruta-fixture>/logs/production-sample.log --repo <ruta-fixture>
```

Donde `<ruta-fixture>` es donde tengan este repo checkeado localmente (ver sección de HU-B1.1 en `epicas-historias.md` sobre cómo traerlo como carpeta separada sin cambiar de rama: worktree, ZIP de la rama, o submódulo).

Notas de implementación:

- El archivo es **NDJSON** (una línea = un JSON completo e independiente). Basta iterar línea por línea y hacer `JSON.parse` — no requiere un parser más complejo.
- El motor de reglas es el mismo que el del Analizador Estático (regla dura del proyecto: no se construye uno paralelo). En la práctica, cada línea de log se puede tratar como "contenido a analizar" y pasarse por las mismas reglas propias PCI-DSS que ya corren sobre código, generando un finding con el mismo esquema pero `"origin": "log"`.
- Para validar el resultado, comparar los hallazgos emitidos contra `log_violations`, `log_negative_controls` y `log_anomalies` en `findings-expected.json` (no solo contra `real_violations`/`negative_controls`, que son los de código).

### Correlación código↔log (HU-B4.2)

Los mensajes de log reutilizan el **mismo literal fijo** que el `console.log`/`console.error` del código fuente que los origina (VULN-013 a VULN-017, más VULN-003a, VULN-007 y VULN-009). Esto es a propósito: la especificación del proyecto dice que la correlación se resuelve con un grep del string literal del log sobre el repo — no algo más sofisticado. Ejemplo: la línea de log con `"Procesando cargo de ..."` se resuelve haciendo `grep -r "Procesando cargo de" .`, que apunta directo a `pages/api/payments/charge.ts`.

`findings-expected.json` tiene un bloque `log_violations` con 8 hallazgos, cada uno con su `grep_literal` (el string a buscar) y `correlates_with` (el VULN-ID y archivo de código esperado como resultado de esa correlación) — pensado para automatizar el test de HU-B4.1/B4.2 sin intervención manual.

### Controles negativos en logs

`log_negative_controls` en el mismo JSON cubre los mismos dos casos de falso positivo que en código, ahora en logs: un PAN que falla Luhn (no debe marcarse) y un PAN ya enmascarado (no debe marcarse).

### Anomalía por umbral (HU-B4.3)

El log incluye una ráfaga de 55 intentos fallidos de login desde la misma IP (`203.0.113.7`) en menos de 60 segundos, seguida de un login exitoso — pensado para probar una regla de umbral simple ("más de N intentos fallidos por IP en una ventana de tiempo"). Está documentada en `log_anomalies` → `LOG-ANOM-1`, junto con la regla de detección sugerida. Importante: esto **no es detección con ML**, es una regla de umbral explícita — decirlo tal cual si se muestra en la demo (regla dura del proyecto).

## Nota sobre el mapeo a requisitos

Los números de requisito PCI-DSS v4.0 usados aquí son el mapeo más cercano y representativo para cada patrón de falla (hardcoded secrets, PAN sin proteger, SAD persistida, etc.), pensado para la demo del hackathon. Antes de citarlos en cualquier material externo o de cumplimiento real, verificar contra el texto oficial de PCI-DSS v4.0.1.

## Estructura

```
pci-dss-vulnerable-demo/
├── README.md
├── findings-expected.json     # ground truth (código + logs) para medir precisión/recall
├── migrations/001_init.sql
├── lib/
│   ├── db.ts                  # VULN-001, VULN-011, VULN-013
│   ├── crypto.ts              # VULN-004, trampa T3
│   ├── auth.ts                # VULN-005, VULN-014
│   ├── mask.ts                # trampa T2
│   └── testCards.ts           # trampa T1
├── pages/
│   ├── index.tsx
│   └── api/
│       ├── payments/charge.ts       # VULN-003
│       ├── payments/[id].ts         # VULN-006, VULN-017
│       ├── payments/refund.ts       # VULN-007, VULN-016
│       ├── webhooks/stripe.ts       # VULN-009
│       └── auth/login.ts            # VULN-012, VULN-015
├── components/
│   ├── CheckoutForm.tsx        # VULN-008
│   └── AdminReconciliation.tsx # VULN-010
├── scripts/
│   └── generate-production-logs.js  # genera logs/production-sample.log
└── logs/
    └── production-sample.log  # Fase 2 — target del Analizador de Logs
```

# pci-dss-vulnerable-demo

Repo de práctica con fallas de seguridad **intencionales**, mapeadas a **PCI-DSS v4.0**, para usar como target de prueba de IONIX Sentinel (analizador estático de la Fase 1).

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

Cada archivo tiene el hallazgo comentado inline con el prefijo `VULN-XXX` y el requisito PCI-DSS correspondiente — útil tanto para que el LLM del Motor de Razonamiento tenga contexto, como para auditar manualmente los resultados.

## Controles negativos / trampas de falso positivo (3)

Para probar que el motor de reglas determinístico no dispara falsos positivos (uno de los "gotchas" del proyecto: regex de PAN sin Luhn genera ruido masivo):

- **`lib/testCards.ts`** — números de 16 dígitos que fallan el checksum de Luhn. No son PAN reales y no deberían marcarse como hallazgo.
- **`lib/mask.ts`** — implementación correcta de enmascaramiento de PAN (primeros 6 + últimos 4). No debería marcarse.
- **`lib/crypto.ts` → `encryptPanStrong`** — AES-256-GCM con clave desde variable de entorno e IV aleatorio: ejemplo de cifrado fuerte correctamente implementado. No debería marcarse como violación.

## Nota sobre el mapeo a requisitos

Los números de requisito PCI-DSS v4.0 usados aquí son el mapeo más cercano y representativo para cada patrón de falla (hardcoded secrets, PAN sin proteger, SAD persistida, etc.), pensado para la demo del hackathon. Antes de citarlos en cualquier material externo o de cumplimiento real, verificar contra el texto oficial de PCI-DSS v4.0.1.

## Estructura

```
pci-dss-vulnerable-demo/
├── README.md
├── findings-expected.json     # ground truth para medir precisión/recall
├── migrations/001_init.sql
├── lib/
│   ├── db.ts                  # VULN-001, VULN-011
│   ├── crypto.ts              # VULN-004, trampa T3
│   ├── auth.ts                # VULN-005
│   ├── mask.ts                # trampa T2
│   └── testCards.ts           # trampa T1
├── pages/
│   ├── index.tsx
│   └── api/
│       ├── payments/charge.ts       # VULN-003
│       ├── payments/[id].ts         # VULN-006
│       ├── payments/refund.ts       # VULN-007
│       ├── webhooks/stripe.ts       # VULN-009
│       └── auth/login.ts            # VULN-012
└── components/
    ├── CheckoutForm.tsx        # VULN-008
    └── AdminReconciliation.tsx # VULN-010
```

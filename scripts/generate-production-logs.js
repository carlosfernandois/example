#!/usr/bin/env node
/**
 * Generador de logs de producción (Fase 2 — Analizador de Logs).
 *
 * Simula el tráfico que el "producto demo" (la app Next.js de
 * pci-dss-vulnerable-demo) emitiría en sus logs de aplicación al recibir
 * pagos, refunds, webhooks y logins. Los mensajes usan EXACTAMENTE los
 * mismos literales fijos que los console.log/console.error del código
 * fuente (ver comentarios VULN-XXX en lib/ y pages/api/), para que la
 * correlación código↔log de HU-B4.2 (grep del string literal del log sobre
 * el repo) funcione tal como está especificado en el proyecto.
 *
 * Uso: node scripts/generate-production-logs.js > logs/production-sample.log
 */

const LINES = [];
let t = new Date("2026-07-02T14:00:00.000Z").getTime();

function ts() {
  t += 1000 + Math.floor(Math.random() * 4000);
  return new Date(t).toISOString();
}

function reqId(n) {
  return `req_${String(n).padStart(5, "0")}`;
}

function line(level, service, route, message, extra = {}) {
  LINES.push(
    JSON.stringify({
      timestamp: ts(),
      level,
      service,
      route,
      message,
      ...extra,
    })
  );
}

// ---- Tráfico benigno de fondo (ruido, sin violaciones) ---------------------
line("info", "payments-api", null, "Server listening on port 3000");
line("info", "payments-api", "/api/health", "Health check OK");
line("info", "payments-api", "/api/health", "Health check OK");

// ---- LOG-001 [correlaciona con pages/api/payments/charge.ts VULN-003a] ----
// Tarjetas de prueba con Luhn válido (generadas para la demo, no reales).
const validPans = [
  "4539148803436467",
  "5500005555555559",
  "340000000000009",
  "6011000000000004",
];
validPans.forEach((pan, i) => {
  const amount = (25 + i * 10).toFixed(2);
  const cvv = 100 + i;
  line(
    "info",
    "payments-api",
    "/api/payments/charge",
    `Procesando cargo de ${amount} para PAN=${pan} CVV=${cvv}`,
    { requestId: reqId(i + 1) }
  );
});

// ---- LOG-002 [correlaciona con pages/api/webhooks/stripe.ts VULN-009] -----
line(
  "info",
  "payments-api",
  "/api/webhooks/stripe",
  "Verificando webhook con key: sk_live_FAKE_DEMO_KEY_NOT_REAL_0000000000",
  { requestId: reqId(10) }
);

// ---- LOG-016 [correlaciona con pages/api/payments/refund.ts VULN-016] ----
line(
  "info",
  "payments-api",
  "/api/payments/refund",
  `Refund solicitado con PAN=${validPans[0]} monto=25.00`,
  { requestId: reqId(11) }
);
// Acceso HTTP crudo mostrando el PAN en la query string (VULN-007).
line(
  "info",
  "access-log",
  "/api/payments/refund",
  `GET /api/payments/refund?pan=${validPans[0]}&amount=25.00 HTTP/1.1 200`,
  { requestId: reqId(11), sourceIp: "190.100.45.12" }
);

// ---- LOG-017 [correlaciona con pages/api/payments/[id].ts VULN-017] ------
line(
  "info",
  "payments-api",
  "/api/payments/42",
  `Registro de conciliación consultado: {"id":42,"customer_email":"cliente42@ionix.cl","pan":"${validPans[1]}","cvv":"321","track2_data":";4539148803436467=29051019999900000000?","expiry_date":"09/29"}`,
  { requestId: reqId(12) }
);

// ---- LOG-013 [correlaciona con lib/db.ts VULN-013] ------------------------
line(
  "error",
  "payments-api",
  null,
  "Error en el pool de Postgres usando postgres://app_user:P4ymentsProd!2024@db.ionix-payments.internal:5432/ionix_payments",
  { requestId: reqId(13), errorCode: "ECONNRESET" }
);

// ---- LOG-014 [correlaciona con lib/auth.ts VULN-014] ----------------------
line(
  "error",
  "payments-api",
  "/api/payments/1",
  "Fallo al verificar token con secret=changeme jwt malformed",
  { requestId: reqId(14) }
);

// ---- LOG-015b [correlaciona con pages/api/auth/login.ts VULN-015b] -------
line(
  "error",
  "payments-api",
  "/api/auth/login",
  'Error de login: relation "users" does not exist at Object.query (/app/lib/db.ts:19:10)',
  { requestId: reqId(15) }
);

// ---- Controles negativos (no deberían marcarse como PAN real) -----------
// TRAP: número de 16 dígitos que falla Luhn (definido en lib/testCards.ts).
line(
  "warn",
  "payments-api",
  "/api/payments/charge",
  "Intento de pago con PAN=4111111111111112 rechazado: número de tarjeta inválido",
  { requestId: reqId(16) }
);
// TRAP: PAN ya enmascarado correctamente (usa el formato de lib/mask.ts).
line(
  "info",
  "payments-api",
  "/api/payments/charge",
  "Pago confirmado para tarjeta 453914******6467",
  { requestId: reqId(17) }
);

// ---- LOG-ANOM-1 [HU-B4.3 — anomalía por umbral, NO es ML] -----------------
// Ráfaga de intentos fallidos de login desde la misma IP en una ventana
// corta: regla simple "más de N intentos fallidos por IP en 60s".
const bruteForceIp = "203.0.113.7";
for (let i = 0; i < 55; i++) {
  line(
    "warn",
    "payments-api",
    "/api/auth/login",
    `Error de login: credenciales inválidas para email=admin@ionix.cl`,
    { requestId: reqId(100 + i), sourceIp: bruteForceIp }
  );
}
// Intento exitoso justo después de la ráfaga (posible cuenta comprometida).
line(
  "info",
  "payments-api",
  "/api/auth/login",
  "Login exitoso para email=admin@ionix.cl",
  { requestId: reqId(200), sourceIp: bruteForceIp }
);

// ---- Más ruido benigno al final ------------------------------------------
line("info", "payments-api", "/api/health", "Health check OK");

console.log(LINES.join("\n"));

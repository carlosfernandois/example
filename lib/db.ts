import { Pool } from "pg";

// VULN-001 [PCI-DSS 8.6.2] — Credenciales de la cuenta de aplicación hardcodeadas
// en el código fuente en vez de leerse desde variables de entorno / vault.
// VULN-011 [PCI-DSS 4.2.1] — ssl explícitamente deshabilitado: la conexión a la
// base de datos (que transporta PAN) viaja sin cifrado fuerte.
const CONNECTION_STRING =
  "postgres://app_user:P4ymentsProd!2024@db.ionix-payments.internal:5432/ionix_payments";

export const pool = new Pool({
  host: "db.ionix-payments.internal",
  port: 5432,
  user: "app_user",
  password: "P4ymentsProd!2024", // VULN-001: password hardcodeada
  database: "ionix_payments",
  ssl: false, // VULN-011: sin TLS para tráfico que incluye PAN
});

// VULN-013 [PCI-DSS 8.6.2] — Ante un error del pool, se loguea la connection
// string completa (con password en texto plano) en vez de un mensaje genérico
// sin credenciales. Este mismo literal es el que debería aparecer en los logs
// de producción para la correlación código↔log de la Fase 2.
pool.on("error", (err) => {
  console.error(`Error en el pool de Postgres usando ${CONNECTION_STRING}`, err);
});

export async function query(text: string, params?: unknown[]) {
  return pool.query(text, params);
}

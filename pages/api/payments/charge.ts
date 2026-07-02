import type { NextApiRequest, NextApiResponse } from "next";
import { query } from "../../../lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { pan, cvv, expiry, amount, customerEmail } = req.body;

  // VULN-003a [PCI-DSS 3.4.1 / 10.2] — PAN y CVV completos van a los logs de
  // la aplicación en texto plano (console.log termina en stdout/agregador de
  // logs). El CVV (SAD) nunca debe registrarse, ni siquiera cifrado.
  console.log(`Procesando cargo de ${amount} para PAN=${pan} CVV=${cvv}`);

  // VULN-003b [PCI-DSS 6.2.4] — Inyección SQL: el PAN y otros campos vienen
  // directo del body y se concatenan en el query en vez de usar parámetros
  // preparados (la función `query` sí soporta params, pero aquí no se usan).
  const insertSql = `INSERT INTO cardholders (customer_email, pan, cvv, expiry_date)
    VALUES ('${customerEmail}', '${pan}', '${cvv}', '${expiry}') RETURNING id`;

  const result = await query(insertSql);
  const cardholderId = result.rows[0].id;

  // VULN-003c [PCI-DSS 3.3.2 / 3.3.3] — Se persiste track2_data y CVV en la
  // tabla cardholders (ver migrations/001_init.sql) — dato de autenticación
  // sensible que nunca debe almacenarse después de la autorización.
  await query(
    "UPDATE cardholders SET track2_data = $1 WHERE id = $2",
    [req.body.track2 ?? null, cardholderId]
  );

  await query(
    "INSERT INTO transactions (cardholder_id, amount, status, raw_gateway_response) VALUES ($1, $2, $3, $4)",
    [cardholderId, amount, "approved", JSON.stringify({ pan, cvv })]
    // VULN-003d [PCI-DSS 3.3.2] — PAN/CVV también quedan embebidos en el JSONB
    // de respuesta del gateway, otra vía de almacenamiento no controlada.
  );

  res.status(200).json({ ok: true, cardholderId });
}

import type { NextApiRequest, NextApiResponse } from "next";
import { query } from "../../../lib/db";

// VULN-007 [PCI-DSS 4.2.1 / 3.4.1] — El PAN viaja como query param en una
// petición GET (ej: /api/payments/refund?pan=4111111111111111&amount=50).
// Queda expuesto en logs de acceso del servidor, proxies intermedios,
// historial del navegador y herramientas de monitoreo — sin importar si el
// canal usa HTTPS, el dato queda registrado en texto plano en esos puntos.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { pan, amount } = req.query;

  await query(
    "INSERT INTO transactions (cardholder_id, amount, status) SELECT id, $1, 'refunded' FROM cardholders WHERE pan = $2",
    [amount, pan]
  );

  res.status(200).json({ ok: true });
}

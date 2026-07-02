import type { NextApiRequest, NextApiResponse } from "next";
import { query } from "../../../lib/db";

// VULN-006 [PCI-DSS 7.2.1] — Endpoint de conciliación/consulta de cardholder
// sin ninguna verificación de autenticación ni autorización. Cualquiera que
// conozca o adivine el id puede leer PAN, CVV y track2_data completos.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query;

  const result = await query("SELECT * FROM cardholders WHERE id = $1", [id]);
  // No hay chequeo de sesión/rol antes de devolver los datos completos.
  res.status(200).json(result.rows[0]);
}

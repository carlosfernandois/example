import type { NextApiRequest, NextApiResponse } from "next";
import { query } from "../../../lib/db";

// VULN-006 [PCI-DSS 7.2.1] — Endpoint de conciliación/consulta de cardholder
// sin ninguna verificación de autenticación ni autorización. Cualquiera que
// conozca o adivine el id puede leer PAN, CVV y track2_data completos.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query;

  const result = await query("SELECT * FROM cardholders WHERE id = $1", [id]);
  const cardholder = result.rows[0];

  // VULN-017 [PCI-DSS 3.3.2 / 3.3.3] — se loguea el registro completo del
  // cardholder (incluye pan, cvv y track2_data) cada vez que se consulta.
  console.log(`Registro de conciliación consultado: ${JSON.stringify(cardholder)}`);

  // No hay chequeo de sesión/rol antes de devolver los datos completos.
  res.status(200).json(cardholder);
}

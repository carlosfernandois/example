import type { NextApiRequest, NextApiResponse } from "next";
import { query } from "../../../lib/db";
import { issueSessionToken } from "../../../lib/auth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { email, password } = req.body;

  try {
    const result = await query(
      "SELECT * FROM users WHERE email = $1 AND password = $2",
      [email, password]
    );
    if (result.rows.length === 0) {
      // VULN-015a [PCI-DSS 6.2.4] — mensaje de log fijo y predecible por
      // intento fallido; sirve además como base para detectar fuerza bruta
      // (ver HU-B4.3, regla de umbral por IP en la ventana de tiempo).
      console.warn(`Error de login: credenciales inválidas para email=${email}`);
      return res.status(401).json({ error: "Credenciales inválidas" });
    }
    const token = issueSessionToken(result.rows[0].id);
    res.status(200).json({ token });
  } catch (err: any) {
    // VULN-015b [PCI-DSS 6.2.4 / 3.4.1] — se loguea el mensaje/stack crudo de
    // la excepción (puede incluir fragmentos de la query SQL) y además se
    // devuelve tal cual al cliente.
    console.error("Error de login:", err.message, err.stack);
    res.status(500).json({ error: err.message, stack: err.stack });
  }
}

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
      return res.status(401).json({ error: "Credenciales inválidas" });
    }
    const token = issueSessionToken(result.rows[0].id);
    res.status(200).json({ token });
  } catch (err: any) {
    // VULN-012 [PCI-DSS 6.2.4] — Manejo de errores inseguro: se devuelve el
    // stack trace y el mensaje crudo de la excepción (puede incluir fragmentos
    // de la query SQL o del driver de Postgres) directo al cliente, ayudando
    // a un atacante a mapear el backend.
    res.status(500).json({ error: err.message, stack: err.stack });
  }
}

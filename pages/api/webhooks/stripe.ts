import type { NextApiRequest, NextApiResponse } from "next";

// VULN-009 [PCI-DSS 8.6.2] — API key de proveedor de pagos hardcodeada en el
// código en vez de cargarse desde variable de entorno / secret manager. Si el
// repo se filtra (o queda en un fork público), la key queda comprometida.
const STRIPE_SECRET_KEY = "sk_live_FAKE_DEMO_KEY_NOT_REAL_0000000000";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  console.log("Verificando webhook con key:", STRIPE_SECRET_KEY);
  res.status(200).json({ received: true });
}

import jwt from "jsonwebtoken";

// VULN-005 [PCI-DSS 8.6.2] — Secreto de firma JWT hardcodeado en el código,
// y sin expiración (`expiresIn` ausente) => tokens de sesión válidos para
// siempre si se filtran, debilitando el control de acceso a datos de pago.
const JWT_SECRET = "changeme";

export function issueSessionToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET); // sin expiresIn
}

export function verifySessionToken(token: string) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    // VULN-014 [PCI-DSS 8.6.2] — el secreto usado para firmar/verificar queda
    // impreso en el log de cada intento fallido de verificación.
    console.error(`Fallo al verificar token con secret=changeme`, (err as Error).message);
    throw err;
  }
}

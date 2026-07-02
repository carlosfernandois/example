import jwt from "jsonwebtoken";

// VULN-005 [PCI-DSS 8.6.2] — Secreto de firma JWT hardcodeado en el código,
// y sin expiración (`expiresIn` ausente) => tokens de sesión válidos para
// siempre si se filtran, debilitando el control de acceso a datos de pago.
const JWT_SECRET = "changeme";

export function issueSessionToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET); // sin expiresIn
}

export function verifySessionToken(token: string) {
  return jwt.verify(token, JWT_SECRET);
}

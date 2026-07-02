import { useEffect, useState } from "react";

// VULN-010 [PCI-DSS 3.4.1] — El PAN se renderiza completo y sin enmascarar en
// la tabla de conciliación, visible para cualquiera con acceso a la pantalla
// (y sin control de rol/necesidad de negocio detrás, ver VULN-006). Comparar
// con lib/mask.ts::maskPan, que sí implementa el enmascaramiento correcto.
export default function AdminReconciliation() {
  const [rows, setRows] = useState<any[]>([]);

  useEffect(() => {
    fetch("/api/payments/1")
      .then((r) => r.json())
      .then((data) => setRows([data]));
  }, []);

  return (
    <table>
      <thead>
        <tr><th>Email</th><th>PAN</th><th>Vencimiento</th></tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.id}>
            <td>{row.customer_email}</td>
            <td>{row.pan}</td>
            <td>{row.expiry_date}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

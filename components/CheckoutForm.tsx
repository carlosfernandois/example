import { useState } from "react";

export default function CheckoutForm() {
  const [pan, setPan] = useState("");
  const [cvv, setCvv] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    // VULN-008a [PCI-DSS 3.3 / protección de SAD] — El número de tarjeta y el
    // CVV completos se guardan en localStorage del navegador, sin cifrar y sin
    // expiración, quedando accesibles a cualquier script (XSS) o a quien use
    // el mismo dispositivo.
    localStorage.setItem("last_card_pan", pan);
    localStorage.setItem("last_card_cvv", cvv);

    // VULN-008b [PCI-DSS 3.4.1] — PAN y CVV completos impresos en la consola
    // del navegador (visible para cualquiera con devtools abiertas, y a veces
    // capturado por herramientas de monitoreo de frontend/RUM).
    console.log("Enviando pago con tarjeta", pan, "cvv", cvv);

    await fetch("/api/payments/charge", {
      method: "POST",
      body: JSON.stringify({ pan, cvv }),
    });
  }

  return (
    <form onSubmit={handleSubmit}>
      <input value={pan} onChange={(e) => setPan(e.target.value)} placeholder="Número de tarjeta" />
      <input value={cvv} onChange={(e) => setCvv(e.target.value)} placeholder="CVV" />
      <button type="submit">Pagar</button>
    </form>
  );
}

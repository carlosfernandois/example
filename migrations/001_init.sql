-- VULN-002 [PCI-DSS 3.3.2 / 3.5.1] — CVV, track2 y PAN se guardan en texto plano.
-- El CVV/CVC (SAD) NUNCA debe persistirse después de la autorización, y el PAN
-- debe quedar ilegible (hash/tokenización/cifrado fuerte), no en VARCHAR plano.
CREATE TABLE cardholders (
    id SERIAL PRIMARY KEY,
    customer_email VARCHAR(255) NOT NULL,
    pan VARCHAR(19) NOT NULL,          -- VULN-002: PAN en claro, sin truncar/tokenizar
    cvv VARCHAR(4),                    -- VULN-002: CVV persistido (prohibido post-autorización)
    track2_data TEXT,                  -- VULN-002: data de banda magnética completa (prohibido siempre)
    expiry_date VARCHAR(5) NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    cardholder_id INTEGER REFERENCES cardholders(id),
    amount NUMERIC(12,2) NOT NULL,
    status VARCHAR(20) NOT NULL,
    raw_gateway_response JSONB,
    created_at TIMESTAMP DEFAULT now()
);

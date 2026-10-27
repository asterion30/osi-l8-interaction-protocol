//! RFC-ILP-2026: Embedded SLM Gatekeeper Simulation (Deep Content & DLP Inspection)

use std::fmt;

/// Categoría de amenaza detectada en el payload semántico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatekeeperThreat {
    FinancialExfiltration(String),
    CredentialLeak(String),
    GovernmentIdLeak(String),
    PromptInjectionAttempt(String),
}

impl fmt::Display for GatekeeperThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinancialExfiltration(msg) => write!(f, "Fuga Financiera (DLP): {}", msg),
            Self::CredentialLeak(msg) => write!(f, "Fuga de Credenciales (Secret Scanner): {}", msg),
            Self::GovernmentIdLeak(msg) => write!(f, "Fuga de Identidad Gubernamental (PII): {}", msg),
            Self::PromptInjectionAttempt(msg) => write!(f, "Inyección de Prompt / Jailbreak Cognitivo: {}", msg),
        }
    }
}

/// Guardián SLM de borde: Realiza inspección heurística ultrarrápida (<5 ms) de DLP y seguridad cognitiva.
#[derive(Debug, Clone, Default)]
pub struct SlmGatekeeper;

impl SlmGatekeeper {
    pub fn new() -> Self {
        Self
    }

    /// Analiza el payload en busca de patrones sensibles o vectores de ataque.
    pub fn inspect(&self, payload: &[u8]) -> Result<(), GatekeeperThreat> {
        let text = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Ok(()), // Payloads puramente binarios cifrados pasan al control criptográfico
        };

        // 1. Detección de tokens y claves de API
        if text.contains("sk-") || text.contains("ghp_") || text.contains("Bearer ") || text.contains("PRIVATE KEY") {
            return Err(GatekeeperThreat::CredentialLeak(
                "Detectado token de API o clave privada en texto plano".into(),
            ));
        }

        // 2. Detección de patrones de evasión o Cross-Agent Prompt Injection
        let lower = text.to_lowercase();
        if lower.contains("ignore previous instructions")
            || lower.contains("ignora las instrucciones anteriores")
            || lower.contains("bypass cognitive policy")
            || lower.contains("system override")
            || lower.contains("act as an unfiltered")
        {
            return Err(GatekeeperThreat::PromptInjectionAttempt(
                "Detectada directiva de alteración de directivas cognitivas".into(),
            ));
        }

        // 3. Detección heurística de tarjetas de crédito con algoritmo de Luhn
        if let Some(card_num) = Self::find_credit_card_candidate(&text) {
            return Err(GatekeeperThreat::FinancialExfiltration(format!(
                "Detectado número de tarjeta de crédito válido (terminación ****{})",
                &card_num[card_num.len().saturating_sub(4)..]
            )));
        }

        // 4. Detección simple de SSN / DNI explícito
        if lower.contains("ssn:") || lower.contains("dni:") || lower.contains("pasaporte:") {
            return Err(GatekeeperThreat::GovernmentIdLeak(
                "Detectado prefijo de identificación ciudadana sensible".into(),
            ));
        }

        Ok(())
    }

    /// Busca candidatos a números de tarjeta de crédito de 13 a 19 dígitos y valida con Luhn.
    fn find_credit_card_candidate(text: &str) -> Option<String> {
        let mut digits = String::new();
        for ch in text.chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
            } else if !digits.is_empty() && (ch == ' ' || ch == '-') {
                // Posible separador, continúa acumulando
            } else {
                if digits.len() >= 13 && digits.len() <= 19 && Self::luhn_check(&digits) {
                    return Some(digits);
                }
                digits.clear();
            }
        }

        if digits.len() >= 13 && digits.len() <= 19 && Self::luhn_check(&digits) {
            return Some(digits);
        }

        None
    }

    /// Algoritmo de Luhn para verificación de tarjetas de crédito.
    fn luhn_check(digits: &str) -> bool {
        let mut sum = 0;
        let mut alternate = false;

        for ch in digits.chars().rev() {
            if let Some(mut d) = ch.to_digit(10) {
                if alternate {
                    d *= 2;
                    if d > 9 {
                        d -= 9;
                    }
                }
                sum += d;
                alternate = !alternate;
            } else {
                return false;
            }
        }

        sum % 10 == 0
    }
}

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

pub(super) fn summaries(config: &Map<String, Value>) -> Option<Value> {
    let certificate = config
        .get("idpMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("cert"))
        .or_else(|| config.get("cert"))?;
    let certificates = certificate
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| std::slice::from_ref(certificate));
    Some(Value::Array(
        certificates.iter().map(summary_or_error).collect(),
    ))
}

fn summary_or_error(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|certificate| summary(certificate).ok())
        .unwrap_or_else(|| json!({ "error": "Failed to parse certificate" }))
}

fn summary(certificate: &str) -> Result<Value, ()> {
    let pem = if certificate.contains("-----BEGIN") {
        certificate.to_owned()
    } else {
        format!("-----BEGIN CERTIFICATE-----\n{certificate}\n-----END CERTIFICATE-----")
    };
    let (remainder, pem) = parse_x509_pem(pem.as_bytes()).map_err(|_| ())?;
    if !remainder.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
        return Err(());
    }
    let (remainder, certificate) = parse_x509_certificate(&pem.contents).map_err(|_| ())?;
    if !remainder.is_empty() {
        return Err(());
    }
    let fingerprint = Sha256::digest(&pem.contents)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(json!({
        "fingerprintSha256": fingerprint,
        "notBefore": node_date(certificate.validity().not_before.timestamp())?,
        "notAfter": node_date(certificate.validity().not_after.timestamp())?,
        "publicKeyAlgorithm": key_algorithm(
            &certificate.public_key().algorithm.algorithm.to_id_string()
        ),
    }))
}

fn node_date(timestamp: i64) -> Result<String, ()> {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|date| date.format("%b %e %H:%M:%S %Y GMT").to_string())
        .ok_or(())
}

fn key_algorithm(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10040.4.1" => "DSA",
        "1.3.101.110" => "X25519",
        "1.3.101.111" => "X448",
        "1.3.101.112" => "ED25519",
        "1.3.101.113" => "ED448",
        "1.2.840.113549.1.3.1" => "DH",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nMIICujCCAaICCQCgwZcSUe7IzjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRz\nc28tY29uZm9ybWFuY2UudGVzdDAeFw0yNjA4MzAyMTU2MDRaFw0zNjA4MjcyMTU2\nMDRaMB8xHTAbBgNVBAMMFHNzby1jb25mb3JtYW5jZS50ZXN0MIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCNOdb+A2in05vMOR/COwCOtDsFLGby4VjsA\n8A5k0x3m8BtDPOzVA/Pdu3MAq5UKAmO/kaAuAIZF9BDqMJemVtgd/Z3uNFPjYNUU\nZ439seQ136XxVYLG36+TPKj2taGdRgEFkg7NhtaoCbq2dycN0DqtXLQFlGRHcSKW\nTqYdEVIlaIETa2I3acnqsjwheLViebGHjwRu0xsOutRJrN5x/lMF7xH1zqLg1hi3\n3sJDuX156uuQSz9SnCr8JLn8Xrojdz2ElLSeyMcnjDoWqVWTblrv6eXGmnSf5kWX\nbpOpczkMwg/t22Bkhjsw42ltwSeWBKRJ+bAycQUEnaHhHi/ikQIDAQABMA0GCSqG\nSIb3DQEBCwUAA4IBAQA2KQQQ5OuBOUAGU7gmmQtAqkiuudzCjLFpmF/RYTBylrWt\n0IVB5V0d6bv6lP0TU/tTg+dnUn09TBdgb9BgzVWAqnB6z0WPwNvSy5a666hwjXdx\nmYIUE5Sg99CR0qg77xBlkbd7BvRfiVtoQfLHz+I4slL33+Qf6dvB1oDx0QMjAO7T\nlM5JOJBdZPtVqq0fM8arAcWS1BrVm7WfyVtB8qr4dxl5sooaVWJgWtQPBQFzrjRb\n2qYxqG7WtviL3htxssRM4NdWjQX1XmcXYvtzyqcII5UBmpnbiPUWoxKEmnW7MaRD\nm9xEFyOES9Zs+d3vNAqwyJu4T1WwfWkN1mFqsBkw\n-----END CERTIFICATE-----\n";

    #[test]
    fn certificate_summary_matches_node_x509_certificate() {
        assert_eq!(
            summary(CERTIFICATE),
            Ok(json!({
                "fingerprintSha256": "2F:1B:69:76:AA:34:D4:E8:55:99:EA:F9:66:6B:73:05:13:AA:6A:F9:D3:BA:7D:9F:63:FE:9D:4A:9B:23:A2:D0",
                "notBefore": "Aug 30 21:56:04 2026 GMT",
                "notAfter": "Aug 27 21:56:04 2036 GMT",
                "publicKeyAlgorithm": "RSA",
            }))
        );
    }

    #[test]
    fn idp_certificate_takes_precedence_and_invalid_items_are_safe() {
        let config = json!({
            "cert": CERTIFICATE,
            "idpMetadata": { "cert": [CERTIFICATE, "not a certificate"] }
        });
        let output = summaries(config.as_object().unwrap()).unwrap();
        assert_eq!(output.as_array().unwrap().len(), 2);
        assert_eq!(output[1], json!({ "error": "Failed to parse certificate" }));
    }
}

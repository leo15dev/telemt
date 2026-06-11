use serde::{Deserialize, Serialize};
use std::time::SystemTime;

const EXT_KEY_SHARE: u16 = 0x0033;
const TLS_NAMED_GROUP_X25519: u16 = 0x001d;
const TLS_NAMED_GROUP_X25519MLKEM768: u16 = 0x11ec;

/// Parsed representation of an unencrypted TLS ServerHello.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedServerHello {
    pub version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: [u8; 2],
    pub compression: u8,
    pub extensions: Vec<TlsExtension>,
}

/// Generic TLS extension container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl ParsedServerHello {
    /// Return the TLS record body length that would contain this ServerHello.
    pub(crate) fn record_body_len(&self) -> usize {
        let extensions_len = self
            .extensions
            .iter()
            .map(|extension| 4 + extension.data.len())
            .sum::<usize>();

        4 + 2 + 32 + 1 + self.session_id.len() + 2 + 1 + 2 + extensions_len
    }

    /// Return visible ServerHello extension types in wire order.
    pub(crate) fn extension_types(&self) -> Vec<u16> {
        self.extensions
            .iter()
            .map(|extension| extension.ext_type)
            .collect()
    }

    /// Return a replay-safe ServerHello key_share group when the extension is well-formed.
    pub(crate) fn key_share_group(&self) -> Option<u16> {
        self.extensions
            .iter()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .and_then(|extension| parse_key_share_group(&extension.data))
    }
}

fn parse_key_share_group(data: &[u8]) -> Option<u16> {
    if data.len() < 4 {
        return None;
    }

    let group = u16::from_be_bytes([data[0], data[1]]);
    let key_exchange_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() != 4 + key_exchange_len {
        return None;
    }

    match group {
        TLS_NAMED_GROUP_X25519 | TLS_NAMED_GROUP_X25519MLKEM768 => Some(group),
        _ => None,
    }
}

/// Basic certificate metadata (optional, informative).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCertificateInfo {
    pub not_after_unix: Option<i64>,
    pub not_before_unix: Option<i64>,
    pub issuer_cn: Option<String>,
    pub subject_cn: Option<String>,
    pub san_names: Vec<String>,
}

/// TLS certificate payload captured from profiled upstream.
///
/// `certificate_message` stores an encoded TLS 1.3 Certificate handshake
/// message body that can be replayed as opaque ApplicationData bytes in FakeTLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertPayload {
    pub cert_chain_der: Vec<Vec<u8>>,
    pub certificate_message: Vec<u8>,
}

/// Provenance of the cached TLS behavior profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfileSource {
    /// Built from hardcoded defaults or legacy cache entries.
    #[default]
    Default,
    /// Derived from raw TLS record capture only.
    Raw,
    /// Derived from rustls-only metadata fallback.
    Rustls,
    /// Merged from raw TLS capture and rustls certificate metadata.
    Merged,
}

/// DPI-facing quality class of a cached TLS front profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfileQuality {
    /// No raw origin ServerHello shape is available.
    #[default]
    Fallback,
    /// Raw origin ServerHello was captured, but encrypted flight shape is incomplete.
    RawPartial,
    /// Raw origin ServerHello and encrypted flight record sizes were captured.
    RawStrict,
}

/// Coarse-grained TLS response behavior captured per SNI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsBehaviorProfile {
    /// Number of ChangeCipherSpec records observed before encrypted flight.
    #[serde(default = "default_change_cipher_spec_count")]
    pub change_cipher_spec_count: u8,
    /// Sizes of the primary encrypted flight records carrying cert-like payload.
    #[serde(default)]
    pub app_data_record_sizes: Vec<usize>,
    /// Sizes of small tail ApplicationData records that look like tickets.
    #[serde(default)]
    pub ticket_record_sizes: Vec<usize>,
    /// Source of this behavior profile.
    #[serde(default)]
    pub source: TlsProfileSource,
    /// DPI-facing quality of this profile.
    #[serde(default)]
    pub quality: TlsProfileQuality,
    /// Captured ServerHello TLS record body length.
    #[serde(default)]
    pub server_hello_record_len: usize,
    /// Captured visible ServerHello extension types in wire order.
    #[serde(default)]
    pub server_hello_extension_types: Vec<u16>,
    /// Captured ServerHello key_share group when replay-safe.
    #[serde(default)]
    pub server_hello_key_share_group: Option<u16>,
}

fn default_change_cipher_spec_count() -> u8 {
    1
}

impl Default for TlsBehaviorProfile {
    fn default() -> Self {
        Self {
            change_cipher_spec_count: default_change_cipher_spec_count(),
            app_data_record_sizes: Vec::new(),
            ticket_record_sizes: Vec::new(),
            source: TlsProfileSource::Default,
            quality: TlsProfileQuality::Fallback,
            server_hello_record_len: 0,
            server_hello_extension_types: Vec::new(),
            server_hello_key_share_group: None,
        }
    }
}

impl TlsBehaviorProfile {
    /// Refresh cached visible ServerHello summary fields and quality.
    pub(crate) fn refresh_server_hello_summary(&mut self, server_hello: &ParsedServerHello) {
        if matches!(self.source, TlsProfileSource::Raw | TlsProfileSource::Merged) {
            if self.server_hello_record_len == 0 {
                self.server_hello_record_len = server_hello.record_body_len();
            }
            self.server_hello_extension_types = server_hello.extension_types();
            self.server_hello_key_share_group = server_hello.key_share_group();
        } else {
            self.server_hello_record_len = 0;
            self.server_hello_extension_types.clear();
            self.server_hello_key_share_group = None;
        }

        self.refresh_quality();
    }

    /// Recompute the profile quality from current source and record-size evidence.
    pub(crate) fn refresh_quality(&mut self) {
        let has_raw_server_hello = matches!(self.source, TlsProfileSource::Raw | TlsProfileSource::Merged)
            && self.server_hello_record_len > 0;
        self.quality = if has_raw_server_hello && !self.app_data_record_sizes.is_empty() {
            TlsProfileQuality::RawStrict
        } else if has_raw_server_hello {
            TlsProfileQuality::RawPartial
        } else {
            TlsProfileQuality::Fallback
        };
    }
}

/// Cached data per SNI used by the emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTlsData {
    pub server_hello_template: ParsedServerHello,
    pub cert_info: Option<ParsedCertificateInfo>,
    #[serde(default)]
    pub cert_payload: Option<TlsCertPayload>,
    pub app_data_records_sizes: Vec<usize>,
    pub total_app_data_len: usize,
    #[serde(default)]
    pub behavior_profile: TlsBehaviorProfile,
    #[serde(default = "now_system_time", skip_serializing, skip_deserializing)]
    pub fetched_at: SystemTime,
    pub domain: String,
}

fn now_system_time() -> SystemTime {
    SystemTime::now()
}

/// Result of attempting to fetch real TLS artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFetchResult {
    pub server_hello_parsed: ParsedServerHello,
    pub app_data_records_sizes: Vec<usize>,
    pub total_app_data_len: usize,
    #[serde(default)]
    pub behavior_profile: TlsBehaviorProfile,
    pub cert_info: Option<ParsedCertificateInfo>,
    pub cert_payload: Option<TlsCertPayload>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_tls_data_deserializes_without_behavior_profile() {
        let json = r#"
        {
            "server_hello_template": {
                "version": [3, 3],
                "random": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "session_id": [],
                "cipher_suite": [19, 1],
                "compression": 0,
                "extensions": []
            },
            "cert_info": null,
            "cert_payload": null,
            "app_data_records_sizes": [1024],
            "total_app_data_len": 1024,
            "domain": "example.com"
        }
        "#;

        let cached: CachedTlsData = serde_json::from_str(json).unwrap();
        assert_eq!(cached.behavior_profile.change_cipher_spec_count, 1);
        assert!(cached.behavior_profile.app_data_record_sizes.is_empty());
        assert!(cached.behavior_profile.ticket_record_sizes.is_empty());
        assert_eq!(cached.behavior_profile.source, TlsProfileSource::Default);
        assert_eq!(cached.behavior_profile.quality, TlsProfileQuality::Fallback);
    }
}

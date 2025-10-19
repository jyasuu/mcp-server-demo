use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{
        router::tool::ToolRouter,
        wrapper::Parameters,
    },
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde_json::json;
use chrono::{Utc, Local};
use base64::{Engine as _, engine::general_purpose};
use uuid::Uuid;
use sha2::{Sha256, Sha512, Digest};
use sha1::Sha1;
use md5;
use bcrypt::{hash, verify, DEFAULT_COST};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey};
use rand::rngs::OsRng;

#[derive(Clone)]
pub struct UtilityToolsServer {
    tool_router: ToolRouter<UtilityToolsServer>,
}

// Parameter structures for various tools
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PingRequest {
    /// Message to echo back
    #[serde(default = "default_ping_message")]
    pub message: String,
}

fn default_ping_message() -> String {
    "pong".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TimeFormatRequest {
    /// Format string (iso, unix, rfc3339, custom)
    #[serde(default = "default_time_format")]
    pub format: String,
    /// Custom format pattern (for custom format type)
    pub custom_pattern: Option<String>,
    /// Timezone (utc, local, or timezone name)
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

fn default_time_format() -> String {
    "iso".to_string()
}

fn default_timezone() -> String {
    "utc".to_string()
}


#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Base64Request {
    /// Text to encode/decode
    pub text: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TokenGeneratorRequest {
    /// Length of the token
    #[serde(default = "default_token_length")]
    pub length: usize,
    /// Character set (alphanumeric, hex, base64)
    #[serde(default = "default_charset")]
    pub charset: String,
}

fn default_token_length() -> usize {
    32
}

fn default_charset() -> String {
    "alphanumeric".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PasswordAnalysisRequest {
    /// Password to analyze
    pub password: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct JwtParseRequest {
    /// JWT token to parse
    pub token: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HashRequest {
    /// Text to hash
    pub text: String,
    /// Hash algorithm (md5, sha1, sha256, sha512)
    pub algorithm: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BcryptRequest {
    /// Text to hash or verify
    pub text: String,
    /// For verification: the hash to compare against
    pub hash: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UuidRequest {
    /// UUID version (v4 default)
    #[serde(default = "default_uuid_version")]
    pub version: String,
}

fn default_uuid_version() -> String {
    "v4".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RsaKeyGenRequest {
    /// Key size in bits
    #[serde(default = "default_key_size")]
    pub key_size: usize,
}

fn default_key_size() -> usize {
    2048
}

#[tool_router]
impl UtilityToolsServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Simple ping-pong tool for testing connectivity")]
    fn ping(&self, Parameters(req): Parameters<PingRequest>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Ping received! Echo: {}",
            req.message
        ))]))
    }

    #[tool(description = "Get current time in various formats")]
    fn get_current_time(&self, Parameters(req): Parameters<TimeFormatRequest>) -> Result<CallToolResult, McpError> {
        let now = Utc::now();
        
        let result = match req.format.as_str() {
            "iso" => now.to_rfc3339(),
            "unix" => now.timestamp().to_string(),
            "rfc3339" => now.to_rfc3339(),
            "custom" => {
                if let Some(pattern) = req.custom_pattern {
                    now.format(&pattern).to_string()
                } else {
                    return Err(McpError::invalid_params("Custom format requires custom_pattern parameter", None));
                }
            }
            _ => return Err(McpError::invalid_params("Invalid format. Use: iso, unix, rfc3339, or custom", None)),
        };

        let timezone_info = match req.timezone.as_str() {
            "utc" => format!("UTC time: {}", result),
            "local" => {
                let local_time = Local::now();
                format!("Local time: {}", local_time.to_rfc3339())
            }
            _ => format!("{} time: {}", req.timezone, result),
        };

        Ok(CallToolResult::success(vec![Content::text(timezone_info)]))
    }

    #[tool(description = "Encode text to base64")]
    fn base64_encode(&self, Parameters(req): Parameters<Base64Request>) -> Result<CallToolResult, McpError> {
        let encoded = general_purpose::STANDARD.encode(req.text.as_bytes());
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Base64 encoded: {}",
            encoded
        ))]))
    }

    #[tool(description = "Decode base64 text")]
    fn base64_decode(&self, Parameters(req): Parameters<Base64Request>) -> Result<CallToolResult, McpError> {
        match general_purpose::STANDARD.decode(&req.text) {
            Ok(decoded_bytes) => {
                match String::from_utf8(decoded_bytes) {
                    Ok(decoded_string) => Ok(CallToolResult::success(vec![Content::text(format!(
                        "Base64 decoded: {}",
                        decoded_string
                    ))])),
                    Err(_) => Err(McpError::invalid_params("Decoded data is not valid UTF-8", None)),
                }
            }
            Err(e) => Err(McpError::invalid_params(format!("Base64 decode error: {}", e), None)),
        }
    }

    #[tool(description = "Generate a random token")]
    fn generate_token(&self, Parameters(req): Parameters<TokenGeneratorRequest>) -> Result<CallToolResult, McpError> {
        use rand::Rng;
        
        let charset = match req.charset.as_str() {
            "alphanumeric" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "hex" => "0123456789abcdef",
            "base64" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            _ => return Err(McpError::invalid_params("Invalid charset. Use: alphanumeric, hex, or base64", None)),
        };

        let mut rng = rand::thread_rng();
        let token: String = (0..req.length)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset.chars().nth(idx).unwrap()
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Generated token ({}): {}",
            req.charset, token
        ))]))
    }

    #[tool(description = "Analyze password strength")]
    fn analyze_password(&self, Parameters(req): Parameters<PasswordAnalysisRequest>) -> Result<CallToolResult, McpError> {
        let password = &req.password;
        let length = password.len();
        
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        let mut score = 0;
        let mut feedback = Vec::new();
        
        if length >= 8 { score += 2; } else { feedback.push("Use at least 8 characters".to_string()); }
        if length >= 12 { score += 1; }
        if has_lower { score += 1; } else { feedback.push("Add lowercase letters".to_string()); }
        if has_upper { score += 1; } else { feedback.push("Add uppercase letters".to_string()); }
        if has_digit { score += 1; } else { feedback.push("Add numbers".to_string()); }
        if has_special { score += 2; } else { feedback.push("Add special characters".to_string()); }
        
        let strength = match score {
            0..=2 => "Very Weak",
            3..=4 => "Weak",
            5..=6 => "Fair",
            7..=8 => "Strong",
            _ => "Very Strong",
        };
        
        let analysis = json!({
            "length": length,
            "strength": strength,
            "score": format!("{}/8", score),
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_special_chars": has_special,
            "feedback": feedback
        });
        
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Password Analysis:\n{}",
            serde_json::to_string_pretty(&analysis).unwrap()
        ))]))
    }

    #[tool(description = "Parse JWT token")]
    fn parse_jwt(&self, Parameters(req): Parameters<JwtParseRequest>) -> Result<CallToolResult, McpError> {
        let parts: Vec<&str> = req.token.split('.').collect();
        if parts.len() != 3 {
            return Err(McpError::invalid_params("Invalid JWT format. Expected 3 parts separated by dots", None));
        }

        fn decode_base64_url(input: &str) -> Result<String, String> {
            let mut padded = input.replace('-', "+").replace('_', "/");
            while padded.len() % 4 != 0 {
                padded.push('=');
            }
            
            general_purpose::STANDARD.decode(&padded)
                .map_err(|e| format!("Base64 decode error: {}", e))
                .and_then(|bytes| String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {}", e)))
        }

        let header = decode_base64_url(parts[0]).map_err(|e| McpError::invalid_params(format!("Header decode error: {}", e), None))?;
        let payload = decode_base64_url(parts[1]).map_err(|e| McpError::invalid_params(format!("Payload decode error: {}", e), None))?;

        let result = json!({
            "header": serde_json::from_str::<serde_json::Value>(&header).unwrap_or(json!(header)),
            "payload": serde_json::from_str::<serde_json::Value>(&payload).unwrap_or(json!(payload)),
            "signature": parts[2]
        });

        Ok(CallToolResult::success(vec![Content::text(format!(
            "JWT Parsed:\n{}",
            serde_json::to_string_pretty(&result).unwrap()
        ))]))
    }

    #[tool(description = "Hash text using various algorithms")]
    fn hash_text(&self, Parameters(req): Parameters<HashRequest>) -> Result<CallToolResult, McpError> {
        let hash_result = match req.algorithm.to_lowercase().as_str() {
            "md5" => {
                format!("{:x}", md5::compute(req.text.as_bytes()))
            }
            "sha1" => {
                let mut hasher = Sha1::new();
                hasher.update(req.text.as_bytes());
                format!("{:x}", hasher.finalize())
            }
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(req.text.as_bytes());
                format!("{:x}", hasher.finalize())
            }
            "sha512" => {
                let mut hasher = Sha512::new();
                hasher.update(req.text.as_bytes());
                format!("{:x}", hasher.finalize())
            }
            _ => return Err(McpError::invalid_params("Invalid algorithm. Use: md5, sha1, sha256, sha512", None)),
        };

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{} hash: {}",
            req.algorithm.to_uppercase(), hash_result
        ))]))
    }

    #[tool(description = "Hash or verify text using bcrypt")]
    fn bcrypt_hash(&self, Parameters(req): Parameters<BcryptRequest>) -> Result<CallToolResult, McpError> {
        if let Some(hash_to_verify) = req.hash {
            // Verify mode
            match verify(&req.text, &hash_to_verify) {
                Ok(is_valid) => Ok(CallToolResult::success(vec![Content::text(format!(
                    "Bcrypt verification: {}",
                    if is_valid { "VALID" } else { "INVALID" }
                ))])),
                Err(e) => Err(McpError::invalid_params(format!("Bcrypt verification error: {}", e), None)),
            }
        } else {
            // Hash mode
            match hash(&req.text, DEFAULT_COST) {
                Ok(hash_result) => Ok(CallToolResult::success(vec![Content::text(format!(
                    "Bcrypt hash: {}",
                    hash_result
                ))])),
                Err(e) => Err(McpError::invalid_params(format!("Bcrypt hash error: {}", e), None)),
            }
        }
    }

    #[tool(description = "Generate UUID")]
    fn generate_uuid(&self, Parameters(req): Parameters<UuidRequest>) -> Result<CallToolResult, McpError> {
        let uuid_result = match req.version.as_str() {
            "v4" => Uuid::new_v4().to_string(),
            _ => return Err(McpError::invalid_params("Only UUID v4 is currently supported", None)),
        };

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Generated UUID ({}): {}",
            req.version, uuid_result
        ))]))
    }

    #[tool(description = "Generate RSA key pair")]
    fn generate_rsa_keypair(&self, Parameters(req): Parameters<RsaKeyGenRequest>) -> Result<CallToolResult, McpError> {
        let mut rng = OsRng;
        
        let private_key = match RsaPrivateKey::new(&mut rng, req.key_size) {
            Ok(key) => key,
            Err(e) => return Err(McpError::invalid_params(format!("Failed to generate RSA key: {}", e), None)),
        };

        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = match private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF) {
            Ok(pem) => pem.to_string(),
            Err(e) => return Err(McpError::invalid_params(format!("Failed to encode private key: {}", e), None)),
        };

        let public_pem = match public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF) {
            Ok(pem) => pem,
            Err(e) => return Err(McpError::invalid_params(format!("Failed to encode public key: {}", e), None)),
        };

        let result = json!({
            "key_size": req.key_size,
            "private_key": private_pem,
            "public_key": public_pem
        });

        Ok(CallToolResult::success(vec![Content::text(format!(
            "RSA Key Pair Generated:\n{}",
            serde_json::to_string_pretty(&result).unwrap()
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for UtilityToolsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation {
                name: "utility-tools-server".to_string(),
                version: "1.0.0".to_string(),
                icons: None,
                title: None,
                website_url: None,
            },
            instructions: Some(
                "This server provides various utility tools including:\n\
                - ping: Simple connectivity test\n\
                - get_current_time: Get current time in various formats\n\
                - base64_encode/base64_decode: Base64 encoding/decoding\n\
                - generate_token: Generate random tokens\n\
                - analyze_password: Analyze password strength\n\
                - parse_jwt: Parse JWT tokens\n\
                - hash_text: Hash text using MD5, SHA1, SHA256, SHA512\n\
                - bcrypt_hash: Hash/verify with bcrypt\n\
                - generate_uuid: Generate UUIDs\n\
                - generate_rsa_keypair: Generate RSA key pairs".to_string()
            ),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        if let Some(http_request_part) = context.extensions.get::<axum::http::request::Parts>() {
            let initialize_headers = &http_request_part.headers;
            let initialize_uri = &http_request_part.uri;
            tracing::info!(?initialize_headers, %initialize_uri, "initialize from http server");
        }
        Ok(self.get_info())
    }
}
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
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use hex;
use url::Url;
use regex::Regex;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AesEncryptRequest {
    /// Text to encrypt
    pub text: String,
    /// AES-256 key (64 hex characters) - if not provided, one will be generated
    pub key: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AesDecryptRequest {
    /// Encrypted data (hex encoded)
    pub encrypted_data: String,
    /// AES-256 key (64 hex characters)
    pub key: String,
    /// Nonce/IV (24 hex characters)
    pub nonce: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HmacRequest {
    /// Message to authenticate
    pub message: String,
    /// Secret key for HMAC
    pub key: String,
    /// HMAC algorithm (sha256, sha512)
    #[serde(default = "default_hmac_algo")]
    pub algorithm: String,
}

fn default_hmac_algo() -> String {
    "sha256".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HmacVerifyRequest {
    /// Message to verify
    pub message: String,
    /// Secret key for HMAC
    pub key: String,
    /// HMAC signature to verify (hex encoded)
    pub signature: String,
    /// HMAC algorithm (sha256, sha512)
    #[serde(default = "default_hmac_algo")]
    pub algorithm: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct JwtCreateRequest {
    /// JWT payload (JSON object)
    pub payload: serde_json::Value,
    /// Secret key for signing
    pub secret: String,
    /// Algorithm (HS256, HS512)
    #[serde(default = "default_jwt_algo")]
    pub algorithm: String,
    /// Expiration time in seconds from now
    pub expires_in: Option<u64>,
}

fn default_jwt_algo() -> String {
    "HS256".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct JwtVerifyRequest {
    /// JWT token to verify
    pub token: String,
    /// Secret key for verification
    pub secret: String,
    /// Algorithm (HS256, HS512)
    #[serde(default = "default_jwt_algo")]
    pub algorithm: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UrlRequest {
    /// URL to parse or encode/decode
    pub url: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RegexRequest {
    /// Text to search in
    pub text: String,
    /// Regular expression pattern
    pub pattern: String,
    /// Replace with (for replacement operations)
    pub replacement: Option<String>,
    /// Global replacement (replace all matches)
    #[serde(default)]
    pub global: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TextUtilsRequest {
    /// Text to process
    pub text: String,
    /// Operation (word_count, char_count, line_count, reverse, slugify)
    pub operation: String,
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

    #[tool(description = "Encrypt text using AES-256-GCM")]
    fn aes_encrypt(&self, Parameters(req): Parameters<AesEncryptRequest>) -> Result<CallToolResult, McpError> {
        use rand::RngCore;
        
        // Generate or parse key
        let key_bytes = if let Some(key_hex) = req.key {
            hex::decode(&key_hex).map_err(|e| McpError::invalid_params(format!("Invalid key hex: {}", e), None))?
        } else {
            let mut key_bytes = vec![0u8; 32]; // 256 bits
            rand::thread_rng().fill_bytes(&mut key_bytes);
            key_bytes
        };

        if key_bytes.len() != 32 {
            return Err(McpError::invalid_params("Key must be 32 bytes (64 hex characters)", None));
        }

        // Generate random nonce
        let mut nonce_bytes = vec![0u8; 12]; // 96 bits for GCM
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.encrypt(nonce, req.text.as_bytes()) {
            Ok(ciphertext) => {
                let result = json!({
                    "encrypted_data": hex::encode(&ciphertext),
                    "key": hex::encode(&key_bytes),
                    "nonce": hex::encode(&nonce_bytes),
                    "algorithm": "AES-256-GCM"
                });

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "AES Encryption Result:\n{}",
                    serde_json::to_string_pretty(&result).unwrap()
                ))]))
            }
            Err(e) => Err(McpError::invalid_params(format!("Encryption failed: {}", e), None)),
        }
    }

    #[tool(description = "Decrypt text using AES-256-GCM")]
    fn aes_decrypt(&self, Parameters(req): Parameters<AesDecryptRequest>) -> Result<CallToolResult, McpError> {
        let key_bytes = hex::decode(&req.key).map_err(|e| McpError::invalid_params(format!("Invalid key hex: {}", e), None))?;
        let nonce_bytes = hex::decode(&req.nonce).map_err(|e| McpError::invalid_params(format!("Invalid nonce hex: {}", e), None))?;
        let encrypted_data = hex::decode(&req.encrypted_data).map_err(|e| McpError::invalid_params(format!("Invalid encrypted data hex: {}", e), None))?;

        if key_bytes.len() != 32 {
            return Err(McpError::invalid_params("Key must be 32 bytes (64 hex characters)", None));
        }
        if nonce_bytes.len() != 12 {
            return Err(McpError::invalid_params("Nonce must be 12 bytes (24 hex characters)", None));
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.decrypt(nonce, encrypted_data.as_slice()) {
            Ok(plaintext) => {
                match String::from_utf8(plaintext) {
                    Ok(decrypted_text) => Ok(CallToolResult::success(vec![Content::text(format!(
                        "AES Decryption Result: {}",
                        decrypted_text
                    ))])),
                    Err(_) => Err(McpError::invalid_params("Decrypted data is not valid UTF-8", None)),
                }
            }
            Err(e) => Err(McpError::invalid_params(format!("Decryption failed: {}", e), None)),
        }
    }

    #[tool(description = "Generate HMAC signature for message authentication")]
    fn hmac_sign(&self, Parameters(req): Parameters<HmacRequest>) -> Result<CallToolResult, McpError> {
        type HmacSha256 = Hmac<Sha256>;
        type HmacSha512 = Hmac<Sha512>;

        let signature = match req.algorithm.to_lowercase().as_str() {
            "sha256" => {
                let mut mac = <HmacSha256 as KeyInit>::new_from_slice(req.key.as_bytes())
                    .map_err(|e| McpError::invalid_params(format!("HMAC key error: {}", e), None))?;
                mac.update(req.message.as_bytes());
                hex::encode(mac.finalize().into_bytes())
            }
            "sha512" => {
                let mut mac = <HmacSha512 as KeyInit>::new_from_slice(req.key.as_bytes())
                    .map_err(|e| McpError::invalid_params(format!("HMAC key error: {}", e), None))?;
                mac.update(req.message.as_bytes());
                hex::encode(mac.finalize().into_bytes())
            }
            _ => return Err(McpError::invalid_params("Invalid algorithm. Use: sha256, sha512", None)),
        };

        let result = json!({
            "message": req.message,
            "algorithm": format!("HMAC-{}", req.algorithm.to_uppercase()),
            "signature": signature,
            "key_length": req.key.len()
        });

        Ok(CallToolResult::success(vec![Content::text(format!(
            "HMAC Signature:\n{}",
            serde_json::to_string_pretty(&result).unwrap()
        ))]))
    }

    #[tool(description = "Verify HMAC signature")]
    fn hmac_verify(&self, Parameters(req): Parameters<HmacVerifyRequest>) -> Result<CallToolResult, McpError> {
        type HmacSha256 = Hmac<Sha256>;
        type HmacSha512 = Hmac<Sha512>;

        let expected_signature = hex::decode(&req.signature)
            .map_err(|e| McpError::invalid_params(format!("Invalid signature hex: {}", e), None))?;

        let is_valid = match req.algorithm.to_lowercase().as_str() {
            "sha256" => {
                let mut mac = <HmacSha256 as KeyInit>::new_from_slice(req.key.as_bytes())
                    .map_err(|e| McpError::invalid_params(format!("HMAC key error: {}", e), None))?;
                mac.update(req.message.as_bytes());
                let computed = mac.finalize().into_bytes();
                computed.ct_eq(&expected_signature).into()
            }
            "sha512" => {
                let mut mac = <HmacSha512 as KeyInit>::new_from_slice(req.key.as_bytes())
                    .map_err(|e| McpError::invalid_params(format!("HMAC key error: {}", e), None))?;
                mac.update(req.message.as_bytes());
                let computed = mac.finalize().into_bytes();
                computed.ct_eq(&expected_signature).into()
            }
            _ => return Err(McpError::invalid_params("Invalid algorithm. Use: sha256, sha512", None)),
        };

        let result = json!({
            "message": req.message,
            "algorithm": format!("HMAC-{}", req.algorithm.to_uppercase()),
            "signature": req.signature,
            "is_valid": is_valid,
            "verification_status": if is_valid { "VALID" } else { "INVALID" }
        });

        Ok(CallToolResult::success(vec![Content::text(format!(
            "HMAC Verification:\n{}",
            serde_json::to_string_pretty(&result).unwrap()
        ))]))
    }

    #[tool(description = "Create and sign JWT token")]
    fn jwt_create(&self, Parameters(req): Parameters<JwtCreateRequest>) -> Result<CallToolResult, McpError> {
        let algorithm = match req.algorithm.as_str() {
            "HS256" => Algorithm::HS256,
            "HS512" => Algorithm::HS512,
            _ => return Err(McpError::invalid_params("Invalid algorithm. Use: HS256, HS512", None)),
        };

        let mut claims = req.payload;
        
        // Add expiration if specified
        if let Some(expires_in) = req.expires_in {
            let exp = Utc::now().timestamp() + expires_in as i64;
            claims["exp"] = json!(exp);
        }
        
        // Add issued at time
        claims["iat"] = json!(Utc::now().timestamp());

        let header = Header::new(algorithm);
        let encoding_key = EncodingKey::from_secret(req.secret.as_bytes());

        match encode(&header, &claims, &encoding_key) {
            Ok(token) => {
                let result = json!({
                    "token": token,
                    "algorithm": req.algorithm,
                    "payload": claims,
                    "expires_in": req.expires_in
                });

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "JWT Created:\n{}",
                    serde_json::to_string_pretty(&result).unwrap()
                ))]))
            }
            Err(e) => Err(McpError::invalid_params(format!("JWT creation failed: {}", e), None)),
        }
    }

    #[tool(description = "Verify JWT token signature and decode payload")]
    fn jwt_verify(&self, Parameters(req): Parameters<JwtVerifyRequest>) -> Result<CallToolResult, McpError> {
        let algorithm = match req.algorithm.as_str() {
            "HS256" => Algorithm::HS256,
            "HS512" => Algorithm::HS512,
            _ => return Err(McpError::invalid_params("Invalid algorithm. Use: HS256, HS512", None)),
        };

        let decoding_key = DecodingKey::from_secret(req.secret.as_bytes());
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;

        match decode::<serde_json::Value>(&req.token, &decoding_key, &validation) {
            Ok(token_data) => {
                let result = json!({
                    "is_valid": true,
                    "algorithm": req.algorithm,
                    "header": token_data.header,
                    "payload": token_data.claims,
                    "verification_status": "VALID"
                });

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "JWT Verification:\n{}",
                    serde_json::to_string_pretty(&result).unwrap()
                ))]))
            }
            Err(e) => {
                let result = json!({
                    "is_valid": false,
                    "algorithm": req.algorithm,
                    "error": format!("{}", e),
                    "verification_status": "INVALID"
                });

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "JWT Verification:\n{}",
                    serde_json::to_string_pretty(&result).unwrap()
                ))]))
            }
        }
    }

    #[tool(description = "Parse and analyze URLs")]
    fn url_parse(&self, Parameters(req): Parameters<UrlRequest>) -> Result<CallToolResult, McpError> {
        match Url::parse(&req.url) {
            Ok(parsed_url) => {
                let result = json!({
                    "original": req.url,
                    "scheme": parsed_url.scheme(),
                    "host": parsed_url.host_str(),
                    "port": parsed_url.port(),
                    "path": parsed_url.path(),
                    "query": parsed_url.query(),
                    "fragment": parsed_url.fragment(),
                    "domain": parsed_url.domain(),
                    "is_secure": parsed_url.scheme() == "https",
                    "full_url": parsed_url.as_str()
                });

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "URL Analysis:\n{}",
                    serde_json::to_string_pretty(&result).unwrap()
                ))]))
            }
            Err(e) => Err(McpError::invalid_params(format!("Invalid URL: {}", e), None)),
        }
    }

    #[tool(description = "URL encode text")]
    fn url_encode(&self, Parameters(req): Parameters<UrlRequest>) -> Result<CallToolResult, McpError> {
        let encoded = urlencoding::encode(&req.url);
        Ok(CallToolResult::success(vec![Content::text(format!(
            "URL Encoded: {}",
            encoded
        ))]))
    }

    #[tool(description = "URL decode text")]
    fn url_decode(&self, Parameters(req): Parameters<UrlRequest>) -> Result<CallToolResult, McpError> {
        match urlencoding::decode(&req.url) {
            Ok(decoded) => Ok(CallToolResult::success(vec![Content::text(format!(
                "URL Decoded: {}",
                decoded
            ))])),
            Err(e) => Err(McpError::invalid_params(format!("URL decode error: {}", e), None)),
        }
    }

    #[tool(description = "Find regex matches in text")]
    fn regex_find(&self, Parameters(req): Parameters<RegexRequest>) -> Result<CallToolResult, McpError> {
        match Regex::new(&req.pattern) {
            Ok(regex) => {
                let matches: Vec<_> = regex.find_iter(&req.text).map(|m| {
                    json!({
                        "match": m.as_str(),
                        "start": m.start(),
                        "end": m.end()
                    })
                }).collect();

                let result = json!({
                    "pattern": req.pattern,
                    "text": req.text,
                    "matches": matches,
                    "match_count": matches.len()
                });

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Regex Find Results:\n{}",
                    serde_json::to_string_pretty(&result).unwrap()
                ))]))
            }
            Err(e) => Err(McpError::invalid_params(format!("Invalid regex pattern: {}", e), None)),
        }
    }

    #[tool(description = "Replace text using regex")]
    fn regex_replace(&self, Parameters(req): Parameters<RegexRequest>) -> Result<CallToolResult, McpError> {
        let replacement = req.replacement.as_deref().unwrap_or("");
        
        match Regex::new(&req.pattern) {
            Ok(regex) => {
                let result_text = if req.global {
                    regex.replace_all(&req.text, replacement).into_owned()
                } else {
                    regex.replace(&req.text, replacement).into_owned()
                };

                let result = json!({
                    "pattern": req.pattern,
                    "original": req.text,
                    "replacement": replacement,
                    "result": result_text,
                    "global": req.global
                });

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Regex Replace Result:\n{}",
                    serde_json::to_string_pretty(&result).unwrap()
                ))]))
            }
            Err(e) => Err(McpError::invalid_params(format!("Invalid regex pattern: {}", e), None)),
        }
    }

    #[tool(description = "Text processing utilities")]
    fn text_utils(&self, Parameters(req): Parameters<TextUtilsRequest>) -> Result<CallToolResult, McpError> {
        let result = match req.operation.as_str() {
            "word_count" => {
                let word_count = req.text.split_whitespace().count();
                json!({
                    "operation": "word_count",
                    "text": req.text,
                    "result": word_count
                })
            }
            "char_count" => {
                let char_count = req.text.chars().count();
                json!({
                    "operation": "char_count",
                    "text": req.text,
                    "result": char_count
                })
            }
            "line_count" => {
                let line_count = req.text.lines().count();
                json!({
                    "operation": "line_count",
                    "text": req.text,
                    "result": line_count
                })
            }
            "reverse" => {
                let reversed = req.text.chars().rev().collect::<String>();
                json!({
                    "operation": "reverse",
                    "original": req.text,
                    "result": reversed
                })
            }
            "slugify" => {
                let slug = req.text
                    .to_lowercase()
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c } else { '-' })
                    .collect::<String>()
                    .split('-')
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<&str>>()
                    .join("-");
                json!({
                    "operation": "slugify",
                    "original": req.text,
                    "result": slug
                })
            }
            "uppercase" => {
                json!({
                    "operation": "uppercase",
                    "original": req.text,
                    "result": req.text.to_uppercase()
                })
            }
            "lowercase" => {
                json!({
                    "operation": "lowercase",
                    "original": req.text,
                    "result": req.text.to_lowercase()
                })
            }
            "trim" => {
                json!({
                    "operation": "trim",
                    "original": req.text,
                    "result": req.text.trim()
                })
            }
            _ => return Err(McpError::invalid_params("Invalid operation. Use: word_count, char_count, line_count, reverse, slugify, uppercase, lowercase, trim", None)),
        };

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Text Processing Result:\n{}",
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
                "This server provides comprehensive utility tools including:\n\n\
                🏓 BASIC TOOLS:\n\
                - ping: Simple connectivity test\n\
                - get_current_time: Get current time in various formats\n\n\
                🔐 CRYPTOGRAPHY & SECURITY:\n\
                - hash_text: Hash text using MD5, SHA1, SHA256, SHA512\n\
                - bcrypt_hash: Hash/verify passwords with bcrypt\n\
                - generate_rsa_keypair: Generate RSA key pairs\n\
                - aes_encrypt/aes_decrypt: AES-256-GCM symmetric encryption\n\
                - hmac_sign/hmac_verify: HMAC message authentication\n\n\
                🔧 ENCODING & UTILITIES:\n\
                - base64_encode/base64_decode: Base64 encoding/decoding\n\
                - generate_token: Generate random tokens\n\
                - generate_uuid: Generate UUIDs\n\
                - url_parse/url_encode/url_decode: URL utilities\n\n\
                🔍 ANALYSIS & PROCESSING:\n\
                - analyze_password: Comprehensive password strength analysis\n\
                - parse_jwt: Parse JWT tokens (basic)\n\
                - jwt_create/jwt_verify: Create and verify signed JWT tokens\n\
                - regex_find/regex_replace: Regular expression operations\n\
                - text_utils: Text processing (word count, case conversion, etc.)".to_string()
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
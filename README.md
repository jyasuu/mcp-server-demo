# MCP Utility Tools Server

A comprehensive Model Context Protocol (MCP) server providing various utility tools for developers. Built with Rust using the RMCP SDK.

## Features

This server implements the following utility tools:

### 🏓 Basic Tools
- **ping**: Simple ping-pong tool for testing connectivity
- **get_current_time**: Get current time in various formats (ISO, Unix timestamp, RFC3339, custom)

### 🔐 Cryptography & Security
- **hash_text**: Hash text using multiple algorithms (MD5, SHA1, SHA256, SHA512)
- **bcrypt_hash**: Hash and verify passwords using bcrypt
- **generate_rsa_keypair**: Generate RSA private/public key pairs
- **aes_encrypt**: Encrypt text using AES-256-GCM with auto-generated or custom keys
- **aes_decrypt**: Decrypt AES-256-GCM encrypted data
- **hmac_sign**: Generate HMAC signatures for message authentication
- **hmac_verify**: Verify HMAC signatures with constant-time comparison

### 🔧 Encoding & Utilities
- **base64_encode**: Encode text to base64
- **base64_decode**: Decode base64 text
- **generate_token**: Generate random tokens with customizable character sets
- **generate_uuid**: Generate UUIDs (v4 supported)
- **url_parse**: Parse and analyze URL components
- **url_encode**: URL encode text for safe transmission
- **url_decode**: URL decode percent-encoded text

### 🔍 Analysis & Processing Tools
- **analyze_password**: Comprehensive password strength analysis
- **parse_jwt**: Parse and decode JWT tokens (basic parsing)
- **jwt_create**: Create and sign JWT tokens with expiration and custom claims
- **jwt_verify**: Verify JWT token signatures and decode payload
- **regex_find**: Find all regex matches in text with position information
- **regex_replace**: Replace text using regex patterns (single or global)
- **text_utils**: Text processing utilities (word count, case conversion, trim, slugify, etc.)

## Installation & Running

1. Clone the repository
2. Build and run the server:

```bash
cargo run
```

The server will start on `http://127.0.0.1:8000` with the MCP endpoint at `/mcp`.

## Usage Examples

### Ping Tool
```json
{
  "method": "tools/call",
  "params": {
    "name": "ping",
    "arguments": {
      "message": "Hello MCP!"
    }
  }
}
```

### Password Analysis
```json
{
  "method": "tools/call",
  "params": {
    "name": "analyze_password",
    "arguments": {
      "password": "MySecurePass123!"
    }
  }
}
```

### Generate RSA Key Pair
```json
{
  "method": "tools/call",
  "params": {
    "name": "generate_rsa_keypair",
    "arguments": {
      "key_size": 2048
    }
  }
}
```

### AES Encryption
```json
{
  "method": "tools/call",
  "params": {
    "name": "aes_encrypt",
    "arguments": {
      "text": "Secret message to encrypt"
    }
  }
}
```

### Create JWT Token
```json
{
  "method": "tools/call",
  "params": {
    "name": "jwt_create",
    "arguments": {
      "payload": {"user_id": 123, "role": "admin"},
      "secret": "your-secret-key",
      "algorithm": "HS256",
      "expires_in": 3600
    }
  }
}
```

### HMAC Signature
```json
{
  "method": "tools/call",
  "params": {
    "name": "hmac_sign",
    "arguments": {
      "message": "Important message",
      "key": "secret-key",
      "algorithm": "sha256"
    }
  }
}
```

### Regex Find
```json
{
  "method": "tools/call",
  "params": {
    "name": "regex_find",
    "arguments": {
      "text": "Contact us at support@example.com or admin@test.org",
      "pattern": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    }
  }
}
```

### Text Utilities
```json
{
  "method": "tools/call",
  "params": {
    "name": "text_utils",
    "arguments": {
      "text": "Hello World! This is a Test String.",
      "operation": "slugify"
    }
  }
}
```

## Architecture

This project follows MCP best practices:
- Built using the official Rust MCP SDK (RMCP)
- Implements proper error handling with descriptive messages
- Uses structured request/response types with JSON Schema validation
- Supports HTTP transport with streamable connections
- Provides comprehensive tool documentation

## Development

Based on the counter_streamhttp.rs example from the RMCP SDK, this server demonstrates:
- Tool router implementation with macros
- Parameter validation using schemars
- Proper MCP protocol compliance
- Error handling best practices

## Dependencies

- **rmcp**: Official Rust MCP SDK (v0.8.1 with comprehensive features)
- **tokio**: Async runtime
- **axum**: HTTP framework
- **serde**: Serialization
- **chrono**: Date/time handling
- **Various crypto libraries**: For cryptographic operations

## Package Configuration

This project uses the published `rmcp` package (v0.8.1) with the following features enabled:
- `server`: Core MCP server functionality
- `macros`: Macro support for tool and handler definitions
- `client`: Client capabilities for testing
- `transport-sse-server`: Server-Sent Events transport
- `transport-io`: I/O transport layer
- `transport-streamable-http-server`: HTTP streaming transport
- `auth`: Authentication support
- `elicitation`: Dynamic parameter elicitation
- `schemars`: JSON Schema generation
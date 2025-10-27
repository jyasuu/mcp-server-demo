use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    {self},
};
use axum::http::{Method, HeaderName};
use tower_http::cors::{CorsLayer, Any};

mod utility_tools;
use utility_tools::UtilityToolsServer;

const BIND_ADDRESS: &str = "0.0.0.0:8000";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let service = StreamableHttpService::new(
        || Ok(UtilityToolsServer::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .expose_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("mcp-session-id"),
            HeaderName::from_static("access-control-allow-origin"),
        ]);

    let router = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(cors);
    let tcp_listener = tokio::net::TcpListener::bind(BIND_ADDRESS).await?;
    
    println!("MCP Utility Tools Server starting on http://{}", BIND_ADDRESS);
    println!("Available endpoints:");
    println!("  - HTTP MCP endpoint: http://{}/mcp", BIND_ADDRESS);
    
    let _ = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap() })
        .await;
    Ok(())
}

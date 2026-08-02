use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use clap::Parser;
use commons_identity_core::{SigningKeyMaterial, crypto::random_urlsafe};
use commons_identity_service::{AppState, ServiceConfig, app};
use rand::rngs::OsRng;
use time::OffsetDateTime;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

/// Commons Identity Community Authority, Issuer, and Verifier reference service.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Loopback listen address for the ephemeral Developer Preview.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,

    /// Loopback base URL matching the listen address.
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    public_base_url: String,

    #[arg(long, default_value = "did:webvh:developer-preview:localhost")]
    community_id: String,

    #[arg(long, default_value = "Commons Identity Developer Preview")]
    community_name: String,

    #[arg(long, default_value = "did:webvh:developer-preview-operator:localhost")]
    operator_id: String,

    #[arg(long, default_value = "did:webvh:developer-preview-verifier:localhost")]
    verifier_id: String,

    #[arg(long, default_value = "sha256-developer-preview-policy")]
    policy_hash: String,

    /// Generate ephemeral local secrets and expose one-time enrollment transaction codes.
    #[arg(long)]
    demo: bool,

    /// Offline governance controller in DID=Ed25519Multikey form; repeat exactly five times.
    #[arg(long = "governance-controller", value_name = "DID=PUBLIC_KEY")]
    governance_controllers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();
    if !args.demo {
        bail!(
            "this reference service is intentionally limited to --demo until durable key/state persistence and an independent audit are complete"
        );
    }
    if !args.bind.ip().is_loopback() {
        bail!("--demo may only bind to a loopback address");
    }
    let mut rng = OsRng;
    let enrollment_code = Zeroizing::new(random_urlsafe(&mut rng, 24));
    let admin_token = Zeroizing::new(random_urlsafe(&mut rng, 32));
    let governance_controllers = governance_controllers(&args.governance_controllers)?;
    if args.demo {
        eprintln!(
            "Developer Preview demo enrollment code: {}",
            enrollment_code.as_str()
        );
        eprintln!(
            "Developer Preview demo admin token: {}",
            admin_token.as_str()
        );
        eprintln!("These ephemeral secrets are printed once and must not be used in production.");
    }

    let state = AppState::new(
        ServiceConfig {
            public_base_url: args.public_base_url,
            community_id: args.community_id,
            community_name: args.community_name,
            operator_id: args.operator_id,
            verifier_id: args.verifier_id,
            policy_hash: args.policy_hash,
            mirrors: vec![
                "https://mirror-a.invalid".into(),
                "https://mirror-b.invalid".into(),
                "https://mirror-c.invalid".into(),
            ],
            governance_controllers,
            enrollment_code,
            admin_token,
            expose_demo_codes: args.demo,
            ephemeral_developer_preview: true,
        },
        OffsetDateTime::now_utc(),
    )?;

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    info!(address = %args.bind, "Commons Identity Developer Preview is listening");
    let heartbeat_state = Arc::clone(&state);
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(error) =
                heartbeat_state.refresh_status_checkpoints(OffsetDateTime::now_utc())
            {
                tracing::error!(%error, "status checkpoint heartbeat failed");
            }
        }
    });
    let result = axum::serve(listener, app(Arc::clone(&state)))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server stopped unexpectedly");
    heartbeat.abort();
    result?;
    Ok(())
}

fn governance_controllers(values: &[String]) -> Result<BTreeMap<String, String>> {
    if values.is_empty() {
        eprintln!(
            "Operator Migration HTTP actions are unavailable until five offline controller public keys are supplied."
        );
        return Ok((0_u8..5)
            .map(|_| {
                let key = SigningKeyMaterial::generate();
                (key.did_key(), key.public_key_multibase())
            })
            .collect());
    }
    if values.len() != 5 {
        bail!("--governance-controller must be supplied exactly five times");
    }
    values
        .iter()
        .map(|value| {
            let (id, public_key) = value
                .split_once('=')
                .context("governance controller must use DID=PUBLIC_KEY")?;
            if id.is_empty() || public_key.is_empty() {
                bail!("governance controller DID and public key cannot be empty");
            }
            Ok((id.to_string(), public_key.to_string()))
        })
        .collect()
}

async fn shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}

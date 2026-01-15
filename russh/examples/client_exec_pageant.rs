
/// Run this example with:
/// cargo run --example client_exec_pageant -- -u xxx -p 22 xx.xx.xx.xx
///
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use log::info;
use russh::keys::agent::client::AgentClient;
use russh::keys::key::PublicKeyOrCert;
use russh::keys::*;
use russh::*;

struct Client {}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // CLI options are defined later in this file
    let cli = Cli::parse();

    info!("Connecting to {}:{}", cli.host, cli.port);
    let config = russh::client::Config::default();
    let sh = Client {};
    let mut session = russh::client::connect(Arc::new(config), (cli.host, cli.port), sh)
        .await?;
    let mut agent = AgentClient::connect_pageant().await?;

    let hash_alg = session.best_supported_rsa_hash().await?.flatten();
    let identities = agent.request_identities().await?;

    let username = cli.username;
    let mut authenticated = false;
    info!("get keys count: {}", identities.len());
    for key in &identities {
        match key {
            PublicKeyOrCert::PublicKey(identity) => {
                let alg = match identity.algorithm() {
                    Algorithm::Dsa | Algorithm::Rsa { .. } => hash_alg,
                    _ => None,
                };
                let auth_result = session
                    .authenticate_publickey_with(
                        username.clone(),
                        identity.clone(),
                        alg,
                        &mut agent,
                    )
                .await;
                if matches!(auth_result, Ok(res) if res.success()) {
                    authenticated = true;
                    break;
                }
            }
            _ => {}
        }
    }
    if authenticated {
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "ls").await?;
        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    info!("{}", String::from_utf8_lossy(data));
                }
                _ => {}
            }
        }
    }

    Ok(())
}

#[derive(clap::Parser)]
#[clap(trailing_var_arg = true)]
pub struct Cli {
    #[clap(index = 1)]
    host: String,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short)]
    username: String,
}

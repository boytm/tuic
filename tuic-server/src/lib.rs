// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicUsize},
};

use moka::future::Cache;
use uuid::Uuid;

pub mod acl;
pub mod compat;
pub mod config;
pub mod connection;
pub mod error;
pub mod io;
pub mod restful;
pub mod server;
pub mod tls;
pub mod utils;

pub use config::{Cli, Config, Control};

pub struct AppContext {
	pub cfg:            Config,
	pub online_counter: HashMap<Uuid, AtomicUsize>,
	pub online_clients: Cache<Uuid, Arc<Cache<usize, compat::QuicClient>>>,
	pub traffic_stats:  HashMap<Uuid, (AtomicUsize, AtomicUsize)>,
}

/// Run the TUIC server with the given configuration
pub async fn run(cfg: Config) -> eyre::Result<()> {
	let mut online_counter = HashMap::new();
	for (user, _) in cfg.users.iter() {
		online_counter.insert(user.to_owned(), AtomicUsize::new(0));
	}

	let mut traffic_stats = HashMap::new();
	for (user, _) in cfg.users.iter() {
		traffic_stats.insert(user.to_owned(), (AtomicUsize::new(0), AtomicUsize::new(0)));
	}

	let ctx = Arc::new(AppContext {
		online_counter,
		online_clients: Cache::new(cfg.users.len() as u64),
		traffic_stats,
		cfg,
	});
	let server = server::Server::init(ctx.clone()).await?;

	#[cfg(unix)]
	{
		use tracing::{info, warn};
		if let Some(user) = &ctx.cfg.user {
			info!("Dropping privileges to user: {}", user);
			let mut pd = privdrop::PrivDrop::default();
			pd = pd.user(user);
			if let Some(group) = &ctx.cfg.group {
				pd = pd.group(group);
			}
			pd.apply().map_err(|e| eyre::eyre!("Failed to drop privileges: {}", e))?;
			warn!("Privileges dropped successfully");
		} else if let Some(group) = &ctx.cfg.group {
			info!("Dropping privileges to group: {}", group);
			privdrop::PrivDrop::default()
				.group(group)
				.apply()
				.map_err(|e| eyre::eyre!("Failed to drop privileges: {}", e))?;
			warn!("Privileges dropped successfully");
		}
	}

	server.start().await;
	Ok(())
}

//! pvemcp: MCP server for Proxmox VE.

mod catalog;
mod config;
mod errors;
mod http;
mod js;
mod prompts;
mod proxmox;
mod resources;
mod runtime;
mod schema;
mod server;
mod ssh;
mod tools;

use errors::PveError;
use runtime::Runtime;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const HELP: &str = "pvemcp: MCP server for Proxmox VE

Usage: pvemcp [--http] [--host 127.0.0.1] [--port 8765] [--list-tools]

Default transport: stdio. Configuration comes from the environment, see the README.
  PROXMOX_URL, PROXMOX_TOKEN                the cluster (user@realm!id=secret)
  PROXMOX_ALLOW_WRITES=true                 enable changes (read-only by default)
  PROXMOX_ALLOW_ELEVATED=true               also allow changes to the cluster itself
  PROXMOX_ALLOW_GUEST_EXEC=true             allow commands through the QEMU guest agent
  PROXMOX_ALLOW_SSH=true                    allow SSH to nodes and containers
  PROXMOX_ALLOW_SENSITIVE=true              allow reads that return secrets
  PROXMOX_DRY_RUN=true                      show writes instead of sending them
  PROXMOX_TOOLSETS=vm,lxc,storage           load only these domains, or \"all\"
  PROXMOX_CONFIG=instances.json             several clusters
  PROXMOX_MCP_TOKEN                         bearer token for --http
";

struct Cli {
    http: bool,
    host: String,
    port: String,
    list_tools: bool,
    help: bool,
}

/// parseArgs of Node, strict: unknown options and positionals are errors.
fn parse_cli(args: impl Iterator<Item = String>) -> Result<Cli, String> {
    let mut cli = Cli { http: false, host: "127.0.0.1".into(), port: "8765".into(), list_tools: false, help: false };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        match name.as_str() {
            "--http" | "--list-tools" | "--help" | "-h" if inline.is_some() => return Err(format!("Option '{name}' does not take an argument")),
            "--http" => cli.http = true,
            "--list-tools" => cli.list_tools = true,
            "--help" | "-h" => cli.help = true,
            "--host" | "--port" => {
                let value = match inline {
                    Some(v) => v,
                    None => match args.next() {
                        Some(v) if !v.starts_with('-') || v == "-" => v,
                        _ => return Err(format!("Option '{name} <value>' argument missing")),
                    },
                };
                if name == "--host" {
                    cli.host = value;
                } else {
                    cli.port = value;
                }
            }
            other if other.starts_with('-') && other != "-" => return Err(format!("Unknown option '{other}'")),
            other => return Err(format!("Unexpected argument '{other}'. This command does not take positional arguments")),
        }
    }
    Ok(cli)
}

fn fail(err: &PveError) -> ! {
    match &err.hint {
        Some(hint) => eprintln!("[pvemcp] {}\n        {hint}", err.message),
        None => eprintln!("[pvemcp] {}", err.message),
    }
    std::process::exit(1);
}

static STOPPING: AtomicBool = AtomicBool::new(false);

/// SSH sessions and connections must not outlive the server.
async fn stop(runtime: Arc<Runtime>) -> ! {
    if !STOPPING.swap(true, Ordering::SeqCst) {
        runtime.shutdown().await;
        std::process::exit(0);
    }
    std::future::pending().await
}

async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn run() -> Result<(), PveError> {
    let cli = parse_cli(std::env::args().skip(1)).map_err(|m| PveError::config(m))?;
    if cli.help {
        print!("{HELP}");
        return Ok(());
    }
    let config = config::load_config(&config::process_env())?;
    let runtime = Runtime::new(config, None)?;

    if cli.list_tools {
        use std::io::Write;
        let tools = server::visible_tools(&runtime)?;
        let mut out = std::io::stdout().lock();
        for def in tools {
            let _ = writeln!(out, "{}\t{}\t{}", def.domain, def.gate.as_str(), def.name);
        }
        drop(out);
        runtime.shutdown().await;
        return Ok(());
    }

    {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            signal().await;
            stop(runtime).await;
        });
    }

    if cli.http {
        let port: u16 = match cli.port.parse::<f64>() {
            Ok(p) if p.fract() == 0.0 && (1.0..=65535.0).contains(&p) => p as u16,
            _ => return Err(PveError::config(format!("--port: \"{}\" is not a valid port.", cli.port))),
        };
        let token = std::env::var("PROXMOX_MCP_TOKEN").ok().filter(|t| !t.is_empty());
        let allowed_hosts = std::env::var("PROXMOX_MCP_ALLOWED_HOSTS").unwrap_or_default().split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
        let serving = http::start_http(runtime, http::HttpOptions { host: cli.host, port, token, allowed_hosts }).await?;
        let _ = serving.await;
        return Ok(());
    }

    // The client closing stdin is how a stdio server is normally told to stop.
    server::serve_stdio(runtime.clone()).await?;
    stop(runtime).await
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    if let Err(err) = rt.block_on(run()) {
        fail(&err);
    }
}

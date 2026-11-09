//! What this server allows: the first thing an agent should ask.

use super::ToolDef;
use crate::proxmox::policy::Gate;
use serde_json::Value;

pub fn info_tools() -> Vec<ToolDef> {
    vec![
        ToolDef::new(
            "pve_mcp_info",
            "About this server",
            "api",
            Gate::Read,
            "Says what this server allows, per cluster: read-only or not, elevated changes, guest execution, SSH, sensitive data, dry run, protected guests, which toolsets are loaded and how many tools. Call this first.",
        )
        .idempotent()
        .handler(|_args, ctx| async move { Ok(Value::Object(crate::server::info(&ctx.runtime))) }),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&super::info_tools());
    }
}

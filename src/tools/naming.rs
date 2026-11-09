//! Tool names are the main interface for an agent, so they read as an action on a thing:
//! pve_start_vm, pve_list_lxc_snapshots. The rules below name most of the API. Where they
//! produce something awkward or misleading, OVERRIDES says it by hand.

use crate::catalog::{CatalogEndpoint, find_endpoint};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

fn word(segment: &str) -> Option<&'static str> {
    match segment {
        "qemu" => Some("vm"),
        "domains" => Some("realms"),
        _ => None,
    }
}

fn known_plural(word: &str) -> Option<&'static str> {
    Some(match word {
        "vm" => "vms",
        "alias" => "aliases",
        "lxc" => "lxc",
        "status" => "status",
        "dns" => "dns",
        "ipset" => "ipsets",
        "acl" => "acl",
        "config" => "config",
        "options" => "options",
        "log" => "log",
        "content" => "content",
        "syslog" => "syslog",
        "entry" => "entries",
        "entries" => "entries",
        "prefix_list" => "prefix_lists",
        "route_map" => "route_maps",
        "ceph" => "ceph",
        "fs" => "filesystems",
        "mds" => "mds",
        "mgr" => "managers",
        "mon" => "monitors",
        "osd" => "osds",
        "rrddata" => "rrd_data",
        "directory" => "directories",
        "zfs" => "zfs",
        "lvm" => "lvm",
        "lvmthin" => "lvmthin",
        "pci" => "pci",
        "usb" => "usb",
        "dir" => "dir",
        _ => return None,
    })
}

/// Top-level node resources whose name would otherwise collide with, or read as, a cluster-wide thing.
const NODE_PREFIXED: &[&str] = &["replication", "firewall", "version", "config", "dns", "hosts", "time", "capabilities", "hardware", "certificates", "scan", "sdn"];

/// Things under /cluster that need the word.
const CLUSTER_PREFIXED: &[&str] = &["firewall", "status", "log", "tasks", "options", "config", "resources"];

fn singular(word: &str) -> String {
    match word {
        "aliases" => return "alias".into(),
        "status" | "dns" | "options" => return word.into(),
        "entries" => return "entry".into(),
        "vms" => return "vm".into(),
        "realms" => return "realm".into(),
        _ => {}
    }
    if word.ends_with("ss") {
        return word.into();
    }
    if word.ends_with('s') && !word.ends_with("us") {
        return word[..word.len() - 1].into();
    }
    word.into()
}

fn plural(word: &str) -> String {
    if let Some(known) = known_plural(word) {
        return known.into();
    }
    if word.ends_with('s') {
        return word.into();
    }
    let vowel_y = word.len() >= 2 && word.ends_with('y') && matches!(word.as_bytes()[word.len() - 2], b'a' | b'e' | b'i' | b'o' | b'u');
    if word.ends_with('y') && !vowel_y {
        return format!("{}ies", &word[..word.len() - 1]);
    }
    format!("{word}s")
}

#[derive(Clone)]
struct Parts {
    /// Literal path segments, in tool-name form, without node and cluster prefixes.
    nouns: Vec<String>,
    /// Whether each noun is followed by a placeholder in the path.
    addressed: Vec<bool>,
    ends_with_placeholder: bool,
}

fn split_template(template: &str) -> Parts {
    let mut segments: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();
    let mut nouns = Vec::new();
    let mut addressed = Vec::new();
    if segments.first() == Some(&"nodes") && segments.get(1) == Some(&"{node}") {
        segments.drain(..2);
        if segments.is_empty() || NODE_PREFIXED.contains(&segments[0]) {
            nouns.push("node".to_string());
            addressed.push(true);
        }
    } else if segments.first() == Some(&"nodes") {
        segments.drain(..1);
        nouns.push("nodes".to_string());
        addressed.push(false);
    } else if segments.first() == Some(&"access") {
        segments.drain(..1);
    } else if segments.first() == Some(&"cluster") {
        segments.drain(..1);
        if segments.is_empty() || CLUSTER_PREFIXED.contains(&segments[0]) {
            nouns.push("cluster".to_string());
            addressed.push(false);
        }
    }
    for segment in &segments {
        if segment.starts_with('{') {
            if let Some(last) = addressed.last_mut() {
                *last = true;
            }
            continue;
        }
        nouns.push(word(segment).map(str::to_string).unwrap_or_else(|| segment.replace('-', "_")));
        addressed.push(false);
    }
    let ends_with_placeholder = segments.last().is_some_and(|s| s.starts_with('{'));
    Parts { nouns, addressed, ends_with_placeholder }
}

#[derive(PartialEq)]
enum Form {
    Singular,
    PluralLast,
    AsIs,
}

/// rules/{pos}/config: every noun that names one item reads in the singular.
fn noun_phrase(parts: &Parts, form: Form) -> String {
    let n = parts.nouns.len();
    parts
        .nouns
        .iter()
        .enumerate()
        .map(|(i, noun)| {
            let last = i + 1 == n;
            if last && form == Form::PluralLast {
                return plural(&singular(noun));
            }
            if parts.addressed[i] || (last && form == Form::Singular) {
                return singular(noun);
            }
            noun.clone()
        })
        .collect::<Vec<_>>()
        .join("_")
}

/// GETs that list sub-paths rather than data.
static DIRECTORY_INDEXES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "/access", "/access/openid", "/cluster", "/cluster/acme", "/cluster/backup-info", "/cluster/bulk-action", "/cluster/bulk-action/guest", "/cluster/ceph", "/cluster/config", "/cluster/firewall", "/cluster/ha", "/cluster/ha/status", "/cluster/jobs", "/cluster/mapping",
        "/cluster/metrics", "/cluster/notifications", "/cluster/notifications/endpoints", "/cluster/qemu", "/cluster/sdn", "/cluster/sdn/fabrics", "/cluster/sdn/vnets/{vnet}/firewall", "/nodes/{node}", "/nodes/{node}/apt", "/nodes/{node}/capabilities",
        "/nodes/{node}/capabilities/qemu", "/nodes/{node}/ceph", "/nodes/{node}/ceph/cfg", "/nodes/{node}/ceph/osd/{osdid}", "/nodes/{node}/ceph/pool/{name}", "/nodes/{node}/certificates", "/nodes/{node}/certificates/acme", "/nodes/{node}/disks", "/nodes/{node}/firewall",
        "/nodes/{node}/hardware", "/nodes/{node}/hardware/pci/{pci-id-or-mapping}", "/nodes/{node}/lxc/{vmid}", "/nodes/{node}/lxc/{vmid}/firewall", "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}", "/nodes/{node}/lxc/{vmid}/status", "/nodes/{node}/qemu/{vmid}",
        "/nodes/{node}/qemu/{vmid}/agent", "/nodes/{node}/qemu/{vmid}/firewall", "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}", "/nodes/{node}/qemu/{vmid}/status", "/nodes/{node}/replication/{id}", "/nodes/{node}/scan", "/nodes/{node}/sdn", "/nodes/{node}/sdn/fabrics/{fabric}",
        "/nodes/{node}/sdn/vnets/{vnet}", "/nodes/{node}/sdn/zones/{zone}", "/nodes/{node}/services/{service}", "/nodes/{node}/storage/{storage}", "/nodes/{node}/tasks/{upid}",
    ]
    .into_iter()
    .collect()
});

/// The rule-based name, without the prefix.
fn rule_name(method: &str, template: &str, endpoint: Option<&CatalogEndpoint>) -> String {
    let parts = split_template(template);
    let last_literal = parts.nouns.last().cloned().unwrap_or_else(|| "root".into());
    let or_root = |s: String| if s.is_empty() { "root".to_string() } else { s };
    match method {
        "GET" => {
            if DIRECTORY_INDEXES.contains(template) {
                return format!("index_{}", or_root(noun_phrase(&parts, Form::AsIs)));
            }
            if !parts.ends_with_placeholder && endpoint.is_some_and(|e| e.returns.kind == "array") {
                return format!("list_{}", noun_phrase(&parts, Form::PluralLast));
            }
            return format!("get_{}", noun_phrase(&parts, if parts.ends_with_placeholder { Form::Singular } else { Form::AsIs }));
        }
        "PUT" => return format!("update_{}", noun_phrase(&parts, Form::Singular)),
        "DELETE" => return format!("delete_{}", noun_phrase(&parts, Form::Singular)),
        _ => {}
    }
    // POST: creating in a collection, or an action named by the last segment.
    let is_collection = !parts.ends_with_placeholder && find_endpoint("GET", template).is_some_and(|e| e.returns.kind == "array");
    if is_collection || parts.ends_with_placeholder {
        return format!("create_{}", noun_phrase(&parts, Form::Singular));
    }
    let n = parts.nouns.len().saturating_sub(1);
    let rest = Parts { nouns: parts.nouns[..n].to_vec(), addressed: vec![true; n], ends_with_placeholder: false };
    let phrase = noun_phrase(&rest, Form::AsIs);
    let noun = phrase.strip_suffix("_status").unwrap_or(&phrase).to_string();
    if noun.is_empty() { last_literal } else { format!("{last_literal}_{noun}") }
}

/// "METHOD template" to the tool name, without the prefix.
pub static OVERRIDES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| OVERRIDE_LIST.iter().copied().collect());

const OVERRIDE_LIST: &[(&str, &str)] = &[
    ("GET /version", "get_version"),
    ("GET /nodes", "list_nodes"),
    ("GET /nodes/{node}", "index_node"),
    ("GET /pools", "list_pools"),
    ("POST /pools", "create_pool"),
    ("PUT /pools", "update_pool"),
    ("DELETE /pools", "delete_pool"),
    ("GET /pools/{poolid}", "get_pool"),
    ("PUT /pools/{poolid}", "update_pool_by_path"),
    ("DELETE /pools/{poolid}", "delete_pool_by_path"),
    ("GET /nodes/{node}/qemu/{vmid}/status/current", "get_vm_status"),
    ("GET /nodes/{node}/lxc/{vmid}/status/current", "get_lxc_status"),
    ("PUT /nodes/{node}/qemu/{vmid}/config", "update_vm_config"),
    ("POST /nodes/{node}/qemu/{vmid}/config", "update_vm_config_async"),
    ("PUT /nodes/{node}/lxc/{vmid}/config", "update_lxc_config"),
    ("GET /nodes/{node}/qemu/{vmid}/migrate", "check_vm_migration"),
    ("GET /nodes/{node}/lxc/{vmid}/migrate", "check_lxc_migration"),
    ("POST /nodes/{node}/qemu/{vmid}/remote_migrate", "remote_migrate_vm"),
    ("POST /nodes/{node}/lxc/{vmid}/remote_migrate", "remote_migrate_lxc"),
    ("POST /nodes/{node}/qemu/{vmid}/move_disk", "move_vm_disk"),
    ("POST /nodes/{node}/lxc/{vmid}/move_volume", "move_lxc_volume"),
    ("PUT /nodes/{node}/qemu/{vmid}/resize", "resize_vm_disk"),
    ("PUT /nodes/{node}/lxc/{vmid}/resize", "resize_lxc_disk"),
    ("POST /nodes/{node}/qemu/{vmid}/template", "convert_vm_to_template"),
    ("POST /nodes/{node}/lxc/{vmid}/template", "convert_lxc_to_template"),
    ("PUT /nodes/{node}/qemu/{vmid}/sendkey", "send_key_to_vm"),
    ("PUT /nodes/{node}/qemu/{vmid}/unlink", "unlink_vm_disks"),
    ("POST /nodes/{node}/qemu/{vmid}/monitor", "run_vm_monitor_command"),
    ("POST /nodes/{node}/qemu/{vmid}/dbus-vmstate", "control_vm_dbus_vmstate"),
    ("GET /nodes/{node}/qemu/{vmid}/feature", "check_vm_feature"),
    ("GET /nodes/{node}/lxc/{vmid}/feature", "check_lxc_feature"),
    ("GET /nodes/{node}/qemu/{vmid}/pending", "list_vm_pending_changes"),
    ("GET /nodes/{node}/lxc/{vmid}/pending", "list_lxc_pending_changes"),
    ("GET /nodes/{node}/qemu/{vmid}/rrd", "get_vm_rrd_graph"),
    ("GET /nodes/{node}/lxc/{vmid}/rrd", "get_lxc_rrd_graph"),
    ("GET /nodes/{node}/qemu/{vmid}/rrddata", "get_vm_rrd_data"),
    ("GET /nodes/{node}/lxc/{vmid}/rrddata", "get_lxc_rrd_data"),
    ("GET /nodes/{node}/lxc/{vmid}/interfaces", "list_lxc_interfaces"),
    ("GET /nodes/{node}/qemu/{vmid}/cloudinit", "list_vm_cloudinit_changes"),
    ("PUT /nodes/{node}/qemu/{vmid}/cloudinit", "regenerate_vm_cloudinit"),
    ("GET /nodes/{node}/qemu/{vmid}/cloudinit/dump", "dump_vm_cloudinit"),
    ("POST /nodes/{node}/qemu/{vmid}/vncproxy", "open_vm_vnc_proxy"),
    ("POST /nodes/{node}/lxc/{vmid}/vncproxy", "open_lxc_vnc_proxy"),
    ("POST /nodes/{node}/qemu/{vmid}/termproxy", "open_vm_terminal_proxy"),
    ("POST /nodes/{node}/lxc/{vmid}/termproxy", "open_lxc_terminal_proxy"),
    ("POST /nodes/{node}/qemu/{vmid}/spiceproxy", "open_vm_spice_proxy"),
    ("POST /nodes/{node}/lxc/{vmid}/spiceproxy", "open_lxc_spice_proxy"),
    ("POST /nodes/{node}/vncshell", "open_node_vnc_shell"),
    ("POST /nodes/{node}/termproxy", "open_node_terminal_proxy"),
    ("POST /nodes/{node}/spiceshell", "open_node_spice_shell"),
    ("POST /access/vncticket", "verify_vnc_ticket"),
    ("POST /nodes/{node}/qemu/{vmid}/agent", "run_vm_agent_command"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/exec", "exec_in_vm"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/exec-status", "get_vm_exec_status"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/file-read", "read_vm_file"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/file-write", "write_vm_file"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/fsfreeze-freeze", "freeze_vm_filesystems"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/fsfreeze-status", "get_vm_fsfreeze_status"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/fsfreeze-thaw", "thaw_vm_filesystems"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/fstrim", "trim_vm_filesystems"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-fsinfo", "get_vm_agent_fsinfo"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-host-name", "get_vm_agent_hostname"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-memory-block-info", "get_vm_agent_memory_block_info"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-memory-blocks", "get_vm_agent_memory_blocks"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-osinfo", "get_vm_agent_osinfo"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-time", "get_vm_agent_time"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-timezone", "get_vm_agent_timezone"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-users", "get_vm_agent_users"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/get-vcpus", "get_vm_agent_vcpus"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/info", "get_vm_agent_info"),
    ("GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces", "get_vm_agent_network_interfaces"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/ping", "ping_vm_agent"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/set-user-password", "set_vm_user_password"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/shutdown", "shutdown_vm_via_agent"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/suspend-disk", "suspend_vm_to_disk_via_agent"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/suspend-hybrid", "suspend_vm_hybrid_via_agent"),
    ("POST /nodes/{node}/qemu/{vmid}/agent/suspend-ram", "suspend_vm_to_ram_via_agent"),
    ("POST /nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback", "rollback_vm_snapshot"),
    ("POST /nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback", "rollback_lxc_snapshot"),
    ("POST /nodes/{node}/status", "reboot_or_shutdown_node"),
    ("GET /nodes/{node}/status", "get_node_status"),
    ("POST /nodes/{node}/startall", "start_all_guests_on_node"),
    ("POST /nodes/{node}/stopall", "stop_all_guests_on_node"),
    ("POST /nodes/{node}/suspendall", "suspend_all_guests_on_node"),
    ("POST /nodes/{node}/migrateall", "migrate_all_guests_from_node"),
    ("POST /nodes/{node}/wakeonlan", "wake_node_on_lan"),
    ("GET /nodes/{node}/rrd", "get_node_rrd_graph"),
    ("GET /nodes/{node}/rrddata", "get_node_rrd_data"),
    ("GET /nodes/{node}/report", "get_node_report"),
    ("GET /nodes/{node}/syslog", "get_node_syslog"),
    ("GET /nodes/{node}/journal", "get_node_journal"),
    ("GET /nodes/{node}/netstat", "get_node_network_stats"),
    ("GET /nodes/{node}/aplinfo", "list_appliance_templates"),
    ("POST /nodes/{node}/aplinfo", "download_appliance_template"),
    ("GET /nodes/{node}/query-url-metadata", "query_url_metadata"),
    ("GET /nodes/{node}/query-oci-repo-tags", "list_oci_repository_tags"),
    ("GET /nodes/{node}/hardware/pci", "list_node_pci_devices"),
    ("GET /nodes/{node}/hardware/pci/{pci-id-or-mapping}", "index_node_pci_device"),
    ("GET /nodes/{node}/hardware/pci/{pci-id-or-mapping}/mdev", "list_node_pci_mdev_types"),
    ("GET /nodes/{node}/hardware/usb", "list_node_usb_devices"),
    ("GET /nodes/{node}/capabilities/qemu", "index_node_qemu_capabilities"),
    ("GET /nodes/{node}/capabilities/qemu/cpu", "list_node_qemu_cpu_models"),
    ("GET /nodes/{node}/capabilities/qemu/cpu-flags", "list_node_qemu_cpu_flags"),
    ("GET /nodes/{node}/capabilities/qemu/machines", "list_node_qemu_machine_types"),
    ("GET /nodes/{node}/capabilities/qemu/migration", "get_node_qemu_migration_capabilities"),
    ("POST /nodes/{node}/vzdump", "run_backup"),
    ("GET /nodes/{node}/vzdump/defaults", "get_backup_defaults"),
    ("GET /nodes/{node}/vzdump/extractconfig", "extract_backup_config"),
    ("GET /nodes/{node}/tasks", "list_node_tasks"),
    ("GET /nodes/{node}/tasks/{upid}", "index_task"),
    ("DELETE /nodes/{node}/tasks/{upid}", "stop_task"),
    ("GET /nodes/{node}/tasks/{upid}/log", "get_task_log"),
    ("GET /nodes/{node}/tasks/{upid}/status", "get_task_status"),
    ("GET /cluster/tasks", "list_cluster_tasks"),
    ("GET /nodes/{node}/services", "list_node_services"),
    ("GET /nodes/{node}/services/{service}", "index_node_service"),
    ("GET /nodes/{node}/services/{service}/state", "get_node_service_state"),
    ("POST /nodes/{node}/services/{service}/reload", "reload_node_service"),
    ("POST /nodes/{node}/services/{service}/restart", "restart_node_service"),
    ("POST /nodes/{node}/services/{service}/start", "start_node_service"),
    ("POST /nodes/{node}/services/{service}/stop", "stop_node_service"),
    ("GET /nodes/{node}/apt/changelog", "get_apt_package_changelog"),
    ("GET /nodes/{node}/apt/repositories", "get_apt_repositories"),
    ("POST /nodes/{node}/apt/repositories", "change_apt_repository"),
    ("PUT /nodes/{node}/apt/repositories", "add_apt_repository"),
    ("GET /nodes/{node}/apt/update", "list_apt_updates"),
    ("POST /nodes/{node}/apt/update", "refresh_apt_index"),
    ("GET /nodes/{node}/apt/versions", "list_apt_package_versions"),
    ("GET /nodes/{node}/network", "list_network_interfaces"),
    ("POST /nodes/{node}/network", "create_network_interface"),
    ("PUT /nodes/{node}/network", "apply_network_changes"),
    ("DELETE /nodes/{node}/network", "revert_network_changes"),
    ("GET /nodes/{node}/network/{iface}", "get_network_interface"),
    ("PUT /nodes/{node}/network/{iface}", "update_network_interface"),
    ("DELETE /nodes/{node}/network/{iface}", "delete_network_interface"),
    ("GET /nodes/{node}/certificates/info", "get_node_certificates"),
    ("POST /nodes/{node}/certificates/custom", "upload_node_certificate"),
    ("DELETE /nodes/{node}/certificates/custom", "delete_node_certificate"),
    ("POST /nodes/{node}/certificates/acme/certificate", "order_node_acme_certificate"),
    ("PUT /nodes/{node}/certificates/acme/certificate", "renew_node_acme_certificate"),
    ("DELETE /nodes/{node}/certificates/acme/certificate", "revoke_node_acme_certificate"),
    ("GET /nodes/{node}/subscription", "get_node_subscription"),
    ("POST /nodes/{node}/subscription", "refresh_node_subscription"),
    ("PUT /nodes/{node}/subscription", "set_node_subscription_key"),
    ("DELETE /nodes/{node}/subscription", "delete_node_subscription_key"),
    ("PUT /nodes/{node}/dns", "update_node_dns"),
    ("POST /nodes/{node}/hosts", "update_node_hosts"),
    ("PUT /nodes/{node}/time", "update_node_time"),
    ("PUT /nodes/{node}/config", "update_node_config"),
    ("GET /nodes/{node}/disks/list", "list_disks"),
    ("GET /nodes/{node}/disks/smart", "get_disk_smart"),
    ("POST /nodes/{node}/disks/initgpt", "init_disk_gpt"),
    ("PUT /nodes/{node}/disks/wipedisk", "wipe_disk"),
    ("GET /nodes/{node}/disks/directory", "list_disk_directories"),
    ("POST /nodes/{node}/disks/directory", "create_disk_directory"),
    ("DELETE /nodes/{node}/disks/directory/{name}", "delete_disk_directory"),
    ("GET /nodes/{node}/disks/lvm", "list_lvm_volume_groups"),
    ("POST /nodes/{node}/disks/lvm", "create_lvm_volume_group"),
    ("DELETE /nodes/{node}/disks/lvm/{name}", "delete_lvm_volume_group"),
    ("GET /nodes/{node}/disks/lvmthin", "list_lvm_thin_pools"),
    ("POST /nodes/{node}/disks/lvmthin", "create_lvm_thin_pool"),
    ("DELETE /nodes/{node}/disks/lvmthin/{name}", "delete_lvm_thin_pool"),
    ("GET /nodes/{node}/disks/zfs", "list_zfs_pools"),
    ("POST /nodes/{node}/disks/zfs", "create_zfs_pool"),
    ("GET /nodes/{node}/disks/zfs/{name}", "get_zfs_pool"),
    ("DELETE /nodes/{node}/disks/zfs/{name}", "delete_zfs_pool"),
    ("GET /nodes/{node}/scan/cifs", "scan_cifs_shares"),
    ("GET /nodes/{node}/scan/iscsi", "scan_iscsi_targets"),
    ("GET /nodes/{node}/scan/lvm", "scan_lvm_volume_groups"),
    ("GET /nodes/{node}/scan/lvmthin", "scan_lvm_thin_pools"),
    ("GET /nodes/{node}/scan/nfs", "scan_nfs_exports"),
    ("GET /nodes/{node}/scan/pbs", "scan_pbs_datastores"),
    ("GET /nodes/{node}/scan/zfs", "scan_zfs_pools"),
    ("GET /storage", "list_storage_configs"),
    ("POST /storage", "create_storage"),
    ("GET /storage/{storage}", "get_storage_config"),
    ("PUT /storage/{storage}", "update_storage_config"),
    ("DELETE /storage/{storage}", "delete_storage"),
    ("GET /nodes/{node}/storage", "list_node_storage"),
    ("GET /nodes/{node}/storage/{storage}", "index_node_storage"),
    ("GET /nodes/{node}/storage/{storage}/content", "list_storage_content"),
    ("POST /nodes/{node}/storage/{storage}/content", "allocate_storage_volume"),
    ("GET /nodes/{node}/storage/{storage}/content/{volume}", "get_storage_volume"),
    ("POST /nodes/{node}/storage/{storage}/content/{volume}", "copy_storage_volume"),
    ("PUT /nodes/{node}/storage/{storage}/content/{volume}", "update_storage_volume"),
    ("DELETE /nodes/{node}/storage/{storage}/content/{volume}", "delete_storage_volume"),
    ("POST /nodes/{node}/storage/{storage}/download-url", "download_url_to_storage"),
    ("POST /nodes/{node}/storage/{storage}/oci-registry-pull", "pull_oci_image_to_storage"),
    ("GET /nodes/{node}/storage/{storage}/file-restore/download", "download_backup_file"),
    ("GET /nodes/{node}/storage/{storage}/file-restore/list", "list_backup_files"),
    ("GET /nodes/{node}/storage/{storage}/identity", "get_storage_identity"),
    ("GET /nodes/{node}/storage/{storage}/import-metadata", "get_storage_import_metadata"),
    ("GET /nodes/{node}/storage/{storage}/prunebackups", "list_prunable_backups"),
    ("DELETE /nodes/{node}/storage/{storage}/prunebackups", "prune_backups"),
    ("GET /nodes/{node}/storage/{storage}/rrd", "get_storage_rrd_graph"),
    ("GET /nodes/{node}/storage/{storage}/rrddata", "get_storage_rrd_data"),
    ("GET /nodes/{node}/storage/{storage}/status", "get_storage_status"),
    ("GET /cluster/backup", "list_backup_jobs"),
    ("POST /cluster/backup", "create_backup_job"),
    ("GET /cluster/backup/{id}", "get_backup_job"),
    ("PUT /cluster/backup/{id}", "update_backup_job"),
    ("DELETE /cluster/backup/{id}", "delete_backup_job"),
    ("GET /cluster/backup/{id}/included_volumes", "get_backup_job_included_volumes"),
    ("GET /cluster/backup-info", "index_backup_info"),
    ("GET /cluster/backup-info/not-backed-up", "list_guests_not_backed_up"),
    ("GET /cluster/bulk-action", "index_bulk_actions"),
    ("GET /cluster/bulk-action/guest", "index_bulk_guest_actions"),
    ("POST /cluster/bulk-action/guest/migrate", "bulk_migrate_guests"),
    ("POST /cluster/bulk-action/guest/shutdown", "bulk_shutdown_guests"),
    ("POST /cluster/bulk-action/guest/start", "bulk_start_guests"),
    ("POST /cluster/bulk-action/guest/suspend", "bulk_suspend_guests"),
    ("GET /cluster/nextid", "get_next_vmid"),
    ("GET /cluster/status", "get_cluster_status"),
    ("GET /cluster/log", "get_cluster_log"),
    ("GET /cluster/config", "index_cluster_config"),
    ("POST /cluster/config", "create_cluster"),
    ("GET /cluster/config/apiversion", "get_cluster_api_version"),
    ("GET /cluster/config/join", "get_cluster_join_info"),
    ("POST /cluster/config/join", "join_cluster"),
    ("GET /cluster/config/nodes", "list_cluster_config_nodes"),
    ("POST /cluster/config/nodes/{node}", "add_cluster_node"),
    ("DELETE /cluster/config/nodes/{node}", "remove_cluster_node"),
    ("GET /cluster/config/qdevice", "get_cluster_qdevice_status"),
    ("GET /cluster/config/totem", "get_cluster_totem_config"),
    ("GET /cluster/replication", "list_replication_jobs"),
    ("POST /cluster/replication", "create_replication_job"),
    ("GET /cluster/replication/{id}", "get_replication_job"),
    ("PUT /cluster/replication/{id}", "update_replication_job"),
    ("DELETE /cluster/replication/{id}", "delete_replication_job"),
    ("GET /nodes/{node}/replication", "list_node_replication_jobs"),
    ("GET /nodes/{node}/replication/{id}", "index_node_replication_job"),
    ("GET /nodes/{node}/replication/{id}/log", "get_node_replication_log"),
    ("POST /nodes/{node}/replication/{id}/schedule_now", "run_replication_job_now"),
    ("GET /nodes/{node}/replication/{id}/status", "get_node_replication_status"),
    ("GET /cluster/jobs", "index_cluster_jobs"),
    ("GET /cluster/jobs/schedule-analyze", "analyze_job_schedule"),
    ("GET /cluster/jobs/realm-sync", "list_realm_sync_jobs"),
    ("GET /cluster/jobs/realm-sync/{id}", "get_realm_sync_job"),
    ("POST /cluster/jobs/realm-sync/{id}", "create_realm_sync_job"),
    ("PUT /cluster/jobs/realm-sync/{id}", "update_realm_sync_job"),
    ("DELETE /cluster/jobs/realm-sync/{id}", "delete_realm_sync_job"),
    ("GET /cluster/metrics", "index_metrics"),
    ("GET /cluster/metrics/export", "export_metrics"),
    ("GET /cluster/metrics/server", "list_metric_servers"),
    ("GET /cluster/metrics/server/{id}", "get_metric_server"),
    ("POST /cluster/metrics/server/{id}", "create_metric_server"),
    ("PUT /cluster/metrics/server/{id}", "update_metric_server"),
    ("DELETE /cluster/metrics/server/{id}", "delete_metric_server"),
    ("GET /cluster/qemu", "index_cluster_qemu"),
    ("GET /cluster/qemu/cpu-flags", "list_cluster_cpu_flags"),
    ("GET /cluster/qemu/custom-cpu-models", "list_custom_cpu_models"),
    ("POST /cluster/qemu/custom-cpu-models", "create_custom_cpu_model"),
    ("GET /cluster/qemu/custom-cpu-models/{cputype}", "get_custom_cpu_model"),
    ("PUT /cluster/qemu/custom-cpu-models/{cputype}", "update_custom_cpu_model"),
    ("DELETE /cluster/qemu/custom-cpu-models/{cputype}", "delete_custom_cpu_model"),
    ("GET /cluster/firewall/refs", "list_cluster_firewall_refs"),
    ("GET /cluster/firewall/macros", "list_firewall_macros"),
    ("GET /cluster/firewall/groups", "list_firewall_security_groups"),
    ("POST /cluster/firewall/groups", "create_firewall_security_group"),
    ("DELETE /cluster/firewall/groups/{group}", "delete_firewall_security_group"),
    ("GET /cluster/firewall/groups/{group}", "list_firewall_security_group_rules"),
    ("POST /cluster/firewall/groups/{group}", "create_firewall_security_group_rule"),
    ("GET /cluster/firewall/groups/{group}/{pos}", "get_firewall_security_group_rule"),
    ("PUT /cluster/firewall/groups/{group}/{pos}", "update_firewall_security_group_rule"),
    ("DELETE /cluster/firewall/groups/{group}/{pos}", "delete_firewall_security_group_rule"),
    ("GET /cluster/firewall/ipset/{name}", "list_cluster_firewall_ipset_entries"),
    ("POST /cluster/firewall/ipset/{name}", "add_cluster_firewall_ipset_entry"),
    ("DELETE /cluster/firewall/ipset/{name}", "delete_cluster_firewall_ipset"),
    ("GET /cluster/firewall/ipset/{name}/{cidr}", "get_cluster_firewall_ipset_entry"),
    ("PUT /cluster/firewall/ipset/{name}/{cidr}", "update_cluster_firewall_ipset_entry"),
    ("DELETE /cluster/firewall/ipset/{name}/{cidr}", "delete_cluster_firewall_ipset_entry"),
    ("GET /nodes/{node}/firewall/log", "get_node_firewall_log"),
    ("GET /nodes/{node}/qemu/{vmid}/firewall/ipset/{name}", "list_vm_firewall_ipset_entries"),
    ("POST /nodes/{node}/qemu/{vmid}/firewall/ipset/{name}", "add_vm_firewall_ipset_entry"),
    ("DELETE /nodes/{node}/qemu/{vmid}/firewall/ipset/{name}", "delete_vm_firewall_ipset"),
    ("GET /nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}", "get_vm_firewall_ipset_entry"),
    ("PUT /nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}", "update_vm_firewall_ipset_entry"),
    ("DELETE /nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}", "delete_vm_firewall_ipset_entry"),
    ("GET /nodes/{node}/lxc/{vmid}/firewall/ipset/{name}", "list_lxc_firewall_ipset_entries"),
    ("POST /nodes/{node}/lxc/{vmid}/firewall/ipset/{name}", "add_lxc_firewall_ipset_entry"),
    ("DELETE /nodes/{node}/lxc/{vmid}/firewall/ipset/{name}", "delete_lxc_firewall_ipset"),
    ("GET /nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}", "get_lxc_firewall_ipset_entry"),
    ("PUT /nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}", "update_lxc_firewall_ipset_entry"),
    ("DELETE /nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}", "delete_lxc_firewall_ipset_entry"),
    ("GET /nodes/{node}/qemu/{vmid}/firewall/log", "get_vm_firewall_log"),
    ("GET /nodes/{node}/lxc/{vmid}/firewall/log", "get_lxc_firewall_log"),
    ("GET /nodes/{node}/qemu/{vmid}/firewall/refs", "list_vm_firewall_refs"),
    ("GET /nodes/{node}/lxc/{vmid}/firewall/refs", "list_lxc_firewall_refs"),
    ("GET /cluster/ha/status", "index_ha_status"),
    ("GET /cluster/ha/status/current", "get_ha_status"),
    ("GET /cluster/ha/status/manager_status", "get_ha_manager_status"),
    ("POST /cluster/ha/status/arm-ha", "arm_ha"),
    ("POST /cluster/ha/status/disarm-ha", "disarm_ha"),
    ("POST /cluster/ha/resources/{sid}/migrate", "migrate_ha_resource"),
    ("POST /cluster/ha/resources/{sid}/relocate", "relocate_ha_resource"),
    ("GET /access", "index_access"),
    ("GET /access/acl", "list_acl"),
    ("PUT /access/acl", "update_acl"),
    ("POST /access/domains/{realm}/sync", "sync_realm"),
    ("GET /access/openid", "index_openid"),
    ("POST /access/openid/auth-url", "get_openid_auth_url"),
    ("PUT /access/password", "change_user_password"),
    ("GET /access/permissions", "get_effective_permissions"),
    ("GET /access/tfa", "list_all_tfa"),
    ("GET /access/tfa/{userid}", "list_user_tfa"),
    ("POST /access/tfa/{userid}", "add_user_tfa"),
    ("GET /access/tfa/{userid}/{id}", "get_user_tfa_entry"),
    ("PUT /access/tfa/{userid}/{id}", "update_user_tfa_entry"),
    ("DELETE /access/tfa/{userid}/{id}", "delete_user_tfa_entry"),
    ("GET /access/users/{userid}/tfa", "get_user_tfa_types"),
    ("PUT /access/users/{userid}/unlock-tfa", "unlock_user_tfa"),
    ("GET /access/users/{userid}/token", "list_user_tokens"),
    ("GET /access/users/{userid}/token/{tokenid}", "get_user_token"),
    ("POST /access/users/{userid}/token/{tokenid}", "create_user_token"),
    ("PUT /access/users/{userid}/token/{tokenid}", "update_user_token"),
    ("DELETE /access/users/{userid}/token/{tokenid}", "delete_user_token"),
    ("GET /cluster/ceph", "index_cluster_ceph"),
    ("GET /cluster/ceph/flags", "list_ceph_flags"),
    ("PUT /cluster/ceph/flags", "update_ceph_flags"),
    ("GET /cluster/ceph/flags/{flag}", "get_ceph_flag"),
    ("PUT /cluster/ceph/flags/{flag}", "update_ceph_flag"),
    ("GET /cluster/ceph/health-mute", "list_ceph_health_mutes"),
    ("PUT /cluster/ceph/health-mute/{code}", "mute_ceph_health_check"),
    ("GET /cluster/ceph/metadata", "get_cluster_ceph_metadata"),
    ("GET /cluster/ceph/status", "get_cluster_ceph_status"),
    ("POST /cluster/ceph/restart-bulk", "bulk_restart_cluster_ceph_services"),
    ("GET /nodes/{node}/ceph", "index_node_ceph"),
    ("POST /nodes/{node}/ceph/restart-bulk", "bulk_restart_node_ceph_services"),
    ("GET /nodes/{node}/ceph/status", "get_node_ceph_status"),
    ("GET /nodes/{node}/ceph/cfg", "index_ceph_config"),
    ("GET /nodes/{node}/ceph/cfg/db", "list_ceph_config_db"),
    ("GET /nodes/{node}/ceph/cfg/raw", "get_ceph_config_raw"),
    ("GET /nodes/{node}/ceph/cfg/value", "get_ceph_config_values"),
    ("GET /nodes/{node}/ceph/cmd-safety", "check_ceph_command_safety"),
    ("GET /nodes/{node}/ceph/crush", "get_ceph_crush_map"),
    ("GET /nodes/{node}/ceph/rules", "list_ceph_crush_rules"),
    ("GET /nodes/{node}/ceph/log", "get_ceph_log"),
    ("GET /nodes/{node}/ceph/fs", "list_ceph_filesystems"),
    ("POST /nodes/{node}/ceph/fs/{name}", "create_ceph_filesystem"),
    ("DELETE /nodes/{node}/ceph/fs/{name}", "delete_ceph_filesystem"),
    ("GET /nodes/{node}/ceph/mds", "list_ceph_mds"),
    ("POST /nodes/{node}/ceph/mds/{name}", "create_ceph_mds"),
    ("DELETE /nodes/{node}/ceph/mds/{name}", "delete_ceph_mds"),
    ("GET /nodes/{node}/ceph/mgr", "list_ceph_managers"),
    ("POST /nodes/{node}/ceph/mgr/{id}", "create_ceph_manager"),
    ("DELETE /nodes/{node}/ceph/mgr/{id}", "delete_ceph_manager"),
    ("GET /nodes/{node}/ceph/mon", "list_ceph_monitors"),
    ("POST /nodes/{node}/ceph/mon/{monid}", "create_ceph_monitor"),
    ("DELETE /nodes/{node}/ceph/mon/{monid}", "delete_ceph_monitor"),
    ("GET /nodes/{node}/ceph/osd", "get_ceph_osd_tree"),
    ("POST /nodes/{node}/ceph/osd", "create_ceph_osd"),
    ("POST /nodes/{node}/ceph/osd/{osdid}/in", "mark_ceph_osd_in"),
    ("POST /nodes/{node}/ceph/osd/{osdid}/out", "mark_ceph_osd_out"),
    ("POST /nodes/{node}/ceph/restart", "restart_ceph_services"),
    ("POST /nodes/{node}/ceph/start", "start_ceph_services"),
    ("POST /nodes/{node}/ceph/stop", "stop_ceph_services"),
    ("GET /cluster/sdn", "index_cluster_sdn"),
    ("PUT /cluster/sdn", "apply_sdn_config"),
    ("POST /cluster/sdn/lock", "lock_sdn"),
    ("DELETE /cluster/sdn/lock", "unlock_sdn"),
    ("POST /cluster/sdn/rollback", "rollback_sdn"),
    ("GET /cluster/sdn/dry-run", "preview_sdn_changes"),
    ("GET /cluster/sdn/ipams/{ipam}/status", "list_sdn_ipam_entries"),
    ("GET /cluster/sdn/fabrics/all", "get_all_sdn_fabrics"),
    ("GET /cluster/sdn/fabrics/fabric", "list_sdn_fabrics"),
    ("POST /cluster/sdn/fabrics/fabric", "create_sdn_fabric"),
    ("GET /cluster/sdn/fabrics/fabric/{id}", "get_sdn_fabric"),
    ("PUT /cluster/sdn/fabrics/fabric/{id}", "update_sdn_fabric"),
    ("DELETE /cluster/sdn/fabrics/fabric/{id}", "delete_sdn_fabric"),
    ("GET /cluster/sdn/fabrics/node", "list_all_sdn_fabric_nodes"),
    ("GET /cluster/sdn/fabrics/node/{fabric_id}", "list_sdn_fabric_nodes"),
    ("POST /cluster/sdn/fabrics/node/{fabric_id}", "create_sdn_fabric_node"),
    ("GET /cluster/sdn/fabrics/node/{fabric_id}/{node_id}", "get_sdn_fabric_node"),
    ("PUT /cluster/sdn/fabrics/node/{fabric_id}/{node_id}", "update_sdn_fabric_node"),
    ("DELETE /cluster/sdn/fabrics/node/{fabric_id}/{node_id}", "delete_sdn_fabric_node"),
    ("GET /cluster/sdn/route-maps/entries", "list_all_sdn_route_map_entries"),
    ("POST /cluster/sdn/route-maps/entries", "create_sdn_route_map_entry"),
    ("GET /cluster/sdn/route-maps/entries/{route-map-id}", "list_sdn_route_map_entries"),
    ("GET /cluster/sdn/route-maps/entries/{route-map-id}/entry/{order}", "get_sdn_route_map_entry"),
    ("PUT /cluster/sdn/route-maps/entries/{route-map-id}/entry/{order}", "update_sdn_route_map_entry"),
    ("DELETE /cluster/sdn/route-maps/entries/{route-map-id}/entry/{order}", "delete_sdn_route_map_entry"),
    ("POST /cluster/sdn/vnets/{vnet}/ips", "create_sdn_vnet_ip"),
    ("GET /nodes/{node}/sdn/vnets/{vnet}/mac-vrf", "list_node_sdn_vnet_mac_vrf"),
    ("GET /nodes/{node}/sdn/zones/{zone}/ip-vrf", "list_node_sdn_zone_ip_vrf"),
    ("GET /nodes/{node}/sdn/zones/{zone}/content", "list_node_sdn_zone_content"),
    ("GET /cluster/notifications/endpoints", "index_notification_endpoints"),
    ("GET /cluster/notifications/matchers", "list_notification_matchers"),
    ("POST /cluster/notifications/matchers", "create_notification_matcher"),
    ("GET /cluster/notifications/matchers/{name}", "get_notification_matcher"),
    ("PUT /cluster/notifications/matchers/{name}", "update_notification_matcher"),
    ("DELETE /cluster/notifications/matchers/{name}", "delete_notification_matcher"),
    ("GET /cluster/notifications/targets", "list_notification_targets"),
    ("GET /cluster/notifications/endpoints/gotify", "list_notification_gotify_endpoints"),
    ("POST /cluster/notifications/endpoints/gotify", "create_notification_gotify_endpoint"),
    ("GET /cluster/notifications/endpoints/gotify/{name}", "get_notification_gotify_endpoint"),
    ("PUT /cluster/notifications/endpoints/gotify/{name}", "update_notification_gotify_endpoint"),
    ("DELETE /cluster/notifications/endpoints/gotify/{name}", "delete_notification_gotify_endpoint"),
    ("GET /cluster/notifications/endpoints/sendmail", "list_notification_sendmail_endpoints"),
    ("POST /cluster/notifications/endpoints/sendmail", "create_notification_sendmail_endpoint"),
    ("GET /cluster/notifications/endpoints/sendmail/{name}", "get_notification_sendmail_endpoint"),
    ("PUT /cluster/notifications/endpoints/sendmail/{name}", "update_notification_sendmail_endpoint"),
    ("DELETE /cluster/notifications/endpoints/sendmail/{name}", "delete_notification_sendmail_endpoint"),
    ("GET /cluster/notifications/endpoints/smtp", "list_notification_smtp_endpoints"),
    ("POST /cluster/notifications/endpoints/smtp", "create_notification_smtp_endpoint"),
    ("GET /cluster/notifications/endpoints/smtp/{name}", "get_notification_smtp_endpoint"),
    ("PUT /cluster/notifications/endpoints/smtp/{name}", "update_notification_smtp_endpoint"),
    ("DELETE /cluster/notifications/endpoints/smtp/{name}", "delete_notification_smtp_endpoint"),
    ("GET /cluster/notifications/endpoints/webhook", "list_notification_webhook_endpoints"),
    ("POST /cluster/notifications/endpoints/webhook", "create_notification_webhook_endpoint"),
    ("GET /cluster/notifications/endpoints/webhook/{name}", "get_notification_webhook_endpoint"),
    ("PUT /cluster/notifications/endpoints/webhook/{name}", "update_notification_webhook_endpoint"),
    ("DELETE /cluster/notifications/endpoints/webhook/{name}", "delete_notification_webhook_endpoint"),
    ("POST /cluster/notifications/targets/{name}/test", "test_notification_target"),
    ("GET /cluster/notifications/matcher-field-values", "list_notification_matcher_field_values"),
    ("GET /cluster/notifications/matcher-fields", "list_notification_matcher_fields"),
    ("GET /cluster/acme/tos", "get_acme_terms_of_service"),
    ("GET /cluster/acme/meta", "get_acme_directory_meta"),
    ("GET /cluster/acme/challenge-schema", "list_acme_challenge_schemas"),
    ("GET /cluster/acme/account", "list_acme_accounts"),
    ("POST /cluster/acme/account", "register_acme_account"),
    ("GET /cluster/acme/account/{name}", "get_acme_account"),
    ("PUT /cluster/acme/account/{name}", "update_acme_account"),
    ("DELETE /cluster/acme/account/{name}", "deactivate_acme_account"),
    ("GET /cluster/mapping/dir", "list_dir_mappings"),
    ("POST /cluster/mapping/dir", "create_dir_mapping"),
    ("GET /cluster/mapping/dir/{id}", "get_dir_mapping"),
    ("PUT /cluster/mapping/dir/{id}", "update_dir_mapping"),
    ("DELETE /cluster/mapping/dir/{id}", "delete_dir_mapping"),
    ("GET /cluster/mapping/pci", "list_pci_mappings"),
    ("POST /cluster/mapping/pci", "create_pci_mapping"),
    ("GET /cluster/mapping/pci/{id}", "get_pci_mapping"),
    ("PUT /cluster/mapping/pci/{id}", "update_pci_mapping"),
    ("DELETE /cluster/mapping/pci/{id}", "delete_pci_mapping"),
    ("GET /cluster/mapping/usb", "list_usb_mappings"),
    ("POST /cluster/mapping/usb", "create_usb_mapping"),
    ("GET /cluster/mapping/usb/{id}", "get_usb_mapping"),
    ("PUT /cluster/mapping/usb/{id}", "update_usb_mapping"),
    ("DELETE /cluster/mapping/usb/{id}", "delete_usb_mapping"),
];

pub fn tool_name(method: &str, template: &str) -> String {
    let key = format!("{method} {template}");
    if let Some(name) = OVERRIDES.get(key.as_str()) {
        return format!("pve_{name}");
    }
    format!("pve_{}", rule_name(method, template, find_endpoint(method, template)))
}

pub struct DomainOf {
    pub domain: &'static str,
    pub also: Option<Vec<&'static str>>,
}

fn rx(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

type DomainRule = (Regex, &'static str, Option<Vec<&'static str>>);

static DOMAIN_RULES: LazyLock<Vec<DomainRule>> = LazyLock::new(|| {
    vec![
        (rx(r"^/nodes/\{node\}/qemu/\{vmid\}/firewall"), "firewall", Some(vec!["vm"])),
        (rx(r"^/nodes/\{node\}/lxc/\{vmid\}/firewall"), "firewall", Some(vec!["lxc"])),
        (rx(r"^/nodes/\{node\}/qemu"), "vm", None),
        (rx(r"^/nodes/\{node\}/lxc"), "lxc", None),
        (rx(r"^/cluster/sdn|^/nodes/\{node\}/sdn"), "sdn", None),
        (rx(r"^/cluster/ceph|^/nodes/\{node\}/ceph"), "ceph", None),
        (rx(r"^/cluster/notifications"), "notifications", None),
        (rx(r"^/cluster/acme|^/nodes/\{node\}/certificates/acme"), "acme", None),
        (rx(r"^/cluster/mapping"), "mapping", None),
        (rx(r"^/cluster/ha"), "ha", None),
        (rx(r"^/cluster/firewall|^/nodes/\{node\}/firewall"), "firewall", None),
        (rx(r"^/access|^/cluster/jobs/realm-sync"), "access", None),
        (rx(r"^/pools"), "pools", None),
        (rx(r"^/cluster/backup|^/nodes/\{node\}/vzdump|^/nodes/\{node\}/storage/\{storage\}/(?:file-restore|prunebackups)"), "backup", None),
        // A container is created from a template, and backups are listed as the content of a storage.
        (rx(r"^/nodes/\{node\}/aplinfo"), "storage", Some(vec!["lxc"])),
        (rx(r"^/nodes/\{node\}/storage/\{storage\}/content"), "storage", Some(vec!["backup"])),
        (rx(r"^/storage|^/nodes/\{node\}/storage|^/nodes/\{node\}/scan|^/nodes/\{node\}/aplinfo|^/nodes/\{node\}/query-(?:oci|url)"), "storage", None),
        (rx(r"^/nodes/\{node\}/tasks|^/cluster/tasks"), "tasks", None),
        (rx(r"^/nodes/\{node\}/network"), "network", None),
        (rx(r"^/nodes/\{node\}/disks"), "disks", None),
        (rx(r"^/nodes/\{node\}/(?:dns|hosts)$"), "node", Some(vec!["network"])),
        (rx(r"^/nodes"), "node", None),
    ]
});

pub fn domain_of(template: &str) -> DomainOf {
    for (pattern, domain, also) in DOMAIN_RULES.iter() {
        if pattern.is_match(template) {
            return DomainOf { domain, also: also.clone() };
        }
    }
    DomainOf { domain: "cluster", also: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_like_typescript() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/reference/names.txt")).unwrap();
        let mut wrong = Vec::new();
        for line in text.lines() {
            let mut f = line.split('\t');
            let (method, path, name, domain) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
            let got = tool_name(method, path);
            if got != name || domain_of(path).domain != domain {
                wrong.push(format!("{method} {path}: {got} / {name}, {} / {domain}", domain_of(path).domain));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn no_override_for_a_method_that_does_not_exist() {
        for (key, _) in OVERRIDE_LIST {
            let (method, path) = key.split_once(' ').unwrap();
            assert!(find_endpoint(method, path).is_some(), "{key}");
        }
        assert_eq!(OVERRIDES.len(), OVERRIDE_LIST.len(), "an override is listed twice");
    }

    #[test]
    fn puts_tools_in_every_domain_that_needs_them() {
        let of = |p: &str| {
            let d = domain_of(p);
            (d.domain, d.also)
        };
        assert_eq!(of("/nodes/{node}/aplinfo"), ("storage", Some(vec!["lxc"])));
        assert_eq!(of("/nodes/{node}/dns"), ("node", Some(vec!["network"])));
        assert_eq!(of("/nodes/{node}/hosts"), ("node", Some(vec!["network"])));
        assert_eq!(of("/nodes/{node}/storage/{storage}/content"), ("storage", Some(vec!["backup"])));
        assert_eq!(of("/nodes/{node}/storage/{storage}/content/{volume}"), ("storage", Some(vec!["backup"])));
        assert_eq!(of("/nodes/{node}/storage/{storage}/status"), ("storage", None));
        assert_eq!(of("/nodes/{node}/time"), ("node", None));
    }
}

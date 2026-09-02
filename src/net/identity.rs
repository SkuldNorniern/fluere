//! Turning a flow's key into what plugins and the exporter report.
//!
//! The key knows what separated this flow from another with the same addresses
//! and ports. Both output paths need that, and both must describe it the same
//! way, so the translation lives here rather than in each of them.

use fluereflow::Flow;

/// VLAN tags, outermost first, dot-separated. Empty when untagged.
pub fn vlan(flow: &Flow) -> String {
    flow.key
        .vlan
        .tags()
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The kind of tunnel that carried the flow, empty when it was not tunnelled.
pub fn encapsulation(flow: &Flow) -> &'static str {
    flow.key
        .encapsulation
        .map_or("", |encapsulation| encapsulation.kind.as_str())
}

/// The tunnel's segment, key, label or session. Empty when it has none.
pub fn tunnel_id(flow: &Flow) -> String {
    match flow
        .key
        .encapsulation
        .and_then(|encapsulation| encapsulation.id)
    {
        Some(id) => id.to_string(),
        None => String::new(),
    }
}

/// The tunnel's own endpoints. Empty for encapsulations that sit below IP.
pub fn tunnel_endpoints(flow: &Flow) -> String {
    match flow.key.encapsulation.and_then(|e| e.outer) {
        Some((source, destination)) => format!("{source}->{destination}"),
        None => String::new(),
    }
}

/// Endpoints the flow arrived from, semicolon-separated. Empty when it never
/// moved, where the key's own addresses already say where it was.
pub fn paths(flow: &Flow) -> String {
    if !flow.record.paths.migrated() {
        return String::new();
    }

    flow.record
        .paths
        .endpoints()
        .iter()
        .map(|change| change.to_string())
        .collect::<Vec<_>>()
        .join(";")
}

/// EtherType, for traffic that is not IP. Empty otherwise, where the address
/// family already says it.
pub fn ethertype(flow: &Flow) -> String {
    match flow.key.ethertype {
        Some(ethertype) if !flow.is_ip() => format!("0x{ethertype:04x}"),
        _ => String::new(),
    }
}

/// Everything a plugin is told about what identified this flow.
/// Hand a finished flow to the plugins.
///
/// The identity is built only when a plugin is loaded to receive it. Describing
/// a flow allocates, and a run with no plugins would otherwise pay for one on
/// every flow just to have it dropped at the far end of the queue.
pub fn offer_to_plugins(
    plugin_manager: &fluere_plugin::PluginManager,
    flow: &Flow,
) -> Result<(), crate::FluereError> {
    if !plugin_manager.is_active() {
        return Ok(());
    }

    plugin_manager
        .process_flow_data(flow.record, for_plugin(flow))
        .map_err(|error| crate::FluereError::Plugin(error.to_string()))
}

pub fn for_plugin(flow: &Flow) -> fluere_plugin::FlowIdentity {
    let encapsulation = flow.key.encapsulation;

    fluere_plugin::FlowIdentity {
        source: Some(flow.key.source),
        destination: Some(flow.key.destination),
        ports: flow.key.endpoints.ports(),
        icmp: flow.record.transport.icmp,
        spi: flow.key.endpoints.security_association(),
        gre_protocol: flow.key.endpoints.gre_protocol(),
        ip_version: flow.key.ip_version(),
        protocol: flow.protocol_name().to_string(),
        protocol_number: flow.is_ip().then_some(flow.key.protocol),
        ethertype: (!flow.is_ip()).then_some(flow.key.ethertype).flatten(),
        vlan: flow.key.vlan.tags().to_vec(),
        encapsulation: encapsulation.map(|e| e.kind.as_str().to_string()),
        tunnel_id: encapsulation.and_then(|e| e.id),
        tunnel_endpoints: encapsulation.and_then(|e| e.outer),
    }
}

let src_ip = packet.get_source();
let dst_ip = packet.get_destination();
let src_port = packet.get_source_port();
let dst_port = packet.get_destination_port();

// Check if the flow already exists in the active flows
let key = (src_ip, src_port, dst_ip, dst_port);
let flow = active_flows.get(&key);

if flow.is_some() {
    println!("Packet is in the established flow direction");
} else {
    // check for the reverse direction flow
    let reverse_key = (dst_ip, dst_port, src_ip, src_port);
    let flow = active_flows.get(&reverse_key);
    if flow.is_some() {
        println!("Packet is in the reverse flow direction");
    } else {
        println!("Packet is in a new flow direction");
    }
}
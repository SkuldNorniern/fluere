use pnet::datalink;

pub fn get_local_ip() {
    let _interfaces = datalink::interfaces();
    //for iface in interfaces {
        //println!("{:?}", iface);
    //}
}

// pub fn is_in_subnet() -> bool {

// }

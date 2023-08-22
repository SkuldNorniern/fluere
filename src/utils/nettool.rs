use pnet::datalink;

pub fn get_local_ip()  {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        println!("{:?}", iface);
    }
}

// pub fn is_in_subnet() -> bool {

// }

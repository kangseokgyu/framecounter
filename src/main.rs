use std::collections::LinkedList;

use macaddr::MacAddr6;

fn main() {
    let mac = MacAddr6::new(0x0, 0x0, 0x0, 0x66, 0x0, 0x1);
    println!("{mac}");

    let c1: framecounter::Config = framecounter::Config {
        filename: String::from("pcaps/5.pcap"),
        filter: format!(
            "wlan type mgt subtype disassoc and wlan addr1 {}",
            mac.to_string()
        ),
    };
    let c2: framecounter::Config = framecounter::Config {
        filename: String::from("pcaps/5.pcap"),
        filter: format!(
            "wlan type mgt subtype beacon and wlan addr1 {} and ether[68:1] == 0x7f",
            mac.to_string()
        ),
    };
    let c3: framecounter::Config = framecounter::Config {
        filename: String::from("pcaps/5.pcap"),
        filter: format!(
            "wlan type mgt subtype beacon and wlan addr1 {} and ether[68:1] == 0x7f",
            mac.to_string()
        ),
    };

    let cfgs: LinkedList<framecounter::Config> = LinkedList::from([c1, c2, c3]);
    for cfg in cfgs {
        println!("count: {}", framecounter::count(&cfg).unwrap());
    }
}

use pcap;
use radiotap::Radiotap;

pub struct Config {
    pub filename: String,
    pub filter: String,
}

pub fn count(config: &Config) -> Result<u32, pcap::Error> {
    let mut cap_file = pcap::Capture::from_file(&config.filename)?;
    cap_file.filter(&config.filter, true)?;

    let mut count = 0;
    while let Ok(packet) = cap_file.next_packet() {
        let radiotap = Radiotap::from_bytes(&packet).unwrap();
        if radiotap.antenna_signal.unwrap().value > -50 {
            count += 1;
        }
    }
    Ok(count)
}

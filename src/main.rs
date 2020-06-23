mod tun;

//use std::io::prelude::*;

fn main() {
    let tun = tun::Tun::open(
        "{B39A9AFB-F07B-4E5E-AC35-780C4712769B}",
        std::net::Ipv4Addr::new(10, 99, 0, 1),
        16,
        1300,
    )
    .unwrap();

    std::thread::sleep(std::time::Duration::from_secs(10));
}

mod tun;

fn main() {
    let tun = tun::Tun::open(
        "中文",
        std::net::Ipv4Addr::new(10, 99, 0, 1),
        16,
        1300,
    )
    .unwrap();

    std::thread::sleep(std::time::Duration::from_secs(1000));
}

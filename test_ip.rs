use std::net::SocketAddr;
fn main() {
    let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
    println!("{}", addr.is_ipv4());
}

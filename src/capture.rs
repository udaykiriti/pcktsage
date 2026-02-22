use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, NetworkInterface};
use std::time::Duration;

pub struct CaptureEngine {
    rx: Box<dyn DataLinkReceiver>,
}

impl CaptureEngine {
    pub fn new(interface: NetworkInterface) -> Result<Self, String> {
        let config = datalink::Config {
            // Keep receiver responsive so UI controls work even during quiet traffic periods.
            read_timeout: Some(Duration::from_millis(200)),
            write_buffer_size: 4096,
            read_buffer_size: 65_536,
            promiscuous: true,
            ..Default::default()
        };

        match datalink::channel(&interface, config) {
            Ok(Ethernet(_tx, rx)) => Ok(Self { rx }),
            Ok(_) => Err("unsupported datalink channel type".to_string()),
            Err(e) => {
                if e.raw_os_error() == Some(1) {
                    return Err(format!(
                        "failed to open datalink channel on {}: {e}\n\
hint: raw packet capture requires elevated privileges.\n\
try: sudo packetsage\n\
or grant capability once: sudo setcap cap_net_raw,cap_net_admin=eip target/debug/packetsage",
                        interface.name
                    ));
                }

                Err(format!(
                    "failed to open datalink channel on {}: {e}",
                    interface.name
                ))
            }
        }
    }

    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, String> {
        match self.rx.next() {
            Ok(frame) => Ok(Some(frame)),
            Err(e) => {
                let message = e.to_string().to_lowercase();
                let timeout_like = message.contains("timed out")
                    || message.contains("timeout")
                    || e.raw_os_error() == Some(11);
                if timeout_like {
                    return Ok(None);
                }
                Err(format!("failed reading next frame: {e}"))
            }
        }
    }
}

pub fn print_interfaces() {
    for iface in datalink::interfaces() {
        let ips: Vec<String> = iface.ips.iter().map(|ip| ip.to_string()).collect();
        let status = if iface.is_up() { "UP" } else { "DOWN" };
        println!("{} [{}] {}", iface.name, status, ips.join(", "));
    }
}

pub fn select_interface(name: Option<String>) -> Result<NetworkInterface, String> {
    let interfaces = datalink::interfaces();

    if let Some(name) = name {
        return interfaces
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| format!("interface not found: {name}"));
    }

    interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
        .ok_or_else(|| "no active interface found; provide one with --interface".to_string())
}

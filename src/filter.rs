use crate::cli::{Cli, ProtocolArg};
use crate::parser::{L4Protocol, ParsedPacket};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default)]
pub struct PacketFilter {
    protocol: Option<ProtocolFilter>,
    port: Option<u16>,
    src: Option<Ipv4Addr>,
    dst: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy)]
enum ProtocolFilter {
    Tcp,
    Udp,
    Arp,
    Ipv6,
    Igmp,
}

impl PacketFilter {
    pub fn from_cli(cli: &Cli) -> Result<Self, String> {
        let protocol = match cli.protocol {
            Some(ProtocolArg::Tcp) => Some(ProtocolFilter::Tcp),
            Some(ProtocolArg::Udp) => Some(ProtocolFilter::Udp),
            Some(ProtocolArg::Arp) => Some(ProtocolFilter::Arp),
            Some(ProtocolArg::Ipv6) => Some(ProtocolFilter::Ipv6),
            Some(ProtocolArg::Igmp) => Some(ProtocolFilter::Igmp),
            None => None,
        };

        if let Some(port) = cli.port {
            if port == 0 {
                return Err("invalid --port value 0".to_string());
            }
        }

        Ok(Self {
            protocol,
            port: cli.port,
            src: cli.src,
            dst: cli.dst,
        })
    }

    pub fn matches(&self, packet: &ParsedPacket) -> bool {
        if let Some(protocol) = self.protocol {
            let matched = match protocol {
                ProtocolFilter::Tcp => packet.protocol == L4Protocol::Tcp,
                ProtocolFilter::Udp => packet.protocol == L4Protocol::Udp,
                ProtocolFilter::Arp => packet.label == "ARP",
                ProtocolFilter::Ipv6 => packet.label == "IPv6",
                ProtocolFilter::Igmp => packet.label == "IGMP",
            };
            if !matched {
                return false;
            }
        }

        if let Some(src) = self.src {
            if packet.src_ip != Some(src) {
                return false;
            }
        }

        if let Some(dst) = self.dst {
            if packet.dst_ip != Some(dst) {
                return false;
            }
        }

        if let Some(port) = self.port {
            let is_match = packet.src_port == Some(port) || packet.dst_port == Some(port);
            if !is_match {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ParsedPacket;

    #[test]
    fn matches_non_l4_protocol_filter() {
        let cli = Cli {
            interface: None,
            list_interfaces: false,
            protocol: Some(ProtocolArg::Arp),
            port: None,
            src: None,
            dst: None,
            count: None,
            stats_interval: 0,
            quiet: false,
            dashboard: false,
            json: false,
            pcap_out: None,
            syn_threshold: 20,
        };
        let filter = PacketFilter::from_cli(&cli).expect("filter creation should succeed");
        let packet = ParsedPacket {
            src_mac: "aa:bb:cc:dd:ee:ff".into(),
            dst_mac: "ff:ff:ff:ff:ff:ff".into(),
            ethertype: "Arp".into(),
            src_ip: None,
            dst_ip: None,
            ttl: None,
            protocol: L4Protocol::Other,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            sequence: None,
            udp_length: None,
            label: "ARP",
            note: Some("test".into()),
        };

        assert!(filter.matches(&packet));
    }
}

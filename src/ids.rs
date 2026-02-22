use crate::parser::{L4Protocol, ParsedPacket};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct IntrusionDetector {
    syn_threshold: u64,
    syn_by_src: HashMap<Ipv4Addr, u64>,
    telnet_seen: HashSet<(Ipv4Addr, u16)>,
}

impl IntrusionDetector {
    pub fn new(syn_threshold: u64) -> Self {
        Self {
            syn_threshold,
            syn_by_src: HashMap::new(),
            telnet_seen: HashSet::new(),
        }
    }

    pub fn inspect(&mut self, packet: &ParsedPacket) -> Option<String> {
        if packet.protocol != L4Protocol::Tcp {
            return None;
        }

        let flags = packet.tcp_flags?;
        let src = packet.src_ip?;
        let dst_port = packet.dst_port?;

        if flags.syn && !flags.ack {
            let count = self.syn_by_src.entry(src).or_insert(0);
            *count += 1;
            if *count == self.syn_threshold {
                return Some(format!(
                    "possible SYN scan/flood from {src} ({} SYN packets)",
                    self.syn_threshold
                ));
            }
        }

        if (dst_port == 23 || dst_port == 2323) && self.telnet_seen.insert((src, dst_port)) {
            return Some(format!(
                "telnet traffic observed from {src} to port {dst_port}"
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::TcpFlags;

    #[test]
    fn triggers_on_threshold() {
        let mut ids = IntrusionDetector::new(2);
        let base = ParsedPacket {
            src_mac: "a".into(),
            dst_mac: "b".into(),
            ethertype: "Ipv4".into(),
            src_ip: Some(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: Some(Ipv4Addr::new(5, 6, 7, 8)),
            ttl: Some(64),
            protocol: L4Protocol::Tcp,
            src_port: Some(4567),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
            }),
            sequence: Some(10),
            udp_length: None,
            label: "TCP",
            note: None,
        };

        assert!(ids.inspect(&base).is_none());
        let alert = ids.inspect(&base);
        assert!(alert.is_some());
    }

    #[test]
    fn telnet_alert_is_not_repeated_for_same_source_port() {
        let mut ids = IntrusionDetector::new(20);
        let packet = ParsedPacket {
            src_mac: "a".into(),
            dst_mac: "b".into(),
            ethertype: "Ipv4".into(),
            src_ip: Some(Ipv4Addr::new(10, 1, 1, 7)),
            dst_ip: Some(Ipv4Addr::new(10, 1, 1, 10)),
            ttl: Some(64),
            protocol: L4Protocol::Tcp,
            src_port: Some(40000),
            dst_port: Some(23),
            tcp_flags: Some(TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
            }),
            sequence: Some(42),
            udp_length: None,
            label: "TCP",
            note: None,
        };

        assert!(ids.inspect(&packet).is_some());
        assert!(ids.inspect(&packet).is_none());
    }
}

use crate::parser::{L4Protocol, ParsedPacket};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::Ipv4Addr;

#[derive(Debug, Default)]
pub struct TrafficStats {
    total_packets: u64,
    tcp_packets: u64,
    udp_packets: u64,
    per_ip: HashMap<Ipv4Addr, u64>,
    per_port: HashMap<u16, u64>,
}

impl TrafficStats {
    pub fn record(&mut self, packet: &ParsedPacket) {
        self.total_packets += 1;

        match packet.protocol {
            L4Protocol::Tcp => self.tcp_packets += 1,
            L4Protocol::Udp => self.udp_packets += 1,
            L4Protocol::Other => {}
        }

        if let Some(ip) = packet.src_ip {
            *self.per_ip.entry(ip).or_insert(0) += 1;
        }
        if let Some(ip) = packet.dst_ip {
            *self.per_ip.entry(ip).or_insert(0) += 1;
        }

        if let Some(port) = packet.src_port {
            *self.per_port.entry(port).or_insert(0) += 1;
        }
        if let Some(port) = packet.dst_port {
            *self.per_port.entry(port).or_insert(0) += 1;
        }
    }

    pub fn render(&self) -> String {
        let top_ip = self
            .per_ip
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ip, count)| format!("{ip} ({count})"))
            .unwrap_or_else(|| "-".to_string());

        let top_port = self
            .per_port
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(port, count)| format!("{port} ({count})"))
            .unwrap_or_else(|| "-".to_string());

        format!(
            "\n--- Traffic Stats ---\nTotal: {}\nTCP: {}\nUDP: {}\nTop IP: {}\nTop Port: {}",
            self.total_packets, self.tcp_packets, self.udp_packets, top_ip, top_port
        )
    }

    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    pub fn tcp_packets(&self) -> u64 {
        self.tcp_packets
    }

    pub fn udp_packets(&self) -> u64 {
        self.udp_packets
    }

    pub fn top_ips(&self, limit: usize) -> Vec<(Ipv4Addr, u64)> {
        top_k_counts(&self.per_ip, limit)
    }

    pub fn top_ports(&self, limit: usize) -> Vec<(u16, u64)> {
        top_k_counts(&self.per_port, limit)
    }
}

fn top_k_counts<K>(map: &HashMap<K, u64>, limit: usize) -> Vec<(K, u64)>
where
    K: Copy + Ord + Eq + std::hash::Hash,
{
    if limit == 0 || map.is_empty() {
        return Vec::new();
    }

    let mut heap: BinaryHeap<Reverse<(u64, K)>> = BinaryHeap::with_capacity(limit + 1);
    for (&key, &count) in map {
        heap.push(Reverse((count, key)));
        if heap.len() > limit {
            heap.pop();
        }
    }

    let mut out: Vec<(K, u64)> = heap
        .into_iter()
        .map(|Reverse((count, key))| (key, count))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{L4Protocol, ParsedPacket, TcpFlags};
    use std::net::Ipv4Addr;

    #[test]
    fn records_totals() {
        let mut stats = TrafficStats::default();
        let p = ParsedPacket {
            src_mac: "a".into(),
            dst_mac: "b".into(),
            ethertype: "Ipv4".into(),
            src_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            ttl: Some(64),
            protocol: L4Protocol::Tcp,
            src_port: Some(1234),
            dst_port: Some(80),
            tcp_flags: Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
            }),
            sequence: Some(1),
            udp_length: None,
            label: "TCP",
            note: None,
        };
        stats.record(&p);
        let output = stats.render();
        assert!(output.contains("Total: 1"));
        assert!(output.contains("TCP: 1"));
    }
}

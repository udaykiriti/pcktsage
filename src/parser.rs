use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Protocol {
    Tcp,
    Udp,
    Other,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: String,
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub ttl: Option<u8>,
    pub protocol: L4Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub sequence: Option<u32>,
    pub udp_length: Option<u16>,
    pub label: &'static str,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.syn {
            parts.push("SYN");
        }
        if self.ack {
            parts.push("ACK");
        }
        if self.fin {
            parts.push("FIN");
        }
        if self.rst {
            parts.push("RST");
        }
        if parts.is_empty() {
            parts.push("-");
        }
        write!(f, "{}", parts.join("|"))
    }
}

pub fn parse_packet(frame: &[u8]) -> Option<ParsedPacket> {
    let eth = EthernetPacket::new(frame)?;
    let src_mac = eth.get_source().to_string();
    let dst_mac = eth.get_destination().to_string();
    let ethertype = format!("{:?}", eth.get_ethertype());

    let mut packet = ParsedPacket {
        src_mac,
        dst_mac,
        ethertype,
        src_ip: None,
        dst_ip: None,
        ttl: None,
        protocol: L4Protocol::Other,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        sequence: None,
        udp_length: None,
        label: "ETH",
        note: None,
    };

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(eth.payload())?;
            packet.src_ip = Some(ipv4.get_source());
            packet.dst_ip = Some(ipv4.get_destination());
            packet.ttl = Some(ipv4.get_ttl());

            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp = TcpPacket::new(ipv4.payload())?;
                    let flags = tcp.get_flags();
                    packet.label = "TCP";
                    packet.protocol = L4Protocol::Tcp;
                    packet.src_port = Some(tcp.get_source());
                    packet.dst_port = Some(tcp.get_destination());
                    packet.sequence = Some(tcp.get_sequence());
                    packet.tcp_flags = Some(TcpFlags {
                        syn: flags & 0x02 != 0,
                        ack: flags & 0x10 != 0,
                        fin: flags & 0x01 != 0,
                        rst: flags & 0x04 != 0,
                    });
                }
                IpNextHeaderProtocols::Udp => {
                    let udp = UdpPacket::new(ipv4.payload())?;
                    packet.label = "UDP";
                    packet.protocol = L4Protocol::Udp;
                    packet.src_port = Some(udp.get_source());
                    packet.dst_port = Some(udp.get_destination());
                    packet.udp_length = Some(udp.get_length());
                }
                IpNextHeaderProtocols::Igmp => {
                    packet.label = "IGMP";
                }
                _ => {
                    packet.label = "IPv4";
                }
            }
        }
        EtherTypes::Arp => {
            packet.label = "ARP";
            if let Some(arp) = ArpPacket::new(eth.payload()) {
                packet.note = Some(format!(
                    "op={:?} {}({}) -> {}({})",
                    arp.get_operation(),
                    arp.get_sender_proto_addr(),
                    arp.get_sender_hw_addr(),
                    arp.get_target_proto_addr(),
                    arp.get_target_hw_addr()
                ));
            }
        }
        EtherTypes::Ipv6 => {
            packet.label = "IPv6";
            if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                packet.note = Some(format!(
                    "{} -> {} nh={:?} hop={}",
                    ipv6.get_source(),
                    ipv6.get_destination(),
                    ipv6.get_next_header(),
                    ipv6.get_hop_limit()
                ));
            }
        }
        _ => {
            packet.label = "ETH";
        }
    }

    Some(packet)
}

pub fn render_packet_line(packet: &ParsedPacket) -> String {
    let src_ip = packet
        .src_ip
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_ip = packet
        .dst_ip
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let src_port = packet
        .src_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .dst_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    match packet.label {
        "TCP" => format!(
            "[TCP] {}:{} -> {}:{} ttl={} flags={} seq={}",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet.ttl.unwrap_or_default(),
            packet
                .tcp_flags
                .map(|f| f.to_string())
                .unwrap_or_else(|| "-".to_string()),
            packet
                .sequence
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string())
        ),
        "UDP" => format!(
            "[UDP] {}:{} -> {}:{} ttl={} len={}",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet.ttl.unwrap_or_default(),
            packet
                .udp_length
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string())
        ),
        "IGMP" => format!(
            "[IGMP] {} -> {} ttl={} src_mac={} dst_mac={}",
            src_ip,
            dst_ip,
            packet.ttl.unwrap_or_default(),
            packet.src_mac,
            packet.dst_mac
        ),
        "ARP" => format!(
            "[ARP] {} src_mac={} dst_mac={}",
            packet.note.as_deref().unwrap_or("-"),
            packet.src_mac,
            packet.dst_mac
        ),
        "IPv6" => format!(
            "[IPv6] {} src_mac={} dst_mac={}",
            packet.note.as_deref().unwrap_or("-"),
            packet.src_mac,
            packet.dst_mac
        ),
        _ => format!(
            "[ETH] ethertype={} src_mac={} dst_mac={}",
            packet.ethertype, packet.src_mac, packet.dst_mac
        ),
    }
}

pub fn render_packet_json(packet: &ParsedPacket) -> String {
    let src_ip = packet
        .src_ip
        .map(|v| format!("\"{}\"", v))
        .unwrap_or_else(|| "null".to_string());
    let dst_ip = packet
        .dst_ip
        .map(|v| format!("\"{}\"", v))
        .unwrap_or_else(|| "null".to_string());
    let ttl = packet
        .ttl
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string());
    let src_port = packet
        .src_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string());
    let dst_port = packet
        .dst_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string());
    let sequence = packet
        .sequence
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string());
    let udp_length = packet
        .udp_length
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string());
    let tcp_flags = packet
        .tcp_flags
        .map(|f| format!("\"{}\"", escape_json(&f.to_string())))
        .unwrap_or_else(|| "null".to_string());
    let note = packet
        .note
        .as_ref()
        .map(|n| format!("\"{}\"", escape_json(n)))
        .unwrap_or_else(|| "null".to_string());

    format!(
        "{{\"type\":\"packet\",\"label\":\"{}\",\"ethertype\":\"{}\",\"src_mac\":\"{}\",\"dst_mac\":\"{}\",\"src_ip\":{},\"dst_ip\":{},\"ttl\":{},\"protocol\":\"{}\",\"src_port\":{},\"dst_port\":{},\"tcp_flags\":{},\"sequence\":{},\"udp_length\":{},\"note\":{}}}",
        escape_json(packet.label),
        escape_json(&packet.ethertype),
        escape_json(&packet.src_mac),
        escape_json(&packet.dst_mac),
        src_ip,
        dst_ip,
        ttl,
        protocol_name(packet.protocol),
        src_port,
        dst_port,
        tcp_flags,
        sequence,
        udp_length,
        note
    )
}

fn protocol_name(protocol: L4Protocol) -> &'static str {
    match protocol {
        L4Protocol::Tcp => "tcp",
        L4Protocol::Udp => "udp",
        L4Protocol::Other => "other",
    }
}

pub fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

use clap::{Parser, ValueEnum};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, ValueEnum)]
pub enum ProtocolArg {
    Tcp,
    Udp,
    Arp,
    Ipv6,
    Igmp,
}

#[derive(Debug, Parser)]
#[command(
    name = "packetsage",
    version,
    about = "An intelligent network packet analyzer built in Rust"
)]
pub struct Cli {
    #[arg(
        long,
        help = "Capture interface name. If omitted, auto-select active interface."
    )]
    pub interface: Option<String>,

    #[arg(long, help = "List available network interfaces and exit.")]
    pub list_interfaces: bool,

    #[arg(
        long,
        value_enum,
        help = "Filter by protocol (tcp, udp, arp, ipv6, igmp)."
    )]
    pub protocol: Option<ProtocolArg>,

    #[arg(long, help = "Filter by source port or destination port.")]
    pub port: Option<u16>,

    #[arg(long, help = "Filter by source IPv4 address.")]
    pub src: Option<Ipv4Addr>,

    #[arg(long, help = "Filter by destination IPv4 address.")]
    pub dst: Option<Ipv4Addr>,

    #[arg(long, help = "Stop after capturing this many matched packets.")]
    pub count: Option<u64>,

    #[arg(
        long,
        default_value_t = 50,
        help = "Print statistics every N matched packets (0 disables interval stats)."
    )]
    pub stats_interval: u64,

    #[arg(long, help = "Suppress per-packet output.")]
    pub quiet: bool,

    #[arg(long, help = "Start interactive terminal dashboard view.")]
    pub dashboard: bool,

    #[arg(long, help = "Emit newline-delimited JSON instead of plain text.")]
    pub json: bool,

    #[arg(long, help = "Write matched packets to a PCAP file.")]
    pub pcap_out: Option<String>,

    #[arg(
        long,
        default_value_t = 20,
        help = "IDS SYN threshold before scan/flood alert."
    )]
    pub syn_threshold: u64,
}

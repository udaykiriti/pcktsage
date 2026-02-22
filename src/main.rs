mod capture;
mod cli;
mod dashboard;
mod filter;
mod ids;
mod parser;
mod pcap;
mod stats;

use crate::capture::CaptureEngine;
use crate::filter::PacketFilter;
use crate::ids::IntrusionDetector;
use crate::pcap::PcapWriter;
use crate::stats::TrafficStats;
use clap::Parser;
use std::time::{Duration, Instant};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = cli::Cli::parse();
    if args.dashboard && args.json {
        return Err("--dashboard cannot be used with --json".to_string());
    }

    if args.list_interfaces {
        capture::print_interfaces();
        return Ok(());
    }

    let interface = capture::select_interface(args.interface.clone())?;
    println!("using interface: {}", interface.name);
    let interface_name = interface.name.clone();

    let filter = PacketFilter::from_cli(&args)?;
    let mut stats = TrafficStats::default();
    let mut ids = IntrusionDetector::new(args.syn_threshold);
    let mut engine = CaptureEngine::new(interface)?;
    let mut pcap_writer = match args.pcap_out.as_deref() {
        Some(path) => {
            println!("writing matched packets to pcap: {path}");
            Some(PcapWriter::create(path)?)
        }
        None => None,
    };

    let result = if args.dashboard {
        run_dashboard(
            &args,
            &interface_name,
            &mut engine,
            &filter,
            &mut stats,
            &mut ids,
            &mut pcap_writer,
        )
    } else {
        println!("starting packet capture (requires elevated privileges)");
        println!("press Ctrl+C to stop");
        run_stream(
            &args,
            &mut engine,
            &filter,
            &mut stats,
            &mut ids,
            &mut pcap_writer,
        )
    };

    if let Some(writer) = pcap_writer.as_mut() {
        writer.flush()?;
    }

    result
}

fn run_stream(
    args: &cli::Cli,
    engine: &mut CaptureEngine,
    filter: &PacketFilter,
    stats: &mut TrafficStats,
    ids: &mut IntrusionDetector,
    pcap_writer: &mut Option<PcapWriter>,
) -> Result<(), String> {
    let mut matched = 0_u64;
    loop {
        let Some(frame) = engine.next_frame()? else {
            continue;
        };
        if let Some(packet) = parser::parse_packet(frame) {
            if !filter.matches(&packet) {
                continue;
            }

            matched += 1;
            stats.record(&packet);

            if let Some(writer) = pcap_writer.as_mut() {
                writer.write_frame(frame)?;
            }

            if let Some(alert) = ids.inspect(&packet) {
                print_alert(&alert, args.json);
            }

            if !args.quiet && args.json {
                println!("{}", parser::render_packet_json(&packet));
            } else if !args.quiet {
                println!("{}", parser::render_packet_line(&packet));
            }

            if args.stats_interval > 0 && matched % args.stats_interval == 0 {
                if args.json {
                    println!("{}", render_stats_json(stats));
                } else {
                    println!("{}", stats.render());
                }
            }

            if let Some(limit) = args.count {
                if matched >= limit {
                    if !args.json {
                        println!("\nreached capture limit: {limit}");
                        println!("{}", stats.render());
                    } else {
                        println!(
                            "{{\"type\":\"event\",\"message\":\"reached capture limit: {}\"}}",
                            limit
                        );
                        println!("{}", render_stats_json(stats));
                    }
                    return Ok(());
                }
            }
        }
    }
}

fn run_dashboard(
    args: &cli::Cli,
    interface_name: &str,
    engine: &mut CaptureEngine,
    filter: &PacketFilter,
    stats: &mut TrafficStats,
    ids: &mut IntrusionDetector,
    pcap_writer: &mut Option<PcapWriter>,
) -> Result<(), String> {
    let mut ui = dashboard::Dashboard::new()?;
    let draw_interval = Duration::from_millis(120);
    let mut dirty = false;
    let mut matched = 0_u64;
    let mut paused = false;
    ui.draw(stats, interface_name, matched, paused)?;
    let mut last_draw = Instant::now();

    loop {
        match ui.poll_action()? {
            dashboard::DashboardAction::Quit => break,
            dashboard::DashboardAction::TogglePause => {
                paused = !paused;
                dirty = true;
            }
            dashboard::DashboardAction::Clear => {
                ui.clear();
                dirty = true;
            }
            dashboard::DashboardAction::None => {}
        }

        if paused {
            if dirty || last_draw.elapsed() >= draw_interval {
                ui.draw(stats, interface_name, matched, paused)?;
                last_draw = Instant::now();
                dirty = false;
            }
            std::thread::sleep(Duration::from_millis(40));
            continue;
        }

        let Some(frame) = engine.next_frame()? else {
            if dirty || last_draw.elapsed() >= draw_interval {
                ui.draw(stats, interface_name, matched, paused)?;
                last_draw = Instant::now();
                dirty = false;
            }
            continue;
        };
        if let Some(packet) = parser::parse_packet(frame) {
            if !filter.matches(&packet) {
                continue;
            }

            matched += 1;
            stats.record(&packet);
            ui.push_packet(&packet);
            if let Some(writer) = pcap_writer.as_mut() {
                writer.write_frame(frame)?;
            }

            if let Some(alert) = ids.inspect(&packet) {
                ui.push_alert(alert);
            }

            dirty = true;
            if last_draw.elapsed() >= draw_interval {
                ui.draw(stats, interface_name, matched, paused)?;
                last_draw = Instant::now();
                dirty = false;
            }

            if let Some(limit) = args.count {
                if matched >= limit {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn print_alert(alert: &str, json: bool) {
    if json {
        println!(
            "{{\"type\":\"alert\",\"message\":\"{}\"}}",
            parser::escape_json(alert)
        );
    } else {
        println!("[ALERT] {alert}");
    }
}

fn render_stats_json(stats: &TrafficStats) -> String {
    let top_ip = stats
        .top_ips(1)
        .first()
        .map(|(ip, count)| format!("{{\"ip\":\"{}\",\"count\":{}}}", ip, count))
        .unwrap_or_else(|| "null".to_string());
    let top_port = stats
        .top_ports(1)
        .first()
        .map(|(port, count)| format!("{{\"port\":{},\"count\":{}}}", port, count))
        .unwrap_or_else(|| "null".to_string());

    format!(
        "{{\"type\":\"stats\",\"total\":{},\"tcp\":{},\"udp\":{},\"top_ip\":{},\"top_port\":{}}}",
        stats.total_packets(),
        stats.tcp_packets(),
        stats.udp_packets(),
        top_ip,
        top_port
    )
}

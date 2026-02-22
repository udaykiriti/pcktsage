use crate::parser::ParsedPacket;
use crate::stats::TrafficStats;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Sparkline, Table,
};
use ratatui::Terminal;
use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

pub struct Dashboard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    model: DashboardModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardAction {
    None,
    Quit,
    TogglePause,
    Clear,
}

#[derive(Debug)]
struct DashboardModel {
    recent_packets: VecDeque<String>,
    recent_alerts: VecDeque<String>,
    last_rate_sample: Instant,
    last_total_packets: u64,
    current_pps: u64,
    rate_history: VecDeque<u64>,
}

impl Dashboard {
    pub fn new() -> Result<Self, String> {
        enable_raw_mode().map_err(|e| format!("failed to enable raw mode: {e}"))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)
            .map_err(|e| format!("failed to enter alternate screen: {e}"))?;
        let backend = CrosstermBackend::new(stdout);
        let terminal =
            Terminal::new(backend).map_err(|e| format!("failed to initialize terminal: {e}"))?;
        Ok(Self {
            terminal,
            model: DashboardModel::new(),
        })
    }

    pub fn push_packet(&mut self, packet: &ParsedPacket) {
        self.model
            .push_packet(crate::parser::render_packet_line(packet));
    }

    pub fn push_alert(&mut self, alert: String) {
        self.model.push_alert(alert);
    }

    pub fn poll_action(&mut self) -> Result<DashboardAction, String> {
        if event::poll(Duration::from_millis(0)).map_err(|e| format!("event poll failed: {e}"))? {
            let evt = event::read().map_err(|e| format!("event read failed: {e}"))?;
            if let Event::Key(key) = evt {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(DashboardAction::Quit),
                    KeyCode::Char(' ') => return Ok(DashboardAction::TogglePause),
                    KeyCode::Char('c') | KeyCode::Char('C') => return Ok(DashboardAction::Clear),
                    _ => {}
                }
            }
        }
        Ok(DashboardAction::None)
    }

    pub fn clear(&mut self) {
        self.model.clear();
    }

    pub fn draw(
        &mut self,
        stats: &TrafficStats,
        interface_name: &str,
        matched: u64,
        paused: bool,
    ) -> Result<(), String> {
        let total = stats.total_packets();
        let tcp = stats.tcp_packets();
        let udp = stats.udp_packets();
        let other = total.saturating_sub(tcp + udp);

        self.model.update_rate(total);

        let top_ips = stats.top_ips(5);
        let top_ports = stats.top_ports(5);
        let rate_values: Vec<u64> = if self.model.rate_history.is_empty() {
            vec![0]
        } else {
            self.model.rate_history.iter().copied().collect()
        };
        let rate_peak = rate_values.iter().copied().max().unwrap_or(1).max(1);

        let total_nonzero = total.max(1);
        let tcp_ratio = tcp as f64 / total_nonzero as f64;
        let udp_ratio = udp as f64 / total_nonzero as f64;
        let other_ratio = other as f64 / total_nonzero as f64;

        self.terminal
            .draw(|f| {
                let root = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Length(9),
                        Constraint::Min(8),
                        Constraint::Min(10),
                    ])
                    .split(f.area());

                let header = Paragraph::new(Line::from(vec![
                    Span::styled(
                        " PacketSage ",
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(" {} ", Self::rate_badge(self.model.current_pps)),
                        Style::default()
                            .fg(Color::Black)
                            .bg(Self::rate_badge_color(self.model.current_pps))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        if paused { " PAUSED " } else { " LIVE " },
                        Style::default()
                            .fg(Color::Black)
                            .bg(if paused { Color::DarkGray } else { Color::Green })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        " iface={}  matched={}  total={}  pps={}  [space] pause/resume  [c] clear  [q] quit ",
                        interface_name, matched, total, self.model.current_pps
                    )),
                ]))
                .block(Self::panel_block("Status", Color::Cyan));
                f.render_widget(header, root[0]);

                let top_row = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
                    .split(root[1]);

                let meters = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(2),
                        Constraint::Length(2),
                        Constraint::Length(2),
                        Constraint::Min(1),
                    ])
                    .split(top_row[0]);

                let tcp_meter = Gauge::default()
                    .block(Self::panel_block("TCP Share", Color::Green))
                    .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
                    .label(format!("{:>5.1}% ({tcp})", tcp_ratio * 100.0))
                    .ratio(tcp_ratio);
                f.render_widget(tcp_meter, meters[0]);

                let udp_meter = Gauge::default()
                    .block(Self::panel_block("UDP Share", Color::Yellow))
                    .gauge_style(Style::default().fg(Color::Yellow).bg(Color::Black))
                    .label(format!("{:>5.1}% ({udp})", udp_ratio * 100.0))
                    .ratio(udp_ratio);
                f.render_widget(udp_meter, meters[1]);

                let other_meter = Gauge::default()
                    .block(Self::panel_block("Other Share", Color::Magenta))
                    .gauge_style(Style::default().fg(Color::Magenta).bg(Color::Black))
                    .label(format!("{:>5.1}% ({other})", other_ratio * 100.0))
                    .ratio(other_ratio);
                f.render_widget(other_meter, meters[2]);

                let spark = Sparkline::default()
                    .block(Self::panel_block("Packet Rate Trend", Color::Blue))
                    .data(&rate_values)
                    .max(rate_peak)
                    .style(Style::default().fg(Color::LightBlue));
                f.render_widget(spark, meters[3]);

                let quick_stats = vec![
                    Row::new(vec![
                        Cell::from("Metric").style(
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Cell::from("Value").style(
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Row::new(vec![
                        Cell::from("Packets/s"),
                        Cell::from(self.model.current_pps.to_string()),
                    ]),
                    Row::new(vec![Cell::from("TCP"), Cell::from(tcp.to_string())]),
                    Row::new(vec![Cell::from("UDP"), Cell::from(udp.to_string())]),
                    Row::new(vec![Cell::from("Other"), Cell::from(other.to_string())]),
                ];
                let quick_table =
                    Table::new(quick_stats, [Constraint::Length(12), Constraint::Min(6)])
                        .block(Self::panel_block("Quick Stats", Color::White))
                        .column_spacing(2);
                f.render_widget(quick_table, top_row[1]);

                let middle = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(root[2]);

                let ip_rows: Vec<Row> = if top_ips.is_empty() {
                    vec![Row::new(vec![Cell::from("-"), Cell::from("-")])]
                } else {
                    top_ips
                        .iter()
                        .enumerate()
                        .map(|(idx, (ip, count))| {
                            Row::new(vec![
                                Cell::from(ip.to_string()),
                                Cell::from(count.to_string()),
                            ])
                            .style(Self::zebra(idx))
                        })
                        .collect()
                };
                let ip_table = Table::new(
                    ip_rows,
                    [Constraint::Percentage(70), Constraint::Percentage(30)],
                )
                .header(
                    Row::new(vec!["Source/Destination IP", "Count"]).style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                )
                .block(Self::panel_block("Top Talkers", Color::Cyan));
                f.render_widget(ip_table, middle[0]);

                let port_rows: Vec<Row> = if top_ports.is_empty() {
                    vec![Row::new(vec![Cell::from("-"), Cell::from("-")])]
                } else {
                    top_ports
                        .iter()
                        .enumerate()
                        .map(|(idx, (port, count))| {
                            Row::new(vec![
                                Cell::from(port.to_string()),
                                Cell::from(count.to_string()),
                            ])
                            .style(Self::zebra(idx))
                        })
                        .collect()
                };
                let port_table = Table::new(
                    port_rows,
                    [Constraint::Percentage(60), Constraint::Percentage(40)],
                )
                .header(
                    Row::new(vec!["Port", "Count"]).style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                )
                .block(Self::panel_block("Top Services", Color::Yellow));
                f.render_widget(port_table, middle[1]);

                let bottom = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
                    .split(root[3]);

                let packet_items: Vec<ListItem> = if self.model.recent_packets.is_empty() {
                    vec![ListItem::new("Waiting for packets...")]
                } else {
                    self.model
                        .recent_packets
                        .iter()
                        .enumerate()
                        .map(|(idx, line)| {
                            ListItem::new(line.clone()).style(if idx % 2 == 0 {
                                Style::default().fg(Color::White)
                            } else {
                                Style::default().fg(Color::Gray)
                            })
                        })
                        .collect()
                };
                let packets = List::new(packet_items)
                    .block(Self::panel_block("Live Packet Stream", Color::LightBlue));
                f.render_widget(packets, bottom[0]);

                let alert_items: Vec<ListItem> = if self.model.recent_alerts.is_empty() {
                    vec![ListItem::new(Line::from(vec![Span::styled(
                        "No IDS alerts",
                        Style::default().fg(Color::Green),
                    )]))]
                } else {
                    self.model
                        .recent_alerts
                        .iter()
                        .map(|line| {
                            ListItem::new(Line::from(vec![Span::styled(
                                line.clone(),
                                Style::default().fg(Color::LightRed),
                            )]))
                        })
                        .collect()
                };
                let alerts =
                    List::new(alert_items).block(Self::panel_block("Threat Feed", Color::Red));
                f.render_widget(alerts, bottom[1]);
            })
            .map_err(|e| format!("dashboard draw failed: {e}"))?;

        Ok(())
    }

    fn panel_block<'a>(title: &'a str, color: Color) -> Block<'a> {
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(color))
            .title(Line::from(Span::styled(
                format!(" {title} "),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )))
    }

    fn zebra(idx: usize) -> Style {
        if idx % 2 == 0 {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::Gray)
        }
    }

    fn rate_badge(pps: u64) -> &'static str {
        match pps {
            0..=50 => "CALM",
            51..=300 => "BUSY",
            _ => "HOT",
        }
    }

    fn rate_badge_color(pps: u64) -> Color {
        match pps {
            0..=50 => Color::Green,
            51..=300 => Color::Yellow,
            _ => Color::Red,
        }
    }
}

impl DashboardModel {
    const MAX_PACKETS: usize = 14;
    const MAX_ALERTS: usize = 10;
    const MAX_RATE_POINTS: usize = 60;

    fn new() -> Self {
        Self {
            recent_packets: VecDeque::new(),
            recent_alerts: VecDeque::new(),
            last_rate_sample: Instant::now(),
            last_total_packets: 0,
            current_pps: 0,
            rate_history: VecDeque::new(),
        }
    }

    fn push_packet(&mut self, rendered_packet: String) {
        self.recent_packets.push_front(rendered_packet);
        while self.recent_packets.len() > Self::MAX_PACKETS {
            self.recent_packets.pop_back();
        }
    }

    fn push_alert(&mut self, alert: String) {
        self.recent_alerts.push_front(alert);
        while self.recent_alerts.len() > Self::MAX_ALERTS {
            self.recent_alerts.pop_back();
        }
    }

    fn update_rate(&mut self, total_packets: u64) {
        let elapsed = self.last_rate_sample.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let delta = total_packets.saturating_sub(self.last_total_packets);
            let secs = elapsed.as_secs().max(1);
            self.current_pps = delta / secs;
            self.last_total_packets = total_packets;
            self.last_rate_sample = Instant::now();
            self.rate_history.push_back(self.current_pps);
            while self.rate_history.len() > Self::MAX_RATE_POINTS {
                self.rate_history.pop_front();
            }
        }
    }

    fn clear(&mut self) {
        self.recent_packets.clear();
        self.recent_alerts.clear();
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

#[cfg(test)]
mod tests {
    use super::DashboardModel;
    use std::time::{Duration, Instant};

    #[test]
    fn packet_buffer_is_bounded() {
        let mut model = DashboardModel::new();
        for i in 0..40 {
            model.push_packet(format!("pkt-{i}"));
        }
        assert_eq!(model.recent_packets.len(), DashboardModel::MAX_PACKETS);
        assert_eq!(
            model.recent_packets.front().map(String::as_str),
            Some("pkt-39")
        );
    }

    #[test]
    fn alert_buffer_is_bounded() {
        let mut model = DashboardModel::new();
        for i in 0..40 {
            model.push_alert(format!("alert-{i}"));
        }
        assert_eq!(model.recent_alerts.len(), DashboardModel::MAX_ALERTS);
        assert_eq!(
            model.recent_alerts.front().map(String::as_str),
            Some("alert-39")
        );
    }

    #[test]
    fn rate_updates_and_history_is_bounded() {
        let mut model = DashboardModel::new();
        model.last_rate_sample = Instant::now() - Duration::from_secs(2);
        model.update_rate(20);
        assert_eq!(model.current_pps, 10);
        assert_eq!(model.last_total_packets, 20);
        assert_eq!(model.rate_history.back().copied(), Some(10));

        for i in 1..200 {
            model.last_rate_sample = Instant::now() - Duration::from_secs(1);
            model.update_rate(20 + i);
        }
        assert_eq!(model.rate_history.len(), DashboardModel::MAX_RATE_POINTS);
    }
}

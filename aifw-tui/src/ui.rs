use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs},
};

use crate::app::{App, Tab};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tabs
            Constraint::Min(0),    // content
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    draw_tabs(f, app, chunks[0]);

    match app.tab {
        Tab::Dashboard => draw_dashboard(f, app, chunks[1]),
        Tab::Rules => draw_rules(f, app, chunks[1]),
        Tab::Nat => draw_nat(f, app, chunks[1]),
        Tab::Connections => draw_connections(f, app, chunks[1]),
        Tab::Logs => draw_logs(f, app, chunks[1]),
    }

    draw_status_bar(f, app, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| {
            let style = if *t == app.tab {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(t.title(), style))
        })
        .collect();

    let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" AiFw "))
        .select(idx)
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let pf_status = if app.pf_stats.running {
        "pf: UP"
    } else {
        "pf: DOWN"
    };
    let text = format!(
        " {} | Rules: {} | NAT: {} | Conns: {} | q=quit Tab/1-5=switch r=refresh d=delete",
        pf_status,
        app.rules.len(),
        app.nat_rules.len(),
        app.connections.len(),
    );
    let bar = Paragraph::new(text).style(Style::default().fg(Color::White).bg(Color::DarkGray));
    f.render_widget(bar, area);
}

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9), // stats
            Constraint::Min(0),    // top talkers
        ])
        .split(area);

    // Stats panel
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    let pf = &app.pf_stats;
    let left_text = vec![
        Line::from(vec![
            Span::styled("pf status: ", Style::default().fg(Color::Gray)),
            Span::styled(
                if pf.running { "RUNNING" } else { "STOPPED" },
                Style::default()
                    .fg(if pf.running { Color::Green } else { Color::Red })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(format!("States:       {}", pf.states_count)),
        Line::from(format!("pf Rules:     {}", pf.rules_count)),
        Line::from(format!(
            "AiFw Rules:   {} ({} active)",
            app.rules.len(),
            app.rules
                .iter()
                .filter(|r| r.status == aifw_common::RuleStatus::Active)
                .count()
        )),
        Line::from(format!("NAT Rules:    {}", app.nat_rules.len())),
        Line::from(format!("Queues:       {}", app.queues.len())),
        Line::from(format!("Rate Limits:  {}", app.rate_limits.len())),
    ];

    let left =
        Paragraph::new(left_text).block(Block::default().borders(Borders::ALL).title(" System "));
    f.render_widget(left, stats_chunks[0]);

    let cs = &app.conntrack_stats;
    let right_text = vec![
        Line::from(format!("Connections:  {}", cs.total_connections)),
        Line::from(format!("  TCP:        {}", cs.tcp_connections)),
        Line::from(format!("  UDP:        {}", cs.udp_connections)),
        Line::from(format!("  ICMP:       {}", cs.icmp_connections)),
        Line::from(format!("Packets In:   {}", pf.packets_in)),
        Line::from(format!("Packets Out:  {}", pf.packets_out)),
        Line::from(format!("Bytes In:     {}", format_bytes(pf.bytes_in))),
    ];

    let right =
        Paragraph::new(right_text).block(Block::default().borders(Borders::ALL).title(" Traffic "));
    f.render_widget(right, stats_chunks[1]);

    // Top talkers
    let header = Row::new(vec!["IP Address", "Bytes"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .top_talkers
        .iter()
        .map(|(ip, bytes)| Row::new(vec![ip.to_string(), format_bytes(*bytes)]))
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(60), Constraint::Percentage(40)],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Top Talkers "),
    );

    f.render_widget(table, chunks[1]);
}

fn draw_rules(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        "PRI",
        "ACTION",
        "DIR",
        "PROTO",
        "SOURCE",
        "DESTINATION",
        "STATE",
        "LABEL",
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let src = format!(
                "{}{}",
                r.rule_match.src_addr,
                r.rule_match
                    .src_port
                    .as_ref()
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default()
            );
            let dst = format!(
                "{}{}",
                r.rule_match.dst_addr,
                r.rule_match
                    .dst_port
                    .as_ref()
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default()
            );
            let style = if i == app.rules_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else if r.status == aifw_common::RuleStatus::Disabled {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(vec![
                r.priority.to_string(),
                r.action.to_string(),
                r.direction.to_string(),
                r.protocol.to_string(),
                src,
                dst,
                r.state_options.tracking.to_string(),
                r.label.clone().unwrap_or_default(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Length(14),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Rules ({}) ", app.rules.len())),
    );

    let mut state = TableState::default();
    state.select(Some(app.rules_selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_nat(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        "TYPE",
        "IFACE",
        "PROTO",
        "SOURCE",
        "DESTINATION",
        "REDIRECT",
        "LABEL",
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .nat_rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let src = format!(
                "{}{}",
                r.src_addr,
                r.src_port
                    .as_ref()
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default()
            );
            let dst = format!(
                "{}{}",
                r.dst_addr,
                r.dst_port
                    .as_ref()
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default()
            );
            let style = if i == app.nat_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                r.nat_type.to_string(),
                r.interface.to_string(),
                r.protocol.to_string(),
                src,
                dst,
                r.redirect.to_string(),
                r.label.clone().unwrap_or_default(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Percentage(18),
            Constraint::Percentage(18),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" NAT Rules ({}) ", app.nat_rules.len())),
    );

    let mut state = TableState::default();
    state.select(Some(app.nat_selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_connections(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        "PROTO",
        "SOURCE",
        "DESTINATION",
        "STATE",
        "AGE",
        "PKTS IN",
        "PKTS OUT",
        "BYTES",
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .connections
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == app.conn_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(c.protocol.clone()),
                Cell::from(format!("{}:{}", c.src_addr, c.src_port)),
                Cell::from(format!("{}:{}", c.dst_addr, c.dst_port)),
                Cell::from(c.state.clone()),
                Cell::from(format_duration(c.age_secs)),
                Cell::from(c.packets_in.to_string()),
                Cell::from(c.packets_out.to_string()),
                Cell::from(format_bytes(c.bytes_in + c.bytes_out)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Percentage(18),
            Constraint::Percentage(18),
            Constraint::Percentage(15),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Connections ({}) ", app.connections.len())),
    );

    let mut state = TableState::default();
    state.select(Some(app.conn_selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_logs(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["TIME", "ACTION", "RULE ID", "DETAILS", "SOURCE"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .audit_entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let style = if i == app.log_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let time = e.timestamp.format("%H:%M:%S").to_string();
            let action = format!("{:?}", e.action);
            let rule_id = e
                .rule_id
                .map(|id| id.to_string()[..8].to_string())
                .unwrap_or_default();
            Row::new(vec![
                Cell::from(time),
                Cell::from(action),
                Cell::from(rule_id),
                Cell::from(e.details.clone()),
                Cell::from(e.source.clone()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Percentage(50),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Audit Log ({}) ", app.audit_entries.len())),
    );

    let mut state = TableState::default();
    state.select(Some(app.log_selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

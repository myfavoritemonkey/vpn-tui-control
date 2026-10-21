use base64::{engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}, Engine};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use std::{fs, io::{self, Write}, net::{TcpStream, ToSocketAddrs}, path::{Path, PathBuf}, process::{Child, Command, Stdio}, sync::mpsc::{self, Receiver}, thread, time::{Duration, Instant}};
use url::Url;

const DEFAULT_OUTPUT: &str = "/etc/sing-box/config.json";

#[derive(Debug, Clone)]
struct Server { label: String, protocol: String, outbound: Value }

fn query(url: &Url, key: &str, default: &str) -> String {
    url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned()).unwrap_or_else(|| default.into())
}

fn decode_b64(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = format!("{}{}", clean, "=".repeat((4 - clean.len() % 4) % 4));
    URL_SAFE_NO_PAD.decode(clean.as_bytes()).or_else(|_| URL_SAFE.decode(padded.as_bytes())).or_else(|_| STANDARD.decode(padded.as_bytes())).map_err(|e| format!("invalid Base64: {e}"))
}

fn display_label(u: &Url, fallback: String) -> String {
    u.fragment()
        .and_then(|value| percent_encoding::percent_decode_str(value).decode_utf8().ok())
        .map(|value| value.into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .trim()
        .to_string()
}

fn parse_vless(raw: &str, number: usize) -> Result<Server, String> {
    let u = Url::parse(raw).map_err(|e| e.to_string())?;
    let host = u.host_str().ok_or("VLESS host is missing")?;
    let port = u.port().ok_or("VLESS port is missing")?;
    let uuid = percent_encoding::percent_decode_str(u.username()).decode_utf8().map_err(|_| "invalid VLESS UUID")?.into_owned();
    if uuid.is_empty() { return Err("VLESS UUID is missing".into()); }
    let security = query(&u, "security", "none").to_lowercase();
    let transport = query(&u, "type", "tcp").to_lowercase();
    if !["none", "tls", "reality"].contains(&security.as_str()) { return Err(format!("unsupported security: {security}")); }
    if !["tcp", "grpc", "ws", "http", "h2"].contains(&transport.as_str()) { return Err(format!("unsupported transport: {transport}")); }
    let mut out = json!({"type":"vless", "tag":"vpn", "server":host, "server_port":port, "uuid":uuid});
    if let Some(flow) = u.query_pairs().find(|(k, _)| k == "flow").map(|(_,v)| v.into_owned()).filter(|v| !v.is_empty()) { out["flow"] = json!(flow); }
    if security != "none" {
        let mut tls = json!({"enabled":true});
        let sni = query(&u, "sni", "");
        let server_name = if sni.is_empty() { query(&u, "serverName", host) } else { sni };
        tls["server_name"] = json!(server_name);
        if query(&u, "allowInsecure", "") == "1" || query(&u, "insecure", "") == "1" { tls["insecure"] = json!(true); }
        let alpn = query(&u, "alpn", ""); if !alpn.is_empty() { tls["alpn"] = json!(alpn.split(',').collect::<Vec<_>>()); }
        let fp = query(&u, "fp", ""); if !fp.is_empty() { tls["utls"] = json!({"enabled":true,"fingerprint":fp}); }
        if security == "reality" { let pbk = query(&u, "pbk", ""); if pbk.is_empty() { return Err("Reality public key (pbk) is missing".into()); } tls["reality"] = json!({"enabled":true,"public_key":pbk,"short_id":query(&u,"sid","")}); }
        out["tls"] = tls;
    }
    match transport.as_str() {
        "grpc" => out["transport"] = json!({"type":"grpc","service_name":query(&u,"serviceName","")}),
        "ws" => { let mut t = json!({"type":"ws","path":query(&u,"path","/")}); let host_header=query(&u,"host",""); if !host_header.is_empty() { t["headers"]=json!({"Host":host_header}); } out["transport"]=t; },
        "http" | "h2" => { let mut t=json!({"type":"http","path":query(&u,"path","/").split(',').collect::<Vec<_>>()}); let h=query(&u,"host",""); if !h.is_empty() { t["host"]=json!(h.split(',').collect::<Vec<_>>()); } out["transport"]=t; },
        _ => {}
    }
    let label = display_label(&u, format!("VLESS {number}"));
    Ok(Server { label, protocol: format!("VLESS {security}/{transport}"), outbound: out })
}

fn parse_ss(raw: &str, number: usize) -> Result<Server, String> {
    let u=Url::parse(raw).map_err(|e| e.to_string())?;
    if raw.contains("plugin=") { return Err("Shadowsocks plugins are not supported".into()); }
    let rest=&raw[5..]; let authority=rest.split('#').next().unwrap_or(rest).split('?').next().unwrap_or(rest);
    let (userinfo, endpoint) = if let Some((a,b))=authority.rsplit_once('@') { (a.to_string(), b.to_string()) } else { let decoded=String::from_utf8(decode_b64(authority)?).map_err(|_| "invalid Shadowsocks Base64")?; decoded.rsplit_once('@').map(|(a,b)|(a.to_string(),b.to_string())).ok_or("invalid Shadowsocks address")? };
    let userinfo = if userinfo.contains(':') { userinfo } else { String::from_utf8(decode_b64(&userinfo)?).map_err(|_| "invalid Shadowsocks credentials")? };
    let (method,password)=userinfo.split_once(':').ok_or("Shadowsocks method/password missing")?;
    let endpoint_url=Url::parse(&format!("ss://{endpoint}")).map_err(|e| e.to_string())?; let host=endpoint_url.host_str().ok_or("Shadowsocks host missing")?; let port=endpoint_url.port().ok_or("Shadowsocks port missing")?;
    let label=display_label(&u, format!("Shadowsocks {number}"));
    Ok(Server { label, protocol:"Shadowsocks".into(), outbound:json!({"type":"shadowsocks","tag":"vpn","server":host,"server_port":port,"method":method,"password":password}) })
}

fn subscription(data: &[u8]) -> Result<String, String> {
    let text=String::from_utf8_lossy(data).trim().trim_start_matches('\u{feff}').to_string();
    if text.contains("vless://") || text.contains("ss://") { return Ok(text); }
    let decoded=String::from_utf8(decode_b64(&text)?).map_err(|_| "subscription is not UTF-8")?;
    if decoded.contains("vless://") || decoded.contains("ss://") { Ok(decoded) } else { Err("no VLESS/SS links found".into()) }
}

fn parse_servers(text: &str) -> Result<Vec<Server>, String> {
    let mut servers = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let result = if line.starts_with("vless://") { parse_vless(line, line_no + 1) }
            else if line.starts_with("ss://") { parse_ss(line, line_no + 1) }
            else { continue };
        if let Ok(server) = result { servers.push(server); }
    }
    if servers.is_empty() { Err("поддерживаемые серверы не найдены".into()) } else { Ok(servers) }
}

fn fetch_servers(client: &Client, link: &str, cache: &Path) -> Result<Vec<Server>, String> {
    let data = client.get(link).send().map_err(|e| format!("ошибка загрузки: {e}"))?
        .error_for_status().map_err(|e| format!("HTTP ошибка: {e}"))?
        .bytes().map_err(|e| e.to_string())?;
    let text = subscription(&data)?;
    if let Some(parent) = cache.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    fs::write(cache, &text).map_err(|e| format!("не удалось сохранить кеш: {e}"))?;
    parse_servers(&text)
}

fn spawn_subscription_refresh(client: &Client, link: &str, cache: &Path) -> Receiver<Result<Vec<Server>, String>> {
    let (sender, receiver) = mpsc::channel();
    let client = client.clone();
    let link = link.to_string();
    let cache = cache.to_path_buf();
    thread::spawn(move || {
        let _ = sender.send(fetch_servers(&client, &link, &cache));
    });
    receiver
}

fn pid_path(base: &Path) -> PathBuf { base.join("vpn-selector.pid") }
fn state_path(base: &Path) -> PathBuf { base.join("selected-server.json") }

fn save_state(path: &Path, server: &Server) -> Result<(), String> {
    fs::write(path, serde_json::to_vec_pretty(&json!({"label": server.label, "protocol": server.protocol, "outbound": server.outbound})).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn load_state(path: &Path) -> Result<Server, String> {
    let value: Value = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(Server { label: value["label"].as_str().ok_or("состояние сервера повреждено")?.into(), protocol: value["protocol"].as_str().ok_or("состояние сервера повреждено")?.into(), outbound: value["outbound"].clone() })
}

fn read_pid(path: &Path) -> Option<u32> { fs::read_to_string(path).ok()?.trim().parse().ok() }

fn pid_alive(pid: u32) -> bool {
    Command::new("kill").args(["-0", &pid.to_string()]).status().map(|status| status.success()).unwrap_or(false)
}

fn stop_background(base: &Path) -> Result<bool, String> {
    let path = pid_path(base);
    let Some(pid) = read_pid(&path) else { return Ok(false); };
    if pid_alive(pid) { Command::new("kill").arg(pid.to_string()).status().map_err(|e| e.to_string())?; }
    let _ = fs::remove_file(path);
    Ok(true)
}

fn start_background(base: &Path, output: &Path) -> Result<u32, String> {
    if let Some(pid) = read_pid(&pid_path(base)) {
        if pid_alive(pid) { return Ok(pid); }
    }
    let child = start_vpn(output)?;
    let pid = child.id();
    fs::write(pid_path(base), pid.to_string()).map_err(|e| e.to_string())?;
    drop(child);
    Ok(pid)
}

fn print_background_status(base: &Path) -> Result<(), String> {
    let state = load_state(&state_path(base)).ok();
    let Some(server) = state else { println!("VPN выключен: выбранный сервер ещё не сохранён."); return Ok(()); };
    let Some(pid) = read_pid(&pid_path(base)) else { println!("VPN выключен. Последний сервер: {}.", server.label); return Ok(()); };
    if !pid_alive(pid) { let _ = fs::remove_file(pid_path(base)); println!("VPN выключен. Последний сервер: {}.", server.label); return Ok(()); }
    match ping_one(&server) {
        Ok(ms) => println!("VPN запущен\nСервер: {}\nПинг: {} ms\nPID: {}", server.label, ms, pid),
        Err(_) => println!("VPN запущен\nСервер: {}\nСоединение с сервером отсутствует\nPID: {}", server.label, pid),
    }
    Ok(())
}

fn run_background_command(command: &str, name: Option<&str>, servers: &[Server], base: &Path, output: &Path) -> Result<(), String> {
    match command {
        "start" => {
            if let Some(name) = name {
                let number: usize = name.parse().map_err(|_| "укажите номер сервера из списка, например: start 11".to_string())?;
                if number == 0 { return Err("номер сервера начинается с 1".into()); }
                let server = servers.get(number - 1).ok_or_else(|| format!("номер вне диапазона: выберите от 1 до {}", servers.len()))?;
                stop_background(base)?;
                write_config(output, &config(server))?;
                save_state(&state_path(base), server)?;
                let pid = start_background(base, output)?;
                println!("Запущен сервер: {}\nPID: {}", server.label, pid);
            } else {
                print_background_status(base)?;
            }
        }
        "status" => print_background_status(base)?,
        "on" => {
            let server = load_state(&state_path(base))?;
            if let Some(pid) = read_pid(&pid_path(base)).filter(|pid| pid_alive(*pid)) {
                println!("VPN уже включён: {}\nPID: {}", server.label, pid);
                return Ok(());
            }
            write_config(output, &config(&server))?;
            let pid = start_background(base, output)?;
            println!("VPN включён: {}\nPID: {}", server.label, pid);
        }
        "off" => {
            if stop_background(base)? { println!("VPN выключен."); } else { println!("VPN уже выключен."); }
        }
        _ => {}
    }
    Ok(())
}

fn config(server: &Server) -> Value { json!({"log":{"level":"info"},"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"singtun0","address":["172.19.0.1/30"],"auto_route":true,"strict_route":true,"stack":"system"}],"outbounds":[server.outbound,{"type":"direct","tag":"direct"}],"route":{"auto_detect_interface":true,"final":"vpn"}}) }

fn write_config(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent)=path.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let tmp=path.with_extension("json.pending"); fs::write(&tmp, serde_json::to_vec_pretty(value).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    match Command::new("sing-box").args(["check","-c"]).arg(&tmp).output() {
        Ok(check) if !check.status.success() => {
            let _=fs::remove_file(&tmp);
            return Err(String::from_utf8_lossy(&check.stderr).trim().to_string());
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("Предупреждение: sing-box не найден; конфигурация сохранена без проверки.");
        }
        Err(error) => {
            let _=fs::remove_file(&tmp);
            return Err(format!("не удалось запустить sing-box check: {error}"));
        }
    }
    fs::rename(&tmp,path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn start_vpn(output: &Path) -> Result<Child, String> {
    let log = fs::File::create("/tmp/vpn-selector-sing-box.log").map_err(|e| e.to_string())?;
    let mut child = Command::new("sing-box")
        .args(["run", "-c"])
        .arg(output)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .map_err(|error| format!("не удалось запустить sing-box: {error}"))?;
    thread::sleep(Duration::from_millis(300));
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
        return Err(format!("sing-box завершился сразу ({status}). Лог: /tmp/vpn-selector-sing-box.log"));
    }
    Ok(child)
}

fn endpoint(server: &Server) -> Option<(String, u16)> {
    Some((server.outbound.get("server")?.as_str()?.to_string(), server.outbound.get("server_port")?.as_u64()? as u16))
}

fn ping_one(server: &Server) -> Result<u128, String> {
    let (host, port) = endpoint(server).ok_or("нет адреса")?;
    let started = Instant::now();
    let addresses = format!("{host}:{port}").to_socket_addrs().map_err(|e| e.to_string())?;
    let mut last_error = String::from("нет ответа");
    for address in addresses {
        match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
            Ok(_) => return Ok(started.elapsed().as_millis()),
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(last_error)
}

fn spawn_ping_checks(servers: &[Server]) -> Receiver<(usize, Result<u128, String>)> {
    let (sender, receiver) = mpsc::channel();
    for (index, server) in servers.iter().cloned().enumerate() {
        let sender = sender.clone();
        thread::spawn(move || {
            let result = ping_one(&server);
            let _ = sender.send((index, result));
        });
    }
    receiver
}

fn draw_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    servers: &[Server],
    selected: usize,
    child: &mut Option<Child>,
    active: Option<usize>,
    message: &str,
    pings: &[Option<Result<u128, String>>],
    ping_running: bool,
    animation_tick: usize,
) -> Result<(), String> {
    if let Some(process) = child.as_mut() {
        if process.try_wait().map_err(|e| e.to_string())?.is_some() {
            *child = None;
        }
    }
    let connected = child.is_some();
    terminal.draw(|frame| {
        let areas = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([Constraint::Length(5), Constraint::Min(5)])
            .split(frame.area());
        let status = if connected { "● Подключение запущено" } else { "○ VPN выключен" };
        let status_style = if connected { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Rgb(156, 163, 175)) };
        let header = Paragraph::new(vec![
                Line::from(Span::styled(status, status_style)),
                Line::from("R пинг   •   T обновить список   •   Z сменить ссылку"),
                Line::from(Span::styled(message, Style::default().fg(Color::Rgb(175, 175, 175)))),
            ])
            .style(Style::default().fg(Color::Rgb(203, 203, 203)))
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Rgb(115, 115, 115))).title(" VPN CONTROL "))
            .wrap(Wrap { trim: true });
        frame.render_widget(header, areas[0]);

        let items: Vec<ListItem> = servers.iter().enumerate().map(|(index, server)| {
            let latency = pings.get(index).and_then(|ping| ping.as_ref()).map(|ping| match ping { Ok(ms) => format!("  {ms} ms"), Err(_) => "  нет ответа".into() }).unwrap_or_else(|| if ping_running { format!("  {}", ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'][animation_tick % 10]) } else { String::new() });
            let style = if active == Some(index) { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Rgb(205, 205, 205)) };
            ListItem::new(format!("{:>2}. {}   [{}]{}", index + 1, server.label, server.protocol, latency)).style(style)
        }).collect();
        let selected_style = if active == Some(selected) {
            Style::default().bg(Color::Rgb(60, 75, 60)).fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().bg(Color::Rgb(85, 85, 85)).fg(Color::White).add_modifier(Modifier::BOLD)
        };
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Rgb(115, 115, 115))).title(" SERVERS / REGIONS "))
            .highlight_style(selected_style)
            .highlight_symbol("▶ ")
            .style(Style::default().fg(Color::Rgb(205, 205, 205)));
        let mut state = ListState::default(); state.select(Some(selected));
        frame.render_stateful_widget(list, areas[1], &mut state);

    }).map_err(|e| e.to_string())?;
    Ok(())
}

fn run_ui(mut servers: Vec<Server>, output: &Path, client: &Client, cache: &Path, state: &Path, mut link: String) -> Result<(), String> {
    enable_raw_mode().map_err(|e| e.to_string())?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| e.to_string())?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| e.to_string())?;
    let mut selected = 0usize;
    let mut active: Option<usize> = None;
    let mut child: Option<Child> = None;
    let mut pings: Vec<Option<Result<u128, String>>> = vec![None; servers.len()];
    let mut ping_receiver: Option<Receiver<(usize, Result<u128, String>)>> = Some(spawn_ping_checks(&servers));
    let mut ping_running = true;
    let mut refresh_receiver: Option<Receiver<Result<Vec<Server>, String>>> = None;
    let mut refresh_running = false;
    let mut animation_tick = 0usize;
    let mut message = "Проверка серверов запущена".to_string();
    let result = loop {
        if let Some(receiver) = ping_receiver.as_ref() {
            let was_running = ping_running;
            while let Ok((index, result)) = receiver.try_recv() {
                pings[index] = Some(result);
            }
            ping_running = pings.iter().any(|ping| ping.is_none());
            if !ping_running {
                ping_receiver = None;
                if was_running {
                    let online = pings.iter().filter(|ping| matches!(ping, Some(Ok(_)))).count();
                    message = format!("Проверка завершена: {online}/{} серверов доступны", servers.len());
                }
            }
        }
        if let Some(receiver) = refresh_receiver.as_ref() {
            if let Ok(result) = receiver.try_recv() {
                refresh_receiver = None;
                refresh_running = false;
                match result {
                    Ok(new_servers) => {
                        let active_label = active.and_then(|index| servers.get(index).map(|server| server.label.clone()));
                        ping_receiver = None;
                        ping_running = false;
                        servers = new_servers;
                        selected = selected.min(servers.len().saturating_sub(1));
                        active = active_label.and_then(|label| servers.iter().position(|server| server.label == label));
                        pings = vec![None; servers.len()];
                        message = format!("Список обновлён: {} серверов", servers.len());
                    }
                    Err(error) => message = format!("Ошибка обновления: {error}"),
                }
            }
        }
        if refresh_running {
            message = format!("{} Обновление списка серверов...", ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'][animation_tick % 10]);
        }
        animation_tick = animation_tick.wrapping_add(1);
        draw_ui(&mut terminal, &servers, selected, &mut child, active, &message, &pings, ping_running, animation_tick)?;
        if !event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())? { continue; }
        let Event::Key(KeyEvent { code, modifiers, .. }) = event::read().map_err(|e| e.to_string())? else { continue; };
        if code == KeyCode::Char('q') || code == KeyCode::Esc { break Ok(()); }
        match code {
            KeyCode::Up => { selected = selected.saturating_sub(1); }
            KeyCode::Down => { selected = (selected + 1).min(servers.len() - 1); }
            KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Char('к') | KeyCode::Char('К') => {
                pings = vec![None; servers.len()];
                ping_receiver = Some(spawn_ping_checks(&servers));
                ping_running = true;
                message = "Проверка серверов запущена".into();
            }
            KeyCode::Char('t') | KeyCode::Char('T') | KeyCode::Char('е') | KeyCode::Char('Е') => {
                if !refresh_running {
                    refresh_receiver = Some(spawn_subscription_refresh(client, &link, cache));
                    refresh_running = true;
                    message = "Обновление списка серверов...".into();
                }
            }
            KeyCode::Char('z') | KeyCode::Char('Z') | KeyCode::Char('я') | KeyCode::Char('Я') => {
                let _ = disable_raw_mode();
                let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
                print!("\nНовая HTTPS-ссылка: "); let _ = io::stdout().flush();
                let mut input = String::new();
                let result = io::stdin().read_line(&mut input).map_err(|e| e.to_string()).and_then(|_| {
                    let value = input.trim();
                    if !value.starts_with("https://") { return Err("нужна HTTPS-ссылка".into()); }
                    fs::write(output.parent().unwrap_or(Path::new("." )).join("subscription.url"), format!("{value}\n")).map_err(|e| e.to_string())?;
                    link = value.to_string();
                    fetch_servers(client, &link, cache)
                });
                let _ = execute!(terminal.backend_mut(), EnterAlternateScreen);
                let _ = enable_raw_mode();
                match result { Ok(new_servers) => { ping_receiver = None; ping_running = false; servers = new_servers; selected = 0; pings = vec![None; servers.len()]; message = "Ссылка и список серверов обновлены".into(); }, Err(error) => message = error }
            }
            KeyCode::Enter => {
                if active == Some(selected) {
                    if let Some(mut process) = child.take() { let _ = process.kill(); let _ = process.wait(); }
                    active = None;
                    message = "VPN выключен".into();
                } else {
                    let result = write_config(output, &config(&servers[selected])).and_then(|_| {
                        if let Some(mut process) = child.take() { let _ = process.kill(); let _ = process.wait(); }
                        child = Some(start_vpn(output)?);
                        Ok(())
                    });
                    match result { Ok(()) => { let _ = save_state(state, &servers[selected]); active = Some(selected); message = format!("Выбран: {}", servers[selected].label); }, Err(error) => { active = None; message = error; } }
                }
            }
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => break Ok(()),
            _ => {}
        }
    };
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    if let Some(mut process) = child { let _ = process.kill(); let _ = process.wait(); }
    result
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let output=args.iter().find_map(|a| a.strip_prefix("--output=").map(PathBuf::from)).unwrap_or_else(||PathBuf::from(DEFAULT_OUTPUT));
    let command_position = args.iter().position(|arg| !arg.starts_with("--"));
    let command = command_position.and_then(|position| args.get(position).map(String::as_str));
    let command_name = command.filter(|name| matches!(*name, "start" | "status" | "on" | "off"));
    let command_argument = command_position.and_then(|position| args.get(position + 1)).map(String::as_str);
    let client=Client::builder().timeout(Duration::from_secs(30)).user_agent("vpn-selector/0.1").build().map_err(|e|e.to_string())?;
    let base = output.parent().unwrap_or(Path::new("."));
    let url_file = base.join("subscription.url");
    let cache_file = base.join("subscription.cache");
    let state_file = state_path(base);
    let mut link = fs::read_to_string(&url_file).unwrap_or_default().trim().to_string();
    let servers = if cache_file.is_file() {
        parse_servers(&fs::read_to_string(&cache_file).map_err(|e| e.to_string())?)?
    } else {
        if link.is_empty() {
            print!("HTTPS-ссылка на подписку: "); io::stdout().flush().map_err(|e| e.to_string())?;
            let mut input = String::new(); io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
            link = input.trim().to_string();
        }
        if !link.starts_with("https://") { return Err("нужна HTTPS-ссылка".into()); }
        fs::write(&url_file, format!("{link}\n")).map_err(|e| format!("не удалось сохранить URL: {e}"))?;
        fetch_servers(&client, &link, &cache_file)?
    };
    if let Some(command) = command_name {
        run_background_command(command, command_argument, &servers, base, &output)
    } else {
        run_ui(servers, &output, &client, &cache_file, &state_file, link)
    }
}

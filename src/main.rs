#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use byteorder::{BigEndian, ByteOrder};
use gpui::ParentElement as _;
use gpui::*;
use gpui_component::{
    button::{Button, ButtonVariants}, h_flex,
    input::{Input, InputState},
    v_flex,
    Root,
    StyledExt,
};
use std::io::{self, Error, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Copy, Clone, PartialEq)]
struct NtpTimestamp {
    ts: u64,
}

impl NtpTimestamp {
    fn now() -> NtpTimestamp {
        let now = SystemTime::now();
        let dur = now.duration_since(UNIX_EPOCH).unwrap();
        let secs = dur.as_secs() + 2208988800; // 1900 epoch
        let nanos = dur.subsec_nanos();

        NtpTimestamp {
            ts: (secs << 32) + (nanos as f64 * 4.294967296) as u64,
        }
    }

    fn zero() -> NtpTimestamp {
        NtpTimestamp { ts: 0 }
    }

    fn diff_to_sec(&self, ts: &NtpTimestamp) -> f64 {
        self.ts.wrapping_sub(ts.ts) as i64 as f64 / 4294967296.0
    }

    fn read(buf: &[u8]) -> NtpTimestamp {
        NtpTimestamp {
            ts: BigEndian::read_u64(buf),
        }
    }

    fn write(&self, buf: &mut [u8]) {
        BigEndian::write_u64(buf, self.ts);
    }
}

#[derive(Debug, Copy, Clone)]
struct NtpFracValue {
    val: u32,
}

impl NtpFracValue {
    fn read(buf: &[u8]) -> NtpFracValue {
        NtpFracValue {
            val: BigEndian::read_u32(buf),
        }
    }

    fn write(&self, buf: &mut [u8]) {
        BigEndian::write_u32(buf, self.val);
    }

    fn zero() -> NtpFracValue {
        NtpFracValue { val: 0 }
    }
}

#[derive(Debug)]
struct NtpPacket {
    remote_addr: SocketAddr,
    local_ts: NtpTimestamp,
    leap: u8,
    version: u8,
    mode: u8,
    stratum: u8,
    poll: i8,
    precision: i8,
    delay: NtpFracValue,
    dispersion: NtpFracValue,
    ref_id: u32,
    ref_ts: NtpTimestamp,
    orig_ts: NtpTimestamp,
    rx_ts: NtpTimestamp,
    tx_ts: NtpTimestamp,
}

impl NtpPacket {
    fn receive(socket: &UdpSocket) -> io::Result<NtpPacket> {
        let mut buf = [0; 1024];
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                let local_ts = NtpTimestamp::now();

                if len < 48 {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "Packet too short"));
                }

                let leap = buf[0] >> 6;
                let version = (buf[0] >> 3) & 0x7;
                let mode = buf[0] & 0x7;

                if version < 1 || version > 4 {
                    return Err(Error::new(ErrorKind::Other, "Unsupported version"));
                }

                Ok(NtpPacket {
                    remote_addr: addr,
                    local_ts,
                    leap,
                    version,
                    mode,
                    stratum: buf[1],
                    poll: buf[2] as i8,
                    precision: buf[3] as i8,
                    delay: NtpFracValue::read(&buf[4..8]),
                    dispersion: NtpFracValue::read(&buf[8..12]),
                    ref_id: BigEndian::read_u32(&buf[12..16]),
                    ref_ts: NtpTimestamp::read(&buf[16..24]),
                    orig_ts: NtpTimestamp::read(&buf[24..32]),
                    rx_ts: NtpTimestamp::read(&buf[32..40]),
                    tx_ts: NtpTimestamp::read(&buf[40..48]),
                })
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                Err(Error::new(ErrorKind::WouldBlock, "Would Block"))
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    fn send(&self, socket: &UdpSocket) -> io::Result<usize> {
        let mut buf = [0; 48];

        buf[0] = self.leap << 6 | self.version << 3 | self.mode;
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;
        self.delay.write(&mut buf[4..8]);
        self.dispersion.write(&mut buf[8..12]);
        BigEndian::write_u32(&mut buf[12..16], self.ref_id);
        self.ref_ts.write(&mut buf[16..24]);
        self.orig_ts.write(&mut buf[24..32]);
        self.rx_ts.write(&mut buf[32..40]);
        self.tx_ts.write(&mut buf[40..48]);

        socket.send_to(&buf, self.remote_addr)
    }

    fn is_request(&self) -> bool {
        self.mode == 1
            || self.mode == 3
            || (self.mode == 0 && self.version == 1 && self.remote_addr.port() != 123)
    }

    fn make_response(&self, state: &NtpServerState) -> Option<NtpPacket> {
        if !self.is_request() {
            return None;
        }

        Some(NtpPacket {
            remote_addr: self.remote_addr,
            local_ts: NtpTimestamp::zero(),
            leap: state.leap,
            version: self.version,
            mode: if self.mode == 1 { 2 } else { 4 },
            stratum: state.stratum,
            poll: self.poll,
            precision: state.precision,
            delay: state.delay,
            dispersion: state.dispersion,
            ref_id: state.ref_id,
            ref_ts: state.ref_ts,
            orig_ts: self.tx_ts, // 复制客户端发送时间戳，以便供客户端库校验合法性
            rx_ts: self.local_ts,
            tx_ts: NtpTimestamp::now(),
        })
    }
}

#[derive(Copy, Clone)]
struct NtpServerState {
    leap: u8,
    stratum: u8,
    precision: i8,
    ref_id: u32,
    ref_ts: NtpTimestamp,
    dispersion: NtpFracValue,
    delay: NtpFracValue,
}

pub struct NtpServer {
    state: Arc<Mutex<NtpServerState>>,
    sockets: Vec<UdpSocket>,
    rx: Receiver<()>,
    debug: bool,
}

impl NtpServer {
    fn process_requests(
        thread_id: u32,
        debug: bool,
        socket: UdpSocket,
        state: Arc<Mutex<NtpServerState>>,
        rx: Receiver<()>,
    ) {
        let mut last_update = NtpTimestamp::now();
        let mut cached_state = *state.lock().unwrap();

        loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match NtpPacket::receive(&socket) {
                Ok(request) => {
                    if request.local_ts.diff_to_sec(&last_update).abs() > 0.1 {
                        cached_state = *state.lock().unwrap();
                        last_update = request.local_ts;
                    }

                    match request.make_response(&cached_state) {
                        Some(response) => match response.send(&socket) {
                            Ok(_) => {}
                            Err(e) => {
                                if debug {
                                    println!(
                                        "Thread #{} failed to send response: {}",
                                        thread_id, e
                                    );
                                }
                            }
                        },
                        None => {}
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    // 过滤网络非致命阻断错误，保持 UDP 循环不中断
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    pub fn new(addr: String, rx: Receiver<()>, debug: bool) -> Result<NtpServer, String> {
        let state = NtpServerState {
            leap: 0,
            stratum: 1,
            precision: 0,
            ref_id: 0,
            ref_ts: NtpTimestamp::zero(),
            dispersion: NtpFracValue::zero(),
            delay: NtpFracValue::zero(),
        };
        let mut sockets = vec![];
        let socket = UdpSocket::bind(&addr).map_err(|e| {
            format!(
                "UDP 绑定 {} 失败: {} (提示: Unix系统小于1024端口需要管理员权限)",
                addr, e
            )
        })?;
        socket.set_nonblocking(true).unwrap();
        sockets.push(socket);

        Ok(NtpServer {
            state: Arc::new(Mutex::new(state)),
            sockets,
            rx,
            debug,
        })
    }

    pub fn run(&self) {
        let mut threads = vec![];
        let mut id = 0;
        let mut txs: Vec<Sender<()>> = vec![];

        for socket in &self.sockets {
            id += 1;
            let state = self.state.clone();
            let debug = self.debug;
            let cloned_socket = socket.try_clone().unwrap();
            let (tx, rx) = mpsc::channel();
            threads.push(thread::spawn(move || {
                NtpServer::process_requests(id, debug, cloned_socket, state, rx);
            }));
            txs.push(tx);
        }

        loop {
            if self.rx.try_recv().is_ok() {
                for tx in txs {
                    let _ = tx.send(());
                }
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        for thread in threads {
            let _ = thread.join();
        }
    }
}

#[derive(Debug, Clone)]
pub struct NtpResult {
    pub server_time: String,
    pub local_time: String,
    pub offset_ms: f64,
    pub delay_ms: f64,
    pub stratum: u8,
    // 已移除 precision 时钟精度参数
}

pub fn check_ntp_server(addr: &str) -> Result<NtpResult, String> {
    let mut client = rsntp::SntpClient::new();
    client.set_timeout(Duration::from_secs(3));

    let target_addr = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:123", addr)
    };

    match client.synchronize(&target_addr) {
        Ok(result) => {
            let datetime_utc: chrono::DateTime<chrono::Utc> = result
                .datetime()
                .try_into()
                .map_err(|_| "时间格式解析失败".to_string())?;
            let server_time: chrono::DateTime<chrono::Local> = chrono::DateTime::from(datetime_utc);
            let server_time_str = server_time.format("%Y-%m-%d %H:%M:%S.%3f").to_string();

            let local_time_str = chrono::Local::now()
                .format("%Y-%m-%d %H:%M:%S.%3f")
                .to_string();

            let offset_sec = result.clock_offset().as_secs_f64();
            let offset_ms = offset_sec * 1000.0;

            let delay_ms = result.round_trip_delay().as_secs_f64() * 1000.0;
            let stratum = result.stratum();

            Ok(NtpResult {
                server_time: server_time_str,
                local_time: local_time_str,
                offset_ms,
                delay_ms,
                stratum,
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub struct NtpChecker {
    focus_handle: FocusHandle,
    server_input: Entity<InputState>,
    loading: bool,
    result: Option<Result<NtpResult, String>>,

    // 本地临时服务状态控制
    local_server_running: bool,
    local_server_handle: Option<JoinHandle<()>>,
    local_server_stop_tx: Option<Sender<()>>,
    local_server_error: Option<String>,
}

impl NtpChecker {
    pub fn new(window: &mut Window, cx: &mut App) -> Entity<Self> {
        let server_input =
            cx.new(|cx| InputState::new(window, cx).default_value("ntp.aliyun.com:123"));

        cx.new(|cx| Self {
            focus_handle: cx.focus_handle(),
            server_input,
            loading: false,
            result: None,
            local_server_running: false,
            local_server_handle: None,
            local_server_stop_tx: None,
            local_server_error: None,
        })
    }

    fn start_check(&mut self, cx: &mut Context<Self>) {
        let addr = self.server_input.read(cx).value().trim().to_string();
        if addr.is_empty() {
            self.result = Some(Err("请输入服务器地址".to_string()));
            cx.notify();
            return;
        }

        self.loading = true;
        self.result = None;
        cx.notify();

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let res = check_ntp_server(&addr);
            this.update(cx, |view, cx| {
                view.loading = false;
                view.result = Some(res);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// 开关本地临时 NTP 服务器 (完全非阻塞)
    fn toggle_local_server(&mut self, cx: &mut Context<Self>) {
        if self.local_server_running {
            // 1. 发送停止信号
            if let Some(tx) = self.local_server_stop_tx.take() {
                let _ = tx.send(());
            }
            // 2. 将阻塞式 join 丢入后台线程执行，彻底避免卡死 UI 线程
            if let Some(handle) = self.local_server_handle.take() {
                thread::spawn(move || {
                    let _ = handle.join();
                });
            }
            self.local_server_running = false;
            self.local_server_error = None;
            cx.notify();
        } else {
            // 3. 准备启动本地服务
            let (tx, rx) = mpsc::channel();
            let address = "127.0.0.1:10123".to_string();

            // 在主线程同步进行轻量级端口绑定（UdpSocket::bind），即刻捕获常见错误
            match NtpServer::new(address, rx, true) {
                Ok(server) => {
                    // 4. 在物理系统后台线程跑监听循环，绝不阻塞 GPUI
                    let handle = thread::spawn(move || {
                        server.run();
                    });

                    self.local_server_handle = Some(handle);
                    self.local_server_stop_tx = Some(tx);
                    self.local_server_running = true;
                    self.local_server_error = None;
                }
                Err(e) => {
                    self.local_server_running = false;
                    self.local_server_stop_tx = None;
                    self.local_server_handle = None;
                    self.local_server_error = Some(e);
                }
            }
            cx.notify();
        }
    }

    fn render_quick_button(
        &self,
        label: &'static str,
        addr: &'static str,
        id: &'static str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let short_name = addr.split(':').next().unwrap_or(addr);
        Button::new(id)
            .label(short_name)
            .on_click(cx.listener(move |this, _, window, cx| {
                this.server_input.update(cx, |input, cx| {
                    input.set_value(addr, window, cx);
                });
                cx.notify();
            }))
            .tooltip(label)
    }

    fn render_result_content(&self) -> impl IntoElement {
        if self.loading {
            return v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_2()
                .child(
                    div()
                        .text_lg()
                        .text_color(rgb(0x3182ce))
                        .child("正在向 NTP 服务器发送 UDP 请求，请稍候..."),
                );
        }

        match &self.result {
            None => v_flex().size_full().items_center().justify_center().child(
                div()
                    .text_color(rgb(0xa0aec0))
                    .child("请输入服务器地址，然后点击“开始检查”按钮。"),
            ),
            Some(Err(err)) => v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_2()
                .child(
                    div()
                        .font_bold()
                        .text_lg()
                        .text_color(rgb(0xe53e3e))
                        .child("检测失败"),
                )
                .child(div().text_sm().text_color(rgb(0x718096)).child(err.clone())),
            Some(Ok(res)) => {
                let offset_color = if res.offset_ms.abs() < 50.0 {
                    rgb(0x38a169)
                } else if res.offset_ms.abs() < 200.0 {
                    rgb(0xdd6b20)
                } else {
                    rgb(0xe53e3e)
                };

                v_flex()
                    .gap_4()
                    .child(
                        h_flex()
                            .justify_between()
                            .child(
                                div()
                                    .font_bold()
                                    .text_lg()
                                    .text_color(rgb(0x2d3748))
                                    .child("检测报告"),
                            )
                            .child(div().font_bold().text_color(offset_color).child(
                                if res.offset_ms.abs() < 50.0 {
                                    "同步状态: 极佳"
                                } else {
                                    if res.offset_ms.abs() < 200.0 {
                                        "同步状态: 一般"
                                    } else {
                                        "同步状态: 需校准"
                                    }
                                },
                            )),
                    )
                    .child(div().h_px().bg(rgb(0xe2e8f0)))
                    .child(
                        v_flex()
                            .gap_3()
                            .child(
                                h_flex()
                                    .gap_4()
                                    .child(self.render_info_card(
                                        "服务器 NTP 时间",
                                        &res.server_time,
                                        rgb(0x2d3748),
                                    ))
                                    .child(self.render_info_card(
                                        "本地系统时间",
                                        &res.local_time,
                                        rgb(0x2d3748),
                                    )),
                            )
                            .child(
                                h_flex()
                                    .gap_4()
                                    .child(self.render_info_card(
                                        "时间偏差 (Offset)",
                                        &format!("{:.3} ms", res.offset_ms),
                                        offset_color,
                                    ))
                                    .child(self.render_info_card(
                                        "往返延迟 (RTT)",
                                        &format!("{:.3} ms", res.delay_ms),
                                        rgb(0x3182ce),
                                    )),
                            )
                            .child(h_flex().gap_4().child(self.render_info_card(
                                "层级 (Stratum)",
                                &format!("Stratum {}", res.stratum),
                                rgb(0x4a5568),
                            ))),
                    )
            }
        }
    }

    fn render_info_card(
        &self,
        label: &'static str,
        value: &str,
        value_color: Rgba,
    ) -> impl IntoElement {
        div()
            .flex_1()
            .p_3()
            .bg(rgb(0xffffff))
            .border_1()
            .border_color(rgb(0xe2e8f0))
            .rounded_md()
            .child(
                v_flex()
                    .gap_1()
                    .child(div().text_xs().text_color(rgb(0x718096)).child(label))
                    .child(
                        div()
                            .font_bold()
                            .text_sm()
                            .text_color(value_color)
                            .child(value.to_string()),
                    ),
            )
    }
}

impl Drop for NtpChecker {
    fn drop(&mut self) {
        if let Some(tx) = self.local_server_stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.local_server_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Focusable for NtpChecker {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for NtpChecker {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .p_6()
            .gap_4()
            .bg(rgb(0xffffff))
            // 本地临时服务状态控制卡片
            .child(
                h_flex()
                    .gap_3()
                    .items_center()
                    .p_3()
                    .bg(rgb(0xf7fafc))
                    .border_1()
                    .border_color(rgb(0xe2e8f0))
                    .rounded_lg()
                    .child(
                        v_flex()
                            .flex_1()
                            .gap_1()
                            .child(
                                div()
                                    .font_bold()
                                    .text_sm()
                                    .text_color(rgb(0x2d3748))
                                    .child("本地临时 NTP 服务器 (127.0.0.1:10123)"),
                            )
                            .child(if let Some(err) = &self.local_server_error {
                                div()
                                    .text_xs()
                                    .text_color(rgb(0xe53e3e))
                                    .child(format!("错误: {}", err))
                            } else if self.local_server_running {
                                div().text_xs().text_color(rgb(0x38a169)).child(
                                    "状态: 正在运行 (您可以使用下方 127.0.0.1:10123 进行快捷检测)",
                                )
                            } else {
                                div()
                                    .text_xs()
                                    .text_color(rgb(0x718096))
                                    .child("状态: 已停止")
                            }),
                    )
                    .child(
                        Button::new("toggle_local_server_btn")
                            .primary()
                            .label(if self.local_server_running {
                                "停止服务"
                            } else {
                                "启动服务"
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.toggle_local_server(cx);
                            })),
                    ),
            )
            .child(
                h_flex()
                    .gap_3()
                    .items_center()
                    .child(div().flex_1().child(Input::new(&self.server_input)))
                    .child(
                        Button::new("check_btn")
                            .primary()
                            .label(if self.loading {
                                "检查中..."
                            } else {
                                "开始检查"
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                if !this.loading {
                                    this.start_check(cx);
                                }
                            })),
                    ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(div().text_xs().text_color(rgb(0x4a5568)).child("快捷源:"))
                    .child(self.render_quick_button(
                        "阿里云NTP",
                        "ntp.aliyun.com:123",
                        "btn_aliyun",
                        cx,
                    ))
                    .child(self.render_quick_button(
                        "国家授时中心",
                        "ntp.ntsc.ac.cn:123",
                        "btn_ntsc",
                        cx,
                    ))
                    .child(self.render_quick_button("经典内网", "192.168.1.1:123", "btn_cn", cx))
                    .child(self.render_quick_button(
                        "本地服务器",
                        "127.0.0.1:10123",
                        "btn_apple",
                        cx,
                    )),
            )
            .child(
                div()
                    .flex_1()
                    .border_1()
                    .border_color(rgb(0xe2e8f0))
                    .rounded_lg()
                    .p_4()
                    .bg(rgb(0xf7fafc))
                    .child(self.render_result_content()),
            )
    }
}

fn main() {
    #[cfg(target_os = "windows")]
    unsafe {
        std::env::set_var("GPUI_DISABLE_DIRECT_COMPOSITION", "true");
    }

    gpui_platform::application().run(move |cx| {
        gpui_component::init(cx);

        cx.spawn(async move |cx| {
            cx.update(|cx| {
                let bounds = Bounds::centered(None, size(px(800.0), px(600.0)), cx);
                let options = WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    titlebar: Some(TitlebarOptions {
                        title: Some("NTP工具箱".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                cx.open_window(options, |window, cx| {
                    let view = NtpChecker::new(window, cx);
                    cx.new(|cx| Root::new(view, window, cx))
                })
                .expect("打不开程序主窗口");
            });
        })
        .detach();
    });
}

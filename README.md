# ntp-toolbox

<div align="center">
  <img src="./assets/icon.ico" alt="Logo" width="160">
  <h1 align="center">NTP ToolBox: ntp check and serving</h1>
</div>

## 📖 Features

- [x] check whether the specified ntp server address is valid.
- [x] starting ntp server for temporary test.

Currently, only Windows is supported, Linux and macOS will be supported in the future.

## 📜 License

Distributed under the Apache License. See [`LICENSE`](./LICENSE) for more information.

## 📝 Development & Build

### Development Stack

- [Rust](https://rust-lang.org) A language empowering everyone to build reliable and efficient software.
- [gpui](https://www.gpui.rs) A fast, productive UI framework for Rust from the creators of Zed.
- [gpui-component](https://longbridge.github.io/gpui-component) Rust GUI components for building fantastic
  cross-platform desktop application by using GPUI.
- [rsntp](https://github.com/mlichvar/rsntp) High-performance NTP server written in Rust.

### Build Project

1. Clone the repository
    ```bash
    git clone https://github.com/humbinal/ntp-toolbox.git
    ```

2. Run
    ```bash
    cargo run
    ```

3. Build
    ```bash
    cargo build --release
    ```

use std::io;

fn main() -> io::Result<()> {
    // 仅在编译目标为 Windows 系统时运行该注入逻辑
    #[cfg(target_os = "windows")]
    {
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico") // 指定您的 ico 文件路径
            .compile()?;
    }
    Ok(())
}

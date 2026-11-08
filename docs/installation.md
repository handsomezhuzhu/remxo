# 安装、构建与分发

## 组成

Remxo 的运行时由三部分组成：

1. `remxo` 原生 Rust 可执行文件：CLI、TUI、Broker、Vault、策略与运维逻辑。
2. 系统 OpenSSH：`ssh`；文件传输和交互式文件操作还需要 `scp`、`sftp`。
3. 可选 npm 启动器：定位与用户操作系统、架构、版本匹配的预编译原生核心包。

npm 包中的 Node.js 代码只负责薄启动，不承载 Vault、UI、认证或远程执行协议。

## 环境要求

| 项目 | 要求 |
| --- | --- |
| Rust 源码构建 | Rust 1.88 或兼容的更高稳定版工具链 |
| npm 启动器 | Node.js 18 或更高版本，以及 npm |
| Linux 集成测试入口 | Python 3 |
| SSH 连接 | 可执行的系统 OpenSSH 客户端 |
| Windows 文件权限处理 | 系统 PowerShell 与 .NET `FileSecurity` 能力 |
| TUI 与隐藏密码输入 | 交互式终端；stdout/stderr 被重定向不等同于可交互 TTY |

可检查 OpenSSH 的实际位置：

```console
# Linux
command -v ssh
ssh -V

# Windows PowerShell
Get-Command ssh
ssh -V
```

## npm 安装

```console
npm install --global remxo
remxo --version
```

主包 `remxo` 通过精确同版本的 optional dependencies 选择核心包：

| 运行目标 | 原生包 | Rust target |
| --- | --- | --- |
| Windows x64 | `@remxo/core-win32-x64` | `x86_64-pc-windows-msvc` |
| Linux x64 / glibc | `@remxo/core-linux-x64` | `x86_64-unknown-linux-gnu` |

启动器按 `process.platform` 与 `process.arch` 解析平台包，检查 manifest、平台、CPU、libc 和精确版本，解析 vendored 可执行文件并将路径规范化为真实路径。缺少对应包、包信息不一致或目标文件不可执行时，返回明确错误，不会从 PATH 选取另一个 Remxo 代替。

在 Unix 上使用 `execve`，以原生二进制作为 argv0 并保留用户参数和信号语义；Windows 上通过无本地 shell 的 argv 子进程继承终端输入输出。安装过程不依赖 `postinstall` 下载、用户侧 Cargo 编译或运行时自动更新。

完成安装后检查：

```console
remxo --version
remxo --json status
remxo doctor
```

安装完成后 npm 本身不打印任何横幅（没有 `postinstall`）。引导由原生 CLI 在人类可读输出里提供：`remxo status` 会依据本地文件与主机数量追加一行"下一步"，分别提示 `remxo init`、`remxo unlock` 或 `remxo host add`；初始化完成且已有主机后不再显示。`--json` 输出保持单一机器可读文档，不附加引导文本。

首次运行还需要初始化和登记主机，见 [项目文档](README.md#初始化与首次连接)。

## 源码构建

```console
cargo build --release
```

生成的可执行文件：

```text
Linux:    target/release/remxo
Windows:  target\release\remxo.exe
```

直接使用构建产物：

```console
# Linux
./target/release/remxo --version

# Windows PowerShell
.\target\release\remxo.exe --version
```

需要通过 Rust 工具链安装命令时：

```console
cargo install --path .
remxo --version
```

应从匹配的构建产物执行 `pack` 中的 `--artifact`。原生 `--version`、Cargo 包版本和 npm 主/平台包版本需要保持一致。

## 开发检查

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --test-threads=1
cargo build
npm test --prefix npm
python3 tests/run_all.py
```

Linux/Python 驱动可以限定检查范围：

```console
python3 tests/run_all.py --only checks
python3 tests/run_all.py --only fake
python3 tests/run_all.py --only pty
python3 tests/run_all.py --only real
python3 tests/run_all.py --only sudo
python3 tests/run_all.py --no-real-ssh
```

`real` 测试使用临时容器与临时密钥，传入真实用户 SSH 目录、Vault 或服务器凭据不是这组测试的输入约定。可用性、清理规则和边界见 [TESTING.md](../TESTING.md)。

## 本地打包原生 npm 产物

Linux 核心包：

```console
cargo build --release
node scripts/npm/pack.js --platform linux-x64 --artifact target/release/remxo --out target/npm/core
```

Windows 核心包：

```console
cargo build --release
node scripts/npm/pack.js --platform win32-x64 --artifact target/release/remxo.exe --out target/npm/core
```

主启动器包：

```console
node scripts/npm/pack.js --main --out target/npm/launcher
```

底层 `npm pack` 使用 `--ignore-scripts`。核心包只将匹配的二进制放入 `vendor/<rust-target>/bin/`；主包只包含 `bin/` 和 `lib/` 中的薄启动器。打包工具通过真正的 native `remxo --version` 核对版本，不是仅检查文件名。

### 离线安装示例

将同一版本的主 tarball 与当前平台的原生 tarball 放在同一个 `artifacts/` 目录。先安装原生包，再在 optional dependency 不访问 registry 的情况下安装主包：

```console
# Windows
npm install --global --ignore-scripts --omit=optional ./artifacts/remxo-core-win32-x64-0.1.1.tgz
npm install --global --ignore-scripts --omit=optional ./artifacts/remxo-0.1.1.tgz

# Linux
npm install --global --ignore-scripts --omit=optional ./artifacts/remxo-core-linux-x64-0.1.1.tgz
npm install --global --ignore-scripts --omit=optional ./artifacts/remxo-0.1.1.tgz
```

安装后执行 `remxo --version`。如版本发生变化，应将示例中的 `0.1.1` 和所有对应包版本一起更新，不能混用不同版本的 launcher/core。

## 数据目录与隔离运行

默认配置路径是用户配置目录下的 `remxo/config.toml`，其所在目录同时是数据根目录：

```console
remxo --config /path/to/remxo-data/config.toml status
```

数据根包含配置、Vault、Broker endpoint、审计和运行时临时文件。不要手工复制正在写入的运行时文件来代替备份；组合备份使用 `remxo backup create`。

同一命令必须让启动器与 Broker 使用同一个数据目录。不同的 `--config` 对应独立配置、Vault、endpoint、解锁状态和运行时状态，适合相互隔离的开发 fixture；同一个真实用户的生产主机清单不应当被测试目录替换。

## Broker 升级与重启

`lock` 与停止 Broker 是两个不同的动作：

```console
remxo lock
remxo lock --stop-broker
```

前者只锁定 Vault 会话；后者还请求后台 Broker 正常关闭。升级正在运行的二进制之前，按明确计划停止旧 Broker，再安装匹配的版本。恢复后由用户运行 `remxo unlock`，并用 `remxo --json status` 读取状态。配置和 Vault 在磁盘上的身份不通过明文会话文件恢复。

## PowerShell 调用细节

npm 为 PowerShell 生成的 shim 使用 `$args` 传递参数。需要显式保留远端命令分隔符时，将其写成 `'--'`：

```console
remxo --json task start prod-01 '--' uptime
remxo --json tunnel start prod-01 '--' --local 127.0.0.1:18080:127.0.0.1:8080
```

未加引号的 `--` 可能被 PowerShell 当作自己的参数结束标记，从而不传给 npm 脚本。这个规则发生在 Remxo CLI 之前；JSON 中没有生成操作报告通常说明需要先检查调用语法。

## 开发环境变量

- `REMXO_CORE_PATH`：指定开发或隔离测试用的原生核心文件；正常安装通过版本化平台包定位。
- `REMXO_SSH`、`REMXO_SCP`、`REMXO_SFTP`：由测试环境指定替代程序或包装器的入口；真实服务器工作流不应把它们指向不可信程序。
- `NO_COLOR` 或 `--no-color`：关闭界面套色。

这些变量都不是密码输入通道。`REMXO_ASKPASS_*` 属于 OpenSSH 调用内部辅助入口所需的进程上下文，AI 和调用脚本不应自行构造、读取或转储它们。

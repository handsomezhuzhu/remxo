# Testing Remxo

目标：仓库之外不需要真实服务器、账号、密码、私钥、SSH Agent 或平台 Token。测试失败和环境不可用分别报告，禁止把跳过写成通过。

## 一键测试

Linux 推荐使用 Python 3 的标准库测试驱动：

```console
python3 tests/run_all.py
```

默认依次运行：

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all-targets -- --test-threads=1`
4. `cargo build`
5. fake 故障注入和并发测试
6. PTY 密码与 TUI 测试
7. Docker 可用时自动运行真实 sshd/SFTP/TCP 隧道/任务测试
8. 同一类隔离环境中的真实 sudo、Vault 和一次性审批测试
9. `integration/check_cleanup.py` 只读检查残留 Broker、容器和临时镜像

命令选项：

```console
python3 tests/run_all.py --only checks
python3 tests/run_all.py --only fake
python3 tests/run_all.py --only pty
python3 tests/run_all.py --only real
python3 tests/run_all.py --only sudo
python3 tests/run_all.py --no-real-ssh
python3 tests/run_all.py --require-real-ssh
python3 tests/run_all.py --require-real-ssh
# 也可以选择其中一个 suite：checks、fake、pty、real、sudo
python3 tests/run_all.py --report target/remxo-test-results.json
```

- `--only fake|pty|real` 在缺二进制时先编译，已有二进制不会隐式视为最新；修改 Rust 后建议先运行 `--only checks`。
- Linux 之外的 Python 集成测试明确跳过；Windows 仍执行 Rust 单元测试和能够运行的 fake Rust 测试。
- Docker 不存在或 daemon 不可用则真实 SSH 测试标为 `skipped / NOT_RUN`，不影响 fake/PTY 结果。
- `--require-real-ssh` 将真实 SSH 缺失或失败作为总测试失败。
- 测试中途失败返回非零，阻止继续运行后续 suite，避免用旧二进制生成误导性结果。

也可以直接提供已编译二进制，单独执行 Python 测试：

```console
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/fault_and_stress.py
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/pty_acceptance.py
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/sshd_acceptance.py
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/sudo_acceptance.py
```

真实 SSH 强制模式：

```console
REMXO_REQUIRE_REAL_SSH=1 REMXO_BIN="$PWD/target/debug/remxo" \
  python3 tests/integration/sshd_acceptance.py
```

## 测试分层

### Rust 单元与 fake 可执行文件

`src` 内的单元测试及 `tests/cli_end_to_end.rs` 覆盖：

- 配置解析、主机编号/登记 IP、拒绝未登记 IP；
- POSIX 参数与 cwd 注入检查、非 POSIX 拒绝、profile 参数；
- 原始 argv、无本地 shell 拼接、BatchMode、默认不弱化主机密钥检查；
- Vault 初始锁定、等效重启锁定、错误主密码、DEK 不明文落盘、改密不换 DEK；
- 异常 KDF 参数、备份验证和全新目录恢复；
- 审批匹配和一次性、任务状态、无自动重试、传输覆盖、隧道默认绑定；
- sudo 标准输入、远端回显清理、sudo 拒绝错误；
- Telnet 未确认拒绝。

### `fault_and_stress.py`

每个测试都有独立临时目录、独立 Broker 和 fake，不连接真实服务器。覆盖：

- fake 主机密钥错误、双流超大输出、超时 kill；
- PEM、API/Password 与控制字符处理；
- 命令和 cwd 注入不在本机创建标记文件；
- 多客户端并发、唯一 request id、每个请求恰好执行一次；
- task 启动/取消/日志、停止已完成任务报错、进程回收和 Broker 重启锁定。

### `pty_acceptance.py`

Linux Python `pty.fork` 自动完成隐藏提示，而不是通过 argv、stdin 管道或 shell history 递送密码。所有 PASSWORD 都是代码中明确标记的 test-only 假值。回复敏感提示前，驱动读取 PTY termios 并等待 `ECHO=off`，避免在密码库关闭回显前抢答。测试会验证配置、Vault/备份和终端 transcript 都没有这些测试 PASSWORD，不能为了消除竞态而取消此项断言。

一个连续流程验证：

- init（密码与确认）、添加 fake host；
- 人工 unlock 的 CLI 行为；
- 加密备份 create/verify/restore；
- change-password 后旧状态 lock / 新密码 unlock；
- 恢复目录仍用原主密码解锁；
- TUI 在 PTY 中启动并通过 q 退出；
- 临时配置、Vault、备份和终端记录不含测试密码。

PTY transcript 仅做内存泄漏检查，不打印密码或大段终端内容；每条命令具有超时和独立子进程回收。

### `sshd_acceptance.py`

这是唯一使用真实 SSH/SFTP/TCP 协议的路径，但仍是测试专用环境：

- 临时 Alpine sshd 容器；Docker host network 只监听 127.0.0.1；
- 每次随机容器名、镜像名、host/user 临时 Ed25519 密钥；
- binary wrapper 只负责向真正的 `/usr/bin/ssh` 和 `/usr/bin/scp` 显式传 `-F <临时配置>`，不替换协议实现；
- 临时 `known_hosts` 来自预先生成的 host public key，保持 `StrictHostKeyChecking=yes`；
- sshd 禁用密码、交互键盘、root 登录；只允许生成的 public key；
- 容器/镜像/Broker 在 teardown 回收，不读取或更改用户 HOME、`~/.ssh`、系统 sshd 或公共端口。

矩阵覆盖：

1. 真实 argv 命令、cwd 副作用隔离、profile、参数和路径注入标记不存在、cwd 不跨 SSH 进程错误保留。
2. 修改 expected host key 后真实 OpenSSH 必须返回 `host_key_failed`，恢复后严格连接成功。
3. SFTP 特殊路径、二进制 round-trip SHA-256、远端覆盖和本地覆盖拒绝、显式覆盖成功。
4. 真实 TCP echo 数据通过 SSH 隧道；stop 生效；0.0.0.0 缺确认拒绝；端口冲突失败。隧道只有在 OpenSSH 输出完成交互初始化且进程仍存活时才登记，不将 bind 前的 `Local forwarding listening on` 预告误判为可用。
5. 真实 task 完成输出恰好一次、退出码、取消和 finish time。

基准镜像 `alpine:3.22` 由 Docker 拉取测试依赖；首次运行需网络。密钥只在临时 volume 中提供，不写入镜像。环境不满足时不可把本 suite 描述成 pass。

### `sudo_acceptance.py`

`SudoFixture` 在同一临时 sshd 基础上通过真正隐藏 PTY 创建和解锁 Vault、写入独立 sudo 凭据。sudoers 只在一次性容器内配置；为兼容 Remxo 当前 raw-command 包装形式，覆盖 `/usr/bin/id` 与 `/bin/sh`，不是向用户机器部署 sudoers 规则。sudo 密码随机生成，以隐藏 PTY 递送，容器启动时写入 shadow hash，密码的原始 gadget 文件权限为 `0600`，teardown 删除，不写入镜像。

验证：普通命令不是 root；第一次 sudo 必须 `approval_required`；显式模拟人类批准后，相同 sudo 命令得到真实 uid 0；下一次相同命令必须重新审批；Vault、输出和审计都不含 sudo 密码。这个场景同时回归了“unlock 的终端退出后 Broker 不得死亡、解锁状态必须保留”的实际问题。自动 Broker 应走 daemon 路径，测试中直接用端口号和 PID 检查生命周期而不是假定它存活。

## GitHub Actions and Instabox CI

- `.github/workflows/ci.yml`: Linux、macOS、Windows 上的 fmt、Clippy、Rust 全部测试和构建，补充 Linux Docker 的 Rust 1.88 MSRV 测试。这些普通 GitHub runner 不占 Instabox 配额。
- `.github/workflows/instabox.yml`: 5 类隔离任务，直接 `runs-on: instabox-medium`，覆盖 Rust/release 检查、cargo-audit/Python 静态检查、fake/PTY/TUI、真实 sshd/sudo、20 轮并发稳定性。GitHub App 为每个 job 提供新 Ubuntu 24.04 runner 并在迭结束时删除；不注入用户 Vault/Secrets。最多 3 个并发，避免一分钟启动限流。
- 该 App 使用 GitHub 所需 Metadata/Actions/Administration 权限注册和回收 runner；App backend 不需要 `runs-on: instabox-medium` 作业配置 API Key。公开 fork PR 不启动这些任务，skipped/not_run 不代表通过。
- `scripts/test/instabox-run.sh` 用官方 `instabox run --push . --timeout 10m` 的方法做开发期单次测试，命令结束自动删机；它不是 GitHub Actions runner，也未用于 push 后的 CI。
- 新增 `tests/property_invariants.rs`：任意 Unicode 多参数 token往返、单 raw script语义、输出UTF8/控制符边界、明确秘密格式，以及 target 优先级。每组 property 128 例。

CI 的新增覆盖并未把本工具自称为跨发行版或跨平台全兼容；Windows/macOS原生基础测试、Linux交互协议测试和L1威胁模型是三个不同层次。

## 清理与安全约束

- 测试仅结束自己启动的 Broker、PTY、进程组和容器。Broker endpoint 只读取数字 PID；token 不显示、打印或用于绕过 Remxo，清理 pid 文件被自动删除。
- 不使用 `pkill ssh`、`pkill remxo`、全局 Docker purge、Instabox rm 或公共 Host 配置修改。
- 超时等待有上限，测试不会向真实服务器发写命令，也不会因断线盲目重试。
- 被测真的临时容器和本机 fake 都会执行命令，但命令只在测试专用隔离环境中。
- 若发生失败，用阶段名、错误类别、退出码及受限日志定位；先检查实际执行输出，再判断生产 bug 或 fixture bug。

## Instabox 并行执行

五台机器意义是隔离风险和并行获取真实结果，不是重复堆高测试计数。源代码同步至每台 `/data/workspace/remxo`，机器均 `--no-vault --secrets none`。下载、完整编译与长测试通过 `instabox ssh` 运行，不依赖 `exec` 的 60 秒上限。

| 机器 | 角色 |
| --- | --- |
| remxo-dev | 全量 Rust 检查、汇总及一键测试 |
| remxo-fake | 故障注入与 fake 安全边界 |
| remxo-cli | PTY、隐藏密码、备份与 TUI |
| remxo-sshd | Docker 真 SSH/SFTP/隧道/任务 |
| remxo-stress | 并发、稳定性与进程回收 |

不启动组织或个人 Vault，不上传 HOME 私钥/Remxo Vault、不公开端口、不删除机器。如果需要额外跨发行版、原生 Windows/macOS、用户真实环境或大规模负载测试，那是环境扩展，不在上述结果保证内。

## 尚不能由这些测试证明的事项

- 无独立安全审计、无“绝对安全”或 L2/L3 保证。
- fake 不证明真远程服务器兼容性；单次 Alpine SSH 测试也不证明所有 SSH 服务端、shell、硬件密钥或网络设备兼容性。
- PTY 基础 TUI 通过不表示尚未实现的编辑/审批/备份向导已经工作。
- 远程脱离任务、跨 Broker 持久化、PowerShell/CMD、Telnet 网络自动化、连接复用、生物识别仍需独立实现与测试。
- 已覆盖一个隔离 Alpine sudo、PTY 和审批流程；其他 sudoers/PTY 细节仍需更多独立系统场景；不猜密码、不穷举。
- 只检查 argv/env/log/输出的泄露，不声称证明所有内存拷贝、core dump 或其他秘密类别均已消失。

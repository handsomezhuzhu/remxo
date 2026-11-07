# Remxo

**Remote execution for humans and agents.**

Remxo 是本地远程服务器管理、命令编排与执行工具：复用系统 OpenSSH，提供主机清单、加密 Vault、同用户 Broker、策略与一次性审批、AI JSON、审计、基础 TUI，以及有限实现的文件传输、隧道和后台任务。

> 当前是未经独立安全审计的开发版，安全等级为 **L1**。它不是 L2 同用户隔离，不宣称“生产绝对安全”，也不替代远程账号自身的授权边界。

## 已实现范围

- 严格 TOML v1 配置；主机别名、编号、已登记 IP 解析；默认拒绝未登记 IP。
- OpenSSH 单次命令和交互式 SSH，通过 `argv` 启动，不调用本地 `sh -c`，不关闭主机密钥检查。
- 外部 Agent 与 OpenSSH 配置认证；非交互默认 `BatchMode=yes`、超时、输出上限。
- Argon2id 派生 KEK、随机 DEK、XChaCha20Poly1305 的加密 Vault；Broker 启动即锁定，修改主密码只重新包裹 DEK。
- 独立加密的 `.rxb` 备份、验证、冲突检测、全新目录恢复。备份嵌套携带仍加密的 Vault，不包含明文 DEK、Socket、任务、审批或日志。
- 同用户 loopback Broker、随机 IPC token、受限请求；CLI/TUI 不向 AI 返回完整 Vault。
- Raw/profile 策略、短期一次性审批、SHA-256 请求摘要、JSONL 元数据审计。
- 输出限长、常见秘密脱敏、控制字符转义；sudo 密码仅经标准输入注入且从回显输出中专门清除。
- Broker 后台任务状态/日志/取消、OpenSSH 隧道生命周期基础管理、经 Broker 授权的 SCP（强制 SFTP 模式）上传下载。
- 基于 ratatui/crossterm 的 Hosts、Sessions、Tasks、Approvals、Audit、Backup、Settings 基础面板。

## 构建与测试

需要稳定版 Rust（MSRV 1.88）和系统 OpenSSH 客户端。

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --test-threads=1
cargo build
```

Linux 下一键运行自包含 fake、PTY 与可选 Docker/真实 sshd 测试；不提供任何真实服务器或凭据：

```console
python3 tests/run_all.py
```

完整测试分层、清理规则、环境要求和未覆盖范围见 [TESTING.md](TESTING.md)。

`REMXO_SSH`、`REMXO_SCP` 可指定测试 fake 可执行文件；不要把这些变量指向不可信程序用于真实主机。

## 快速开始

```console
# 在交互终端中操作；密码只通过隐藏提示输入
remxo init

# 使用现有 OpenSSH Host 别名，不修改 ~/.ssh/config
remxo host add prod-01 --ssh-alias real-prod-alias --number 2 \
  --environment production --auth external-agent

remxo unlock
remxo status
remxo hosts

remxo prod-01 ls -la
remxo 2 df -h
remxo --json prod-01 'cd /var/www && git status'
remxo --cwd /var/www prod-01 ls -la
remxo prod-01 --profile logs --arg service=nginx --arg lines=100
```

target 前的全局参数包括 `--json`、`--no-color`、`--timeout`、`--max-output`、`--cwd`、`--config`、`--verbose`、`--sudo`、`--overwrite`。target 后的参数保留给远程命令，例如 `remxo prod-01 ls -l --help` 不会把远程 `--help` 当成本地帮助。

无 command 且处于 TTY 时打开交互式 SSH；非 TTY 无 command 会立即报用法错误。裸 `remxo` 仅在真正的交互 TTY 中进入 TUI。子命令名和全局选项位置保留给 CLI，主机别名不应与它们冲突。

与 OpenSSH 首次连接所需的主机密钥确认应由人类提前完成。Remxo 从不自动添加 `StrictHostKeyChecking=no`、`UserKnownHostsFile=/dev/null` 或 `ForwardAgent=yes`。

## 策略与审批

主机支持 `raw_mode = "allow" | "read-only" | "deny"` 和 `approval = "never" | "writes" | "always"`。`read-only` 只允许内置 profile；`deny` 禁止 raw 执行。启发式只用于决定审批便利性，**不是命令安全沙箱**。raw 一旦允许，就意味着远程账号本身的权限。

需要审批时，执行返回 `approval_required` 和 `approval_id`，AI 应停止。人类审查后可执行：

```console
remxo approval list
remxo approval approve <approval-id>
# 在过期前原样重跑同一操作；连接配置、命令、参数或输出限制改变都会形成不同摘要
```

同用户 approve 只是 L1 便利，恶意同用户 Agent 可以绕过它。

## sudo

```console
remxo unlock
remxo vault set-sudo prod-01
remxo --sudo prod-01 systemctl restart nginx
```

sudo 使用独立 Vault 记录，不复用 SSH 密码。密码通过 SSH 标准输入交给远程 `sudo -S`，不进入本地远程 argv；输出会清除该精确秘密和常见秘密格式。`requiretty`、远程 sudoers、PAM 等仍可能导致 `sudo_not_permitted` 或远程失败。优先在 sudoers 中做精确授权；不要在脚本、日志或 AI 上下文中放密码。

## 加密备份

```console
remxo backup create ./remxo.rxb
remxo backup verify ./remxo.rxb
# 建议使用新的 --config 数据目录验证恢复；现有文件默认拒绝覆盖
remxo --config /new-dir/config.toml backup restore ./remxo.rxb
```

备份密码与主密码都是隐藏输入且不能经 CLI 参数传入。恢复后仍使用**原 Vault 主密码**显式 `unlock`；备份密码只保护备份外层。生物识别、平台密钥和外部 Agent 私钥不在备份中。

## 文件传输、隧道和任务

```console
remxo put ./app.tar.gz prod-01:/tmp/app.tar.gz
remxo get prod-01:/tmp/app.tar.gz ./app.tar.gz
remxo --overwrite put ./app.tar.gz prod-01:/tmp/app.tar.gz

remxo tunnel start prod-01 --local 15432:127.0.0.1:5432
remxo tunnel list
remxo tunnel stop <tunnel-id>

remxo task start prod-01 -- ./deploy.sh
remxo task list
remxo task logs <task-id>
remxo task stop <task-id>
```

SCP 使用 `scp -s` 强制 SFTP 模式，避免 legacy SCP 的远端 shell 路径展开；旧客户端不支持时明确失败。传输和隧道均经 Broker 做主机策略及审批。隧道默认绑定 `127.0.0.1`，公开绑定要求 `--yes`，动态转发要求审批。

任务只持久于当前 Broker 进程；日志有界并在完成时保存已处理输出。杀掉本地 SSH 不保证远程进程停止，断线后状态可能未知，Remxo 不自动重试写操作。

## JSON 与错误

远程执行返回单个 JSON 文档，含 `schema_version`、`request_id`、`host`、`operation`、`decision`、`status`、`remote_exit_code`、`stdout`、`stderr`、`truncated`、`duration_ms`、`error`。不会混入进度文本。常见错误包括 `vault_locked`、`agent_identity_unavailable`、`host_not_found`、`host_not_allowed`、`policy_denied`、`approval_required`、`host_key_failed`、`timeout`、`output_limit`、`unsupported_shell`、`sudo_password_not_configured`、`insecure_transport`。

远程输出是不可信数据。脱敏和控制字符处理用于降低意外暴露与终端影响，不能识别所有秘密，也不能消除提示词注入语义。

## 当前限制

- 仅 L1；同用户进程、root 或本机失陷不在保护范围。详见 [SECURITY.md](SECURITY.md) 与 [THREAT_MODEL.md](THREAT_MODEL.md)。
- `vault-password` 的非交互 OpenSSH 注入和 `vault-key` 尚未实现；使用 OpenSSH 配置、外部 Agent 或人工交互式 SSH。
- Telnet 数据模型、INSECURE 标记和未确认拒绝已实现，但网络自动化并未实现；Vault 加密不代表 Telnet 网络加密。
- 仅 POSIX 非交互命令组合经过验证；PowerShell、CMD、device/custom 返回明确不支持，绝不套用 POSIX 引用。
- TUI 支持监视、搜索、lock/unlock 和交互 SSH；完整主机增删改向导、TUI 审批/备份操作、设置编辑仍在后续阶段。
- 任务不重启恢复，远程脱离执行、连接复用和完整 SSH 集成未实现；隧道生命周期随 Broker。
- 首版未完成生物识别、Linux Secret Service、TPM、L2 独立 OS 用户 Broker、L3 短期证书与集中授权。

架构见 [ARCHITECTURE.md](ARCHITECTURE.md)。AI 使用约定见 [AGENTS.md](AGENTS.md)。

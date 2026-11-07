# Remxo

**面向人类与 Agent 的远程执行。**

[English](README.md) | [简体中文](README.zh-CN.md)

Remxo 是本地远程服务器清单、编排与执行工具。它复用系统 OpenSSH 客户端，提供加密 Vault、同用户 Broker、策略与一次性审批、面向 AI 的 JSON、元数据审计、基础中英双语 TUI，以及有限实现的文件传输、隧道和后台任务。

> 当前是未经独立安全审计的开发版，安全等级为 **L1**，不是 L2 同用户隔离。它不宣称“生产绝对安全”，也不替代远程账号自身的授权边界。

## 已实现范围

- 严格 TOML v1 配置；主机别名、编号、已登记 IP 解析；默认拒绝未登记 IP。
- 通过 `argv` 启动 OpenSSH 单次命令和交互式 SSH，不调用本地 `sh -c`，不关闭主机密钥检查。
- 四种认证模式：`openssh-config`、`external-agent`、`vault-password` 和 `vault-key`。
- OpenSSH 配置/外部 Agent 非交互认证使用 `BatchMode=yes`；Vault 认证使用 `BatchMode=no`、强制 ASKPASS 和一次密码提示。
- 在 TUI/CLI 中隐藏输入 SSH 密码和私钥口令；Vault 支持从常规文件导入 OpenSSH/RSA/EC/PKCS#8 PEM 私钥，拒绝 symlink，大小不超过 1 MiB。
- Argon2id 派生 KEK、随机 DEK、XChaCha20Poly1305 加密 Vault。Broker 启动即锁定，修改主密码只重新包裹同一个 DEK。
- 独立加密的 `.rxb` 备份、验证、冲突检测、全新目录恢复。备份嵌套携带仍加密的 Vault，不包含明文 DEK、Socket、任务、审批或日志。
- 同用户 loopback Broker、随机 IPC token、受限请求。普通操作结果不包含 Vault；内部认证 RPC 可在 SSH 认证需要时返回单条带类型的 Secret。
- Raw/profile 策略、短期一次性审批、SHA-256 请求摘要、JSONL 元数据审计。
- 输出限长、常见秘密脱敏、控制字符转义，以及精确清除 sudo 密码回显。
- Broker 任务状态/日志/取消、OpenSSH 隧道生命周期基础管理、经 Broker 授权并强制 SFTP 模式的 SCP 上传下载。
- 主 TUI 和主机向导支持英文与简体中文，提供 Hosts、Sessions、Tasks、Approvals、Audit、Backup、Settings 面板。

## 构建与测试

需要稳定版 Rust（MSRV 1.88）、集成测试驱动所需的 Python 3，以及系统 OpenSSH 客户端。

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --test-threads=1
cargo build
```

Linux 下可运行自包含 fake、PTY 与可选 Docker/真实 sshd 测试，无需提供任何真实服务器或凭据：

```console
python3 tests/run_all.py
```

测试分层、清理规则、环境要求和当前验证边界见 [TESTING.md](TESTING.md)。2026-11-08 本次工作副本已通过 Windows 原生 Clippy、全目标 Rust 测试和构建，并在隔离 Instabox 上完整通过 Linux `python3 tests/run_all.py`（fake、5 个 PTY 用例、真实 SSH/SFTP/隧道/任务、Vault 密码/加密私钥执行与 SCP、sudo 和清理）。这些结果不证明 Windows 原生 ACL/真实 Vault 认证、所有 Vault task/tunnel/交互路径、崩溃清理或通用服务端兼容性。

`REMXO_SSH`、`REMXO_SCP` 可指向隔离的测试 fake。真实主机操作时，不要把它们指向不可信程序。

## 快速开始

主密码和备份密码都至少需要 12 字节，只能在交互终端的隐藏提示中输入。短密码会在写入任何配置或 Vault 之前被拒绝。若先前操作留下有效 `config.toml` 但缺少 `vault.json`，重新运行 `init` 会保留该配置并只补齐 Locked Vault，不会重置配置或重新包裹已有 Vault。

```console
# 显式选择 UI 语言；密码通过隐藏提示输入。
remxo init --lang en
# 或选择简体中文：
remxo init --lang zh-CN

# 复用现有 OpenSSH Host 别名，不修改 ~/.ssh/config。
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

未指定 `--lang` 时，TTY 会提供英文/简体中文选择，空回答默认英文。`--json` 或非 TTY 调用默认选择英文，不强制提出语言问题；隐藏主密码输入仍要求交互终端。不含 `settings.language` 的旧配置默认 `en`。恢复已有有效配置时，无论恢复消息选择哪种语言，都会保留配置中保存的语言。主 TUI 和向导遵循该配置语言；这不表示所有 CLI/JSON 错误都已本地化。

target 前的全局参数包括 `--json`、`--no-color`、`--timeout`、`--max-output`、`--cwd`、`--config`、`--verbose`、`--sudo`、`--overwrite`。target 后的参数属于远程命令，例如 `remxo prod-01 ls -l --help` 不会把远程 `--help` 当成本地帮助。

在 `openssh-config`/`external-agent` 模式下，TTY 中无 command 会打开交互式 SSH；非 TTY 无 command 是用法错误。裸 `remxo` 只在真正的交互 TTY 中进入 TUI。子命令名和全局选项位置保留给 CLI，主机别名不应与之冲突。TUI 主机列表中的 **Enter** 路径会为 Vault 管理的交互式 SSH 提供 Broker 认证上下文。

与 OpenSSH 首次连接所需的主机密钥确认应由人类提前完成。Remxo 从不自动添加 `StrictHostKeyChecking=no`、`UserKnownHostsFile=/dev/null` 或 `ForwardAgent=yes`。

## SSH 认证与 Vault 凭据

| Host 的 `auth` 值 | 凭据来源 | OpenSSH 行为 |
| --- | --- | --- |
| `openssh-config` | 现有 OpenSSH 配置及其正常交互登录 | 非交互操作使用 `BatchMode=yes`；交互操作保留正常 OpenSSH 交互。 |
| `external-agent` | 现有外部 SSH Agent | 非交互操作使用 `BatchMode=yes`；所需 Agent 不可用时会失败，不会静默改用其他凭据。 |
| `vault-password` | `<credential-stem>:ssh` 的 `ssh-password` 记录，通常是 `<alias>:ssh` | 使用 `BatchMode=no`、强制 ASKPASS、`NumberOfPasswordPrompts=1`，只允许密码认证，并禁用公钥与 keyboard-interactive 认证。 |
| `vault-key` | `<credential-stem>:key` 的 `ssh-private-key` 记录，通常是 `<alias>:key`；加密私钥还使用 `<stem>:ssh` 保存口令 | 使用受限临时 identity 文件、`IdentitiesOnly=yes`、`IdentityAgent=none`、仅公钥认证、强制 ASKPASS 和一次口令提示。 |

对 `vault-password`，公共 CLI 用 `vault set-ssh-password` 保存 SSH 登录密码。对 `vault-key`，同一命令保存可选私钥口令，`vault import-key` 导入私钥。主机必须事先以匹配的认证模式登记。未加密的 Vault 私钥不需要口令；加密私钥需要正确的 `ssh-password` 记录。

```console
remxo unlock

# 对已登记且 auth = "vault-password" 的主机：
remxo vault set-ssh-password prod-01

# 对已登记且 auth = "vault-key" 的主机：
remxo vault import-key prod-01 --path /path/to/id_ed25519
# 该导入私钥的可选口令：
remxo vault set-ssh-password prod-01
```

私钥路径可以作为选项传入，也可在 TUI 可见字段中输入；它不是私钥内容，也不会持久化到 Host 对象。相对路径会先按调用者的工作目录转换为绝对路径，再交给 Broker，不受 daemon 工作目录变化影响。密码/口令字段隐藏，只显示“entered (hidden)”/“已输入（隐藏）”。导入只接受常规文件，拒绝 symlink、目录和特殊文件，源文件上限为 1 MiB。ASCII 文本 PEM 的第一个私钥标记必须指明 OpenSSH、RSA、EC 或 PKCS#8 格式。这只是结构上的导入校验，并不证明 OpenSSH 能解析或使用该私钥。原文件不会被删除或修改。

exec、task、Broker SCP、交互式 SFTP、由 TUI 启动的交互式 SSH 和 tunnel 共用 `prepare_authentication`。使用 Vault 私钥时，Broker 通过内部认证 RPC 返回私钥，调用方将它写入供 OpenSSH 使用的受限临时文件。临时私钥 guard 会持续到操作/子进程结束，正常 drop 时删除文件。崩溃或强制终止可能留下残余；删除也不等于保证安全擦除。

Vault 密码/私钥认证会把当前 Remxo 可执行文件设为 ASKPASS，由 OpenSSH 用单个 prompt 参数调用，不存在公共 `__askpass` CLI 子命令。`main` 在检测到 `REMXO_ASKPASS_CONFIG` 时选择内部 helper 入口。helper 环境只包含配置路径、目标 alias 和可选的非秘密 pending-Host 元数据。它向 Broker 请求单条带类型的密码/口令，再将值写到 OpenSSH 的 ASKPASS stdout。它拒绝 host-key/yes/no/fingerprint 确认以及 OTP、MFA、硬件 PIN、token 和无法识别的提示。严格 `known_hosts` 处理不会放宽。

普通执行时，Broker 会重新解析登记 Host，以确定预期记录与类型，而不是信任调用方任意指定的秘密名称。未保存向导的连接测试使用显式 pending-Host 上下文；如果 alias 已登记，Broker 会拒绝该路径。内部 RPC 的单 Secret 响应是普通操作结果之外的有意例外，不是通用 Vault 导出接口，也不是 L2 安全边界。

秘密明文必然存在于相关进程内存中，并在认证边界存在于同用户 RPC 数据、ASKPASS stdout 和临时私钥文件中。这些路径不会把秘密值放入 argv、helper 环境变量、主机预览或元数据审计。L1 不能防止恶意同 OS 用户进程接触这些明文。

## 交互式主机向导

缺少连接信息时，CLI 会进入全屏主机添加向导，而不是只报告一个字段错误。此前必须已运行 `remxo init`。

```console
remxo host add
remxo host add prod-01
remxo host add prod-01 --interactive
# 在 Remxo 主 TUI 的 Hosts 页面也可按 a。
```

向导采用连接 → 策略 → 复核流程，支持别名预填、端口/编号检查、环境、平台、全部四种认证模式、raw/approval 策略、可选 sudo、Telnet INSECURE 确认和配置预览。Vault 模式会增加隐藏的 SSH 密码/私钥口令字段和私钥路径字段。焦点使用颜色区分，状态单独显示，窄终端自动收起侧栏；`--no-color` 或 `NO_COLOR` 可关闭该处彩色样式。主 TUI 和向导标签根据 `settings.language` 显示英文或简体中文。

快捷键：

```text
↑ / ↓          移动字段焦点
← / → / Space  切换选项
Enter          下一步、测试连接或保存
Tab / BackTab  移动字段焦点
Backspace      删除一个字符
Delete         清空字段
Esc            取消且不保存 Host
```

凭据导入有意**不是**全事务的 Host 操作。Test 和 Save 都会先把选择的 SSH 密码/口令和/或私钥导入加密 Vault。Test 失败或按 Esc 不保存 Host，但已导入的凭据仍以密文留在 Vault。Save 仅在 SSH 凭据导入成功后写入 Host；直接 Save 不要求此前成功执行过 Test。可选 sudo 在 Host 保存后另行配置，sudo 失败不会回滚 Host。任何秘密值都不会进入预览、Host 对象、argv 或元数据审计。

带完整 `--hostname`/`--ssh-alias` 参数的传统非交互调用继续有效。向导与 `--json` 不兼容，也不会在非 TTY 中启动。连接探针保持严格主机密钥检查并使用上述认证行为，不替代主机授权审查或生产巡检。

UI 布局参考了 Charmbracelet/gum 的分步输入、lazygit 的键盘面板/状态层次和 Rich 的边框及颜色适配理念，核心表单、策略、验证和 Vault 流程均由 Remxo 自身实现。

## 策略与审批

主机支持 `raw_mode = "allow" | "read-only" | "deny"` 和 `approval = "never" | "writes" | "always"`。`read-only` 只允许内置 profile；`deny` 禁止 raw 执行。启发式只用于决定审批便利性，**不是命令安全沙箱**。raw 一旦允许，就意味着远程账号本身的权限。

需要审批时，执行返回 `approval_required` 和 `approval_id`，AI 应停止。人类审查后：

```console
remxo approval list
remxo approval approve <approval-id>
# 在过期前原样重跑同一操作；连接配置、命令/参数或输出限制改变都会形成不同摘要。
```

同用户 approve 只是 L1 便利，恶意同用户 Agent 可以绕过它。

## sudo

```console
remxo unlock
remxo vault set-sudo prod-01
remxo --sudo prod-01 systemctl restart nginx
```

sudo 使用独立的 `sudo-password` Vault 记录，绝不复用 SSH 密码记录。新向导/CLI 登记过程中请求配置 sudo 时，会把 `sudo_credential` 设为 `<alias>:sudo`；旧 Host 及其他没有该字段的 Host 保留裸 `<alias>` sudo 记录查找方式。sudo 密码通过 SSH 标准输入交给远程 `sudo -S`，不进入本地/远程 argv；输出会清除精确的密码回显。`requiretty`、远程 sudoers、PAM 和账号配置仍可能导致 `sudo_not_permitted` 或远程失败。优先在 sudoers 中做精确授权；不要在脚本、日志或 AI 上下文中放密码。

## 加密备份

```console
remxo backup create ./remxo.rxb
remxo backup verify ./remxo.rxb
# 建议使用新的 --config 数据目录验证恢复；现有文件默认拒绝覆盖。
remxo --config /new-dir/config.toml backup restore ./remxo.rxb
```

备份密码与主密码都是隐藏输入，不能通过 CLI 秘密参数传入。恢复后仍使用**原 Vault 主密码**显式 `unlock`；备份密码只保护备份外层。已导入的 SSH 密码、口令、私钥和 sudo 凭据仍位于备份内嵌套的加密 Vault 中。外部 Agent 秘密、平台生物识别以及外部私钥/硬件密钥不会导出到备份。

## 文件传输、隧道和任务

```console
remxo put ./app.tar.gz prod-01:/tmp/app.tar.gz
remxo get prod-01:/tmp/app.tar.gz ./app.tar.gz
remxo --overwrite put ./app.tar.gz prod-01:/tmp/app.tar.gz
remxo sftp prod-01

remxo tunnel start prod-01 --local 15432:127.0.0.1:5432
remxo tunnel list
remxo tunnel stop <tunnel-id>

remxo task start prod-01 -- ./deploy.sh
remxo task list
remxo task logs <task-id>
remxo task stop <task-id>
```

SCP 使用 `scp -s` 强制 SFTP 模式，避免 legacy SCP 的远端 shell 路径展开；旧客户端不支持时明确失败。传输和隧道均经 Broker 做主机策略及审批。隧道默认绑定 `127.0.0.1`，公开绑定要求 `--yes`，动态转发要求审批。Vault 认证也通过共享准备路径覆盖 SFTP 和 tunnel 子进程。

任务只持久于当前 Broker 进程；日志有界并在完成时保存已处理输出。杀掉本地 SSH 不证明远程进程停止，断线后状态可能未知，Remxo 不会自动重试写操作。

## JSON 与错误

远程执行返回单个 JSON 文档，含 `schema_version`、`request_id`、`host`、`operation`、`decision`、`status`、`remote_exit_code`、`stdout`、`stderr`、`truncated`、`duration_ms`、`error`，不会混入进度文本。常见错误包括 `vault_locked`、`authentication_failed`、`agent_identity_unavailable`、`agent_unavailable`、`host_not_found`、`host_not_allowed`、`policy_denied`、`approval_required`、`host_key_failed`、`timeout`、`output_limit`、`unsupported_shell`、`sudo_password_not_configured`、`insecure_transport`。

远程输出是不可信数据。脱敏和控制字符处理用来降低意外暴露与终端影响，但不能识别所有秘密，也不能消除提示词注入语义。

## 当前限制

- 仅 L1；同用户进程、root 或本机失陷不在保护范围。单 Secret 认证 RPC 和明文交接点不构成同用户隔离。详见 [SECURITY.md](SECURITY.md) 与 [THREAT_MODEL.md](THREAT_MODEL.md)。
- Telnet 数据模型、INSECURE 标记和未确认拒绝已实现，但网络自动化尚未实现；Vault 加密不代表 Telnet 网络加密。
- 仅 POSIX 非交互命令组合受支持；PowerShell、CMD、device/custom 返回明确不支持，不套用 POSIX 引用。
- TUI 支持监视、搜索、添加主机、lock/unlock 和交互 SSH；主机编辑/删除向导、TUI 审批/备份操作、设置编辑仍在后续阶段。
- 任务不会在 Broker 重启后恢复；远程脱离执行、连接复用和通用 SSH 服务端兼容性既未全部实现，也未得到证明。
- Windows 原生权限加固和真实 Vault 密码/私钥认证尚未验证。不得把 Unix 临时文件 `0600` 行为宣称为已验证的 Windows ACL 行为或跨平台认证支持。
- 生物识别解锁、Linux Secret Service、TPM、L2 独立 OS 用户 Broker、L3 短期证书与集中授权尚未实现。

架构见 [ARCHITECTURE.md](ARCHITECTURE.md)，安全验证见 [TESTING.md](TESTING.md)，AI 使用与开发约定见 [AGENTS.md](AGENTS.md)。

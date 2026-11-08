# Remxo

**面向人类与 Agent 的远程执行。**

[English](README.md) | [简体中文](README.zh-CN.md)

详细的项目文档与架构文档见 [`docs/README.md`](docs/README.md)；可复用的 AI 运维 Skill 见 [`.opencode/skills/remxo/SKILL.md`](.opencode/skills/remxo/SKILL.md)。

## 快速导航

| 目标 | 命令 |
| --- | --- |
| 安装当前正式版 | `npm install -g remxo` |
| 初始化配置和 Vault | `remxo init --lang zh-CN` |
| 查看已登记主机 | `remxo hosts` |
| 执行只读远程命令 | `remxo --json prod-01 df -hT` |
| 新服务器主机密钥登记 | `remxo host key fetch prod-01` → `remxo host key trust prod-01 --fingerprint SHA256:...` |
| 阅读完整文档 | [`docs/README.md`](docs/README.md) |

Remxo 是本地远程服务器清单、编排与执行工具。它复用系统 OpenSSH 客户端，提供加密 Vault、同用户 Broker、策略与一次性审批、面向 AI 的 JSON、元数据审计、基础中英双语 TUI，以及有限实现的文件传输、隧道和后台任务。

> 当前是未经独立安全审计的开发版，安全等级为 **L1**，不是 L2 同用户隔离。它不宣称“生产绝对安全”，也不替代远程账号自身的授权边界。

## 已实现范围

- 严格 TOML v1 配置；主机别名、编号、已登记 IP 解析；默认拒绝未登记 IP。
- 通过 `argv` 启动 OpenSSH 单次命令和交互式 SSH，不调用本地 `sh -c`，不关闭主机密钥检查。
- 四种认证模式：`openssh-config`、`external-agent`、`vault-password` 和 `vault-key`。
- OpenSSH 配置/外部 Agent 非交互认证使用 `BatchMode=yes`；Vault 认证使用 `BatchMode=no`、强制 ASKPASS 和一次密码提示。
- 在 TUI/CLI 中以 `*` 掩码输入 SSH 密码和私钥口令，支持可见光标编辑；Vault 支持从常规文件导入 OpenSSH/RSA/EC/PKCS#8 PEM 私钥，拒绝 symlink，大小不超过 1 MiB。
- Argon2id 派生 KEK、随机 DEK、XChaCha20Poly1305 加密 Vault。Broker 启动即锁定，修改主密码只重新包裹同一个 DEK。
- 独立加密的 `.rxb` 备份、验证、冲突检测、全新目录恢复。备份嵌套携带仍加密的 Vault，不包含明文 DEK、Socket、任务、审批或日志。
- 同用户 loopback Broker、随机 IPC token、受限请求。普通操作结果不包含 Vault；内部认证 RPC 可在 SSH 认证需要时返回单条带类型的 Secret。
- Raw/profile 策略、短期一次性审批、SHA-256 请求摘要、JSONL 元数据审计。
- 输出限长、常见秘密脱敏、控制字符转义，以及精确清除 sudo 密码回显。
- Broker 任务状态/日志/取消、OpenSSH 隧道生命周期基础管理、经 Broker 授权并强制 SFTP 模式的 SCP 上传下载。
- 主 TUI 和主机向导支持英文与简体中文，提供 Hosts、Sessions、Tasks、Approvals、Audit、Backup、Settings 面板。

## npm 安装与原生二进制分发

发布后的原生安装方式如下：

```console
npm install -g remxo
```

预发布版本改用 `rc` dist-tag：`npm install -g remxo@rc`。

需要 Node.js 18 或更新版本。npm 主包只包含轻量启动器；精确同版本的 optional 平台包携带预编译 Rust 可执行文件。当前打包目标仅包括 Windows x64、Linux x64（glibc），macOS 适配和产物目标在拥有真实 Apple 设备进行验证之前暂停，当前 optional 包有意只覆盖 Windows/Linux。启动器根据 `process.platform`/`process.arch` 选择平台包，校验版本和内嵌二进制，在支持的 Unix 上通过 `execve` 替换 Node，在 Windows 上直接以 argv、`stdio: inherit` 启动子进程。它不使用本地 shell、Node TUI、postinstall 下载、用户侧 Cargo 编译、运行时自动更新，也不会静默回退到 PATH 上任意版本的 Remxo。缺少或错配平台包会明确失败。Alpine/musl 及其他未列出的平台需要独立原生构建与验证，glibc 包不保证能在这些平台运行。

发布产物由 `.github/workflows/npm-release.yml` 在版本 tag 或手动触发时构建并 stage。类似 `v0.1.0` 的 tag 会以 `latest` dist-tag stage 三个包；预发布 tag（如 `v0.1.0-rc3`）则使用 `rc`。需要维护者用 2FA 批准每个 stage 后才会真正公开。包版本与原生 `remxo --version` 必须精确一致。Linux 构建、启动器检查及精确 Linux tarball 安装验收在 `instabox-medium` 上执行，只有不可替代的 Windows 任务消耗 GitHub 原生 runner 额度。本地构建产物暂存方式：

```console
cargo build --release
node scripts/npm/pack.js --platform linux-x64 --artifact target/release/remxo --out target/npm/core
node scripts/npm/pack.js --main --out target/npm/launcher
```

`REMXO_CORE_PATH` 仅用于开发或隔离测试 fake；生产安装通过精确版本的平台包定位二进制，不依赖此覆盖值。

## 构建与测试

需要稳定版 Rust（MSRV 1.88）、集成测试驱动所需的 Python 3，以及系统 OpenSSH 客户端。

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --test-threads=1
cargo build
npm test --prefix npm

Linux 下可运行自包含 fake、PTY 与可选 Docker/真实 sshd 测试，无需提供任何真实服务器或凭据：

```console
python3 tests/run_all.py
```

测试分层、清理规则、环境要求和当前验证边界见 [TESTING.md](TESTING.md)。2026-11-08 本次工作副本已通过 Windows 原生 Clippy、全目标 Rust 测试和构建，并在隔离 Instabox 上完整通过 Linux `python3 tests/run_all.py`（fake、6 个 PTY 用例（含中文数字初始化/中文解锁、掩码、光标主机编辑和保存后 `doctor`）、真实 SSH/SFTP/隧道/任务、Vault 密码/加密私钥执行与 SCP、sudo 和清理）。这些结果不证明 Windows 的所有认证场景、所有 Vault task/tunnel/交互路径、崩溃清理或通用服务端兼容性。

`REMXO_SSH`、`REMXO_SCP` 可指向隔离的测试 fake。真实主机操作时，不要把它们指向不可信程序。

## 快速开始

主密码和备份密码都至少需要 12 字节，只能在交互终端的隐藏提示中输入。短密码会在写入任何配置或 Vault 之前被拒绝。若先前操作留下有效 `config.toml` 但缺少 `vault.json`，重新运行 `init` 会保留该配置并只补齐 Locked Vault，不会重置配置或重新包裹已有 Vault。

```console
# 显式选择 UI 语言；密码输入显示 * 掩码。
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
remxo host edit prod-01
remxo doctor prod-01
remxo prod-01 --profile logs --arg service=nginx --arg lines=100
```

未指定 `--lang` 时，TTY 会提供带编号的语言菜单（`1` 为英文，`2` 为简体中文），空回答默认英文；交互提示仍接受语言名称，而 `--lang` 保持接受 `en|zh-CN`。`--json` 或非 TTY 调用默认选择英文，不强制提出语言问题；显示 `*` 掩码的主密码输入仍要求交互终端。不含 `settings.language` 的旧配置默认 `en`。恢复已有有效配置时，无论恢复消息选择哪种语言，都会保留配置中保存的语言。`unlock` 根据保存的语言显示隐藏输入提示和成功消息。主 TUI 和向导遵循该配置语言；这不表示所有 CLI/JSON 错误都已本地化。

target 前的全局参数包括 `--json`、`--no-color`、`--timeout`、`--max-output`、`--cwd`、`--config`、`--verbose`、`--sudo`、`--overwrite`。target 后的参数属于远程命令，例如 `remxo prod-01 ls -l --help` 不会把远程 `--help` 当成本地帮助。

在 `openssh-config`/`external-agent` 模式下，TTY 中无 command 会打开交互式 SSH；非 TTY 无 command 是用法错误。裸 `remxo` 只在真正的交互 TTY 中进入 TUI。子命令名和全局选项位置保留给 CLI，主机别名不应与之冲突。TUI 主机列表中的 **Enter** 路径会为 Vault 管理的交互式 SSH 提供 Broker 认证上下文。

与 OpenSSH 首次连接所需的主机密钥确认应由人类提前完成。Remxo 从不自动添加 `StrictHostKeyChecking=no`、`UserKnownHostsFile=/dev/null` 或 `ForwardAgent=yes`。可先用 `remxo host key fetch <alias>` 查看指纹，人工核对后用 `remxo host key trust <alias> --fingerprint SHA256:...` 登记。

`remxo doctor [alias]` 先检查本地配置；指定 alias 时，才按用户显式操作，通过同一套认证准备对保存的 Host 执行有界的 POSIX `true` 握手。它报告连接结果，不放宽主机密钥检查，不执行写入命令，也不会在后台自动监视连接。

## Vault 解锁与终端生命周期

`unlock` 解锁的是**本地 Broker 进程内存中的 VaultSession**，不是某一个 PowerShell 窗口。后续其它终端的 CLI 会复用该 Broker 的内存会话，`vault.json` 始终保持密文。关闭已经结束的命令或终端，不会因此自动清除 DEK。第二个终端应该通过 `remxo status` 查看 `vault_locked` 和 `broker_running`。

Windows 使用 `DETACHED_PROCESS` 和 `CREATE_NEW_PROCESS_GROUP` 启动 Broker，使后台 Broker 不再依附启动它的控制台进程组。ACL PowerShell、非交互 SSH/SCP/tunnel 进程分别使用 `CREATE_NO_WINDOW`，避免额外弹出可见控制台窗口；真正的交互式 SSH/SFTP 保持正常终端行为。Unix 在 Tokio 创建线程前完成 daemon 分离，实现对应生命周期。Unix 在 Tokio 创建线程前完成 daemon 分离，实现对应生命周期。Broker 退出、锁定、崩溃或系统重启时，内存中的解锁状态必然丢失。`remxo lock` 只锁定会话；`remxo lock --stop-broker` 则额外请求 Broker 正常退出，用于升级或明确重启。其它 `--config` 目录或其它系统用户拥有独立的 Vault/Broker 生命周期，不会共用同一解锁状态。环境中没有明文主密码，也没有保存明文会话的文件。

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

私钥路径可以作为选项传入，也可在 TUI 可见字段中输入；它不是私钥内容，也不会持久化到 Host 对象。相对路径会先按调用者的工作目录转换为绝对路径，再交给 Broker，不受 daemon 工作目录变化影响。密码/口令字段只显示 `*` 掩码，不显示秘密值，也不会进入表单预览。导入只接受常规文件，拒绝 symlink、目录和特殊文件，源文件上限为 1 MiB。ASCII 文本 PEM 的第一个私钥标记必须指明 OpenSSH、RSA、EC 或 PKCS#8 格式。这只是结构上的导入校验，并不证明 OpenSSH 能解析或使用该私钥。原文件不会被删除或修改。

导入私钥不会自动给服务器授权对应公钥。请选择私钥文件而不是 `.pub`，加密私钥需配置口令，使用正确的远端用户名，并确保对应公钥已写入该账号的 `authorized_keys` 或等价服务端授权配置。Remxo 不会自动上传公钥，也不能在没有真实认证尝试的情况下断言服务端已授权。

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
# 在主 TUI 的 Hosts 页面按 a。
remxo host edit prod-01
# 已登记主机也可在 Hosts 页面按 e，按 t 显式测试当前保存的连接。
```

向导采用连接 → 策略 → 复核流程，支持别名预填、端口/编号检查、环境、平台、全部四种认证模式、raw/approval 策略、可选 sudo、Telnet INSECURE 确认和配置预览。Vault 模式的 SSH 密码/私钥口令只显示 `*` 掩码，私钥路径可见编辑。文本字段有真实光标，支持左右移动、Home/End、中间插入、Backspace/Delete、括号粘贴以及 Ctrl+U/Ctrl+W/Ctrl+L；粘贴私钥路径时，成对包裹路径的单引号或双引号会在导入时移除，其他秘密输入不做这种处理。焦点使用颜色区分，状态单独显示，窄终端自动收起侧栏；`--no-color` 或 `NO_COLOR` 可关闭该处彩色样式。主 TUI 和向导标签根据 `settings.language` 显示英文或简体中文。

快捷键：

```text
↑ / ↓          移动字段焦点
← / →          移动光标或切换选项
Home / End     移动到文本字段开头/结尾
粘贴           在光标处插入（bracketed paste）
Backspace      删除光标前一个字符
Delete         删除光标处字符
Ctrl+U/W/L     删至开头 / 删除前一个词 / 清空字段
Enter          执行当前焦点操作：获取主机密钥、信任主机密钥、测试、保存、保存并测试、保存并退出或退出。长时间操作会显示旋转指示、耗时和重试次数。主 TUI 可按 q、Esc 或 Ctrl+C 退出；顶部页面切换有短时高亮。
Tab / BackTab  移动字段焦点
Esc            询问是否保存：S 保存并退出，Enter 不保存退出，Esc 取消
```

凭据导入有意**不是**全事务的 Host 操作。新建 Host 时，Test 会先把选择的 SSH 密码/口令和/或私钥导入加密 Vault。Test 失败不保存 Host，但已导入的凭据仍以密文留在 Vault。Save 仅在 SSH 凭据导入成功后写入 Host；直接 Save 不要求此前成功执行过 Test。`Save` 保存后留在向导，`Save & exit` 保存后退出，`Exit` 会询问是否保存。可选 sudo 在 Host 保存后另行配置，sudo 失败不会回滚 Host。任何秘密值都不会进入预览、Host 对象、argv 或元数据审计。

`host edit` 固定 alias，并通过 expected-Host 检查防止旧表单静默覆盖更新后的配置。仅修改非秘密字段会沿用现有凭据，不要求重新输入。显式更换凭据或认证方式会使用带版本的 credential stem，因此 Host 保存失败不会在配置引用切换前替换旧 Host 正在使用的秘密。旧凭据仍以密文保留，不承诺配置与 Vault 的整体回滚，也不自动安全删除。保存并测试会先写入编辑后的 Host，再按正式登记 Host 的连接测试路径执行；已登记 alias 不使用 pending Host。测试失败不会回滚已经保存的编辑。

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

备份密码与主密码只显示 `*` 掩码，不能通过 CLI 秘密参数传入。恢复后仍使用**原 Vault 主密码**显式 `unlock`；备份密码只保护备份外层。已导入的 SSH 密码、口令、私钥和 sudo 凭据仍位于备份内嵌套的加密 Vault 中。外部 Agent 秘密、平台生物识别以及外部私钥/硬件密钥不会导出到备份。

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
- TUI 支持监视、搜索、添加/编辑主机、显式连接测试、lock/unlock 和交互 SSH；删除向导、TUI 审批/备份操作仍在后续阶段。设置支持语言、超时和输出上限修改，并原子保存配置。
- 任务不会在 Broker 重启后恢复；远程脱离执行、连接复用和通用 SSH 服务端兼容性既未全部实现，也未得到证明。
- Windows 已有原生 ACE 专项验证，证明临时私钥仅授权当前用户，并验证第一进程退出后第二客户端仍复用解锁 Broker。真实密码认证、完整 ConPTY 场景、崩溃清理和所有 Vault operation 变种仍未全部验证；不得把 Unix `0600` 或 Linux 结果外推为跨平台认证保证。
- 生物识别解锁、Linux Secret Service、TPM、L2 独立 OS 用户 Broker、L3 短期证书与集中授权尚未实现。

架构见 [ARCHITECTURE.md](ARCHITECTURE.md)，安全验证见 [TESTING.md](TESTING.md)，AI 使用与开发约定见 [AGENTS.md](AGENTS.md)。

# 系统架构

Remxo 是一个单 Cargo 包、一个 `remxo` 二进制，以及每个数据目录一个长生命周期本地 Broker 的架构。CLI、TUI 和 AI 调用共享同一套主机解析、策略、Vault、审批、传输和审计路径，避免不同入口持有不同的安全语义。

## 顶层组件

```text
人类 / AI Agent / TUI
        │
        │  本地进程内 RPC（同一 OS 用户）
        ▼
    remxo CLI（入口）
        │
        ▼
    Broker（每个数据目录一个）
        ├─ Config / target 解析
        ├─ Policy / profile / 审批
        ├─ VaultSession（解锁后持有 DEK）
        ├─ TaskManager / TunnelManager
        ├─ Execution / Transfer 编排
        └─ AuditLog
        │
        ▼
    OpensshTransport（argv，本地 shell 无关）
        ├─ ssh         一次性命令 / 交互
        ├─ scp -s      Broker 授权的上传下载
        ├─ sftp        交互式文件操作
        └─ ASKPASS     当前 remxo 可执行文件 + 单条 prompt
```

关键约束：

- Node.js 不参与 Vault、Broker、TUI 或认证决策；npm 只是启动路径。
- OpenSSH 负责 SSH 协议、`known_hosts`、认证转发、SFTP 与本地端口转发。
- Remxo 负责本地主机清单、凭据保管边界、策略、审批、审计元数据和受管临时文件生命周期。
- CLI 不直接读写 Vault 密文内容；Vault 会话由 Broker 持有。

## 进程模型与数据根

`--config <PATH>` 指向 `config.toml`，其父目录是数据根：

```text
<data-root>/config.toml
<data-root>/vault.json
<data-root>/broker.json
<data-root>/audit.jsonl
<data-root>/tasks.json      # 路径定义；当前 TaskManager 不据此持久化任务
<data-root>/runtime/...     # Vault 私钥的受管临时 identity 文件
```

不同数据根之间是彼此独立的生命周期：配置、Vault、Broker endpoint、解锁状态和运行时状态都不共享。同一真实环境应始终使用同一数据根，测试 fixture 应使用独立临时目录。

### Broker 生命周期

Broker 在首次需要连接时自动启动，并在客户端退出后继续存活，使同一终端之后的调用可以复用解锁后的 Vault 会话。

- Unix：`__broker-daemon` 在 Tokio 创建 worker 线程前完成 daemon 化，避免 `unlock` 的 PTY 终端被 Broker 生命周期牵连。
- Windows：使用 `DETACHED_PROCESS` 和 `CREATE_NEW_PROCESS_GROUP`，使关闭启动它的控制台进程组不会直接终结后台 Broker。
- 非交互子进程：ACL PowerShell 辅助进程、被捕获的 SSH/SCP 进程和隧道进程单独使用 `CREATE_NO_WINDOW`，避免分配可见控制台窗口。Windows 会忽略与 `DETACHED_PROCESS` 组合的 `CREATE_NO_WINDOW`，因此每个后台子进程单独设置。
- 交互式 SSH/SFTP 保留继承终端，不套用上述隐藏控制台处理。

`__broker` 是隐藏的前台 Broker 入口，主要服务于测试与进程组生命周期管理；正常 CLI 不应手动启动它。

### 内部入口选择

`main` 在进入 clap 之前只精确识别两类内部形态：

```text
remxo __broker-daemon
remxo --config <PATH> __broker-daemon
```

当 `REMXO_ASKPASS_CONFIG` 存在时，`main` 进入 ASKPASS 内部实现，并只接收 OpenSSH 提供的一条 prompt。公开命令集中没有 `__askpass` 子命令，AI 和脚本也不应伪造这些内部环境上下文。

## 模块边界

| 模块 | 职责 |
| --- | --- |
| `main.rs` | clap 前的内部入口选择；Unix daemon 化 |
| `cli.rs` | 公共 CLI 契约、隐藏密码提示、profile 参数解析、JSON 输出、ASKPASS prompt 分类、本地化消息 |
| `config.rs` | 严格 TOML schema、Host/Settings 模型、目标解析、语言持久化、`AppPaths` |
| `store.rs` | 私有目录/文件限制、原子写入、Windows ACL |
| `vault.rs` | Argon2id 派生 KEK、随机 DEK、XChaCha20Poly1305 包裹、凭据类型检查、显式锁定 |
| `credential.rs` | 私钥导入边界、受管临时私钥文件、凭据记录名 |
| `policy.rs` | 固定 profile 生成、raw-mode 矩阵、审批启发式 |
| `approval.rs` | 过期、摘要绑定、单次消费的内存审批 |
| `host.rs` | CLI 与表单共享的添加/编辑、原子保存、expected-Host 陈旧检查 |
| `broker.rs` | RPC 分发、target 重解析、Vault 操作、执行/传输/任务/隧道准备、审计、生命周期 |
| `task.rs` | 任务状态机、日志缓冲、取消 |
| `tunnel.rs` | forward 解析、OpenSSH 就绪判定、子进程生命周期 |
| `transfer.rs` | 远端路径解析、上传/下载、`scp -s`、交互式 SFTP |
| `shell.rs` | POSIX 命令/cwd/sudo 组合 |
| `transport/` | `Transport` trait、能力报告、有界进程 I/O、认证准备、ASKPASS 环境、Telnet 边界 |
| `output.rs` | sudo 密码精确清除、控制字符处理、UTF-8 安全截断 |
| `redact.rs` | 常见秘密与控制序列处理；远端文本始终视为不可信内容 |
| `audit.rs` | JSONL 元数据事件与请求摘要 |
| `backup.rs` | RXB1 独立加密备份、验证、恢复 |
| `tui.rs` / `tui_wizard.rs` | 双语面板、搜索、主机添加/编辑表单 |
| `process.rs` | Windows 后台非交互子进程的 `CREATE_NO_WINDOW` 辅助 |
| `i18n.rs` | 中英文人类消息；机器 JSON 码稳定 |
| `text_input.rs` / `masked_prompt.rs` | Unicode 安全编辑、`*` 掩码与隐藏输入 |

## 主机目标解析

`resolve_target` 顺序固定：

1. 精确 alias。
2. 可解析为 `u32` 时匹配 `Host.number`。
3. 可解析为 IP 时：
   - 先匹配已登记 `hostname`；
   - 未登记且 `allow_ad_hoc=true` 才合成临时 SSH Host；
   - 否则返回 `host_not_allowed`。
4. 其他返回 `host_not_found`。

合成 ad-hoc Host 的 environment 固定为 `"ad-hoc"`，仍执行 raw_mode、approval、shell 与认证校验。已登记 IP 优先于 ad-hoc 合成。

## 执行链路

一次性 exec、profile 和 task 共享同一准备路径：

```text
resolve target
  → 构造 raw/profile script
  → 校验 transport / shell / auth
  → 组合 cwd
  → policy.evaluate 决策
  → request_digest
  → approvals.require
  → sudo 凭据准备
  → AuthenticationContext
  → prepare_authentication
  → spawn 本地 OpenSSH（argv）
  → 有界读取 stdout/stderr
  → process_with_secrets / sanitize / UTF-8 截断
  → OperationReport + audit
```

要点：

- 命令与目标解析都在 Broker 内重新读取当前配置，不信任客户端传递的过期 Host 结构。
- profile 使用固定模板和类型化参数，不构成任意安全模板语言。
- 审批摘要包含目标 Host、operation、脚本、sudo、timeout 和 max_output；任一项变化都会要求新的审批。
- 本地非交互启动 OpenSSH/scp/sftp 使用 argv，不经过本地 `sh -c`。
- 远端非零退出不是连接错误；CLI 本地成功条件是 `status=="success"` 且 `remote_exit_code==0`。
- timeout/cancel 只表示本地 OpenSSH 被停止，不证明远端进程状态。

## 命令组合语义

| 形式 | 含义 |
| --- | --- |
| `remxo <target> cmd arg1 arg2` | 多参数逐个 POSIX 单引号引用后空格连接 |
| `remxo <target> 'cd /srv && git status'` | 单个字符串按远端 shell 脚本处理 |
| `remxo --cwd /srv <target> ls` | `cd '<cwd>' && ('ls')` |
| `remxo --sudo <target> cmd` | `sudo -S -p '' -- /bin/sh -c '<cmd>'` |
| `remxo <target> sudo cmd` | 与 `--sudo` 等价的快捷形式 |

远端 shell 与账户权限仍是最终执行边界；引用保护的是“远程脚本被重新解释为多个命令”，不是保证脚本本身没有副作用。

## 认证架构

### 外部 OpenSSH 配置与 Agent

- `openssh-config`：连接选择和登录方式交给用户 OpenSSH 配置。
- `external-agent`：签名能力由外部 Agent 提供；不可用时显式失败。
- 非交互执行、SCP、隧道使用 `BatchMode=yes`。
- 交互式 SSH/SFTP 保留正常 OpenSSH 交互。
- 不会自动添加 `StrictHostKeyChecking=no`、`UserKnownHostsFile=/dev/null` 或 `ForwardAgent=yes`。

### Vault 密码

- Host 使用 `<credential-or-alias>:ssh` 的 `ssh-password`。
- 强制 `BatchMode=no`、`SSH_ASKPASS_REQUIRE=force`、`NumberOfPasswordPrompts=1`。
- 只允许密码认证，禁用公钥与 keyboard-interactive。
- ASKPASS 只响应 password/passphrase 类提示。

### Vault 私钥

- Host 使用 `<credential-or-alias>:key` 的 `ssh-private-key`；加密私钥的可选口令保存在 `<stem>:ssh`。
- `prepare_authentication` 向 Broker 请求单条带类型私钥。
- 私钥写入 `<data-root>/runtime` 下受管临时文件，guard 覆盖子进程或隧道生命周期。
- OpenSSH 侧使用 `-i <临时文件>`、`IdentitiesOnly=yes`、`IdentityAgent=none`，仅公钥认证。

### ASKPASS 数据流

```text
OpenSSH 需要口令
  → 启动当前 remxo executable，参数只有一条 prompt
  → main 看到 REMXO_ASKPASS_CONFIG，进入内部 helper
  → helper 只接受 password/passphrase prompt
  → Broker 重新解析登记 Host，选择预期记录与类型
  → 返回单条 ssh-password
  → helper 只把值写向 ASKPASS stdout
```

ASKPASS 环境只包含配置路径、目标 alias 和可选非秘密 pending Host 元数据。口令、私钥、主密码和 DEK 不会进入 argv 或环境变量。host-key、yes/no、fingerprint、OTP、MFA、PIN、token 和未知提示一律拒绝。

## 策略与审批

### raw mode

| 操作 | `allow` | `read-only` | `deny` |
| --- | --- | --- | --- |
| raw exec | 继续审批判断 | `policy_denied` | `policy_denied` |
| 内置 profile | 继续审批判断 | 继续审批判断 | 继续审批判断 |
| put | 继续审批判断 | `policy_denied` | `policy_denied` |
| get | 继续审批判断 | 继续审批判断 | `policy_denied` |
| tunnel start | 继续审批判断 | `policy_denied` | `policy_denied` |

交互式 SSH/SFTP 与 tunnel/exec 的 Broker 授权函数不同，不能把该矩阵推广到所有交互路径。

### approval

| 模式 | exec/profile | put/get | tunnel |
| --- | --- | --- | --- |
| `never` | 不要求一次性审批 | 不额外要求 | local/remote 不额外要求；dynamic 仍要求 |
| `writes` | 非“明确读取”时要求 | 上传或 overwrite 时要求 | local/remote 不额外要求；dynamic 仍要求 |
| `always` | 总是要求 | 上传和下载都要求 | local/remote 要求；dynamic 也要求 |

sudo 总是要求一次性审批。`is_unambiguous_read` 是白名单和元字符启发式，不是命令安全模型。

### 审批生命周期

`Approval` 保存 host、operation、request_digest、created/expires、approved、used。首次要求时创建 5 分钟有效期的一次性请求；同一未过期且未消费请求复用 id；`approval approve` 只标记批准，不执行操作；执行时消费一次；Broker 重启后内存审批清空。

## 任务、传输、隧道

### 任务

任务由 `TaskManager` 持有，初始返回 `pending`，随后转 `running`。终态映射：

- cancellation 已触发 → `cancelled`；
- `timeout` → `timed_out`；
- 其他 error → `failed`；
- 无 error 且报告 success → `succeeded`；
- 无 error 但远端非零 → `failed`。

日志是任务结束时保存的报告输出，不是实时流；任务状态只属于当前 Broker 进程。

### 传输

- put 默认远端存在即 `policy_denied`；存在检查通过后才启动 `scp -s`。
- get 默认本地存在即 `policy_denied`。
- `--overwrite` 或 `settings.allow_overwrite=true` 改变有效 overwrite 状态。
- transfer digest 使用 alias、Host、操作方向、本地路径、远端路径和 overwrite，不包含 timeout/max_output。

### 隧道

forward 语法为 `[bind:]listen_port:remote_host:remote_port`，省略 bind 时使用 `127.0.0.1`。dynamic 使用 `127.0.0.1:<port>`。

- 非 loopback bind 需要 `--yes`；`--yes` 不代替一次性审批。
- dynamic 总是要求一次性审批。
- 就绪判定等待 `Entering interactive session.` 并确认子进程仍存活；总上限 10 秒。
- 失败/超时会 kill 并 reap 本地 OpenSSH，不重试。
- `tunnel list` 清理已退出子进程记录；stop 只影响本地隧道生命周期。

## 输出与审计

OpenSSH 子进程 stdout/stderr 分别有界读取；exec 的原始读取上限为 `max_output * 4`，最高 64 MiB。原始截断返回 `output_limit`。处理后输出依次完成 sudo 密码精确替换、控制字符处理、UTF-8 安全截断。`truncated` 表示处理后截断，不等于原始读取截断。

审计事件包含 request_id、host、operation、request_digest、decision、approval_id、status、exit_code、duration_ms、truncated、error、transport 等元数据。默认不记录完整 stdout/stderr 或凭据值；远端输出仍然不可信。

## Vault 与备份

Vault 采用两层密钥：Argon2id 从主密码派生 KEK，随机 32 字节 DEK 加密记录，DEK 再由 KEK 包裹。修改主密码只重新包裹同一 DEK，不重加密全部记录数据。解锁后 DEK 保存在 Broker 内存；磁盘上不存在明文 DEK 或凭据。

`.rxb` 备份使用独立备份密码和独立 KDF/AEAD，payload 包含原始配置和仍然加密的 VaultFile。备份不含运行时任务、审批、socket、审计日志或解锁状态。恢复仍要求原 Vault 主密码。

## npm 原生启动

npm 主包只包含 Node 启动器；平台包按 `process.platform`/`process.arch` 解析。启动器校验主包与平台包版本一致、manifest 的 os/cpu/libc 匹配、vendored 二进制存在且可执行，并解析到真实路径。Unix 使用 `execve` 以原生二进制为 argv0；Windows 使用无本地 shell 的 argv 子进程。缺包、错版本、目标不符都明确失败，不静默从 PATH 选取另一个可执行文件。

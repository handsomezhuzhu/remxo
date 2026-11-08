# 命令参考

所有全局参数都应放在子命令或 target 之前。target 之后的参数属于远端命令，不会被 Remxo 解释为本地选项。

```powershell
remxo [GLOBAL_OPTIONS] <COMMAND>
remxo [GLOBAL_OPTIONS] <TARGET> [REMOTE_ARGUMENTS...]
```

## 全局参数

| 参数 | 值/行为 |
| --- | --- |
| `--json` | 分发层成功结果输出 JSON；分发层错误包装为 `{"error":{...}}` |
| `--no-color` | 关闭 TUI/向导着色；`NO_COLOR` 环境变量也有同样效果 |
| `--timeout <DURATION>` | `500ms`、`30s`、`5m`、`1h`；向上取整为秒 |
| `--max-output <N>` | 覆盖 `settings.max_output`；Broker 对 0 归一为 1 |
| `--cwd <PATH>` | exec/task 远端工作目录，要求 POSIX shell |
| `--config <PATH>` | 指定 `config.toml`，其父目录即数据根 |
| `--verbose` | 被 clap 接收；文档不据此承诺特定调试输出 |
| `--sudo` | exec/task 使用独立 sudo 凭据 |
| `--overwrite` | put/get 允许覆盖 |
| `-h`、`--help` | 帮助 |
| `-V`、`--version` | 版本 |

适用范围：

- `--timeout`、`--max-output`：exec/task/put/get；
- `--cwd`、`--sudo`：exec/task；
- `--overwrite`：put/get；
- tunnel 不使用这些全局参数；OpenSSH `ConnectTimeout` 固定 30 秒，启动就绪等待固定 10 秒。

无子命令时：

- stdin/stdout 都是 TTY：进入主 TUI；
- 非 TTY：用法错误，不读取 stdin 中的命令。

## 初始化、状态与锁定

```powershell
remxo init [--lang en|zh-CN]
remxo status
remxo unlock
remxo lock [--stop-broker]
remxo tui
remxo doctor [TARGET]
remxo hosts
```

- `init --lang zh-CN` 显式选择语言；交互 TTY 无参数时可用编号 `1`/`2` 选择，空输入默认英文。
- 主密码与备份密码至少 12 字节，只通过隐藏提示输入。
- `doctor` 不带 alias 检查本地配置与 OpenSSH；带 alias 时对该 Host 执行有界 `true` 连接测试。
- `lock` 只锁定 Vault 会话；`--stop-broker` 额外请求 Broker 关闭。

## 主机管理

```powershell
remxo host add [ALIAS] [OPTIONS]
remxo host edit <ALIAS>
remxo host remove <ALIAS> --yes
```

`host add` 参数：

| 参数 | 说明 |
| --- | --- |
| `--interactive` | 强制向导 |
| `--hostname <HOSTNAME>` | 直接地址 |
| `--ssh-alias <ALIAS>` | 复用 OpenSSH Host alias |
| `--number <N>` | 唯一正整数编号 |
| `--transport ssh\|telnet` | 默认 `ssh` |
| `--port <1-65535>` | SSH 默认 22；Telnet CLI 默认 23 |
| `--username <USERNAME>` | 远端用户名 |
| `--platform linux\|macos\|windows\|network-device\|other` | 默认 `linux` |
| `--shell posix\|powershell\|cmd\|device\|custom` | 默认 `posix` |
| `--auth openssh-config\|external-agent\|vault-password\|vault-key` | 默认 `openssh-config` |
| `--environment <STRING>` | 元数据 |
| `--raw-mode allow\|read-only\|deny` | 默认 `allow` |
| `--approval never\|writes\|always` | 默认 `writes` |
| `--tags <A,B,C>` | 逗号分隔 |
| `--ack-insecure` | Telnet 明文确认 |
| `--configure-sudo` | Host 保存后配置 sudo |

规则：

- `--interactive`、缺少 alias 或缺少连接地址时进入向导；
- 自动化模式必须同时提供 alias 和连接地址；
- 向导需要 TTY，不能与 `--json` 组合；
- CLI flags 模式可保存 Vault 认证 Host，但 SSH 密码/私钥仍需后续 `vault set-ssh-password` / `vault import-key`；
- `host edit` 和 `host remove` 只按精确 alias 处理；
- `host remove` 只改配置，不删除 Vault 凭据；旧配置先备份。

## 主机密钥 onboarding

```powershell
remxo host key status <TARGET>
remxo host key fetch <TARGET>
remxo host key trust <TARGET> [--fingerprint SHA256:...]
remxo host key list
remxo host key remove <TARGET> --yes
```

- `fetch` 只从网络侧读取服务器主机密钥并显示指纹，不写入 known_hosts。
- `trust` 交互模式必须人工输入 `TRUST`；非交互模式必须提供 `--fingerprint`，且与实际 fetch 到的指纹一致。
- `trust` 只写入 OpenSSH `known_hosts`，不会添加 `StrictHostKeyChecking=no` 或其他绕过选项。
- `remove` 需要 `--yes`，只移除该目标对应的 known_hosts 条目。

## Vault 凭据

```powershell
remxo vault change-password
remxo vault set-sudo <HOST>
remxo vault set-ssh-password <HOST>
remxo vault import-key <HOST> [--path <FILE>]
```

- `change-password` 用旧密码解包同一 DEK，再用新密码重新包裹，保留加密记录。
- `set-ssh-password` 只接受 `vault-password` 或 `vault-key` Host。
- `import-key` 只接受 `vault-key` Host；不提供 `--path` 时提示输入路径。
- 所有秘密输入只通过隐藏终端提示，不能作为 CLI 参数。

## 一次性执行

```powershell
# TTY 中无远端命令：交互式 SSH
remxo <TARGET>

# 单次命令
remxo <TARGET> <COMMAND> [ARG...]

# sudo
remxo --sudo <TARGET> <COMMAND> [ARG...]
remxo <TARGET> sudo <COMMAND> [ARG...]

# profile
remxo <TARGET> --profile <NAME> [--arg KEY=VALUE ...]

# JSON
remxo --json <TARGET> df -hT

# 远端工作目录
remxo --cwd /var/www <TARGET> ls -la

# 单字符串脚本
remxo --json <TARGET> 'cd /var/www && git status'
```

命令组合规则：

- 多个参数逐个 POSIX 单引号引用；
- 单个字符串按远端脚本处理；
- 空命令或含 NUL 参数拒绝；
- 非 POSIX shell 不套用上述组合。

无命令的交互路径要求 stdin/stdout TTY，不能与 `--json` 组合，并返回交互 OpenSSH 退出码而不是 `OperationReport`。

## 后台任务

```powershell
remxo task start <TARGET> -- <COMMAND>...
remxo task list
remxo task status <TASK_ID>
remxo task logs <TASK_ID>
remxo task stop <TASK_ID>
```

示例：

```powershell
remxo task start prod-01 -- ./deploy.sh
remxo --json --timeout 30s task start prod-01 -- "sleep 30"
```

- 启动前完成 target、脚本、审批和 sudo 准备；准备失败不产生任务。
- 启动返回初始 `pending`。
- `task stop` 对已完成任务返回 `invalid_argument`。
- 日志不是实时流；任务状态只存在于当前 Broker 进程。
- 本地停止不证明远端动作未发生。

## 文件传输

```powershell
remxo put <LOCAL> <TARGET>:<REMOTE_PATH>
remxo get <TARGET>:<REMOTE_PATH> <LOCAL>
remxo sftp <TARGET>
```

IPv6 远端路径使用 `[IPv6]:/remote/path`。

- put 默认远端存在即拒绝；get 默认本地存在即拒绝。
- `--overwrite` 或 `settings.allow_overwrite=true` 改变有效覆盖状态。
- SCP 使用 `scp -s` 强制 SFTP 模式。
- `sftp` 是交互路径，要求 TTY，返回子进程退出码。

## 隧道

```powershell
remxo tunnel start <TARGET> --local 15432:127.0.0.1:5432
remxo tunnel start <TARGET> --remote [bind:]listen:remote_host:remote_port
remxo tunnel start <TARGET> --dynamic 1080 [--yes]
remxo tunnel list
remxo tunnel stop <TUNNEL_ID>
```

- 三种模式必须恰好选择一种。
- 省略 bind 时规范化为 `127.0.0.1`。
- 非 loopback bind 需要 `--yes`；`--yes` 不代替审批。
- dynamic 总是要求一次性审批。
- 就绪判定等待 `Entering interactive session.` 并确认子进程存活；总上限 10 秒。

## 审批

```powershell
remxo approval list
remxo approval approve <APPROVAL_ID>
```

- 首次要求时创建 5 分钟有效期的一次性请求。
- `approve` 只标记批准，不执行原操作。
- 批准后必须原样重跑操作。
- 批准后只能消费一次；再次执行需要新审批。
- Agent 收到 `approval_required` 必须停止并交人类，不得自行 approve 或改命令复用摘要。

## 备份

```powershell
remxo backup create <PATH>
remxo backup verify <PATH>
remxo backup restore <PATH> [--force]
```

- `create` 目标已存在时拒绝覆盖。
- `verify` 只解密验证，不恢复文件。
- `restore` 默认在 config 或 Vault 已存在时拒绝。
- `--force` 先分别备份已存在文件，再写 config/Vault。
- 恢复后仍需原 Vault 主密码 `unlock`；外层备份密码不等于 Vault 主密码。

## 内部入口

以下入口属于内部实现，不是公共自动化接口：

- `__broker`：隐藏前台 Broker 子命令；
- `__broker-daemon`：clap 前识别的后台 Broker 形态；
- `REMXO_ASKPASS_CONFIG` 选择 ASKPASS 内部入口。

公共命令集中没有 `__askpass` 子命令。脚本和 AI 不应构造、读取或转储这些内部上下文。

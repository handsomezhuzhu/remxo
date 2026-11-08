# Remxo 项目文档

Remxo 是面向人类与 AI Agent 的本地服务器清单、连接管理与远程执行工具。它把主机登记、凭据保管、命令策略、人工审批、OpenSSH 调用、任务管理、文件传输、隧道和审计组织在同一套本地工作流中。

## 从哪个入口开始

| 需求 | 推荐入口 | 深入阅读 |
| --- | --- | --- |
| 安装或构建 Remxo | `remxo doctor` | [安装、构建与分发](installation.md) |
| 初始化本地环境 | `remxo init --lang zh-CN` | [初始化指南](#初始化与首次连接) |
| 查看登记主机 | `remxo hosts` | [配置、主机与策略](configuration.md) |
| 人类执行远程操作 | 交互终端中的 `remxo <目标> <命令>` | [命令参考](cli.md)、[运维操作指南](operations.md) |
| AI 执行远程操作 | `remxo --json <目标> <命令>` | [AI 接入与自动化](ai-integration.md) |
| 查询本机状态 | `remxo --json status` | [Vault 与 Broker](architecture.md#broker-与-unlock-生命周期) |
| 添加、修改主机 | `remxo host add`、`remxo host edit` | [主机向导读取与保存顺序](configuration.md#主机添加编辑与保存顺序) |
| 申请高风险操作 | `remxo approval list` | [审批规则](configuration.md#审批模型) |
| 加密备份和恢复 | `remxo backup create`、`verify`、`restore` | [备份与恢复](cli.md#备份) |
| 了解核心组成和调用时序 | 本地 Broker + OpenSSH | [系统架构](architecture.md) |
| 了解凭据和信任边界 | L1 同用户安全模型 | [安全模型](security.md) |

## 核心工作方式

```text
人类 / AI Agent
       │
       ▼
   remxo CLI ───────────────► TUI、主机向导
       │
       ▼
   本地 Broker（每个数据目录一份）
       ├─ 解析主机与认证模式
       ├─ 应用 raw/profile 策略和一次性审批
       ├─ 管理解锁后的 Vault 会话
       ├─ 执行任务、传输与隧道
       └─ 处理输出、审计和返回报告
       │
       ▼
   系统 OpenSSH（ssh / scp -s / sftp）
       │
       ▼
   已登记的远程服务器
```

Remxo 不把 Node.js 用作 Vault、Broker 或 TUI 运行时。npm 是原生 Rust 二进制的分发入口；SSH 协议、主机密钥校验和实际的数据传输由系统 OpenSSH 负责。

## 功能地图

### 主机清单

每台登记主机有固定 alias，并可有唯一数字编号。它还可以保存 SSH 地址、端口、用户名、平台、远端 shell、认证模式、环境标签、原始命令策略和 sudo 记录名称。目标解析优先级为 alias、编号、登记 IP；临时 IP 访问由 `allow_ad_hoc` 单独控制。

### 凭据与认证

- `openssh-config`：交给用户已有的 OpenSSH 配置和交互方式。
- `external-agent`：使用外部 SSH Agent。
- `vault-password`：从加密 Vault 取得 SSH 登录密码，通过当前 Remxo 可执行文件的内部 ASKPASS 入口交给 OpenSSH。
- `vault-key`：从加密 Vault 取得导入的私钥，生成受管临时 identity 文件，并在该 OpenSSH 操作的生命周期内保留。

SSH 密码、私钥口令、sudo 密码采用不同的凭据记录和类型检查。密码、私钥内容、主密码和备份密码都通过隐藏的本地提示输入，不设计为命令行参数。

### 命令与策略

既可以直接传递远程命令，也可以用固定 profile 获取状态、磁盘、内存、服务状态和日志。多参数命令会进行 POSIX 单参数引用；单个字符串则明确作为远端脚本处理。`raw_mode` 控制原始命令和传输边界，`approval` 控制人工审批介入程度。

### 运维能力

- 一次性命令与健康检查；
- 可查询状态、日志和取消状态的后台任务；
- 受策略和覆盖保护的上传、下载与交互式 SFTP；
- 本地转发、远端转发、动态 SOCKS 隧道；
- 过期、摘要绑定且只消费一次的人工审批；
- 默认不包含完整远端 stdout/stderr 的 JSONL 元数据审计；
- Vault 与配置组合的独立加密 `.rxb` 备份；
- 中英双语 TUI、搜索、主机向导、任务/审批/审计/设置面板。

### AI 接口

远程操作可以返回单个 JSON 文档，其中包括请求 ID、主机、operation、decision、status、远端退出码、分离的 stdout/stderr、截断标记、耗时和稳定错误对象。任务和传输同样可机器读取。

项目还提供可供 OpenCode 发现的 Skill：`.opencode/skills/remxo/SKILL.md`。它概括 AI 应遵守的操作顺序、凭据边界、审批和 PowerShell 参数规则；详细契约见 [AI 接入与自动化](ai-integration.md)。

## 初始化与首次连接

### 1. 检查本地依赖

```console
ssh -V
remxo --version
remxo doctor
```

不指定主机 alias 的 `doctor` 检查本地配置与 OpenSSH 可用性，不对服务器发起连接。

### 2. 初始化配置和 Vault

```console
remxo init --lang zh-CN
```

在终端中按提示输入主密码，输入显示为 `*`。主密码与备份密码均至少 12 字节。交互终端中不带 `--lang` 的初始化可选择 `1`（English）或 `2`（简体中文）；空输入选择英文。

### 3. 登记主机

复用已有 OpenSSH alias：

```console
remxo host add prod-01 --ssh-alias your-ssh-host --number 1 --environment production
```

或使用 Vault 私钥走交互式向导：

```console
remxo host add
```

向导依次收集连接、策略和确认信息。私钥路径是可见字段；私钥内容和认证密码属于秘密输入。配置确认前应仔细核对服务器身份、账号与远端命令策略。

### 4. 解锁并检查

```console
remxo unlock
remxo status
remxo hosts
remxo doctor prod-01
```

指定 alias 的 `doctor` 按目标主机的确切配置执行有界的 `true` 连接测试；它不会关闭主机密钥检查，也不会借此执行变更。

### 5. 执行第一条只读命令

```console
remxo prod-01 uname -a
remxo --json prod-01 df -hT
remxo prod-01 --profile status
remxo prod-01 --profile service_status --arg service=example.service
```

`example.service` 应替换为实际存在的服务名。Python、Node.js 或 CI 调用 Remxo 时见 [AI 接入与自动化](ai-integration.md)，优先使用参数数组和 JSON 解析，而不是拼接 shell 字符串。

## 状态判断速查

| 场景 | 需要看哪里 |
| --- | --- |
| 无法区分 Vault 锁和服务器问题 | `remxo --json status` 的 `vault_locked` 与 `broker_running` |
| 认证失败 | `remxo doctor <alias>` 的原始脱敏诊断、认证模式和主机密钥状态 |
| 命令正常执行但远端返回非零 | `remote_exit_code`；这与连接失败不是同一个概念 |
| 操作等待人工决定 | `decision=approval_required`、`error.code=approval_required` 和 `approval_id` |
| 输出被截断 | `truncated` 与本次 `max_output` |
| 后台操作是否结束 | `remxo task status <id>` 的 `state`、`finished_at` 和 `remote_exit_code` |
| 隧道是否持有连接 | `remxo tunnel list`，以及实际转发端口的业务连通性 |
| 是否传了错误的远端命令 | 先核对多参数/单字符串规则，再核对 `--cwd` 与 shell 类型 |

## 相关仓库资料

- [README（英文）](../README.md) 与 [README（简体中文）](../README.zh-CN.md)。
- [仓库开发约定](../AGENTS.md)。
- [测试说明](../TESTING.md)。
- [安全政策](../SECURITY.md) 与 [威胁模型](../THREAT_MODEL.md)。
- [模块级架构概述](../ARCHITECTURE.md)。

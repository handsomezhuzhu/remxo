# 配置、主机与策略

## 配置文件位置

默认配置位于平台配置目录：

```text
Linux/macOS: ~/.config/remxo/config.toml
Windows:      %APPDATA%\remxo\config.toml
```

`--config <PATH>` 指向具体的 `config.toml`；它的父目录就是数据根，Vault、Broker endpoint、审计与运行时文件都放在这里。

```powershell
remxo --config E:\remxo-data\config.toml status
```

配置要求：

- `version = 1`；
- `Config`、`Settings`、`Host` 都拒绝未知字段；
- 缺失的带默认值字段按默认值补齐；
- 每次保存先校验，再备份旧配置，最后原子替换。

## Settings

```toml
[settings]
allow_ad_hoc = false
timeout_seconds = 30
max_output = 65536
allow_overwrite = false
audit_output = false
language = "zh-CN"
```

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `allow_ad_hoc` | `false` | 是否允许未登记 IP 的临时 SSH 目标 |
| `timeout_seconds` | `30` | exec/task/put/get 默认超时 |
| `max_output` | `65536` | 处理后输出默认字节上限 |
| `allow_overwrite` | `false` | 与 `--overwrite` 做逻辑 OR |
| `audit_output` | `false` | 审计输出相关配置项；默认不记录完整 stdout/stderr |
| `language` | `"en"` | `en` 或 `zh-CN`；旧配置缺省为英文 |

TUI Settings 页的交互范围与 TOML 校验范围不同：

- timeout：5–3600 秒，`+`/`-` 每次 5 秒；
- max_output：1024–64 MiB，`[`/`]` 每次 4096 字节。

## Host

```toml
[hosts.prod-01]
number = 1
transport = "ssh"
hostname = "203.0.113.10"
port = 22
username = "ubuntu"
platform = "linux"
shell = "posix"
auth = "vault-key"
environment = "production"
tags = ["web"]
raw_mode = "allow"
approval = "writes"
insecure_acknowledged = false
sudo_credential = "prod-01"
credential = "prod-01"
```

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `number` | `None` | 可选唯一正整数编号 |
| `transport` | `"ssh"` | `ssh` 或 `telnet` |
| `ssh_alias` | `None` | 复用现有 OpenSSH Host alias；优先于 hostname |
| `hostname` | `None` | 直接主机名或 IP |
| `port` | `22` | 非零端口；CLI 添加 Telnet 时默认 23 |
| `username` | `None` | 非 `ssh_alias` 时组成 `username@hostname` |
| `platform` | `"linux"` | `linux`、`macos`、`windows`、`network-device`、`other` |
| `shell` | `"posix"` | `posix`、`powershell`、`cmd`、`device`、`custom` |
| `auth` | `"openssh-config"` | `openssh-config`、`external-agent`、`vault-password`、`vault-key` |
| `environment` | `""` | 元数据，参与 Host 摘要 |
| `tags` | `[]` | 元数据 |
| `raw_mode` | `"allow"` | `allow`、`read-only`、`deny` |
| `approval` | `"writes"` | `never`、`writes`、`always` |
| `insecure_acknowledged` | `false` | Telnet 明文风险确认 |
| `sudo_credential` | `None` | sudo 记录名；缺省兼容裸 `<alias>` |
| `credential` | `None` | SSH 凭据 stem；缺省使用 alias |
| `prompt` | `None` | 表单/CLI 保存为 `None` |

destination 规则：

- 有 `ssh_alias`：destination 就是该 alias，不添加 Host.port 的 `-p/-P`。
- 无 `ssh_alias`：destination 是 `username@hostname` 或 `hostname`，并使用 Host.port。

校验要点：

- alias 非空、不能全为数字、不含空白或 NUL；
- `number != 0`、`port != 0`，编号唯一；
- SSH 至少需要 `ssh_alias` 或 `hostname`；Telnet 必须 `hostname`；
- 连接字段非空、不以 `-` 开头、不含空白或控制字符。

## 目标解析

固定顺序：

1. 精确 alias；
2. `u32` 编号；
3. IP：先匹配已登记 hostname；未登记时只有 `allow_ad_hoc=true` 才合成临时 Host，否则 `host_not_allowed`；
4. 其余返回 `host_not_found`。

临时 ad-hoc Host 固定为 SSH、端口 22、无用户名、Linux/POSIX、`openssh-config`、environment=`ad-hoc`、raw allow、approval writes。它不会开放任意未登记 DNS 名。

## 认证模式

### `openssh-config`

交给用户已有 OpenSSH 配置。非交互执行、SCP 和隧道使用 `BatchMode=yes`；交互路径保留正常 OpenSSH 交互。

### `external-agent`

使用外部 SSH Agent。非交互路径使用 `BatchMode=yes`；Agent 不可用时显式失败，不静默改用其它凭据。

### `vault-password`

- 记录名：`<credential-or-alias>:ssh`，类型 `ssh-password`。
- 强制 `BatchMode=no`、`SSH_ASKPASS_REQUIRE=force`、`NumberOfPasswordPrompts=1`。
- 只允许密码认证，禁用公钥与 keyboard-interactive。

配置：

```powershell
remxo vault set-ssh-password prod-01
```

### `vault-key`

- 记录名：`<credential-or-alias>:key`，类型 `ssh-private-key`。
- 加密私钥的可选口令使用 `<stem>:ssh`，类型 `ssh-password`。
- OpenSSH 侧使用 `-i <受管临时文件>`、`IdentitiesOnly=yes`、`IdentityAgent=none`，仅公钥认证。

配置：

```powershell
remxo vault import-key prod-01 --path C:\keys\id_ed25519
remxo vault set-ssh-password prod-01
```

私钥路径是可见非秘密字段，不保存进 Host。导入要求常规文件、ASCII 文本、首个 PEM marker 为 OpenSSH/RSA/EC/PKCS#8，大小不超过 1 MiB。

### sudo 凭据

新注册启用 sudo 的 Host 使用 `<alias>:sudo`；没有 `sudo_credential` 的旧 Host 兼容裸 `<alias>` 查找。sudo 与 SSH 类型不能互换。

```powershell
remxo vault set-sudo prod-01
```

## 主机添加、编辑与保存顺序

### 添加

自动化 flags 形式：

```powershell
remxo host add prod-01 --hostname 203.0.113.10 --number 1 --environment production --auth vault-key
```

缺少 alias 或连接地址时进入交互向导。向导需要 TTY，不能与 `--json` 组合。CLI 非交互 Telnet 必须带 `--ack-insecure`。

向导顺序：

```text
Alias → Connection → Address → Username → Port →
Auth → Number → Environment → Platform →
Raw → Approval → sudo → Telnet ack →
SSH password/passphrase → Private key →
Test connection / Save / Save & test / Save & exit / Exit
```

新建向导的编号默认是当前最大编号 +1；空 environment 显示 `development`；shell 由 platform 推导（Windows→PowerShell，Other→Custom，其余 POSIX）。

### 测试与保存边界

新建 Test：

1. 校验草稿；
2. 先导入 Vault SSH 凭据；
3. 用 pending Host 执行连接测试，不保存 Host；
4. 失败可继续修改；Esc 会进入退出确认，不会直接丢弃。

新建 Save：

1. 再次校验；
2. 先完成 SSH 凭据导入；
3. 成功后保存 Host；
4. 是否先 Test 成功不是直接 Save 的前置条件；
5. 可选 sudo 在 Host 保存后另行配置。

动作边界：

- `Save` 保存后留在向导；
- `Save & test` 保存后测试并留在向导；
- `Save & exit` 保存后退出；
- `Exit` 询问是否保存：`S` 保存并退出，Enter 不保存退出，Esc 取消。

因此：Test 失败不保存 Host，但已导入的秘密仍加密留在 Vault；sudo 失败不回滚 Host；这不是 config+Vault 全事务。

### 编辑

- alias 固定，按精确 alias 查找；
- 保存时用打开表单时的完整 Host 做 expected-Host 检查，拒绝过期表单覆盖；
- 非秘密编辑沿用现有 credential stem，不要求重输秘密；
- 显式轮换使用 `<alias>:rotation:<uuid>` 新 stem；
- Save & test 先保存，再按登记 Host 测试；失败不回滚。

旧加密记录保留，不自动安全擦除。

## 内置 profile

| Name | 参数 | 生成脚本 |
| --- | --- | --- |
| `status` | 无 | `uname -a; uptime` |
| `disk` | 无 | `df -h` |
| `memory` | 无 | `free -m` |
| `service_status` | `service` | `systemctl status -- '<service>'` |
| `logs` | `service`、可选 `lines` | `journalctl -u '<service>' -n <lines> --no-pager` |

参数校验：

- `service` 匹配 `[A-Za-z0-9_.@-]{1,64}`；
- `lines` 为整数 1–1000，默认 100；
- 未列出参数拒绝；
- profile 也要求 POSIX shell。

注意：`status` 含 `;`，在 `approval="writes"` 下仍可能要求审批。内置 profile、只读意图和免审批不是同义词。

## raw mode 矩阵

| 操作 | `allow` | `read-only` | `deny` |
| --- | --- | --- | --- |
| raw exec | 继续审批 | `policy_denied` | `policy_denied` |
| profile | 继续审批 | 继续审批 | 继续审批 |
| put | 继续审批 | `policy_denied` | `policy_denied` |
| get | 继续审批 | 继续审批 | `policy_denied` |
| tunnel start | 继续审批 | `policy_denied` | `policy_denied` |

交互式 SSH/SFTP 不经过该 Broker 授权矩阵。

## 审批模型

| Host approval | exec/profile | put/get | tunnel |
| --- | --- | --- | --- |
| `never` | 不要求 | 不额外要求 | local/remote 不额外要求；dynamic 要求 |
| `writes` | 非明确读取时要求 | 上传或 overwrite 时要求 | local/remote 不额外要求；dynamic 要求 |
| `always` | 总是要求 | 上传和下载都要求 | local/remote 要求；dynamic 也要求 |

sudo 总是要求审批；公开绑定另需 `--yes`，但 `--yes` 不代替审批。

“明确读取”白名单：

```text
ls pwd df free uptime whoami hostname date ps cat uname
systemctl status ...
journalctl ...            # 不含 vacuum/rotate/flush
git status/log/show/diff/branch
```

含换行、CR、`;`、`|`、`&`、`<`、`>`、反引号或 `$` 的脚本不会被视为明确读取。该启发式只是审批便利，不是安全沙箱。

审批摘要：

- exec/profile：alias、完整 Host、operation、已应用 cwd 但未套 sudo 的脚本、sudo 状态、timeout、max_output；
- put/get：alias、Host、方向、本地路径、远端路径、overwrite 状态；
- 不包含 transfer timeout/max_output。

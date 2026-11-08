# Security Policy

## 状态与报告

Remxo 0.1.0 是未经独立安全审计的开发版，目标与当前声明均为 **L1**。请不要把它描述成 L2、L3 或“绝对安全”。Vault 密码/私钥认证、单 Secret RPC 和 ASKPASS 交接都没有改变同用户信任边界。

报告漏洞时请提供影响版本、最小复现、实际影响和修复建议。不要在公开报告中附真实密码、私钥、主机凭据或生产服务器信息。项目尚未配置专用安全邮箱时，可通过仓库维护者的私密安全报告渠道提交。

## 安全目标

- 防止密码、私钥内容、主密码、sudo/备份密码意外进入命令参数、日志、元数据审计、主机预览和 AI 普通操作结果。
- 把不可避免的认证明文限制在相关进程内存、受控同用户 RPC、OpenSSH ASKPASS 输出及短期临时私钥文件中，并明确这些路径不是 L2 隔离。
- 默认关闭 ad-hoc IP、自动 Vault 解锁、自动写操作重试和 SSH 主机密钥绕过。
- 对策略、审批、认证类型和加密解析失败采用 fail-closed。
- 用严格 schema、原子写入及平台实际支持的最小权限措施降低配置和运行时状态风险。
- 复用系统 OpenSSH 的协议、known_hosts、认证、转发和传输实现，不自行实现 SSH；ASKPASS 不回答主机密钥确认。
- 私钥导入必须有明确文件类型、格式和上限约束，临时私钥必须在正常子进程生命周期结束后清理。

## 密码学边界

Vault 使用 Argon2id 从主密码派生 KEK，随机 DEK 加密记录，KEK 经 XChaCha20Poly1305 包裹 DEK。主密码变更重新生成盐并包裹相同 DEK。`ssh-password`、`ssh-private-key`、`sudo-password` 等记录都在 Vault 数据密文中，磁盘密文并不改变运行时同用户暴露面。「秘密内存清理」使用 zeroize 降低残留，但不能保证编译器、分页、崩溃转储、系统内存或进程复制中不存在秘密。

备份使用独立密码、独立盐/KDF 参数和 XChaCha20Poly1305，加密包含配置以及仍加密且包裹 DEK 的 Vault envelope。Vault 中已导入的 SSH 密码、私钥口令、私钥和 sudo 凭据随该密文备份，恢复仍需要原主密码。外部 Agent、平台生物识别以及外部私钥/硬件密钥不会因此被导出。生物识别平台绑定不是可移植秘密源。

## Vault SSH 认证边界

### 记录、类型与命名

新登记主机使用 `<alias>:ssh` 保存 `ssh-password`（SSH 登录密码或私钥口令），使用 `<alias>:key` 保存 `ssh-private-key`，新登记且启用 sudo 的主机使用 `<alias>:sudo` 保存独立 `sudo-password`。Host 的 credential stem 可改变 SSH/key 名称前缀；密码、口令、私钥内容和导入路径不是 Host 中的秘密值字段。

sudo 与 SSH 认证类型不能互换。没有 `sudo_credential` 的 Host（包括旧 Host）仍查找裸 `<alias>` sudo 记录，以保持兼容；这不表示新记录应恢复使用裸名称。

公共配置命令为 `remxo vault set-ssh-password <host>` 和 `remxo vault import-key <host> [--path <file>]`。前者只用于 `vault-password`/`vault-key` 主机，后者只用于 `vault-key`；sudo 另行使用 `vault set-sudo`。命令要求解锁的 Broker/Vault，秘密值不能通过 CLI 参数提供。

### OpenSSH 选项与 ASKPASS

- `openssh-config` 与 `external-agent` 的非交互操作使用 `BatchMode=yes`；Remxo 不为其附加 Vault ASKPASS。
- `vault-password` 使用 `BatchMode=no`、`SSH_ASKPASS_REQUIRE=force`、`NumberOfPasswordPrompts=1` 和仅密码认证选项。
- `vault-key` 使用同样的 ASKPASS 设置，并限定临时 identity、`IdentitiesOnly=yes`、`IdentityAgent=none` 和仅公钥认证，不回退到密码/keyboard-interactive。
- exec、task、SCP、交互式 SFTP、TUI 主机列表中的交互式 SSH 和 tunnel 统一走 `prepare_authentication`，不得在不同路径绕过 Vault 类型检查或退回隐式交互重试。
- `StrictHostKeyChecking=no`、`UserKnownHostsFile=/dev/null`、自动接受新密钥和 `ForwardAgent=yes` 均不会被 Remxo 添加。

OpenSSH 的 `SSH_ASKPASS` 指向当前 Remxo executable，OpenSSH 以单个 prompt 参数调用它。`main` 根据 `REMXO_ASKPASS_CONFIG` 进入内部实现，不存在公共 `__askpass` CLI 子命令。环境变量只含配置路径、目标 alias 和可选 pending Host 元数据，不含密码、口令、私钥、主密码或 DEK。

helper 只响应 password/passphrase 类别的提示，拒绝 host-key、yes/no、fingerprint、continue-connecting、OTP、MFA、硬件 PIN、token 和未知提示。通过校验后，它向 Broker 请求一条 `ssh-password` 并将明文写到 ASKPASS stdout，这是 OpenSSH 获取秘密的必要交接，不得写入日志或调试输出。主机密钥确认仍由人类和严格 known_hosts 流程负责。

对于已保存主机，Broker 在认证读取时重新加载配置并解析登记 Host，然后按 Host 的认证模式和 credential stem 选择记录及预期类型。helper 不能通过任意记录名导出 Vault。未保存向导 test 使用显式 pending Host；若 alias 已在配置中，Broker 拒绝 pending 路径，防止它替代已登记主机的认证解释。

Broker RPC 的 `SecretForAuth` 可以有单个 `Secret { kind, value }` 响应。它是内部认证所需的一条秘密，不是普通 operation result，也不是完整 Vault 导出；旧的“RPC 只返回操作结果、从不返回秘密”表述不再成立。loopback、随机 token 和请求形状降低意外调用风险，但同用户恶意进程仍可能读取 token、调用 RPC 或检查内存，因此这不是对恶意同用户的秘密访问控制。

### 私钥导入与临时文件

导入只接受常规文件，拒绝 symlink、目录和特殊文件，限制为 1 MiB，并要求 ASCII 文本的第一个 PEM marker 为 OpenSSH、RSA、EC 或 PKCS#8 `PRIVATE KEY`。该校验只限制文件形状，不证明密钥可被 OpenSSH 解析、能解锁、属于预期账号或能完成认证。源路径是可见的非秘密参数/字段，不写进 Host；源文件不会被删除或清空。

Vault 私钥仅在 OpenSSH 需要时通过单 Secret RPC 取出，并写入数据目录 `runtime` 下的受管临时文件。guard 持续至 exec/task/交互进程结束或 tunnel guard 销毁，正常 drop 删除文件。Unix 上临时文件设置为 `0600`；当前非 Unix 文件限制 helper 并未建立等价 Windows ACL，Windows 原生权限与真实 Vault 认证尚未验证。强制终止、崩溃、文件系统行为或权限错误可能阻止清理；普通文件删除不是安全擦除保证。

密码/口令明文存在于 Broker/客户端相关进程内存和同用户 RPC 数据中，并经过 ASKPASS stdout；私钥还会短时存在于明文临时文件中。交互输入只显示与用户输入数量对应的 `*`，不显示秘密内容，但掩码数量和终端本身不是防窥探保证。零化、受限文件名和短生命周期只能降低意外暴露，不能抵抗同用户读取内存、替换可执行文件、截获 RPC/stdout 或复制临时文件。

### TUI 向导保存顺序

向导的密码/口令字段仅显示 `*` 掩码和可编辑光标；终端 ECHO 关闭，秘密值不显示。私钥路径作为可见非秘密字段输入。新建 Host 的 Test 和 Save 都先导入 Vault 凭据，未保存 test 使用 pending Host。Test 失败、保存前失败或 Esc 不写 Host，但已经导入的秘密仍加密留在 Vault；这不是 Vault + Host 的全事务。直接 Save 在 SSH 凭据成功后写 Host，不要求先成功 Test。sudo 在 Host 保存后独立配置，失败只产生后续修复提示，不回滚 Host。

编辑已有 Host 固定 alias，执行 expected-Host 防陈旧覆盖检查；非秘密修改沿用现有凭据。显式轮换使用新的版本化 credential stem，配置保存前不改写旧 Host 当前引用的秘密。旧凭据仍加密保留，不承诺跨配置/Vault 整体回滚或自动安全删除。保存并测试先保存编辑，再通过正式登记 Host 执行测试；已登记 alias 不使用 pending Host。测试失败不回滚已保存的配置。

### 初始化语言与配置恢复

`settings.language` 严格持久化为 `en` 或 `zh-CN`，缺失的旧配置默认 `en`。`init --lang en|zh-CN` 显式选择；TTY 无参数时可通过编号 `1`/`2` 或语言名称选择，空输入默认英文，JSON/非 TTY 不强制语言提示，但显示 `*` 掩码的主密码仍要求 TTY。已有有效配置且 Vault 缺失时，恢复初始化保留原配置及语言，只创建缺失的 Locked Vault，不覆盖配置或已有 Vault。`unlock` 的掩码提示与成功消息、主 TUI/向导使用已保存语言，不据此宣称所有 CLI 错误已翻译或完成跨平台 UI 验证。

## 明确不在 L1 保证内

1. CLI、ASKPASS helper 与 Broker 处于同一 OS 用户；同用户恶意 Agent 可读取文件、内存、Socket、Broker token、临时私钥或直接调用 `ssh`。
2. 能读取 `~/.ssh`、Remxo 数据目录、`SSH_AUTH_SOCK`、进程环境/内存或 RPC 的进程可能绕过 Remxo；单 Secret 响应不是同用户访问控制。
3. ssh-agent 不暴露私钥并不等于 Socket 持有者不能请求签名。
4. Vault 保护静态数据与受控 Broker 路径，不提供远程权限隔离；临时明文 key 和 ASKPASS stdout 是必要的运行时扩张面。
5. root、内核、固件、远程超级用户或操作系统失陷不在保护范围。
6. 生产 SSH CA、短期证书、独立身份和远程强制授权尚未实现。
7. 脱敏不保证识别全部秘密；远端文本始终是不可信内容。只有已知 sudo 密码做精确回显清除，不能推广为所有秘密均被清除。
8. Telnet 没有网络保密性或完整性，即使凭据在本地 Vault 中加密。
9. OpenSSH、sudo、PAM、sudoers、网络设备和远端账号配置仍决定真实权限；PEM marker 校验不等于真实认证成功。
10. 本地停止任务或隧道不证明远端动作已经停止或没有发生副作用。
11. zeroize 不能证明所有内存拷贝、core dump、分页或序列化临时副本均被擦除；临时文件正常清理也不能覆盖异常终止。
12. Windows 原生 ACL、OpenSSH ASKPASS 行为及真实 Vault 密码/私钥认证尚未完成本轮验证，不能把 Unix `0600` 或 Linux fixture 结果外推为跨平台保证。
13. 同用户审批、Broker token 和文件权限不构成 L2；语言选择、双语 TUI 或配置 schema 也不改变认证信任边界。

## 安全开发约束

- 禁止通过 CLI 参数新增任何密码、私钥内容、私钥密码、主密码或备份密码；私钥路径必须按非秘密元数据处理且不进入秘密输出。
- 不得自动设置弱化主机密钥检查、Agent 转发或自动接受新主机密钥的选项；ASKPASS 不得回答 yes/no、fingerprint、OTP/MFA、PIN/token 或未知提示。
- ASKPASS 必须复用当前 executable + prompt 的内部入口，不得新增公开秘密子命令，不得把秘密放进环境、argv 或日志。
- Broker 正常认证必须按登记 Host 重新解析并校验 credential kind；仅在未保存 wizard test 中接受 pending Host，已保存 alias 必须拒绝 pending 替代。
- 私钥导入必须保留常规文件、拒 symlink、1 MiB 和支持 PEM 类型的检查；临时 key 必须由 guard 管理覆盖 exec/task/interactive/SCP/SFTP/tunnel 生命周期。
- 不得通过本地 shell 拼接启动 OpenSSH/scp/sftp。
- 未经安全评审不得替换 KDF/AEAD、自制密码学封装或增加自动解锁。
- 安全错误不得包含秘密；测试秘密只能使用测试专用值，不能连接真实生产服务器。
- 备份/审计不得包含运行时 DEK、解锁状态、Socket、审批状态、会话、缓存或默认完整输出；Vault 私钥只能在备份中继续保持密文。
- 改变认证/RPC/秘密交接行为时，必须同步安全与威胁文档，不能把单 Secret 认证例外描述为“RPC 永不返回秘密”。

当前安全能力不代表独立渗透测试、密码学评审或跨平台验证已经完成。本次隔离 Linux fake/PTY/real-sshd/sudo/cleanup 回归和 Windows 原生 Rust 检查/构建状态见 [TESTING.md](TESTING.md)；Windows 原生认证/ACL、未逐项执行的 Vault 操作及异常终止清理仍不得写成通过。

### npm 原生分发边界

- npm 只是原生 Rust 二进制的分发与启动方式，不引入 JS Vault/Broker/TUI。optional 包必须按 os/arch 与主包精确同版本，缺包或版本不一致失败关闭；不使用 PATH 上的任意替代程序。
- 不支持安装脚本下载二进制、用户侧 Cargo 编译或运行时自动更新；暂存时核对 `remxo --version`。npm 主包和 optional 平台包当前只覆盖 Windows x64 与 Linux x64（glibc）；macOS 适配及产物目标在真实设备可验证前暂停，不宣称未验收的 macOS 支持或完整 registry 发布通过。
- 打包后 ASKPASS 与 daemon 仍以 native executable 运行，而非 Node；Node 微调包具有启动本地二进制的权限，其完整性也是供应链边界，不能提供 L2 同用户隔离。

## 依赖审计说明

2026-11-07 对提交的 `Cargo.lock` 执行了 `cargo audit`，没有返回已知漏洞；RustSec 报告 `RUSTSEC-2025-0069`：`daemonize` 被标记为 unmaintained。该库仅用于 Unix Broker 会话分离，非密码学实现。此警告不等于当前没有漏洞或已获维护者背书，也不能覆盖后续认证改动。CI 保留并显示审计结果，不添加忽略规则。后续应评估维护中替代方案或迁移实现，并在替换后重新验证 PTY 生命周期。

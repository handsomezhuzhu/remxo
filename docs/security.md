# 安全模型

Remxo 的安全模型是 **L1**：降低人类和 AI 在真实运维中误用凭据、误执行命令和误扩大暴露面的风险。它不是同用户恶意代码隔离，也不是对远程服务器授权边界的替代。

## 信任边界

主要边界：

1. AI/CLI/TUI 与同用户本地 Broker 之间；
2. Broker 与 OpenSSH 派生的 ASKPASS 子进程之间；
3. 受管临时私钥与 OpenSSH 之间；
4. Remxo/OpenSSH 与远端输出之间。

L1 假设用户可以故意解锁 Vault、导入正确的私钥、批准必要操作，并信任系统 OpenSSH 与当前 Remxo 可执行文件。L1 不假设同 OS 用户的其它进程是善意的。

未来更强的边界需要把 Broker 移到不同 OS 用户，并重新设计跨真实 OS 边界的 Secret/ASKPASS/私钥交接；把 token 或 ASKPASS helper 移到同用户的另一个进程不构成该边界。

## 资产

- 主机清单与连接元数据；
- Vault 中的 SSH 密码、私钥口令、导入私钥、sudo 密码；
- 主密码、备份密码、KEK/DEK；
- 外部 Agent 的签名能力；
- 审批意图与审计元数据；
- 任务、隧道和受管临时密钥文件；
- 远端输出完整性。

## 凭据静态保护

Vault 使用：

- Argon2id 派生 KEK；
- 随机 32 字节 DEK；
- XChaCha20Poly1305 包裹 DEK 与加密记录数据；
- 显式锁定与显式解锁。

主密码和备份密码只通过隐藏终端提示输入，不通过 CLI 参数、环境变量或脚本传递。私钥导入只接受常规文件，拒绝 symlink、目录和特殊文件，限制为 1 MiB，并要求 ASCII 文本的第一个 PEM marker 属于 OpenSSH/RSA/EC/PKCS#8。源文件不被修改。

`.rxb` 备份使用独立备份密码与独立 KDF/AEAD；payload 包含配置和仍加密的 Vault envelope，不包含运行时 socket、任务、审批、审计日志或明文 DEK。

## 凭据运行时边界

不可避免的运行时暴露包括：

- Broker/客户端进程内存中的秘密；
- 同用户 RPC 数据；
- ASKPASS stdout 到 OpenSSH 的交接；
- OpenSSH 读取期间的受管临时私钥文件。

对应控制：

- Vault 认证不使用任意记录名；Broker 按登记 Host 重新解析 credential stem 与类型。
- `SecretForAuth` 只返回认证所需的一条带类型记录，不是 Vault 导出接口。
- 临时私钥保存在数据根 `runtime` 下，guard 覆盖子进程或隧道生命周期；Unix 上为 `0600`，Windows 上使用关闭继承并只授予当前用户的 DACL。
- ASKPASS 环境只含配置路径、目标 alias 和可选 pending Host 元数据。
- sudo 密码通过 SSH stdin 传输，并从输出中精确清除回显。
- 密码输入只显示 `*`；掩码长度与终端本身都不是防窥探保证。

普通操作结果不应包含 Vault 记录。内部认证 RPC 的单 Secret 响应是有意例外，不能反向声称“RPC 从不导出秘密”或“同用户无法访问”。

## OpenSSH 边界

Remxo 复用系统 OpenSSH，不自行实现 SSH 协议。

- 主机密钥检查保持开启；不会自动添加 `StrictHostKeyChecking=no`、`UserKnownHostsFile=/dev/null`。
- `remxo host key fetch` 只展示网络侧指纹；`trust` 必须交互输入 `TRUST` 或提供匹配的 `--fingerprint`，属于人工 TOFU，不是自动接受。
- 不会自动添加 `ForwardAgent=yes`。
- host-key 确认类 ASKPASS 提示一律拒绝；未知主机由人类预先验证和登记。
- Vault 模式使用固定认证组合，不回退到另一种凭据，也不做隐式重试。
- `external-agent` 在非交互路径使用 `BatchMode=yes`；所需 Agent 不可用时显式失败。

远端 sshd 配置、账号权限、sudoers、PAM、防火墙和 `AllowTcpForwarding` 仍是真实授权边界。

## 命令与策略边界

- 本地非交互进程通过 argv 启动，不经过本地 shell 拼接。
- 多参数远端命令逐个 POSIX 单引号引用；单个字符串明确作为远端脚本。
- `--cwd` 使用 `cd '<quoted>' && (<script>)`。
- sudo 使用 `sudo -S -p '' -- /bin/sh -c '<script>'`。
- 固定 profile 只接受类型化参数和有限服务名/行数范围。
- raw-mode 与 approval 只影响 Remxo 授权层，不是远端命令沙箱。
- 明确读取启发式是白名单与元字符判断，不应作为安全过滤依据。

审批是同用户便利控制：相同 host/operation/digest 的未完成请求复用 id；批准只标记意图；执行时消费一次；Broker 重启后清空。同用户进程可以绕过或直接批准，因此它不是 L2。

## 主机与向导边界

- alias 非空、非纯数字、不含空白或 NUL；编号唯一且非零。
- 连接字段非空、不以 `-` 开头、不含空白或控制字符。
- 未登记 IP 默认拒绝；`allow_ad_hoc=true` 只开放 IP 形态临时目标。
- Telnet 需要显式 `insecure_acknowledged=true`；Telnet 路径不提供网络保密性或完整性。
- 编辑固定 alias，保存时做 expected-Host 陈旧检查。
- 非秘密编辑沿用现有凭据；显式轮换使用新的版本化 credential stem。
- 轮换后旧加密记录保留，不自动安全擦除，也不承诺跨配置/Vault 回滚。

向导不是全事务：

- Test 失败或 Esc 不保存 Host，但已导入的秘密仍加密留在 Vault。
- 直接 Save 在 SSH 凭据成功后保存 Host，不要求先成功 Test。
- sudo 在 Host 保存后独立配置，失败不回滚 Host。
- Save & test 先保存，再按登记 Host 测试；失败不回滚配置。

## 输出与提示注入

远端 stdout/stderr 始终视为不可信数据。

- 输出限长、控制字符处理和 UTF-8 安全截断先于最终返回。
- 常见秘密脱敏与 sudo 密码精确清除只覆盖已知模式，不能保证发现任意秘密。
- 控制字符剥离不是提示注入防护；AI 不应把远端文本当作更高优先级指令。

## 审计

审计记录元数据与请求摘要，不默认保存完整远端 stdout/stderr 或凭据值。路径与元数据可能仍敏感；同用户篡改审计文件超出 L1 范围。安全诊断不得打印口令、私钥内容、主密码或 ASKPASS stdout。

## 隐私与本地状态

- 没有共享的明文主密码环境变量。
- 没有保存解锁状态的明文会话文件。
- 不同数据根彼此隔离；Broker endpoint、Vault、任务、审批、隧道和审计不跨数据根共享。
- 解锁状态存在于 Broker 内存；lock、Broker 退出、崩溃或 OS 重启后不应假设其仍可用。

## npm 供应链边界

- 主包与平台包必须精确同版本，os/cpu/libc 与 vendored 二进制匹配。
- 缺包、版本不符、目标不符明确失败，不静默回退 PATH。
- 打包时核对 native `remxo --version`。
- npm 包不包含 JS Vault、JS Broker、JS TUI 或 postinstall 下载逻辑。
- Node 启动器只负责定位原生二进制；它不提供 L2 同用户隔离。

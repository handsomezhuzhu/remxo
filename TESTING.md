# Testing Remxo

目标：仓库之外不需要真实服务器、账号、密码、私钥、SSH Agent 或平台 Token。测试失败和环境不可用分别报告，禁止把跳过写成通过；源码中存在测试也不等于该测试在当前改动上运行过。

## 当前验证状态

### 2026-11-10：主机密钥确认绑定（R02）

当前 `dev` 工作副本在 Instabox `remxo-dev` 上运行了 `python3 tests/run_all.py --require-real-ssh --report target/final-r01-r02-tests.json`：fmt、Clippy、Rust 全目标测试、构建、npm、fake、5 个 PTY suite（原基础 case + CLI changed/stable/partial + Wizard changed）、两个真实 sshd suite、sudo 和 cleanup 全部 PASSED，真实 SSH 未跳过。这不是已推送 main 或 Windows CI 的通过。

R02 原始提交的二进制在临时 HOME + fake keyscan 下实际复现了确认 A 后写入未确认 B；新实现拒绝且不产生 known_hosts。新 PTY 用例进一步覆盖稳定相同抓取A/B集全量登记、哈希 known_hosts 的 A 已登记而 B 缺失时只补 B，以及真实向导确认后变化拒绝。两次 keyscan 和隔离文件内容被独立断言；没有读取真实 `~/.ssh`、真实凭据或用户服务器。新单测覆盖 endpoint 编辑失效与旧 fetch 响应丢弃。下面 R01 段落的历史结果不替代本轮验证：

### 2026-11-10：审批读取判断修复（R01）

本轮修改 `src/policy.rs` 的本工作副本已实际验证：在隔离、无真实 Vault/凭据注入的 Instabox `remxo-dev` 中，`python3 tests/run_all.py --require-real-ssh --report target/policy-r01-tests.json` 的 fmt、Clippy、Rust 全目标测试、构建、npm、fake、PTY、两个 real suite、sudo 和 cleanup 全部 PASSED，真实 SSH 未跳过。5 个 `policy` 单元测试在修改上通过；相同新增测试与原始策略实现对照时，写入误判与审批结果用例失败，因此覆盖并非仅验证测试本身。机器可读报告另附退出码、时长和输出摘要。

新增测试覆盖 `git branch -D`、`git diff --output=...`、`journalctl --vacuum-size` 的分离与等号参数形式、`date --set`/`date -s` 和 `hostname NEWNAME` 的审批需求，以及普通读取选项、sudo、never/always 的既有结果；只判断策略，不执行示例写命令。本轮未执行 Windows 验证，未修 Broker/恢复/路径/进程超时等其他审查项。

下面是 2026-11-08 的历史基线，不能当作后续工作副本已经重新完成了 Windows 验证：

- Windows 原生 `cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --all-targets -- --test-threads=1` 和 `cargo build` 均通过；这只是当前 Rust 自动检查与构建，不代表全部 Windows 认证、ConPTY/窗口场景都完成验证。
- 隔离、无 Vault 注入的 Instabox `remxo-dev` 上，`python3 tests/run_all.py` 的 `checks/fmt`、`checks/clippy`、`checks/unit`、`checks/build`、fake、PTY、两个 real suite、sudo 和 cleanup 均为 PASSED，真实 suite 未跳过。
- 6 个 PTY case 实际覆盖连续掩码密码/备份流程、基础主机向导、光标编辑与主机编辑、交互中文数字语言选择与中文解锁、Vault password 向导 Test→Save、Vault key 路径导入向导 Test→Save。真实 sshd 另行通过 Vault password/加密私钥 exec、Vault password put、Vault key get、严格 HostKey 负例与恢复、正常临时 key 清理及秘密扫描。fake 另验证真实 ASKPASS password 回环、错误提示拒绝和超时临时 key 清理。
- Windows 已实际执行原生 ACE fixture，确认只有当前用户拥有临时私钥授权；隐藏的 ACL PowerShell fixture 会检查自身没有可见控制台窗口。Windows 原生 Clippy/全目标测试也通过 CLI 进程退出后第二客户端仍能读取 `broker_running=true` 与 `vault_locked=false` 的生命周期用例。Linux 结果不等同于该验证。**Windows 真实密码认证、更多 ConPTY/可见窗口变体及完整认证矩阵仍为 NOT_RUN**，不据此宣称全面兼容或独立安全审计。
- Vault task/tunnel/TUI interactive SSH/SFTP、错误凭据矩阵、Test 失败/Esc 的残留凭据边界、启动失败清理和强制终止/崩溃清理仍未全部验证。结果不对应任何远端 GitHub CI 运行，不宣称跨平台、全部服务端或全认证操作矩阵通过。

下面的 suite 描述说明测试入口、实际覆盖与保留缺口。后续的覆盖要求仍列在“Vault 认证验收要求”一节，只有实际执行对应测试才能把新增子项标为通过。

## 一键测试

Linux 推荐使用 Python 3 的标准库测试驱动：

```console
python3 tests/run_all.py
npm test --prefix npm
```

默认依次运行：

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all-targets -- --test-threads=1`
4. `cargo build`
5. Node.js/npm 可用时执行 `npm test --prefix npm`，不可用时标为 `checks/node = skipped / NOT_RUN`
6. fake 故障注入和并发测试
7. PTY 密码与 TUI 测试
8. Docker 可用时自动运行真实 sshd/SFTP/TCP 隧道/任务及 Vault 密码/加密私钥认证测试
9. 同一类隔离环境中的真实 sudo、Vault 和一次性审批测试
10. `integration/check_cleanup.py` 只读检查残留 Broker、容器和临时镜像

命令选项：

```console
python3 tests/run_all.py --only checks
python3 tests/run_all.py --only fake
python3 tests/run_all.py --only pty
python3 tests/run_all.py --only real
python3 tests/run_all.py --only sudo
python3 tests/run_all.py --no-real-ssh
python3 tests/run_all.py --require-real-ssh
# 也可以选择其中一个 suite：checks、fake、pty、real、sudo
python3 tests/run_all.py --report target/remxo-test-results.json
```

- `--only fake|pty|real` 在缺二进制时先编译，已有二进制不会隐式视为最新；修改 Rust 后建议先运行 `--only checks`。
- Linux 之外的 Python 集成测试明确跳过；Windows 仍执行 Rust 单元测试和能够运行的 fake Rust 测试，但这不是 Windows 原生认证验收。
- Docker 不存在或 daemon 不可用则真实 SSH 测试标为 `skipped / NOT_RUN`，不影响 fake/PTY 结果。
- `--require-real-ssh` 将真实 SSH 缺失或失败作为总测试失败。
- 测试中途失败返回非零，阻止继续运行后续 suite，避免用旧二进制生成误导性结果。

也可以直接提供已编译二进制，单独执行 Python 测试：

```console
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/fault_and_stress.py
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/pty_acceptance.py
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/sshd_acceptance.py
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/vault_auth_acceptance.py
REMXO_BIN="$PWD/target/debug/remxo" python3 tests/integration/sudo_acceptance.py
```

真实 SSH 强制模式：

```console
REMXO_REQUIRE_REAL_SSH=1 REMXO_BIN="$PWD/target/debug/remxo" \
  python3 tests/integration/sshd_acceptance.py
```

## 测试分层

### Rust 单元与 fake 可执行文件

`src` 内的单元测试及 `tests/cli_end_to_end.rs` 已有以下局部分层覆盖：

- 配置解析、主机编号/登记 IP、拒绝未登记 IP；`settings.language` 持久化、zh-CN 序列化及旧配置默认英文；
- `init` 短密码预写入校验、有效 config-only 恢复保留原配置；
- ASKPASS 只接受 password/passphrase，拒绝 host-key/yes/no/fingerprint/OTP/PIN/token/未知提示；
- Broker 在读取时使用硬字节上限，限制超长单行请求的缓冲分配；空请求和超限请求均拒绝。
- 子进程 stdin 写入/关闭失败会先 kill/wait 回收子进程再返回，防止在子进程仍可能使用临时 key 时提前释放认证 guard；新增独立 Unix 回归检查已实际通过。
- `tests/cli_end_to_end.rs` 的 fake ssh fixture 调用真实 current-executable ASKPASS，检查 force/target、password prompt 成功与若干拒绝提示、argv/审计无测试秘密及无 `__askpass`；同一用例还覆盖 Vault key 在 transport timeout 后的受限临时文件清理。本次该 Rust suite 已实际通过，但它仍不是服务端密码/公钥兼容性证明。
- 私钥导入拒绝非 key 文本且错误不回显内容、OpenSSH PEM marker；Unix 上拒绝 symlink、临时文件 `0600` 和正常 drop 删除；
- 向导秘密字段只显示 `*` 掩码、中把控件和实际渲染缓冲区，不渲染测试秘密；`text_input` 另验证中间插入、左右/Home/End、Delete/Backspace、Unicode 宽度、长路径窗口、控制字符拒绝及 masked/Debug 不泄密；
- POSIX 参数与 cwd 注入检查、非 POSIX 拒绝、profile 参数；
- 原始 argv、无本地 shell 拼接、外部认证 BatchMode、默认不弱化主机密钥检查；
- Vault 初始锁定、等效重启锁定、错误主密码、DEK 不明文落盘、改密不换 DEK；
- 异常 KDF 参数、备份验证和全新目录恢复；
- 审批匹配和一次性、任务状态、无自动重试、传输覆盖、隧道默认绑定；
- sudo 标准输入、类型隔离、远端回显清理、sudo 拒绝错误；
- Telnet 未确认拒绝。

这些测试不能单独证明完整 ASKPASS 子进程回环、OpenSSH 实际接受密码/口令、私钥对应公钥获远端授权、每种 exec/task/interactive/SCP/SFTP/tunnel 路径都正确使用临时 key，或异常退出后没有明文文件残余。新增认证的真实/PTY 要求不能因上述局部单测而省略。

### `fault_and_stress.py`

每个测试都有独立临时目录、独立 Broker 和 fake，不连接真实服务器。覆盖：

- fake 主机密钥错误、双流超大输出、超时 kill；
- PEM、API/Password 与控制字符处理；
- 命令和 cwd 注入不在本机创建标记文件；
- 多客户端并发、唯一 request id、每个请求恰好执行一次；
- task 启动/取消/日志、停止已完成任务报错、进程回收和 Broker 重启锁定。

故障注入脚本的普通 fake 不覆盖 Vault ASKPASS 回环；应结合上述 `tests/cli_end_to_end.rs` 认证 fixture 阅读，二者都不能替代真实 OpenSSH 服务端认证。新增 fake 应继续记录并断言各认证模式的 argv/env，而敏感断言只能比较测试专用假值是否存在，不能打印秘密。

### `pty_acceptance.py`

Linux Python `pty.fork` 自动完成隐藏提示，而不是通过 argv、stdin 管道或 shell history 递送密码。所有 PASSWORD 都是代码中明确标记的 test-only 假值。回复敏感提示前，驱动读取 PTY termios 并等待 `ECHO=off`，避免在密码库关闭回显前抢答。测试会验证配置、Vault/备份和终端 transcript 都没有这些测试 PASSWORD，不能为了消除竞态而取消此项断言。

现有一个连续基础流程设计为验证：

- init（密码与确认）、添加 fake host；
- 人工 unlock 的 CLI 行为；
- 加密备份 create/verify/restore；
- change-password 后旧状态 lock / 新密码 unlock；
- 恢复目录仍用原主密码解锁；
- TUI 在 PTY 中启动并通过 q 退出；
- 临时配置、Vault、备份和终端记录不含测试密码。

当前基础流程与主机向导 fixture 显式使用 `init --lang en`；交互中文用例通过编号 `2` 选择中文、匹配中文主密码/确认提示、检查配置语言与中文 unlock 文本，并断言出现 `*` 掩码。另有 `host edit` 的真实 PTY 用例在已有主机上通过 Home/Delete/End 修改地址，保存并复核，不需要重建主机。本次 6 个 PTY case 均实际通过。JSON/非 TTY 默认英文的单测/配置覆盖与 `config-only` 恢复保留语言的实现仍需和端到端覆盖区分，不能仅凭 GUI 标签宣称所有 CLI 已翻译。

PTY transcript 仅做内存泄漏检查，不打印密码或大段终端内容；每条命令具有超时和独立子进程回收。新增 SSH 密码、私钥口令和 test-only key PEM 也必须加入 transcript、配置、Vault、审计和临时 runtime 的秘密扫描；路径是可见非秘密数据，不应误判为秘密值。

### 主机添加向导

在 PTY 基础流程之外，`tui_wizard` 单元测试验证 alias 预填、下一可用编号、POSIX 默认值、公开输入清洗、Telnet 未确认拒绝、默认不配置 sudo、控制字段空格输入、秘密不渲染、中控件与实际渲染缓冲区。另一个真实 PTY 按键流程输入示例 OpenSSH alias、完成 fake 连接检查并保存主机；同步以实际 `connection_test` 审计事件落盘为准，不依赖界面增量绘制出的完整 `passed` 字样。测试在指定窗口尺寸下确认字段、测试与保存操作的可见性。连接探针还检查 `raw_mode=allow` 和 POSIX shell，不用测试动作绕过只读/拒绝策略或非 POSIX 能力边界。

本次真实 PTY 已覆盖 `vault-password`/`vault-key` 向导先导入 Vault、使用 pending Host 完成 Test 后 Save，以及密码不渲染、私钥路径不保存到 Host、正常临时 key 清理和密文落盘。Test 失败和 Esc 后 Host 不存在但已导入密文记录仍存在、跳过 Test 直接 Save、sudo 失败不回滚 Host 等分支仍未逐项做 PTY 验证，不得把它们一并写成通过。断言 Vault 残留记录只能检查可解锁后的测试专用记录或密文变化，不能把明文写进断言日志。

界面新增没有完整 Vault 导出、隐式批准、特殊 SSH 绕过或 host-key bypass；单 Secret 内部 RPC 是认证实现的一部分，不是 UI 秘密导出功能。

### `sshd_acceptance.py`

该文件提供真实 SSH/SFTP/TCP 协议基础 fixture；它与 `vault_auth_acceptance.py`、`sudo_acceptance.py` 都只使用测试专用环境，不连接用户服务器：

- 临时 Alpine sshd 容器；Docker host network 只监听 127.0.0.1；
- 每次随机容器名、镜像名、host/user 临时 Ed25519 密钥；
- binary wrapper 只负责向真正的 `/usr/bin/ssh` 和 `/usr/bin/scp` 显式传 `-F <临时配置>`，不替换协议实现；
- 临时 `known_hosts` 来自预先生成的 host public key，保持 `StrictHostKeyChecking=yes`；
- 默认 sshd 配置禁用密码、交互键盘、root 登录，只允许生成的 public key；
- 容器/镜像/Broker 在 teardown 回收，不读取或更改用户 HOME、`~/.ssh`、系统 sshd 或公共端口。

现有矩阵覆盖的是 `openssh-config` public-key Host：

1. 真实 argv 命令、cwd 副作用隔离、profile、参数和路径注入标记不存在、cwd 不跨 SSH 进程错误保留。
2. 修改 expected host key 后真实 OpenSSH 必须返回 `host_key_failed`，恢复后严格连接成功。
3. SFTP 特殊路径、二进制 round-trip SHA-256、远端覆盖和本地覆盖拒绝、显式覆盖成功。
4. 真实 TCP echo 数据通过 SSH 隧道；stop 生效；0.0.0.0 缺确认拒绝；端口冲突失败。隧道只有在 OpenSSH 输出完成交互初始化且进程仍存活时才登记，不将 bind 前的 `Local forwarding listening on` 预告误判为可用。
5. 真实 task 完成输出恰好一次、退出码、取消和 finish time。

基准镜像 `alpine:3.22` 由 Docker 拉取测试依赖；首次运行需网络。密钥只在临时 volume 中提供，不写入镜像。环境不满足时不可把本 suite 描述成 pass，也不能把基础矩阵描述成 Vault 密码/私钥认证的成功矩阵。

### `vault_auth_acceptance.py`

该新增真实 sshd fixture 复用 `SshdFixture` 的临时容器、端口和回收机制，并另外：

- 在同一个隔离容器内为 test-only `rxuser` 设置测试密码、允许 password auth；把原 public key 与新生成的 Vault public key 都写入该临时账号的 `authorized_keys`，不修改用户 sshd 或 SSH 目录。
- 通过隐藏 PTY 运行 `ssh-keygen` 生成带专用 test-only 口令的 Ed25519 key，使用 `init --lang en`、unlock、`vault set-ssh-password` 和 `vault import-key --path` 配置两个临时 Host；密码/key 源文件都在临时目录。
- 对 direct hostname 也显式设置严格 `UserKnownHostsFile`/`StrictHostKeyChecking=yes`。
- fixture 设计的断言是：Vault 密码和 Vault 加密私钥分别完成真实 exec；Vault 密码 `put` 与 Vault 私钥 `get` 走 `scp -s`；篡改 expected host key 返回 `host_key_failed`，恢复后成功；已完成操作后 runtime 不留临时 key。
- `assert_secret_hygiene` 检查 config/Vault/audit 不含测试密码、口令和完整 test-only key，transcript 不回显密码/口令，Host 配置不保存导入 key 路径。

`tests/run_all.py --only real` 把该脚本接在基础 `sshd_acceptance.py` 之后，本次两条 real suite 均实际 PASSED。它仍不覆盖 Vault task、tunnel、TUI interactive SSH、交互式 SFTP、错误密码/口令以及向导 Test 失败/Esc 的事务边界；后面的矩阵用于明确这些缺口，不能用已通过的 exec/SCP 扩大结论。

### `sudo_acceptance.py`

`SudoFixture` 在同一临时 sshd 基础上通过真正隐藏 PTY 创建和解锁 Vault、写入独立 sudo 凭据。sudoers 只在一次性容器内配置；为兼容 Remxo 当前 raw-command 包装形式，覆盖 `/usr/bin/id` 与 `/bin/sh`，不是向用户机器部署 sudoers 规则。sudo 密码随机生成，以隐藏 PTY 递送，容器启动时写入 shadow hash，密码的原始 gadget 文件权限为 `0600`，teardown 删除，不写入镜像。

其既定验证目标是：普通命令不是 root；第一次 sudo 必须 `approval_required`；显式模拟人类批准后，相同 sudo 命令得到真实 uid 0；下一次相同命令必须重新审批；Vault、输出和审计都不含 sudo 密码。这个场景也用于回归“unlock 的终端退出后 Broker 不得死亡、解锁状态必须保留”。自动 Broker 应走 daemon 路径，测试中直接用端口号和 PID 检查生命周期而不是假定它存活。

该 fixture 的 init 驱动显式使用 `init --lang en`，本次真实 sudo suite 已实际通过。它证明真实 sudo + 既有 OpenSSH public-key fixture、隐藏密码和一次性审批路径，不单独证明 Vault SSH 密码/私钥认证，也没有分别覆盖 `<alias>:sudo` 与旧裸 alias 两种记录的真实协议矩阵。

## Vault 认证验收要求

以下是当前新增实现必须补齐并实际执行的 fixture/验收矩阵。已有局部 fixture 只按上节描述计入源码覆盖，仍不表示完整矩阵存在或本轮已经通过：

| 层级 | 必须验证的内容 | 特别约束 |
| --- | --- | --- |
| Rust/fake | 四种 auth 的准确 argv：外部非交互 `BatchMode=yes`；Vault `BatchMode=no`、`SSH_ASKPASS_REQUIRE=force`、一次 password prompt；password-only/publickey-only 无错误回退 | fake 只记录路径/选项，不输出秘密；严格 known_hosts 不放宽。 |
| 内部 ASKPASS | 当前 executable + 单 prompt；环境仅 config/alias/pending Host；password/passphrase 成功；host-key/yes/no/fingerprint/OTP/MFA/PIN/token/未知均拒绝；返回类型错误失败 | 验证 argv/env/transcript/audit 无测试密码或 key；不把 helper 当公共秘密导出 CLI。 |
| Broker 认证上下文 | 已登记 Host 重解析和 kind 检查；普通 alias/编号目标；已保存 alias 的 pending 请求拒绝；未保存 wizard pending 只取预期记录 | 不打印 Broker token、Secret RPC 响应或秘密 fixture。 |
| 私钥导入 | 支持的 OpenSSH/RSA/EC/PKCS#8 形状；非常规文件、symlink、超 1 MiB、非 ASCII/不支持 marker 拒绝；源文件不变 | 每种平台按其语义单独执行，Unix 的 symlink/权限结果不能代替 Windows。 |
| 临时 key | exec/task、SCP、TUI interactive SSH、SFTP、tunnel 生命周期中仅传受限临时路径；正常结束后删除；启动失败路径也清理 | 崩溃/强杀残留只能作为明确限制验证，不得宣称保证清除或安全擦除。 |
| PTY/i18n | `init --lang en|zh-CN`、TTY 数字 `1`/`2` 与空默认、JSON/非 TTY 不提出语言问题、旧配置 en、config-only 恢复保留语言；主 TUI/向导中控件、中文 unlock 与其他用户侧消息 | 隐藏密码检查必须先等 ECHO=off；非交互 init 仍可能因需要掩码主密码而失败，不能伪称完全自动化 init。 |
| PTY/editor | 可见光标、左右/Home/End、插入/Backspace/Delete、bracketed paste、成对引号私钥路径；`host edit` 非秘密配置更新、expected-Host 过期拒绝、保存后登记 Host 测试、版本化凭据 stem | 任何密码/口令只显示 `*`，内容不得进入 transcript、预览或日志；非秘密编辑不要求 Broker/秘密重输；凭据轮换失败、sudo 部分失败仍需逐项覆盖。 |
| PTY/wizard | 隐藏 SSH 密码/口令、私钥路径导入；先导入再 pending test；失败/Esc 不保存 Host 但密文保留；直接 Save；sudo 独立后配置 | 将 SSH 密码/口令/test-only key 纳入 transcript/Vault/audit 泄漏扫描，结果不打印秘密。 |
| 真实 Vault public key | 临时 sshd 只允许 publickey；本地生成 test-only（含加密）私钥，经 Vault 导入并解锁；ASKPASS 提供口令；exec/task/SCP、TUI interactive SSH/SFTP/tunnel 的真实连接 | 临时 known_hosts 严格；错误口令、缺失 key、错误 Host key 必须失败且不重试；不得使用用户 `~/.ssh`。 |
| 真实 Vault password | 另一个隔离 sshd fixture 明确允许仅测试账号 password auth；隐藏导入登录密码并验证共享操作路径 | 密码仅在容器/临时环境生成，auth log/输出不泄露；错误密码最多一次提示，不回退其他身份。 |
| Windows 原生 | 独立临时文件验证 `FileSecurity` 清除继承和旧 ACE，只授权当前用户；独立 CLI/客户端用例验证退出后 Broker 复用；PowerShell fixture 通过 Win32 console visibility 检查后台窗口 | 当前 fixture 已覆盖临时私钥权限、分离生命周期及 scoped 隐藏进程检查。真实密码认证、完整 ConPTY/可见窗口变体、所有认证 operation/权限场景仍为 NOT_RUN，不由 fixture 外推整台桌面的交互体验，不用 Unix `0600` 或平凡 stdout 捕获代替真实终端验收。 |

真实 password 与 publickey fixture 必须隔离服务端配置；不能为了图方便在用户 sshd 上开启密码登录，也不能把容器密码或私钥提交到仓库。若某条路径尚未实现对应 interactive 驱动，应将该子项标 NOT_RUN 或明确 unsupported，而不是改写成 pass。

### npm 薄启动器与分发

- `npm test --prefix npm` 使用 Node 内置测试驱动，校验 os/arch/target triple、可选包缺失/版本错配拒绝、Unix `execve` 的 argv0、Windows argv/退出码与信号转发、发布 manifest 精确版本锁定、native 版本握手及离线 tarball 解包透传。
- 该 suite 在当前 Windows x64 与隔离 Linux x64 上分别实跑 11/11；Windows 还实际打包并启动 native core。Linux 另做实际 platform/core tarball 打包检查。macOS 适配与产物目标暂停，未提供或验证 macOS optional 包。
- 普通安装不用 `postinstall` 下载、用户侧 Cargo、N-API 或 PATH 回退。`REMXO_CORE_PATH` 仅用于开发或隔离 fake，不能把它描述成生产解析规则。
- `.github/workflows/ci.yml` 的 `npm-launcher` 在 Windows 执行上述测试，其余 Linux 检查都放在 Instabox；`.github/workflows/npm-release.yml` 用同一版本 Rust release 构建与 native `--version` 握手打包，并在 tag 触发时执行 `npm stage publish`。stage-only token 不直接公开版本；真实 registry 批准、跨发布版本升级及 npm Trusted Publishing 尚未执行，必须保留为待验收或 `NOT_RUN`；macOS 适配与打包目前暂停。

## GitHub Actions and Instabox CI

- `.github/workflows/ci.yml`: Windows 上的 fmt、Clippy、Rust 全部测试和构建，以及 Windows `npm-launcher` 测试。为节省私有仓库的 GitHub 原生 runner 额度，Ubuntu Rust 检查、Rust 1.88 MSRV Docker 和 Linux npm 检查统一放到 Instabox；不把 Linux 结果外推成其他系统通过。macOS 适配和产物目标目前暂停。
- `.github/workflows/instabox.yml`: 6 类隔离任务，直接 `runs-on: instabox-medium`，覆盖 Rust/release 检查、Rust 1.88 MSRV Docker 与 Linux npm 启动器、cargo-audit/Python 静态检查、fake/PTY/TUI、真实 sshd/sudo、20 轮并发稳定性。GitHub App 为每个 job 提供新 Ubuntu 24.04 runner 并在迭代结束时删除；不注入用户 Vault/Secrets。最多 3 个并发，避免一分钟启动限流。
- 该 App 使用 GitHub 所需 Metadata/Actions/Administration 权限注册和回收 runner；App backend 不需要 `runs-on: instabox-medium` 作业配置 API Key。公开 fork PR 不启动这些任务，skipped/not_run 不代表通过。
- `.github/workflows/npm-release.yml`: 版本 tag 或手动触发，最多 3 个并发。Linux core 与 launcher 在 `instabox-medium` 上完成精确版本构建、打包及精确 tarball 安装验收；Windows 在 GitHub 原生 runner 上构建。tag 触发时上传 tarball artifact 并调用 `npm stage publish`，不注入用户 Vault/Secrets，不直接公开 registry 版本。真实 stage 批准、registry 发布和 npm Trusted Publishing 未因此标为通过，macOS 产物目标目前暂停。
- `scripts/test/instabox-run.sh` 用官方 `instabox run --push . --timeout 10m` 的方法做开发期单次测试，命令结束自动删机；它不是 GitHub Actions runner，也未用于 push 后的 CI。
- `tests/property_invariants.rs`：任意 Unicode 多参数 token 往返、单 raw script 语义、输出 UTF8/控制符边界、明确秘密格式，以及 target 优先级。每组 property 128 例。
- 历史 CI 或另一提交的绿灯不能替代当前认证改动的测试；报告必须对应实际源状态、二进制和 suite。

CI 的覆盖并未把本工具自称为跨发行版或跨平台全兼容；Windows 原生基础测试、Linux 交互协议测试、真实 Vault 认证和 L1 威胁模型是不同层次。macOS 适配与产物目标暂停，未列入当前可选平台包。

## 清理与安全约束

- 测试仅结束自己启动的 Broker、PTY、进程组和容器。Broker endpoint 只读取数字 PID；token 不显示、打印或用于绕过 Remxo，清理 pid 文件被自动删除。
- 不使用 `pkill ssh`、`pkill remxo`、全局 Docker purge、Instabox rm 或公共 Host 配置修改。
- 不向用户或生产服务器发命令；测试写入只发生在隔离 fixture 中，断线、取消和超时不会盲目重试写操作。
- 被测真的临时容器和本机 fake 都会执行命令，但命令只在测试专用隔离环境中。
- 新增私钥 fixture 源文件、密码 gadget 和 managed runtime 都只放临时目录；扫描/失败输出不得复制完整 PEM、密码、Secret RPC 或 ASKPASS stdout。
- 若发生失败，用阶段名、错误类别、退出码及受限日志定位；先检查实际执行输出，再判断生产 bug 或 fixture bug。

## Instabox 并行执行

五台机器意义是隔离风险和并行获取真实结果，不是重复堆高测试计数。源代码同步至每台 `/data/workspace/remxo`，机器均 `--no-vault --secrets none`。下载、完整编译与长测试通过 `instabox ssh` 运行，不依赖 `exec` 的 60 秒上限。

| 机器 | 角色 |
| --- | --- |
| remxo-dev | 全量 Rust 检查、汇总及一键测试 |
| remxo-fake | 故障注入与 fake 安全边界 |
| remxo-cli | PTY、隐藏密码、备份与 TUI |
| remxo-sshd | Docker 真 SSH/SFTP/隧道/任务及新增 Vault 认证矩阵 |
| remxo-stress | 并发、稳定性与进程回收 |

不启动组织或个人 Vault，不上传 HOME 私钥/Remxo Vault、不公开端口、不删除机器。新增认证测试只生成临时 test-only key/password，结果日志不得携带这些值。如果需要额外跨发行版、原生 Windows/macOS、用户真实环境或大规模负载测试，那是环境扩展，不在上述结果保证内。

## 尚不能由这些测试证明的事项

- 无独立安全审计、无“绝对安全”或 L2/L3 保证。
- fake 不证明真远程服务器兼容性；单次 Alpine SSH 测试也不证明所有 SSH 服务端、shell、硬件密钥、MFA 或网络设备兼容性。ASKPASS 明确拒绝 MFA/OTP/PIN/token，不是相关支持声明。
- 局部单测通过不证明未逐项执行的 exec/task/interactive/SCP/SFTP/tunnel 路径都正确；本次已通过的 fake ASKPASS 与真实 Vault password/key exec+SCP 也不能外推为全部操作、错误凭据或超时/取消路径。
- PTY 基础 TUI 通过不表示尚未实现的编辑/审批/备份向导已经工作，也不自动覆盖最新中英语言选择和 Vault 凭据事务边界。
- 远程脱离任务、跨 Broker 持久化、PowerShell/CMD、Telnet 网络自动化、连接复用、生物识别仍需独立实现与测试。
- 既有隔离 Alpine sudo 场景不改变其他 sudoers/PTY 细节仍需独立系统测试的事实；不猜密码、不穷举。
- 只检查 argv/env/log/输出的泄露，不声称证明所有内存拷贝、core dump 或其他秘密类别均已消失。
- 正常 drop 删除临时 key 不等于异常退出清理或安全擦除；专项 ACE/窗口 fixture 不代表完整 Windows 认证、ConPTY 或真实桌面窗口矩阵，不能据此宣称跨平台权限或认证验证。

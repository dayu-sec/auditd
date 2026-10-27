# dayu-sec fork 说明

本仓库 fork 自 [Neo23x0/auditd](https://github.com/Neo23x0/auditd)（Apache-2.0）。
`master` 跟踪上游；**实际下发用 `dayu` 分支**。

fluent-bit 仍只 tail `/var/log/audit/audit.log`，规则变了采集配置不用改。
这是遥测，不是检测引擎：恶意软件 / 漏洞 / 内存马 / 勒索仍看 CWP。

## 相对上游默认关掉的

上游自己把 execve / socket / 失败文件访问标成 *High Volume*，并写「太多就关掉」。
靶机 `LAB-TARGET-01`（LAB-TARGET-01）2026-09-23 实测：

| 规则 | 实测 | 本分支 |
|---|---|---|
| 基线（4 条 `-p x` watch） | ~3 MB/天 | 保留 |
| 全量 `execve` | **+300 MB/天** | **关**（`overlays/high-volume.rules`） |
| `setuid/setgid/setresuid/setresgid` | **+85 MB/天** | **不用**（上游也没有） |
| `execve -F auid!=unset` | 会话内进程（含 root）；靶机无交互用户故实测 ~0 | **开**（`process_creation_user`；2026-10-09 由 `auid>=1000` 放宽） |
| `execve -F exe=/usr/bin/bash` | **+1 MB/天** | **开**（`process_creation_bash`） |
| `connect` 仅 bash / python3 / nc（IPv4/IPv6） | 金丝雀 | **开**（`bash_connect` / `python_connect` / `nc_connect`）；全量 connect 仍关 |
| 当天 SYSCALL 的 97% | `comm=cron` | **排除** cron 其它 syscall；`cron_exec` 已于 09-24 删除（实测 0 命中） |

其余：

| 段 | 处理 | 原因 |
|---|---|---|
| IPv4/IPv6 `connect` success | 关 | 量等同 High Volume |
| `socket` AF_INET/INET6 | 关 | 同上 |
| `-S all` 的 32-bit 兜底 | 关 | 上游标在 High Volume；要开走 overlay |
| `/var/lib/docker -p wa` | **开**（`-w`，非递归） | 只看数据目录本身的创建/删除；不要改成 `-F dir=` |
| IPC（msg/sem/shm） | 关 | docker 易吵 |
| `/var` `/home` `/srv` 失败 open、`auid=unset` EACCES | 关 | 守护进程噪声 |
| High Volume 失败 mkdir/chmod | 关 | 与 `unauthedfileaccess` 重叠 |
| `mknod` | 加 `auid!=unset` | 容器运行时 |
| `31-privileged` 生成 watch | `scripts/gen-privileged-rules.sh` | 提权用 path+perm=x |
| curl/wget/nc/python3 `-p x` | 保留 | `-D` 后需要加回 |
| `-e 2` immutable | 保持关 | 改规则必须能随时加载 |

**仍开着的上游主体**：身份库 / PAM / sudoers / cron 配置 / SSH / root `.ssh` / 内核模块 / 挂载 / 时间 / AppArmor / systemd / `ptrace` / `memfd_create` / `bpf` / `unshare` / `io_uring` / `userfaultfd` / AF_ALG / 原始套接字。

## 2026-10-09：execve 放宽到 `auid!=unset`

现象：靶机上 root 跑 `vi testcr.json`，自采主机日志（audit.log → fluent-bit → 19006）里**没有任何记录**，只有腾讯云 CWP 收到。原因是原 `process_creation_user` 用 `-F auid>=1000`，**把 root（auid=0）整个排除**，而 `process_creation_bash` 的 `-F exe=` 匹配的是被执行的二进制（`vi` 不是 bash）。

改法：`-F auid>=1000 -F auid!=unset` → `-F auid!=unset`（两 arch 各一条，仍保留 `process_creation_bash`）。key 名不变，**引擎侧 `host_audit_syscall/adm.oml` 的 key→operation 映射无需改**。

- **覆盖**：SSH / 本地登录会话里的进程（root 与普通用户都算）。
- **不覆盖**：`auid=unset` 的进程——开机守护进程、cron、云 agent（TAT / CWP），以及经 agent 远程执行的命令。要抓这类只能上全量 execve（overlay，+300 MB/天），不属本次变更。
- **量**：靶机无交互用户，实测近 0；铺生产前按下面流程先靶机 24h 看量。

## 下发（先靶机，24h 看量再铺）

```bash
cp -a /etc/audit/rules.d /etc/audit/rules.d.bak.$(date +%Y%m%d%H%M)
auditctl -l > /tmp/auditctl-l.before

install -m 640 audit.rules /etc/audit/rules.d/99-dayu.rules
# 可选：本机 SUID
bash scripts/gen-privileged-rules.sh > /etc/audit/rules.d/99-privileged.rules

augenrules --load
auditctl -s    # lost 必须为 0
```

麒麟 V10 不走这条：先用 `scripts/prepare-kylin-rules.py` 生成，见下文「麒麟 V10（4.19）」。
不要把 `overlays/` 拷进 `rules.d`。回滚：拷回 `rules.d.bak.*` 再 `augenrules --load`。

24h 检查：

```bash
ls -lh /var/log/audit/audit.log
grep -oE 'key="[^"]+"' /var/log/audit/audit.log | sort | uniq -c | sort -rn | head
auditctl -s | grep -E 'lost|backlog|rate_limit'
```

## 明确不开

- 全量 `execve`（要开走 overlay，先看量）
- `-S setuid,setgid,setresuid,setresgid`
- `-e 2`
- 未验收就铺到 145 / 生产

## 麒麟 V10（4.19）适配

麒麟 V10 的 4.19 内核对 `audit.rules` 里的少数 syscall 名不支持，而 `audit.rules:44` 的 `-i`
会让加载错误被吞掉：一条规则里**只要有一个不识别/不实现的 syscall，整条规则都不加载**，
日志里看不出少了什么。因此麒麟主机不直接下发仓库 `audit.rules`。

已知事实（实测，不按版本号猜）：

| syscall | 现象 | 处理 |
|---|---|---|
| `openat2` | 两架构实际调用都是 `ENOSYS`；audit 3.0 的 libaudit 表里也没有 | 两架构两 ABI 都剔除 |
| aarch64 `open/chmod/chown/lchown/mknod/utimes/futimesat/rmdir/unlink/rename` | libaudit 表里有（asm-generic 1024+），实际 `ENOSYS` | 只剔 `arch=b64`；`arch=b32`（arm 兼容 ABI）真实实现，保留 |
| `io_uring_setup` | 厂商回补过，无效参数调用返回 `EFAULT`（不是 `ENOSYS`） | 保留；加载与行为门禁验证，**不按内核版本号删** |
| 缺路径（`/etc/apt`、`/etc/filebeat`、`/opt/CrowdStrike` 等） | 主机上不存在 | 逐条跳过并在报告里列出 |

生成（目标机、root、只读预检）：

```bash
python3 scripts/prepare-kylin-rules.py --source audit.rules --output-dir /var/tmp/dayu-kylin
bash scripts/gen-privileged-rules.sh > /var/tmp/dayu-kylin/99-privileged.rules   # 本机 SUID，仍要生成
```

产物：`99-dayu.rules`（已去 `-i`，`-D/-b/-f` 保留但本工具不执行）+ `coverage.json`。
`coverage.json` 记录 host/架构/内核/audit 版本/`source_sha256`/`generated_sha256`/`uid_min`/
`kernel_cmdline`/ABI 表，以及每条源规则的行号、key、kept/adapted/skipped、原因、在生成文件里的行号。

门禁：

- 仅 `ID=kylin`、`VERSION_ID=V10`、`x86_64|aarch64`、内核 **4.19 系列**；其他平台失败，不产出可部署文件。
- `audit=0` 或 `auditctl -s` 的 `enabled!=1`：非零退出 + 维护窗口动作说明，**不说内核缺能力**，不自动重启。
- syscall 名按本机 libaudit 的对应 ABI 表解析（`ausyscall <arch> --dump`），不硬编码编号；表不可确认就失败。
- 表里有名字不等于内核能跑：`openat2`（4.19 两架构实测 `ENOSYS`）即使出现在表里也剔除；aarch64 的
  asm-generic legacy 名同理，只保留 `arch=b32`（arm 兼容 ABI）。
- 关键 key 的规则里若有关键 syscall 在表里查不到（例如 `execve` 缺失但 `execveat` 还在），**直接失败**，
  不接受“key 还有别的调用”这种降级覆盖。
- `auid>=1000` 换成该机 `/etc/login.defs` 的 `UID_MIN`（对所有指令生效，包括没有 `-S` 的规则）；
  其他过滤条件、key、目录范围、顺序保持不变；仅改阈值的规则在 `coverage.json` 里记 `adapted`。
- `process_creation_user`、`process_creation_bash`、`unauthedfileaccess`、`perm_mod`、`delete`
  必须都 > 0，否则生成失败；其他 key 归零只报告（厂商/可选路径缺失）。
- 输出目录必须是不存在的新路径：`99-dayu.rules` 与 `coverage.json` 在暂存目录里写全后，
  用 `renameat2(RENAME_NOREPLACE)` 整目录发布（无此原语的平台直接失败，不退化成逐文件发布）。
  并发、竞态或写盘失败都不会留下半套产物，也不跟随已有符号链接；重跑换新目录。

不做：改 GRUB/启动参数、重启、`augenrules --load`、生成 privileged（仍用
`scripts/gen-privileged-rules.sh` 本机生成）、改 Agent/FB。

实测（2026-10-26，两台麒麟 V10 靶机）：

| 项 | 结果 |
|---|---|
| aarch64 靶机（`4.19.90-89.11.v2401.ky10`）已部署 `99-dayu.rules` | 与仓库 `audit.rules` **md5 相同**（即未适配基线） |
| 该机当前实际加载 | 224 条；`unauthedfileaccess` **0 条** —— 10 条失败访问规则因 `openat2` 整条没加载，`-i` 把它藏了；文件里 24 行提到 `openat2` |
| 生成产物 | 159 kept / 16 adapted / 45 skipped，174 条规则行；关键 key：`unauthedfileaccess` 10、`perm_mod` 6、`process_creation_*` 各 2、`delete` 2 |
| 跳过原因 | 全是本机不存在的路径（`/etc/apt`、`/etc/filebeat`、`/etc/docker`、`/opt/CrowdStrike`、`/etc/ld.so.preload`、`/etc/securetty` 等），逐条在 `coverage.json` |
| syscall 实测（aarch64） | `openat2`(437)=`ENOSYS`、legacy `open`(1024)=`ENOSYS`、`io_uring_setup`(425)=`EFAULT`（存在）、`openat`(56)=`ENOENT`（正常） |
| x86_64 靶机 | 启动参数 `audit=0`、`auditctl -s` 报 "Cannot open netlink audit socket"、服务 inactive；生成器 exit 2 且不产出文件 |

生成产物保留了该 key 的 10 条规则（去掉了 `openat2`），但**实际加载与行为验证尚未执行**，见下节待办。

麒麟主机现状与待办：

- x86_64 靶机启动参数仍是 `audit=0`，`auditd.service` 因
  `ConditionKernelCommandLine=!audit=0` 起不来 —— 需维护窗口改 GRUB 后重启，本轮不执行。
- ARM64 靶机当前/默认启动项 `audit=1`，但 `/etc/default/grub` 的
  `GRUB_CMDLINE_LINUX` 仍写 `audit=0`：下次重建 GRUB 可能丢审计。只报告，不自动改。
- aarch64 靶机的 `rules.d` 里还有 `sdm2.0.rules`（7 条生效 `-w`，key 与 dayu 重叠
  `cron-change`/`account-change`/`sudoers-change`/`sshd-config-change`/`ssh-key-change`/
  `net-tool-exec`/`interpreter-exec`）：下发前按 skill 报冲突，未删。
- aarch64 靶机上做过一次**受控加载验证**（2026-10-27，`auditctl -R` 临时加载，未改 `rules.d`、未重启，
  结束后用快照恢复运行态）：
  - 加载 200 条（dayu 171 + privileged 29），0 错误，`openat2` 指令 0 条。
  - 失败读取门禁：`auid=5001`、`uid=65534`、`comm=cat`、`arch=c00000b7 syscall=56(openat)
    success=no exit=-13`，命中 `key="unauthedfileaccess"`，记录含 SYSCALL/EXECVE/CWD/PATH/PROCTITLE。
  - 进程门禁：`/usr/bin/true --dayu-probe-2b74c1`、`auid=5002`，命中
    `key="process_creation_user"`，SYSCALL(execve 221)+EXECVE+CWD+PATH+PROCTITLE 齐全。
  - `lost` 前后均 `70342478`（增量 0），`backlog` 0。
  - 恢复：224 条规则回到快照，`rules.d` md5 未变；唯一差异是 `auditctl -l` 把
    `-w /etc/NetworkManager/` 规范化为 `-w /etc/NetworkManager`（语义等价，已在 skill 里归一化比较）。
- 该次加载暴露两个部署阻塞项，均已用机制处理，不再是靠人眼判断：
  1. `sdm2.0.rules` 与 dayu 有 4 条**逐字相同**的 watch（`curl`/`wget`/`nc`/`python3`），
     `auditctl -R` 在第 540 行答 `Rule exists` 并中断，后面的 privileged 根本没加载。
     实测补充：内核允许同 path+perm **不同 key** 共存（`/etc/passwd` 两条不同 key → 2 条规则，
     exit 0），所以这类只会让事件翻倍，不是加载错误。
  2. `-D` 在 `99-dayu.rules` 里；`augenrules` 用 `ls -1v` 按名拼接（Kylin 的 `/usr/sbin/augenrules`
     就是 `for rules in $(/bin/ls -1v ...); do cat ...`），`98-privileged` 排在它前面会被清掉。
     已把 privileged 产物改名 `99-privileged.rules`（排在 `99-dayu.rules` 之后）。
- 新增 `scripts/preflight-rulesd.sh`（只读）：按 augenrules 顺序检查 `-D` 位置、逐字重复 watch、
  同 path+perm 不同 key 重叠、`-i` 残留、多文件带 `-D`；退出码 0/1/2。
  skill 第 1 节扫现存目录、第 2 节把暂存产物放进模拟目录再扫，全部通过才允许写入 `rules.d`。
  fixture 测试见 `tests/test_preflight_rulesd.py`。
- 2026-10-27 已完成 aarch64 靶机 cutover（用户批准：`sdm2.0.rules` 移入备份、统一用 dayu key）：
  备份到独占创建的备份目录（`COMPLETE` 标记、整目录 `rules.d`、有序运行态快照、`coverage.json`），
  `sdm2.0.rules` 与旧 `98-privileged.rules` 移入 `$bak/moved/`（未删除）。`rules.d` 现为
  `99-dayu.rules` + `99-privileged.rules` + 空的 `audit.rules`；`preflight-rulesd.sh` 0 blocker。
  `augenrules --load` 成功：200 条（dayu 171 + privileged 29），`unauthedfileaccess` 10、
  `process_creation_user/_bash` 各 2、`perm_mod` 6、`privileged` 29，`openat2` 0，`lost` 增量 0。
  实测门禁：`auid=5003` 非特权读 `/etc/shadow` → `exit=-13` 命中 `unauthedfileaccess`；
  `/usr/bin/true --dayu-probe-9c31f2`（`auid=5004`）→ `execve(221)` 命中 `process_creation_user`。
- **下游 key 变化**（sdm2.0 退出后，同路径改由 dayu 的 key 记录）：
  `cron-change`→`cron`、`account-change`→`etcpasswd`、`sudoers-change`→`actions`、
  `sshd-config-change`→`sshd`、`ssh-key-change`→`rootkey`；`net-tool-exec` / `interpreter-exec` 不变。
  依赖旧 key 的引擎映射/看板需要同步确认。
- 仍未做：24h 日志量观察（新规则已在 aarch64 靶机生效，观察 `lost` 与 `/var/log/audit/audit.log` 增长）；
  以及 x86_64 侧的加载验证（该机 `audit=0`，需维护窗口改启动参数并重启）。

仓库测试（不需要麒麟机器）：

```bash
python3 -m unittest discover -s tests
```

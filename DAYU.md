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
| `execve -F auid>=1000` | +0（本机无交互用户） | **开**（`process_creation_user`） |
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

## 下发（先靶机，24h 看量再铺）

```bash
cp -a /etc/audit/rules.d /etc/audit/rules.d.bak.$(date +%Y%m%d%H%M)
auditctl -l > /tmp/auditctl-l.before

install -m 640 audit.rules /etc/audit/rules.d/99-dayu.rules
# 可选：本机 SUID
bash scripts/gen-privileged-rules.sh > /etc/audit/rules.d/98-privileged.rules

augenrules --load
auditctl -s    # lost 必须为 0
```

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

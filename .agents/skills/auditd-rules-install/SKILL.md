---
name: auditd-rules-install
description: 在 Linux 主机安装、验收或回滚 dayu auditd 规则（99-dayu.rules / privileged watches）。用户说安装 audit 规则、新机器下发 audit.rules、99-dayu、augenrules、靶机规则、把 audit 规则铺到某台机时使用。不改 Fluent Bit / Agent 采集配置。
---

# 安装 dayu auditd 规则

权威源：本仓 `audit.rules`（`dayu` 分支）+ `DAYU.md`。采集仍 tail `/var/log/audit/audit.log`，本 skill **不改** `dy-log-collect` / Agent。

金标机：LAB-TARGET-01（`10.118.0.14`）的 `/etc/audit/rules.d/99-dayu.rules` 与仓库 `audit.rules` MD5 必须一致。privileged 规则每台现生成，不要从靶机拷。

## 何时用 / 何时不用

用：新 Linux 主机下发、核对某机是否装了 dayu 基线、回滚、24h 量验收。

不用：改 WPL/OML、改 FB/Agent 配置、把 `overlays/` 或靶机 `97-ctr-probe.rules` 当基线、未验收铺 145 / 生产（`DAYU.md` 明确不开）。

缺 Linux root、缺 `auditd`/`augenrules`、或当前是 macOS → `NEEDS_INPUT`，不要在本机假装加载。

## 禁止

| 禁止 | 原因 |
|---|---|
| 拷 `overlays/high-volume.rules` 进 `rules.d` | 靶机全量 execve +300 MB/天 |
| 拷其他机器的 `9*-privileged.rules` | SUID 集合不同，必须本机 `gen-privileged-rules.sh` |
| 把 `97-ctr-probe.rules`（`auid=unset` + `container_exec`）并进基线 | 仓库没有；cron/容器/云 agent 量 |
| `-e 2` | 锁死后改规则要重启 |
| 提交 145 的 `sdm2.0.rules` | 仅 4 条 watch，已含在 `audit.rules:486-489` |
| 改 `auditd.conf` / 安装 auditd 包逻辑写进规则仓 | 规则仓只管 `rules.d` |

## 下发（目标机、root）

仓库根目录：

```bash
# 0. 包与服务
# Ubuntu: apt-get install -y auditd audispd-plugins
# RHEL:   dnf install -y audit
systemctl enable --now auditd
auditctl -s    # enabled 必须 1

# 1. UID_MIN（不是 1000 就先改 audit.rules 再下发）
awk '$1=="UID_MIN"{print $2}' /etc/login.defs

# 2. 备份
cp -a /etc/audit/rules.d /etc/audit/rules.d.bak.$(date +%Y%m%d%H%M)
auditctl -l > /tmp/auditctl-l.before

# 3. 基线 + 本机 privileged
install -m 640 audit.rules /etc/audit/rules.d/99-dayu.rules
bash scripts/gen-privileged-rules.sh > /etc/audit/rules.d/98-privileged.rules

# 4. 加载
augenrules --load
auditctl -s                 # lost 必须 0
auditctl -l | wc -l         # 靶机约 220；privileged 条数因主机而异
md5sum audit.rules /etc/audit/rules.d/99-dayu.rules   # 必须相同
```

发行版自带的 `rules.d/audit.rules`（只有 `-D/-b/-f` 头）留下。不要再放 `sdm2.0.rules`。

可选严格预检（会因缺路径失败，不作为下发门禁）：

```bash
grep -v '^-i$' audit.rules > /tmp/audit.rules.strict
auditctl -R /tmp/audit.rules.strict
```

## 验收

当场：

```bash
auditctl -s | grep -E 'enabled|lost|backlog|rate_limit'
# enabled 1；lost 0
ls /etc/audit/rules.d/99-dayu.rules /etc/audit/rules.d/98-privileged.rules
```

24h 后再铺下一台：

```bash
ls -lh /var/log/audit/audit.log
grep -oE 'key="[^"]+"' /var/log/audit/audit.log | sort | uniq -c | sort -rn | head
auditctl -s | grep -E 'lost|backlog|rate_limit'
```

`lost` 必须保持 0。涨了先加大 `-b`，不要开 overlay。

采集：确认 FB 或 Agent 在跟 `/var/log/audit/audit.log`。本 skill 不改采集配置。

## 回滚

```bash
rm -f /etc/audit/rules.d/99-dayu.rules /etc/audit/rules.d/98-privileged.rules
cp -a /etc/audit/rules.d.bak.<时间戳>/. /etc/audit/rules.d/
augenrules --load
auditctl -s
```

## 现场对照

| 主机 | 规则 | 说明 |
|---|---|---|
| LAB-TARGET-01 `10.118.0.14` | `99-dayu.rules` = 仓库；另有本机 `99-privileged.rules` + 原型 `97-ctr-probe.rules` | 金标；`container_exec` 不要当基线 |
| WarpAxis-01 `10.168.1.145` | 仅 `sdm2.0.rules` 4 条 `-w`（curl/wget/nc/python3），2026-07-02 起未改 | **未装 dayu**；不是后来删的 |

## 交付

报告：主机、UID_MIN、`99-dayu.rules` MD5 是否等于仓库、`auditctl -s` 的 enabled/lost、加载条数、是否生成 privileged、是否动采集配置（应为否）。缺 SSH/root 标 `NEEDS_INPUT`。

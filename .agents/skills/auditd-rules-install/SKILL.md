---
name: auditd-rules-install
description: 在 Linux 主机安装、验收或回滚 dayu auditd 规则（99-dayu.rules / privileged watches）。用户说安装 audit 规则、新机器下发 audit.rules、99-dayu、麒麟 V10 / Kylin、augenrules、靶机规则、把 audit 规则铺到某台机时使用。不改 Fluent Bit / Agent 采集配置。
---

# 安装 dayu auditd 规则

权威源：本仓 `audit.rules`（`dayu` 分支）+ `DAYU.md`。采集仍 tail `/var/log/audit/audit.log`，本 skill **不改** `dy-log-collect` / Agent。

两条入口，先判发行版再动手：

| 目标 | 下发文件 | 入口 |
|---|---|---|
| Ubuntu / RHEL 系通用主机 | `audit.rules` → `99-dayu.rules` | 直接 `install` |
| 麒麟 V10（x86_64 / aarch64，4.19 系列） | `scripts/prepare-kylin-rules.py` 生成的 `99-dayu.rules` | **先预检生成 + 读 `coverage.json`** |

privileged 规则每台现生成，不要从别的机器拷。

**顺序铁律：先备份 → 再扫描冲突 → 再准备产物 → 隔离机验证 → 最后才写 `rules.d`。**
任何写 `rules.d` 的动作都必须在备份成功之后。

## 何时用 / 何时不用

用：新 Linux 主机下发、核对某机是否装了 dayu 基线、回滚、24h 量验收、麒麟 V10 适配下发。

不用：改 WPL/OML、改 FB/Agent 配置、把 `overlays/` 或靶机 `97-ctr-probe.rules` 当基线、未验收铺生产（`DAYU.md` 明确不开）。

缺 Linux root、缺 `auditd`/`augenrules`、或当前是 macOS → `NEEDS_INPUT`，不要在本机假装加载。

## 禁止

| 禁止 | 原因 |
|---|---|
| 先写 `rules.d` 再备份 | 备份里存的是新文件，原配置无法恢复 |
| 拷 `overlays/high-volume.rules` 进 `rules.d` | 靶机全量 execve +300 MB/天 |
| 拷其他机器的 `9*-privileged.rules` | SUID 集合不同，必须本机 `gen-privileged-rules.sh` |
| 把 `97-ctr-probe.rules`（`auid=unset` + `container_exec`）并进基线 | 仓库没有；cron/容器/云 agent 量 |
| `-e 2` | 锁死后改规则要重启 |
| 把某台主机的 `sdm2.0.rules` 当基线 | 只是几条 `-w`，key 与 dayu 重叠；发现即报冲突，**不删未知规则** |
| 在生产跑 `scripts/validate-rules-ci.sh` | 它会清空 `rules.d` 再加载，只在 CI / 隔离机 |
| 改 `auditd.conf` / 装包逻辑写进规则仓 | 规则仓只管 `rules.d` |
| 用 `\|\| true` 掩盖 `augenrules --load` 失败 | 失败要恢复备份并核对运行态 |

## 0. 预检（目标机、root）

```bash
cat /etc/os-release            # 麒麟要 ID=kylin、VERSION_ID=V10
uname -m                       # x86_64 / aarch64 才是首轮支持面
uname -r                       # 只支持 4.19 系列
cat /proc/cmdline              # audit=0 ⇒ 审计没开，规则加载不了
systemctl enable --now auditd
auditctl -s                    # enabled 必须 1；记录 lost / backlog
awk '$1=="UID_MIN"{print $2}' /etc/login.defs
```

`audit=0`、或 `auditctl -s` 的 `enabled` 不是 1 → 停。这是**启动参数/服务**问题（`auditd.service` 有 `ConditionKernelCommandLine=!audit=0`），不是内核缺审计能力。需要改 GRUB 默认启动项并重启，属维护窗口动作，本 skill 不自动改、不自动重启。

## 1. 备份与冲突扫描（任何写入之前）

```bash
set -euo pipefail                 # 任何一步失败就停，不能带着半个备份继续
ts=$(date +%Y%m%d%H%M%S)
bak=/etc/audit/backup-${ts}
mkdir -m 700 "$bak"               # 独占创建：目录已存在直接失败，绝不复用旧备份
cp -a /etc/audit/rules.d "$bak/rules.d"          # 整个目录，含未知规则
if [ -f /etc/audit/audit.rules ]; then
  cp -a /etc/audit/audit.rules "$bak/audit.rules"
fi
auditctl -l > "$bak/auditctl-l.before"                          # 有序运行态快照：重放用，禁止排序
sort "$bak/auditctl-l.before" > "$bak/auditctl-l.before.sorted"  # 排序副本：仅辅助诊断
auditctl -s > "$bak/auditctl-s.before"
test -d "$bak/rules.d" && test -s "$bak/auditctl-l.before"
touch "$bak/COMPLETE"             # 完成标记放在最后：没有它就不许回滚
ls -la "$bak"/rules.d
```

冲突扫描用仓库脚本，不要靠肉眼 grep——手工扫描会漏掉「同一条 watch 被两个文件重复定义」这种致命冲突：

```bash
# 已知重复文件的策略判断（脚本不删文件，只报冲突）
[ -e /etc/audit/rules.d/sdm2.0.rules ] && echo "CONFLICT(policy): sdm2.0.rules exists"

# 现存布局：加载顺序、-D 位置、已有重复 watch、-i
bash scripts/preflight-rulesd.sh /etc/audit/rules.d
```

脚本检查：`-D` 是否跑在已有规则之后（会把前加载的规则清掉）、是否有**逐字相同**的 watch 重复
（内核答 `Rule exists`，整次加载中断）、同 path+perm 不同 key 的重叠（允许但事件翻倍）、`-i` 残留、
多个文件带 `-D`。全部只读，退出码 `0` 无阻塞项 / `1` 有阻塞项 / `2` 用法错误。

发现 `sdm2.0.rules` 或重复控制项：**报冲突**，说明影响，不删任何未知文件。只有用户批准 cutover 后，才把已确认重复的旧文件**移动**进 `$bak/`。

## 2. 准备产物（只写暂存目录，不碰 `rules.d`）

### 通用主机

```bash
stage=/var/tmp/dayu-stage
install -d -m 700 "$stage"
install -m 640 audit.rules "$stage/99-dayu.rules"
if ! bash scripts/gen-privileged-rules.sh > "$stage/99-privileged.rules"; then
  echo "STAGE INCOMPLETE: privileged 扫描失败（见上方 WARNING），停止部署"; exit 1
fi
test -s "$stage/99-dayu.rules" || { echo "STAGE INCOMPLETE: 缺少 99-dayu.rules"; exit 1; }
grep -qE '^-a ' "$stage/99-privileged.rules" \
  || { echo "STAGE INCOMPLETE: privileged 规则为空，确认本机 SUID/filecap 情况后再继续"; exit 1; }
```

### 麒麟 V10

```bash
stage=/var/tmp/dayu-kylin
# 只读预检 + 生成，不进 rules.d、不加载、不改启动参数。
# 输出目录必须是不存在的新路径：两个产物靠整目录 rename 原子发布，重跑要换目录。
python3 scripts/prepare-kylin-rules.py --source audit.rules --output-dir "$stage" || exit 1
# privileged 仍在本机生成：退出码非 0 = 有目录没扫全，产物不完整，禁止部署
if ! bash scripts/gen-privileged-rules.sh > "$stage/99-privileged.rules"; then
  echo "STAGE INCOMPLETE: privileged 扫描失败（见上方 WARNING），停止部署"; exit 1
fi
test -s "$stage/99-dayu.rules" || { echo "STAGE INCOMPLETE: 缺少 99-dayu.rules"; exit 1; }
grep -qE '^-a ' "$stage/99-privileged.rules" \
  || { echo "STAGE INCOMPLETE: privileged 规则为空，确认本机 SUID/filecap 情况后再继续"; exit 1; }
```

退出码：`0` 生成成功；`2` 环境门禁失败（发行版/版本/内核系列/UID_MIN/`audit=0`/缺 `auditctl`·`ausyscall`/写盘失败）；`3` 输出路径已存在（不覆盖，换新目录）；`4` 覆盖门禁失败（关键 key 归零、关键 syscall 无法确认）。

### 加载前模拟扫描（两个入口都要跑）

暂存产物准备好后，把它们放进模拟目录再扫一遍，覆盖「新规则与现存文件冲突」这一类（现存目录单独扫是看不到的）：

```bash
sim=$(mktemp -d /tmp/dayu-preflight.XXXXXX)
cp -a /etc/audit/rules.d/. "$sim"/
install -m 640 "$stage/99-dayu.rules" "$sim/99-dayu.rules"
install -m 640 "$stage/99-privileged.rules" "$sim/99-privileged.rules"
bash scripts/preflight-rulesd.sh "$sim" && rm -rf "$sim" \
  || { echo "PREFLIGHT FAILED: 先解决上面的 BLOCKER（删/移文件需用户批准 cutover）"; exit 1; }
```

`99-privileged.rules` 必须排在 `99-dayu.rules` 之后（`augenrules` 按文件名拼接）：`-D` 在 dayu 文件里，
privileged 若排在它之前会被清掉。

生成后**必须逐项读 `$stage/coverage.json`**：

- `keys_without_rules`：哪些 key 在这台机上一条规则都没留下（通常是厂商/可选路径不存在）。这是真实缺口，报告里要写，不要当全覆盖。
- `rules[]` 里 `status=skipped` 的原因（缺路径 / 无支持 syscall）与 `status=adapted` 的 `dropped_syscalls`、`reason`。
- `critical_keys` 必须全部 > 0：`process_creation_user`、`process_creation_bash`、`unauthedfileaccess`、`perm_mod`、`delete`。
- `generated_sha256`：之后逐字节核对部署文件。
- `audit_boot_parameter`、`uid_min`、`abi_tables`：确认是这台机的实态。

生成的 `99-dayu.rules` 已去掉 `-i`：未知 syscall、缺路径在生成阶段就解决，加载报错就是真错。

## 3. 隔离验证机加载（生产之前）

往 `rules.d` 写文件前先跑第 1 节的 `preflight-rulesd.sh`（模拟目录版本），它已覆盖 `-D` 排序与重复
watch；这一步通过才允许写入并 `augenrules --load`。

用一台同系列麒麟（同架构、root、`audit=1`、无他人依赖）先走完：

```bash
install -m 640 "$stage/99-dayu.rules" /etc/audit/rules.d/99-dayu.rules
install -m 640 "$stage/99-privileged.rules" /etc/audit/rules.d/99-privileged.rules
augenrules --load        # 失败就是失败，不加重试、不 || true
```

加载条数按**全部** `rules.d` 文件核对，不要拿单文件对总数：

```bash
grep -hE '^-(a|w) ' /etc/audit/rules.d/*.rules | wc -l   # 期望规则数
auditctl -l | wc -l                                      # 实际加载数；两者应相等
auditctl -s | grep -E 'enabled|lost|backlog'
```

行为门禁（缺一不能上生产）。**必须从真实普通用户登录会话执行**，`su`/`sudo -u` 不保证改变 audit loginuid：

```bash
ssh <普通用户>@<隔离验证机> '
  cat /proc/self/loginuid            # 必须 >= UID_MIN，不能是 0 / 4294967295
  cat /etc/shadow 2>&1               # 失败读取 → 命中 unauthedfileaccess
  /usr/bin/true --dayu-probe-<唯一标记>
'
# 用日志确认 auid/exe 与上面一致
ausearch -k unauthedfileaccess -ts recent | tail
ausearch -k process_creation_user -ts recent | grep '<唯一标记>'
```

`process_creation_user` 命中记录必须同时有 SYSCALL/EXECVE/PATH/CWD/PROCTITLE，且 `arch` 与主机一致。

记录开始/结束 `lost`，**增量必须 0**，不要重置累计值；观察 `backlog` 能回落。24h 日志量观察未完成要在报告里明说，不能拿旧基线的事件当本次适配验证。

## 4. 部署到目标机

同样先用 `preflight-rulesd.sh` 扫描模拟目录（含本次暂存产物），通过后再写 `rules.d` 并加载。

```bash
install -m 640 "$stage/99-dayu.rules" /etc/audit/rules.d/99-dayu.rules
install -m 640 "$stage/99-privileged.rules" /etc/audit/rules.d/99-privileged.rules
sha256sum "$stage/99-dayu.rules" /etc/audit/rules.d/99-dayu.rules   # 必须相同
augenrules --load
auditctl -s | grep -E 'enabled|lost|backlog|rate_limit'
```

- 麒麟主机核对的是**生成产物**哈希，不是仓库原始 `audit.rules`（适配后本来就不同）。`coverage.json` 的 `generated_sha256` 对同一台机可复现。
- 加载失败或条数不符：按下面“回滚”恢复**文件 + 运行态**，再报失败原因。
- `auditctl -R` 只接受 root 所有、非 world-writable 的普通文件；快照放在 0700 备份目录里即可，
  不要把快照改成所有人可写。

## 5. 24h 观察

```bash
ls -lh /var/log/audit/audit.log
grep -oE 'key="[^"]+"' /var/log/audit/audit.log | sort | uniq -c | sort -rn | head
auditctl -s | grep -E 'lost|backlog|rate_limit'
```

`lost` 必须保持 0。涨了先加大 `-b`，不要开 overlay。采集：确认 FB 或 Agent 在跟 `/var/log/audit/audit.log`，本 skill 不改采集配置。

## 回滚 / 加载失败恢复

磁盘文件与运行态都要恢复，`augenrules --load` 只重建磁盘配置：

```bash
set -euo pipefail
ts=<备份时间戳>; bak=/etc/audit/backup-${ts}

# 0) 先验证备份完整，再动任何现存文件
[ -f "$bak/COMPLETE" ] || { echo "备份不完整（缺 COMPLETE），禁止回滚"; exit 1; }
test -d "$bak/rules.d" && test -s "$bak/auditctl-l.before"

# 1) 在旁路准备好替换目录，成功后才切换；旧目录保留为证据，不删除
work=/etc/audit/.restore-$$
failed=/etc/audit/rules.d.failed-$$
rm -rf "$work"
cp -a "$bak/rules.d" "$work"
mv /etc/audit/rules.d "$failed"
mv "$work" /etc/audit/rules.d
if [ -f "$bak/audit.rules" ]; then
  cp -a "$bak/audit.rules" /etc/audit/audit.rules
fi

# 磁盘恢复后的加载可能失败（例如备份里的 watch 路径已不存在）；
# 这正是运行态快照要兜底的场景，不能让 errexit 跳过恢复步骤
if augenrules --load; then
  echo "restored files loaded"
else
  echo "恢复后磁盘加载失败：继续用运行态快照恢复，并保留上面错误" >&2
fi

# 2) 按**原始顺序**核对运行态（排序比较会漏掉顺序漂移，只能用于诊断）
#    auditctl -l 会把 `-w /dir/ -p` 规范成 `-w /dir -p`，比较前先归一化，否则误报未恢复
normalize() { sed -E 's#([^[:space:]])/ (-p )#\1 \2#'; }
if diff -u <(normalize < "$bak/auditctl-l.before") <(auditctl -l | normalize); then
  echo "runtime restored (order preserved)"
else
  echo "运行态与快照不同：清空后按原始顺序重放"
  auditctl -D || { echo "清空运行规则失败，需人工处理"; exit 1; }
  auditctl -R "$bak/auditctl-l.before" || { echo "快照重放失败，需人工处理"; exit 1; }
  diff -u <(normalize < "$bak/auditctl-l.before") <(auditctl -l | normalize) \
    && echo "runtime restored (replayed)" \
    || { echo "恢复失败：运行态与备份快照仍不同，需人工处理"; exit 1; }
fi
```

排序副本 `$bak/auditctl-l.before.sorted` 只用于人工对比集合，不参与恢复判定。

`auditctl -R` 读的是规则文件；`auditctl -l` 的输出可直接作为输入。重放会短暂清空规则，只在恢复阶段且文件恢复后仍有漂移时使用。

## 交付

报告：主机/发行版/架构/内核、UID_MIN、入口（通用 / 麒麟生成）、`generated_sha256` 与部署文件是否一致、`auditctl -s` 的 enabled/lost（含开始与结束）、期望与实际加载条数、`keys_without_rules`、是否生成 privileged、是否动采集配置（应为否）、是否做过隔离验证与行为门禁（含 `loginuid` 证据）。

麒麟特有未完成项必须写明：`audit=0` 待维护窗口（x86_64 主机）、GRUB `audit=0` 与运行启动项不一致（ARM64 主机）。缺 SSH/root 标 `NEEDS_INPUT`。

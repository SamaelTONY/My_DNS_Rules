# 🛡️ My_DNS_Rules · AdGuard Home 专用 DNS 过滤规则聚合库

[![Update ADG Rules](https://github.com/SamaelTONY/My_DNS_Rules/actions/workflows/main.yml/badge.svg)](https://github.com/SamaelTONY/My_DNS_Rules/actions/workflows/main.yml)

> 一条订阅链接 = 三大优质上游 + 智能去重优化 + 白名单保护 + 每日自动更新 + 熔断防暴。
> 产出物 `my_adg_rules.txt` 直供 AdGuard Home，服务 OEC 家庭网络净化体系。

---

## 📖 项目简介

本仓库是一座 **DNS 广告/追踪过滤规则的“加工厂”**：每天自动拉取三个高质量上游规则集，经 `process_rules.py` 清洗、去重、优化、白名单豁免后，生成单个 AdGuard Home 可直接订阅的过滤文件 `my_adg_rules.txt`，并由 GitHub Actions 机器人自动提交发布。

设计哲学：

- **量产拦截交给上游**：广告/追踪拦截依托成熟上游规则集（HaGeZi / AdRules），本库不自创拦截规则；
- **本库只做“加工 + 保护”**：去重、体积优化、白名单豁免、版本元数据、更新稳定性；
- **宁漏勿错**：白名单机制保障支付、即时通讯、输入法等核心域名永不误杀。

## 🗂 目录结构

```
My_DNS_Rules/
├── .github/
│   └── workflows/
│       └── main.yml          # GitHub Actions 自动化产线（每日构建 + 熔断 + 自动提交）
├── my_adg_rules.txt          # 📦 产出物（约 46.7 万条 / 约 10MB），AdGuard Home 订阅
├── process_rules.py          # 🧠 规则加工引擎 v5.1
├── whitelist.txt             # 🛡 白名单（永不拦截清单，11 个域名）
└── README.md                 # 本文件
```

> `custom_rules.txt`（自定义补充拦截规则）为预留扩展点：文件存在时引擎自动合并，不存在则静默跳过。

## 🔄 数据流

```
HaGeZi Pro ────────┐
                   │
AdRules dns.txt ───┼──▶ process_rules.py ──▶ my_adg_rules.txt ──▶ AdGuard Home（OEC 旁路由）
                   │     · 格式校验          │  · ||domain^ 拦截规则
HaGeZi TIF Mini ───┘     · 全局去重          │  · @@||domain^ 白名单例外
                         · 父域覆盖优化      │  · 版本/校验和元数据
                         └─ whitelist.txt ───┘
```

## 📥 规则来源

| 上游 | 路径 | 定位 | 贡献量（#165 构建） |
|---|---|---|---|
| **HaGeZi Pro** | `hagezi/dns-blocklists/adblock/pro.txt` | 广告/追踪拦截主力 | 226,420 |
| **Cats-Team AdRules** | `Cats-Team/AdRules/dns.txt` | 国内生态与新兴规则补强 | 117,217（独有） |
| **HaGeZi TIF Mini** | `hagezi/dns-blocklists/adblock/tif.mini.txt` | 追踪/注入/遥测拦截 | 133,824（独有） |

## 🧠 加工引擎（process_rules.py v5.1）

### 1. 格式校验
仅接受标准 AdBlock 语法 `||domain^`；跳过非标准行（每次构建约 60 余行）；域名必须含点、长度 ≥ 4、无空段或连字符首尾段。

### 2. 去重与优化
- 三源全局去重（原始约 47.7 万条）；
- **父域覆盖优化**：父域已保留则删除子域规则（每次构建约移除 9.7k 冗余、压缩 ~2%），体积更小、覆盖不减。

### 3. 白名单机制（核心保护）
- 载入 `whitelist.txt`（`||domain^` 格式，父域名自动覆盖其全部子域名）；
- **物理剔除**：白名单域名及其子域的拦截规则直接从产出物中移除；
- **双保险**：同时在文件尾部追加 `@@||domain^` 例外规则，即使上游未来新增规则也能确保豁免。

### 4. 产出元数据
文件头部包含机器可读元数据，供下游监控消费（见「OEC 生态联动」）：

```
! Title: OEC Master Rules (Pro/AdRules/TIF Mini Build)
! Version: 202609050548          ← UTC 构建时间戳 (YYYYMMDDHHMM)
! Last-Modified: Fri, 05 Sep 2026 ... GMT
! Total Rules: 467,736
! Checksum-MD5:  …
! Checksum-SHA1: …
! Size-Estimated: 10325.0 KB
! Source: https://github.com/SamaelTONY/My_DNS_Rules
```

### 5. 命令行参数（本地调试）

```bash
python process_rules.py -o my_adg_rules.txt   # 指定输出文件
python process_rules.py --dry-run             # 只加工不写文件
python process_rules.py -v                    # 详细日志
python process_rules.py -s <url1> <url2>      # 临时覆盖上游源
```

## 🤖 自动化产线（GitHub Actions）

| 项 | 配置 |
|---|---|
| 触发 | 每日 **北京时间 05:35**（UTC 21:35）+ 手动 `workflow_dispatch` |
| 运行时 | ubuntu-latest · Python 3.11 · **Node 24 原生 Actions** |
| 并发 | `rules-update` 组，重叠运行自动取消 |
| 超时 | 20 分钟 |
| 提交 | `github-actions[bot]` 仅自动提交 `my_adg_rules.txt` |
| 产物 | `rules-<run_number>.zip`（保留 2 天，可追溯） |

### 🛡 三重安全机制

1. **非空校验**：产出为空立即 abort，拒绝提交，杜绝“规则清零”事故；
2. **30% 熔断器**：新旧规则数波动超过 30% 视为上游异常，自动停止提交（换源等大调整可用 `force_accept=true` 手动绕过）；
3. **Git 每日快照**：每次成功构建即一个 commit，可回滚任意历史版本。

## 🛡 白名单哲学

`whitelist.txt` 现含 11 条，分两类：

**历史误杀修复（已实机验证）**

| 域名 | 用途 |
|---|---|
| `ecare365.com` | 历史误杀修复的业务域名 |
| `dns.weixin.qq.com.cn` / `szlong.weixin.qq.com` | 微信长连接 / 小程序 |
| `amdc.alipay.com` | 支付宝调度服务 |
| `ws-keyboard.shouji.sogou.com` | 搜狗输入法云服务 |

**国内高频误杀预防**

| 域名 | 用途 |
|---|---|
| `minorshort.weixin.qq.com` / `szextshort.weixin.qq.com` | 微信短链通道 |
| `acs.m.taobao.com` / `fourier.taobao.com` | 淘宝登录风控 / 滑动验证 |
| `biliapi.net` / `hdslb.com` | 哔哩哔哩 API / CDN |

**原则**：尽量精确子域名、谨慎整域放行（隐私优先）；误杀须经实机验证后才加入。

## 🚀 订阅方式

在 AdGuard Home / AdGuard 的「过滤器 → 自定义」中添加：

```
https://raw.githubusercontent.com/SamaelTONY/My_DNS_Rules/main/my_adg_rules.txt
```

建议更新间隔：**24 小时**（与每日 05:35 构建对齐）。

## 🧩 OEC 生态联动

本仓库是 OEC 家庭网络体系的**“量产规则层”**：

- **下游消费**：OEC（iStoreOS 旁路由）AdGuard Home 订阅本仓库产出物；
- **特例补丁层**：OEC 本地「系统大脑」规则清单负责 `$important` 特例补丁（YouTube 链路、连通性检测等），与本库分工协作；
- **产线监控**：OEC 健康哨兵每日读取 `! Version:` 时间戳，**产出物超过 72 小时未更新即告警**，杜绝“产线静默停摆”。

## 🛠 手动运维指南

| 场景 | 操作 |
|---|---|
| 立即重新构建 | Actions → `🔄 Update ADG Rules` → `Run workflow` |
| 故意换源 / 绕过熔断 | 运行时勾选 `force_accept` |
| 新增白名单 | 编辑 `whitelist.txt` 提交，下次构建自动生效（可手动触发） |
| 回滚规则 | 提交历史中定位日期 commit，Revert `my_adg_rules.txt` |
| 本地调试 | `pip install requests urllib3 && python process_rules.py --dry-run -v` |

## 📊 构建数据快照（#165 · 2026-09-05）

| 指标 | 数值 |
|---|---|
| 原始规则合计 | 477,461 |
| 父域优化后 | 467,734（-9,727，-2.0%） |
| 白名单剔除 | 9 |
| @@ 例外追加 | 11 |
| **最终产出** | **467,736 条 / 约 10.1 MB** |
| 构建耗时 | 约 22 秒 |

## ❓ FAQ

**Q：为什么不直接订阅三个上游？**
A：单一订阅点 = 统一去重 + 白名单保护 + 熔断防暴 + 版本可追溯。上游是“原料”，本库是“成品”。

**Q：某个 App 被误杀怎么办？**
A：确认误杀后，将对应（子）域名加入 `whitelist.txt` 并提交，下次构建同时生效“物理剔除 + @@ 豁免”。

**Q：某天没有新 commit？**
A：规则无变化时 `git-auto-commit-action` 自动跳过；或被熔断器拦截（查看 Actions 日志中的熔断输出）。

**Q：体积会一直涨吗？**
A：引擎内置 15MB 警告线，父域优化持续压缩冗余；真超限可评估上游降级或差异拆分。

## 🙏 致谢

- [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists)
- [Cats-Team AdRules](https://github.com/Cats-Team/AdRules)
- [stefanzweifel/git-auto-commit-action](https://github.com/stefanzweifel/git-auto-commit-action)

---

*本仓库规则按“原样”提供，关键业务请自行验证后使用。拦截不是安全的全部，平衡才是。*

# MRS 规则集生成器

一个自动化工具，用于下载、处理和转换各种网络规则列表，并生成 Mihomo Rule Set (MRS) 格式的规则文件。

## 项目结构

```
.
|-- .github/workflows/mrs.yml  # GitHub Actions 工作流
|-- LICENSE
|-- README.md
|-- config.yaml   # 配置文件
|-- rules/        # 已生成的规则产物
|-- scripts/      # 辅助脚本
|-- tests/        # 测试用例
`-- start.sh      # 主脚本
```

## 输出文件

每个任务会在发布分支的 `rules/` 目录下生成两类文件：

- 纯文本规则文件 `*.txt`
- Mihomo Rule Set 格式文件 `*.mrs`

同时会生成：

- `artifacts-manifest.json`：记录每个规则集的行为类型、来源、文件大小、行数和 SHA-256。
- `README.md`：提供产物列表和可复制的 Mihomo `rule-providers` 配置。

默认发布配置位于 [config.yaml](config.yaml) 的 `publish` 节点下：

- `branch`：产物发布分支，默认使用 `release`
- `rules_dir`：产物目录，默认使用 `rules`
- `raw_base_url`：生成 README 时使用的 Raw URL 前缀

## 当前配置的规则集

| 规则集 | 类型  | 说明                               |
| ------ | ----- | ---------------------------------- |
| `ad`   | 域名  | 广告过滤规则，整合多个广告拦截列表 |
| `SteamCN` | 域名  | Steam 中国区及相关游戏下载域名规则 |
| `cnIP` | IP 段 | 中国大陆 IP 地址段                 |

## 依赖

运行脚本依赖以下命令行工具：

`bash yq jq curl wget gunzip sha256sum python3`

说明：

- GitHub Actions 使用 Linux 环境执行脚本
- 本项目主脚本为 Bash 脚本，本地运行更适合 Linux、WSL 或 Git Bash 环境

## GitHub Actions

项目配置了自动化工作流 [`.github/workflows/mrs.yml`](.github/workflows/mrs.yml)：

- 每天北京时间 3 点 45 分自动运行，可通过 GitHub 界面手动触发，可配置保留历史数量

## 工作流程

脚本 [start.sh](start.sh) 的处理流程如下：

1. 读取 [config.yaml](config.yaml) 配置
2. 从 Mihomo Releases 下载转换程序并校验摘要
3. 下载各任务配置的远程规则源
4. 清洗、转换、重写、排除并去重规则
5. 输出 `txt` 文件，并按需转换为 `mrs` 文件
6. 生成 `artifacts-manifest.json` 和规则使用说明
7. 将结果同步到发布分支的 `rules/` 目录
8. 当规则内容发生变化时，自动提交并推送发布分支

## 配置说明

任务配置位于 [config.yaml](config.yaml) 的 `tasks` 节点下。每个任务至少应包含以下字段：

- `behavior`：规则行为类型，当前仅支持 `domain` 和 `ipcidr`
- `format`：输出格式，填写 `mrs` 时会额外生成 Mihomo Rule Set 文件
- `src`：规则源地址列表

建议：

- 域名规则使用 `behavior: "domain"`
- IP 网段规则使用 `behavior: "ipcidr"`
- 新增任务时显式填写 `behavior`，不要依赖输入内容推断类型

域名任务常用的清洗字段如下：

- `rewrite`：仅用于后缀替换。键为待匹配的后缀，值为替换后的完整规则。
- `exclude`：用于删除规则，支持完整匹配和后缀匹配。
- `exclude_regex`：用于处理前两种方式不方便表达的正则排除场景。

建议约定：

- 需要删除规则时，统一写入 `exclude` 或 `exclude_regex`
- 不要使用 `rewrite: xxx: null` 表达删除；这类规则应直接写入 `exclude`
- 只有确实需要改写规则值时，才使用 `rewrite`


## 许可证

本项目使用 GPL-3.0 许可证。详见 [LICENSE](LICENSE) 文件。

### 🔴 强制要求

- **必须开源**：任何使用本项目代码的软件都必须开源
- **相同许可证**：衍生作品必须使用 GPL-3.0 或兼容许可证
- **提供源码**：分发二进制文件时必须同时提供源代码
- **保留版权**：必须保留原始版权声明和许可证文本

### 🚫 禁止行为

- ❌ 将本项目代码用于闭源商业软件
- ❌ 删除或修改许可证声明
- ❌ 声称拥有本项目的专有权利
- ❌ 在专有软件中静态链接本项目代码

### ✅ 允许行为

- ✅ 自由使用、修改、分发
- ✅ 用于开源项目
- ✅ 商业使用（但必须开源）
- ✅ 通过网络 API 调用（无需开源调用方）

## 规则源说明

本项目目前聚合的规则来源于以下开源项目：

- [anti-AD](https://github.com/privacy-protection-tools/anti-AD)
- [AdRules](https://github.com/Cats-Team/AdRules)
- [meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)
- [a-dove-is-dumb](https://github.com/ignaciocastro/a-dove-is-dumb)

各规则源保持其原有许可证，本项目仅提供聚合和转换服务。

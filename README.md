# RuleList

自动下载、清洗并转换规则源，生成 Mihomo 可用的 `rule-providers` 规则集。

主分支 `main` 只保留源码、配置和自动化脚本；生成结果发布到 `release` 分支，避免规则产物污染源码历史。

## 产物地址

发布分支：[`release`](https://github.com/Jarv1s0/RuleList/tree/release)

规则文件目录：[`release/rules`](https://github.com/Jarv1s0/RuleList/tree/release/rules)

发布说明和索引：

- [`README.md`](https://github.com/Jarv1s0/RuleList/blob/release/README.md)
- [`manifest.json`](https://github.com/Jarv1s0/RuleList/blob/release/manifest.json)

Raw URL 示例：

```text
https://github.com/Jarv1s0/RuleList/raw/release/rules/SteamCN.mrs
```

## 主分支文件

```text
.
|-- .github/workflows/mrs.yml  GitHub Actions 工作流
|-- config.yaml                规则源、发布分支和 Mihomo 下载配置
|-- scripts/release.py
|                               生成 release README 和 manifest
|-- start.sh                   主构建脚本
|-- LICENSE
`-- README.md
```

`rules/` 不再保留在 `main` 分支；规则产物只在 `release` 分支维护。

## 自动更新

工作流 `.github/workflows/mrs.yml` 会在以下情况运行：

- 每天北京时间 03:45 定时运行
- 手动触发 `workflow_dispatch`
- 修改 `.github/workflows/mrs.yml`、`config.yaml`、`start.sh` 或 `scripts/**` 后推送

运行流程：

1. 安装 `bash`、`curl`、`jq`、`wget`、`gzip`、`coreutils`、`python3`、`yq`
2. 执行 `bash ./start.sh`
3. 下载 Mihomo release 二进制并校验 SHA-256
4. 下载并清洗 `config.yaml` 中配置的规则源
5. 生成 `*.txt` 和 `*.mrs`
6. 生成 release 根目录的 `README.md` 和 `manifest.json`
7. 将产物提交并推送到 `release` 分支

## 配置说明

入口配置文件是 `config.yaml`。

发布配置：

```yaml
publish:
  branch: "release"
  rules_dir: "rules"
  raw_base_url: "https://github.com/Jarv1s0/RuleList/raw/release/rules"
```

任务配置位于 `tasks`。每个任务至少需要：

- `behavior`：`domain` 或 `ipcidr`
- `format`：当前使用 `mrs`
- `src`：规则源 URL 列表

域名任务支持：

- `rewrite`：按后缀替换规则
- `exclude`：按完整匹配或后缀匹配删除规则
- `exclude_regex`：按正则删除规则

## 本地运行

本地运行更适合 Linux、WSL 或 Git Bash 环境。

依赖命令：

```text
bash yq jq curl wget gunzip sha256sum git python3 mktemp
```

执行：

```bash
bash ./start.sh
```

注意：脚本会联网下载 Mihomo 和规则源，并在产物变化时提交、推送 `release` 分支。

## 规则来源

- [anti-AD](https://github.com/privacy-protection-tools/anti-AD)
- [AdRules](https://github.com/Cats-Team/AdRules)
- [meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)
- [a-dove-is-dumb](https://github.com/ignaciocastro/a-dove-is-dumb)
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)

各规则源保持其原许可证；本仓库只做聚合、清洗和格式转换。

## License

本项目使用 GPL-3.0。详见 [LICENSE](LICENSE)。

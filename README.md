# RuleList 规则产物

生成时间：`2026-05-11T11:44:45+08:00`

## 产物列表

### SteamCN

- 规则类型：`domain`
- 来源数量：`3`
- `SteamCN.txt`：26 行，616 字节，https://github.com/Jarv1s0/RuleList/raw/release/rules/SteamCN.txt
- `SteamCN.mrs`：497 字节，https://github.com/Jarv1s0/RuleList/raw/release/rules/SteamCN.mrs

### ad

- 规则类型：`domain`
- 来源数量：`4`
- `ad.txt`：198646 行，4409362 字节，https://github.com/Jarv1s0/RuleList/raw/release/rules/ad.txt
- `ad.mrs`：1837021 字节，https://github.com/Jarv1s0/RuleList/raw/release/rules/ad.mrs

### cnIP

- 规则类型：`ipcidr`
- 来源数量：`2`
- `cnIP.txt`：8687 行，140328 字节，https://github.com/Jarv1s0/RuleList/raw/release/rules/cnIP.txt
- `cnIP.mrs`：36707 字节，https://github.com/Jarv1s0/RuleList/raw/release/rules/cnIP.mrs

## Mihomo rule-providers 配置

```yaml
rule-providers:
  SteamCN:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Jarv1s0/RuleList/raw/release/rules/SteamCN.mrs"
    path: ./ruleset/SteamCN.mrs
    interval: 86400
  ad:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Jarv1s0/RuleList/raw/release/rules/ad.mrs"
    path: ./ruleset/ad.mrs
    interval: 86400
  cnIP:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://github.com/Jarv1s0/RuleList/raw/release/rules/cnIP.mrs"
    path: ./ruleset/cnIP.mrs
    interval: 86400
```

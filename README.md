# RuleList 规则产物

生成时间：2026-07-10 05:06:55（北京时间 UTC+08:00）

## 产物列表

### SteamCN

- Behavior: `domain`
- Sources: `3`
- `SteamCN.txt`：28 lines，645 bytes，https://github.com/Jarv1s0/RuleList/raw/release/rules/SteamCN.txt
- `SteamCN.mrs`：515 bytes，https://github.com/Jarv1s0/RuleList/raw/release/rules/SteamCN.mrs

### ad

- Behavior: `domain`
- Sources: `4`
- `ad.txt`：191022 lines，4255465 bytes，https://github.com/Jarv1s0/RuleList/raw/release/rules/ad.txt
- `ad.mrs`：1774844 bytes，https://github.com/Jarv1s0/RuleList/raw/release/rules/ad.mrs

### cnIP

- Behavior: `ipcidr`
- Sources: `2`
- `cnIP.txt`：5770 lines，93473 bytes，https://github.com/Jarv1s0/RuleList/raw/release/rules/cnIP.txt
- `cnIP.mrs`：26515 bytes，https://github.com/Jarv1s0/RuleList/raw/release/rules/cnIP.mrs

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

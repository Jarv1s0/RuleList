# RuleList Artifacts

Generated at: `2026-05-11T11:31:27+08:00`

## Artifacts

### SteamCN

- Behavior: `domain`
- Sources: `3`
- `SteamCN.txt`: 26 lines, 616 bytes, https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/SteamCN.txt
- `SteamCN.mrs`: 497 bytes, https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/SteamCN.mrs

### ad

- Behavior: `domain`
- Sources: `4`
- `ad.txt`: 198646 lines, 4409362 bytes, https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/ad.txt
- `ad.mrs`: 1837021 bytes, https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/ad.mrs

### cnIP

- Behavior: `ipcidr`
- Sources: `2`
- `cnIP.txt`: 8687 lines, 140328 bytes, https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/cnIP.txt
- `cnIP.mrs`: 36707 bytes, https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/cnIP.mrs

## Mihomo rule-providers

```yaml
rule-providers:
  SteamCN:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/SteamCN.mrs"
    path: ./ruleset/SteamCN.mrs
    interval: 86400
  ad:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/ad.mrs"
    path: ./ruleset/ad.mrs
    interval: 86400
  cnIP:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/Jarv1s0/RuleList/release/rules/cnIP.mrs"
    path: ./ruleset/cnIP.mrs
    interval: 86400
```

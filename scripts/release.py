#!/usr/bin/env python3
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def file_lines(path):
    if not path.exists() or path.suffix == ".mrs":
        return None
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def format_list(value):
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def artifact_files(output_dir, task_name, rule_format):
    files = []
    txt_path = output_dir / f"{task_name}.txt"
    if txt_path.exists():
        files.append(txt_path)

    if "mrs" in str(rule_format).split(","):
        mrs_path = output_dir / f"{task_name}.mrs"
        if mrs_path.exists():
            files.append(mrs_path)
    return files


def format_generated_at_display(generated_at, timezone_name):
    offset = generated_at.strftime("%z")
    if offset:
        offset = f"UTC{offset[:3]}:{offset[3:]}"
    else:
        offset = "本地时区"

    if timezone_name == "Asia/Shanghai":
        timezone_label = f"北京时间 {offset}"
    elif timezone_name:
        timezone_label = f"{timezone_name} {offset}"
    else:
        timezone_label = offset

    return f"{generated_at:%Y-%m-%d %H:%M:%S}（{timezone_label}）"


def build_manifest(config, output_dir, publish_branch, rules_dir):
    generated_at = datetime.now(timezone.utc).astimezone()
    timezone_name = (config.get("git") or {}).get("timezone", "")
    manifest = {
        "schema_version": 1,
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "generated_at_display": format_generated_at_display(generated_at, timezone_name),
        "publish": {
            "branch": publish_branch,
            "rules_dir": rules_dir,
        },
        "artifacts": {},
    }

    for task_name, task in sorted((config.get("tasks") or {}).items()):
        rule_format = task.get("format", "")
        files = []
        for path in artifact_files(output_dir, task_name, rule_format):
            files.append(
                {
                    "path": path.name,
                    "bytes": path.stat().st_size,
                    "lines": file_lines(path),
                    "sha256": file_sha256(path),
                }
            )

        manifest["artifacts"][task_name] = {
            "behavior": task.get("behavior"),
            "format": rule_format,
            "sources": format_list(task.get("src")),
            "files": files,
            "empty": not any((item.get("lines") or item["bytes"]) > 0 for item in files),
        }

    return manifest


def provider_format(file_name):
    if file_name.endswith(".mrs"):
        return "mrs"
    return "text"


def write_readme(path, manifest, raw_base_url):
    lines = [
        "# RuleList 规则产物",
        "",
        f"生成时间：{manifest['generated_at_display']}",
        "",
        "## 产物列表",
        "",
    ]

    for task_name, item in manifest["artifacts"].items():
        lines.append(f"### {task_name}")
        lines.append("")
        lines.append(f"- Behavior: `{item['behavior']}`")
        lines.append(f"- Sources: `{len(item['sources'])}`")
        for file_info in item["files"]:
            raw_url = f"{raw_base_url.rstrip('/')}/{file_info['path']}"
            if file_info["lines"] is None:
                lines.append(f"- `{file_info['path']}`：{file_info['bytes']} bytes，{raw_url}")
            else:
                lines.append(
                    f"- `{file_info['path']}`：{file_info['lines']} lines，{file_info['bytes']} bytes，{raw_url}"
                )
        lines.append("")

    lines.extend(
        [
            "## Mihomo rule-providers 配置",
            "",
            "```yaml",
            "rule-providers:",
        ]
    )

    for task_name, item in manifest["artifacts"].items():
        mrs_file = next((f for f in item["files"] if f["path"].endswith(".mrs")), None)
        selected = mrs_file or (item["files"][0] if item["files"] else None)
        if selected is None:
            continue
        raw_url = f"{raw_base_url.rstrip('/')}/{selected['path']}"
        lines.extend(
            [
                f"  {task_name}:",
                "    type: http",
                f"    behavior: {item['behavior']}",
                f"    format: {provider_format(selected['path'])}",
                f"    url: \"{raw_url}\"",
                f"    path: ./ruleset/{selected['path']}",
                "    interval: 86400",
            ]
        )

    lines.extend(["```", ""])
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main():
    config = json.loads(os.environ["CONFIG_JSON"])
    output_dir = Path(os.environ["OUTPUT_DIR"])
    publish_branch = os.environ["PUBLISH_BRANCH"]
    rules_dir = os.environ["RULES_DIR"]
    raw_base_url = os.environ["RAW_BASE_URL"]

    manifest = build_manifest(config, output_dir, publish_branch, rules_dir)
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_readme(output_dir / "README.md", manifest, raw_base_url)


if __name__ == "__main__":
    main()

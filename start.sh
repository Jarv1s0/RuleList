#!/bin/bash
set -e 

config_file="config.yaml"
if [ ! -f "$config_file" ]; then
    echo "错误: 找不到配置文件 $config_file"
    exit 1
fi

# 检查必要命令是否存在
for cmd in yq jq curl wget gunzip sha256sum git python3 mktemp; do
    if ! command -v $cmd &> /dev/null; then
        echo "错误: 系统未安装 $cmd，请先安装。"
        exit 1
    fi
done

work_dir=$(yq -r '.work_dir' "$config_file")
rm -rf "$work_dir" || true
mkdir -p "$work_dir"

api_url=$(yq -r '.mihomo.api_url' "$config_file")
start_with=$(yq -r '.mihomo.start_with' "$config_file")
end_with=$(yq -r '.mihomo.end_with' "$config_file")

if [ -z "$api_url" ] || [ "$api_url" == "null" ]; then
    echo "错误: 无法从 YAML 中解析配置，请检查配置文件格式。"
    exit 1
fi

echo "正在获取 API 信息..."
# 增加 -L 以跟随重定向，-f 以在 HTTP 错误时失败
if [ -n "$GITHUB_TOKEN" ]; then
  AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
else
  AUTH_HEADER="User-Agent: curl"
fi
api_response=$(curl -sL -f -H "$AUTH_HEADER" "$api_url")
if [ $? -ne 0 ]; then
    echo "错误: 无法连接到 API 地址 (可能是速率限制或网络问题)。"
    exit 1
fi

# 使用 jq -c 强制单行输出，确保 head -n 1 截取的是完整的一行 JSON 对象
asset_info=$(echo "$api_response" | jq -c ".[] | .assets[] | select(.name | startswith(\"$start_with\") and endswith(\"$end_with\"))" | head -n 1)
if [ -z "$asset_info" ] || [ "$asset_info" == "null" ]; then
    echo "错误: 未找到符合条件 ($start_with ... $end_with) 的资源。"
    exit 1
fi
echo "解析到的资源信息: $asset_info"

download_url=$(echo "$asset_info" | jq -r '.browser_download_url')
echo "下载链接: $download_url"

# 处理 digest，兼容带 sha256: 前缀或不带的情况
expected_digest=$(echo "$asset_info" | jq -r '.digest' | cut -d ':' -f 2)
echo "预期校验和: $expected_digest"

if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
    echo "错误: JSON 中未找到下载链接。"
    exit 1
fi

echo "开始下载: $download_url"
wget -q -O "$work_dir/mihomo.gz" "$download_url"
if [ $? -ne 0 ]; then
    echo "错误: 下载文件失败。"
    exit 1
fi

echo "验证下载的文件"
# sha256sum 输出格式为 "hash  filename"，awk '{print $1}' 取第一列
actual_digest=$(sha256sum "$work_dir/mihomo.gz" | awk '{print $1}')

if [ "$actual_digest" != "$expected_digest" ]; then
    echo "错误: 文件校验失败！"
    echo "预期: $expected_digest"
    echo "实际: $actual_digest"
    exit 1
fi
echo "文件校验成功。"

echo "正在解压..."
gunzip -f "$work_dir/mihomo.gz"
if [ $? -ne 0 ]; then
    echo "错误: 解压文件失败。"
    exit 1
fi

chmod +x "$work_dir/mihomo"
echo "Mihomo 已就绪: $work_dir/mihomo"

output_dir=$(yq -r '.output_dir' "$config_file")
rm -rf "$output_dir" || true
mkdir -p "$output_dir"

publish_branch=$(yq -r '.publish.branch // ""' "$config_file")
rules_dir=$(yq -r '.publish.rules_dir // "rules"' "$config_file")
raw_base_url=$(yq -r '.publish.raw_base_url // ""' "$config_file")

if [ -z "$publish_branch" ] || [ "$publish_branch" == "null" ]; then
    publish_branch=$(git rev-parse --abbrev-ref HEAD)
fi

if [ -z "$rules_dir" ] || [ "$rules_dir" == "null" ]; then
    rules_dir="rules"
fi

if [ -z "$raw_base_url" ] || [ "$raw_base_url" == "null" ]; then
    origin_url=$(git config --get remote.origin.url || true)
    repo_path=$(echo "$origin_url" | sed -E 's#^git@github.com:##; s#^https://github.com/##; s#\.git$##')
    if [[ "$repo_path" == */* ]]; then
        raw_base_url="https://raw.githubusercontent.com/${repo_path}/${publish_branch}/${rules_dir}"
    else
        raw_base_url="${rules_dir}"
    fi
fi

echo "开始处理任务..."
# 遍历 tasks 下的所有键名
task_names=$(yq -r '.tasks | keys | .[]' "$config_file")

for task in $task_names; do
    echo "---------------------------------------"
    echo "正在处理任务: $task"
    rm -f "$work_dir/tmp.txt"

    # 获取该 task 的所有下载链接
    urls=$(yq -r ".tasks.$task.src[]" "$config_file")
    behavior=$(yq -r ".tasks[\"$task\"].behavior // \"\"" "$config_file")

    if [ -z "$behavior" ]; then
        echo "错误: 任务 $task 未配置 behavior，请在 config.yaml 中显式指定 domain 或 ipcidr。"
        exit 1
    fi

    case "$behavior" in
        domain|ipcidr)
            ;;
        *)
            echo "错误: 任务 $task 的 behavior=$behavior 不受支持，仅允许 domain 或 ipcidr。"
            exit 1
            ;;
    esac

    # 如果 YAML 中没有 custom_script，yq 可能会返回 null，这里做处理
    custom_script_content=$(yq -r ".tasks.$task.custom_script" "$config_file")
    
    # 在 Bash 中判断：如果是 null 则视为空字符串
    if [ "$custom_script_content" == "null" ]; then
        custom_script_content=""
    fi
    
    export CUSTOM_SCRIPT="$custom_script_content"

    for url in $urls; do
        echo "正在下载: $url"
        filename=$(basename "$url")
        download_path="$work_dir/$filename"
        
        if ! wget -q -O "$download_path" "$url"; then
            echo "错误: 下载失败 $url，退出..."
            exit 1
        fi

        # 处理不同格式
        sed -i -e '$a\' "$download_path"  # 确保文件以换行符结尾

        if [[ "$filename" == "pihole.txt" ]]; then
            echo "   -> 检测到 pihole.txt，正在添加 (+.) 前缀..."
            sed -i '/^[a-zA-Z0-9]/ s/^/+./' "$download_path"
        fi

        if [[ "$filename" == *.yaml ]]; then
            sed -n '/^payload:/,$ { /^[[:space:]]*-[[:space:]]*/ { s/^[[:space:]]*-[[:space:]]*//; s/['\'']//g; p } }' "$download_path" >> "$work_dir/tmp.txt"
        else
            cat "$download_path" >> "$work_dir/tmp.txt"
        fi
    done

    output_file="$output_dir/${task}.txt"
    echo "清理格式、处理 Classical 规则前缀 (Domain & IP)..."
    
    # 1. 优先删除前导/尾随空格，删除注释和空行
    sed -i -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' -e 's/^[[:space:]]*//;s/[[:space:]]*$//' "$work_dir/tmp.txt"
    
    # 2. 转换 Classical 格式，提取中间的 payload 并安全剥离尾部策略名
    # 将 DOMAIN-SUFFIX,google.com,Proxy 转换为 +.google.com
    sed -i -E 's/^(DOMAIN-SUFFIX)[,:]([^,]+).*/+.\2/gi' "$work_dir/tmp.txt"
    # 将 DOMAIN,google.com,Proxy 转换为 google.com
    sed -i -E 's/^(DOMAIN)[,:]([^,]+).*/\2/gi' "$work_dir/tmp.txt"
    # 将 IP-CIDR,1.1.1.0/24,no-resolve 转换为 1.1.1.0/24
    sed -i -E 's/^(IP-CIDR6?)[,:]([^,]+).*/\2/gi' "$work_dir/tmp.txt"

    if [ "$behavior" == "ipcidr" ]; then
        echo "类型：IP/CIDR 网段 (由配置指定，启用语义合并)"
        # 使用 Python ipaddress 模块进行 CIDR 合并
        python3 - "$work_dir/tmp.txt" "$output_file" <<-'EOF'
import sys
import ipaddress

input_path = sys.argv[1]
output_path = sys.argv[2]
print(f"Python (IP模式) 正在读取: {input_path}")

ipv4_nets = []
ipv6_nets = []

try:
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                # strict=False 允许非规范写法
                net = ipaddress.ip_network(line, strict=False)
                if net.version == 4:
                    ipv4_nets.append(net)
                else:
                    ipv6_nets.append(net)
            except ValueError:
                pass

    merged_v4 = list(ipaddress.collapse_addresses(ipv4_nets))
    merged_v6 = list(ipaddress.collapse_addresses(ipv6_nets))

    merged_v4.sort()
    merged_v6.sort()

    print(f"Python (IP模式) 正在写入: {output_path}")
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        for net in merged_v4:
            f.write(str(net) + '\n')
        for net in merged_v6:
            f.write(str(net) + '\n')

except FileNotFoundError:
    print(f"错误: 找不到文件 {input_path}")
    sys.exit(1)
except Exception as e:
    print(f"发生未知错误: {e}")
    sys.exit(1)
EOF
        if [ $? -eq 0 ]; then
            echo "生成文件: $output_file (总行数: $(wc -l < "$output_file"))"
        else
            echo "错误：IP 处理脚本执行失败"
            exit 1
        fi

    else
        echo "类型：域名列表 (由配置指定)"

        # 使用 yq 将任务配置转为 JSON 并导出
        # 移除 yq 不支持的 -c 参数（那是 jq 的参数），改用 -o=json 标志位前置
        task_json=$(yq -o=json ".tasks[\"$task\"]" "$config_file")
        export TASK_CONFIG_JSON="$task_json"

        # 让 Python 全权负责：读取 -> 转换 -> 过滤 -> 最终去重 -> 写入
        python3 - "$work_dir/tmp.txt" "$output_file" <<-'EOF'
import sys
import re
import os
import json

input_path = sys.argv[1]
output_path = sys.argv[2]

def get_clean_domain(domain_str):
    return re.sub(r'^[\+\*\.]+', '', domain_str)

def deduplicate_domains(raw_lines):
    """标准的父域名去重算法"""
    # 按干净域名的长度排序，确保父域名先被处理
    raw_lines.sort(key=lambda x: len(get_clean_domain(x)))
    
    roots = set()
    result = []
    
    for line in raw_lines:
        clean = get_clean_domain(line)
        parts = clean.split('.')
        is_redundant = False
        
        # 检查自己或任何父域名是否已在 roots 中
        if clean in roots:
            is_redundant = True
        else:
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in roots:
                    is_redundant = True
                    break
        
        if not is_redundant:
            result.append(line)
            roots.add(clean)
    return result

try:
    # 1. 从环境变量加载 JSON 配置 (无需 yaml 模块)
    task_conf_str = os.environ.get('TASK_CONFIG_JSON', '{}')
    task_conf = json.loads(task_conf_str)
    
    rewrite_conf = task_conf.get('rewrite', {}) or {}
    exclude_list = list(task_conf.get('exclude', []) or [])
    exclude_regex = task_conf.get('exclude_regex', []) or []
    custom_code = task_conf.get('custom_script', '') or ""

    # 统一配置语义：rewrite 只负责替换，删除统一放到 exclude。
    # 这里做严格校验，避免把删除规则误写进 rewrite 后静默产生脏数据。
    if rewrite_conf:
        for suffix, replacement in rewrite_conf.items():
            if replacement is None or not isinstance(replacement, str) or not replacement.strip():
                raise ValueError(
                    f"rewrite 配置非法: {suffix} 的替换值不能为空，请将删除规则写入 exclude"
                )

    # 2. 读取原始数据
    domains = []
    if os.path.exists(input_path):
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line: domains.append(line)

    # 3. 处理 rewrite (仅负责后缀替换，不承担删除)
    if rewrite_conf:
        rewritten_domains = []
        rewrite_suffixes = tuple(rewrite_conf.keys())
        for d in domains:
            matched = False
            for s in rewrite_suffixes:
                if d.endswith(s):
                    replacement = rewrite_conf[s]
                    rewritten_domains.append(replacement)
                    matched = True
                    break
            if not matched:
                rewritten_domains.append(d)
        domains = rewritten_domains

    # 4. 处理 exclude (完整匹配或后缀匹配；统一承担删除)
    if exclude_list:
        exclude_tuple = tuple(exclude_list)
        domains = [d for d in domains if not (d in exclude_list or d.endswith(exclude_tuple))]

    # 5. 处理 exclude_regex
    if exclude_regex:
        regex_patterns = [re.compile(p) for p in exclude_regex]
        domains = [d for d in domains if not any(p.search(d) for p in regex_patterns)]

    # 6. 执行旧有的自定义脚本 (如果仍然存在)
    if custom_code and custom_code.strip():
        try:
            exec_locals = {'domains': domains, 're': re}
            exec(custom_code, {}, exec_locals)
            domains = exec_locals['domains']
        except Exception as e:
            print(f"  -> [警告] 自定义脚本执行失败: {e}")

    # 7. 最终去重 (核心：确保所有来源的规则都经过一致性去重)
    domains = deduplicate_domains(domains)

    # 8. 写入文件
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write("\n".join(domains) + ("\n" if domains else ""))

except Exception as e:
    print(f"Python 处理发生错误: {e}")
    sys.exit(1)
EOF
        if [ $? -eq 0 ]; then
            echo "生成文件: $output_file (总行数: $(wc -l < "$output_file"))"
        else
            echo "错误：域名脚本执行失败"
            exit 1
        fi
    fi

    need_mrs=$(yq -r ".tasks.$task.format" "$config_file" | grep -q "mrs" && echo "true" || echo "false")
    if [ "$need_mrs" == "true" ]; then
        echo "转换为 mrs 格式"
        $work_dir/mihomo convert-ruleset $behavior text "$output_file" "$output_dir/${task}.mrs"
        echo "生成文件: ${task}.mrs (文件大小: $(du -h "$output_dir/${task}.mrs" | awk '{print $1}'))"
    fi
    rm -f "$work_dir/tmp.txt"
done

echo "---------------------------------------"
echo "所有任务处理完成！"
echo "---------------------------------------"

echo "正在生成产物清单和使用说明..."
CONFIG_JSON=$(yq -o=json '.' "$config_file")
export CONFIG_JSON OUTPUT_DIR="$output_dir" PUBLISH_BRANCH="$publish_branch" RULES_DIR="$rules_dir" RAW_BASE_URL="$raw_base_url"
python3 scripts/generate_artifacts.py

current_branch=$(git rev-parse --abbrev-ref HEAD)

echo "开始部署规则到分支: $publish_branch，目录: $rules_dir"

if [ -n "$GITHUB_TOKEN" ]; then
    git config --global user.name "$(yq -r '.git.user_name' "$config_file")"
    git config --global user.email "$(yq -r '.git.user_email' "$config_file")"
fi

if [ "$publish_branch" == "$current_branch" ]; then
    # 确保 rules 目录存在并清理旧内容
    mkdir -p "$rules_dir"
    find "$rules_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

    # 复制新规则
    cp -r "$output_dir"/* "$rules_dir/"

    echo "正在准备 Git 提交..."
    git add "$rules_dir"

    if git diff --staged --quiet; then
        echo "规则无变化，跳过提交和推送。"
        exit 0
    fi

    git commit -m "Auto Update Rules: $(date '+%Y-%m-%d %H:%M:%S')"

    commit_count=$(git rev-list --count HEAD)
    echo "当前分支提交数量: $commit_count"

    # 注意：这里暂不自动执行 --orphan 重置，以保护主分支代码历史。
    # 如果用户确实需要清理主分支历史，建议手动执行或通过专门的清理脚本。

    if [ -n "$GITHUB_TOKEN" ]; then
        origin_url=$(git remote get-url origin)
        auth_url=$(echo "$origin_url" | sed "s/https:\/\//https:\/\/x-access-token:$GITHUB_TOKEN@/")
        git remote set-url origin "$auth_url"
    fi

    echo "正在推送到 GitHub 分支: $current_branch"
    git push origin "$current_branch"
    echo "部署完成！"
    exit 0
fi

publish_worktree=$(mktemp -d)
cleanup_publish_worktree() {
    if [ -n "$publish_worktree" ] && [ -d "$publish_worktree" ]; then
        git worktree remove --force "$publish_worktree" >/dev/null 2>&1 || true
        rm -rf "$publish_worktree" >/dev/null 2>&1 || true
    fi
}
trap cleanup_publish_worktree EXIT

git worktree prune
git fetch origin "$publish_branch" || true

if git show-ref --verify --quiet "refs/remotes/origin/$publish_branch"; then
    git worktree add -B "$publish_branch" "$publish_worktree" "origin/$publish_branch"
else
    git worktree add --detach "$publish_worktree"
    (
        cd "$publish_worktree"
        git checkout --orphan "$publish_branch"
        git rm -rf . >/dev/null 2>&1 || true
    )
fi

deploy_target="$publish_worktree/$rules_dir"
mkdir -p "$deploy_target"
find "$deploy_target" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -r "$output_dir"/* "$deploy_target/"

(
    cd "$publish_worktree"
    echo "正在准备 Git 提交..."
    git add "$rules_dir"

    if git diff --staged --quiet; then
        echo "规则无变化，跳过提交和推送。"
        exit 0
    fi

    git commit -m "Auto Update Rules: $(date '+%Y-%m-%d %H:%M:%S')"

    if [ -n "$GITHUB_TOKEN" ]; then
        origin_url=$(git remote get-url origin)
        auth_url=$(echo "$origin_url" | sed "s/https:\/\//https:\/\/x-access-token:$GITHUB_TOKEN@/")
        git remote set-url origin "$auth_url"
    fi

    echo "正在推送到 GitHub 分支: $publish_branch"
    git push origin "$publish_branch"
)

git worktree remove --force "$publish_worktree"
trap - EXIT
echo "部署完成！"

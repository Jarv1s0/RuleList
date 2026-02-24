#!/bin/bash
set -e 

config_file="config.yaml"
if [ ! -f "$config_file" ]; then
    echo "错误: 找不到配置文件 $config_file"
    exit 1
fi

# 检查必要命令是否存在
for cmd in yq jq curl wget gunzip sha256sum; do
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

echo "开始处理任务..."
# 遍历 tasks 下的所有键名
task_names=$(yq -r '.tasks | keys | .[]' "$config_file")

for task in $task_names; do
    echo "---------------------------------------"
    echo "正在处理任务: $task"

    # 获取该 task 的所有下载链接
    urls=$(yq -r ".tasks.$task.src[]" "$config_file")

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

    # 读取第一行用于判断类型
    first_line=$(head -n 1 "$work_dir/tmp.txt")

    # 判断逻辑：如果包含 冒号(:) 或者 斜杠(/)，认为是 IP段
    if [[ "$first_line" =~ [:/] ]]; then
        echo "类型：IP/CIDR 网段 (启用语义合并)"
        behavior="ipcidr"
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
        echo "类型：域名列表"
        behavior="domain"

        # 让 Python 全权负责：读取 -> 清洗 -> 逻辑去重 -> 写入
        python3 - "$work_dir/tmp.txt" "$output_file" <<-'EOF'
import sys
import re
import os
from collections import defaultdict

input_path = sys.argv[1]
output_path = sys.argv[2]
print(f"Python (域名模式) 正在读取: {input_path}")

def get_clean_domain(domain_str):
    return re.sub(r'^[\+\*\.]+', '', domain_str)

try:
    raw_lines = []
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                raw_lines.append(line)
    
    raw_lines.sort()
    raw_lines.sort(key=lambda x: len(get_clean_domain(x)))

    roots = set()
    domains = [] 
    
    for line in raw_lines:
        clean_domain = get_clean_domain(line)
        parts = clean_domain.split('.')
        is_redundant = False
        
        if clean_domain in roots:
            is_redundant = True
        else:
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in roots:
                    is_redundant = True
                    break
        
        if not is_redundant:
            domains.append(line)
            roots.add(clean_domain)

    custom_code = os.environ.get('CUSTOM_SCRIPT', '')
    if custom_code and custom_code.strip() != "":
        try:
            exec_globals = {}
            exec_locals = {'domains': domains, 're': re}
            exec(custom_code, exec_globals, exec_locals)
            domains = exec_locals['domains']
            print(f"  -> 自定义脚本执行完毕")
        except Exception as e:
            print(f"  -> [警告] 自定义脚本执行失败: {e}")

    suffix_counter = defaultdict(int)
    for line in domains:
        clean = get_clean_domain(line)
        parts = clean.split('.')

        if len(parts) < 4:
            continue
        suffix = ".".join(parts[1:])
        suffix_counter[suffix] += 1
    
    warned = False
    sorted_suffixes = sorted(suffix_counter.items(), key=lambda x: x[1], reverse=True)
    for suffix, count in sorted_suffixes:
        if count >= 17:
            if not warned:
                print("  -> [注意] 检测到以下后缀包含大量子域名:")
                warned = True
            print(f"     Suffix: .{suffix} (包含 {count} 个条目)")

    print(f"Python (域名模式) 正在写入: {output_path}")
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write("\n".join(domains))
        f.write("\n")

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

release_branch=$(yq -r '.git.release_branch' "$config_file")
max_history=$(yq -r '.git.max_history' "$config_file")
echo "开始部署到分支: $release_branch"

if [ -n "$GITHUB_TOKEN" ]; then
    git config --global user.name "$(yq -r '.git.user_name' "$config_file")"
    git config --global user.email "$(yq -r '.git.user_email' "$config_file")"
fi

temp_repo="$work_dir/temp_repo"
rm -rf "$temp_repo" || true
remote_url=$(git config --get remote.origin.url)

echo "正在克隆/初始化目标分支..."
if git clone -q --filter=blob:none --branch "$release_branch" "$remote_url" "$temp_repo" 2>/dev/null; then
    echo "成功拉取远程分支 $release_branch"
else
    echo "远程分支不存在，初始化新仓库"
    mkdir -p "$temp_repo"
    cd "$temp_repo"
    git init
    git checkout -b "$release_branch"
    git remote add origin "$remote_url"
    cd - > /dev/null
fi

find "$temp_repo" -mindepth 1 -maxdepth 1 -not -name '.git' -exec rm -rf {} +
cp -r "$output_dir"/* "$temp_repo/"
cd "$temp_repo"

git add .
if git diff --staged --quiet; then
    echo "规则无变化，跳过提交和推送。"
    exit 0
fi

git commit -m "Auto Update: $(date '+%Y-%m-%d %H:%M:%S')"
commit_count=$(git rev-list --count HEAD)
echo "当前分支提交数量: $commit_count (上限: $max_history)"

if [ "$commit_count" -gt "$max_history" ]; then
    echo "触发历史清理机制..."
    git checkout --orphan temp_reset_branch
    git add .
    git commit -m "Reset History: $(date '+%Y-%m-%d') (Cleaned up old commits)"
    git branch -D "$release_branch"
    git branch -m "$release_branch"
    push_args="--force"
    echo "历史已重置为 1 条提交。"
else
    push_args=""
    echo "历史数量在允许范围内，正常推送。"
fi

if [ -n "$GITHUB_TOKEN" ]; then
    origin_url=$(git remote get-url origin)
    auth_url=$(echo "$origin_url" | sed "s/https:\/\//https:\/\/x-access-token:$GITHUB_TOKEN@/")
    git remote set-url origin "$auth_url"
else
    echo "警告: GITHUB_TOKEN 未设置，推送可能失败！"
fi

echo "正在推送到 GitHub..."
git push $push_args origin "$release_branch"
echo "完成！"

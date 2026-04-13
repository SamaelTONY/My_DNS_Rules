#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADG Home Rules Aggregator
整合多源广告规则，智能去重后输出 AdGuard Home 格式规则文件

Author: Your Name
Date: 2026-04-13
"""

import os
import sys
import hashlib
import logging
import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import defaultdict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==================== 配置区域 ====================
# 规则源列表 - 2026 稳健加强版组合
RULE_SOURCES = [
    # 1. 恶意威胁情报 - 中等强度（防护木马、钓鱼，不影响正常业务）
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
    
    # 2. 中文环境核心 - 全能优化（针对国内 App 和网站的去广告核心）
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    
    # 3. 稳健去广告 - 平衡版（拦截追踪器的同时，确保联想摄像头等智能硬件不被误杀）
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
]

# 输出配置
OUTPUT_FILE = "my_adg_rules.txt"
OUTPUT_TITLE = "OEC Master Rules (Cloud Build)"
MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 输出文件最大 10MB

# 请求配置
REQUEST_TIMEOUT = 60
REQUEST_RETRIES = 3
REQUEST_USER_AGENT = "ADG-Rules-Aggregator/2.0 (+https://github.com/SamaelTONY/My_DNS_Rules)"

# 规则过滤配置
RULE_PREFIX = "||"
RULE_SUFFIX = "^"
MIN_DOMAIN_LENGTH = 4  # 过滤过短的无效域名

# 本地自定义规则文件（可选）
CUSTOM_RULES_FILE = "custom_rules.txt"
WHITELIST_FILE = "whitelist.txt"

# 日志配置
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
# ==================== 配置结束 ====================


def setup_logging():
    """初始化日志配置"""
    logging.basicConfig(
        level=LOG_LEVEL,
        format=LOG_FORMAT,
        datefmt="%H:%M:%S",
        stream=sys.stdout
    )


def get_requests_session():
    """创建带重试机制的 requests session"""
    session = requests.Session()
    retry_strategy = Retry(
        total=REQUEST_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": REQUEST_USER_AGENT})
    return session


def extract_domain_from_rule(rule: str) -> str:
    """
    从 AdGuard 规则中提取纯域名
    ||example.com^ -> example.com
    ||sub.example.com/path -> sub.example.com
    """
    domain = rule.strip()
    if domain.startswith(RULE_PREFIX):
        domain = domain[len(RULE_PREFIX):]
    if domain.endswith(RULE_SUFFIX):
        domain = domain[:-len(RULE_SUFFIX)]
    # 移除路径部分
    domain = domain.split("/")[0]
    return domain.lower().strip()


def is_valid_rule(rule: str) -> bool:
    """验证规则格式是否有效"""
    if not rule.startswith(RULE_PREFIX) or not rule.endswith(RULE_SUFFIX):
        return False
    domain = extract_domain_from_rule(rule)
    # 基础有效性检查
    if len(domain) < MIN_DOMAIN_LENGTH:
        return False
    if "." not in domain:
        return False
    # 简单域名格式校验
    parts = domain.split(".")
    if any(len(p) == 0 or p.startswith("-") or p.endswith("-") for p in parts):
        return False
    return True


def is_subdomain_of(domain: str, parent: str) -> bool:
    """判断 domain 是否是 parent 的子域名"""
    if domain == parent:
        return True
    return domain.endswith("." + parent)


def load_local_rules(filepath: str) -> set:
    """加载本地规则文件"""
    rules = set()
    if not os.path.exists(filepath):
        return rules
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("!") and not line.startswith("#"):
                    if is_valid_rule(line):
                        rules.add(line)
        logging.info(f"Loaded {len(rules)} rules from {filepath}")
    except Exception as e:
        logging.warning(f"Failed to load {filepath}: {e}")
    return rules


def download_rules(sources: list, session: requests.Session) -> set:
    """下载并解析远程规则"""
    raw_rules = set()
    logging.info(f"Step 1: Downloading rules from {len(sources)} sources...")
    
    for idx, url in enumerate(sources, 1):
        try:
            logging.info(f"  [{idx}/{len(sources)}] Fetching: {url[:60]}...")
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            count = 0
            for line in response.text.splitlines():
                line = line.strip()
                if is_valid_rule(line):
                    raw_rules.add(line)
                    count += 1
            logging.info(f"    ✓ Added {count} valid rules")
            
        except requests.exceptions.RequestException as e:
            logging.error(f"    ✗ Failed to fetch {url}: {e}")
        except Exception as e:
            logging.error(f"    ✗ Unexpected error: {e}")
    
    logging.info(f"Total raw rules collected: {len(raw_rules)}")
    return raw_rules


def optimize_rules(raw_rules: set) -> list:
    """
    智能去重优化：
    1. 按域名长度排序（短域名优先）
    2. 如果某域名已被父域名覆盖，则跳过
    3. 保留更精确的规则（当父域名不存在时）
    """
    logging.info(f"Step 2: Optimizing rules (original: {len(raw_rules)})...")
    
    # 按域名长度升序排序：先处理短域名（覆盖范围大）
    sorted_rules = sorted(raw_rules, key=lambda r: len(extract_domain_from_rule(r)))
    
    optimized = []
    covered_domains = set()  # 已被覆盖的域名集合
    
    for rule in sorted_rules:
        domain = extract_domain_from_rule(rule)
        
        # 检查是否已被更上级的域名覆盖
        is_covered = False
        domain_parts = domain.split(".")
        
        # 检查所有可能的父域名
        for i in range(1, len(domain_parts)):
            parent = ".".join(domain_parts[i:])
            if parent in covered_domains:
                is_covered = True
                logging.debug(f"  Skip covered: {domain} (covered by {parent})")
                break
        
        if not is_covered:
            optimized.append(rule)
            covered_domains.add(domain)
    
    logging.info(f"Optimized rules: {len(optimized)} (removed {len(raw_rules) - len(optimized)})")
    return optimized


def merge_custom_rules(rules: list) -> list:
    """合并本地自定义规则和白名单"""
    # 加载自定义规则
    custom_rules = load_local_rules(CUSTOM_RULES_FILE)
    if custom_rules:
        # 去重并合并
        rule_set = set(rules)
        rule_set.update(custom_rules)
        rules = sorted(rule_set, key=lambda r: len(extract_domain_from_rule(r)))
        logging.info(f"Merged {len(custom_rules)} custom rules")
    
    # 应用白名单（移除匹配的规则）
    whitelist = load_local_rules(WHITELIST_FILE)
    if whitelist:
        whitelist_domains = {extract_domain_from_rule(r) for r in whitelist}
        filtered = [
            r for r in rules 
            if extract_domain_from_rule(r) not in whitelist_domains
        ]
        removed = len(rules) - len(filtered)
        if removed > 0:
            logging.info(f"Whitelisted {removed} rules")
            rules = filtered
    
    return rules


def generate_output(rules: list, output_path: str):
    """生成最终输出文件"""
    logging.info(f"Step 3: Writing output to {output_path}...")
    
    # 计算校验和
    rules_content = "\n".join(rules)
    checksum_md5 = hashlib.md5(rules_content.encode("utf-8")).hexdigest()[:16]
    checksum_sha1 = hashlib.sha1(rules_content.encode("utf-8")).hexdigest()[:20]
    
    # 估算文件大小
    estimated_size = len(rules_content.encode("utf-8"))
    if estimated_size > MAX_OUTPUT_SIZE:
        logging.warning(f"⚠️ Output size ({estimated_size/1024/1024:.2f}MB) exceeds limit!")
    
    with open(output_path, "w", encoding="utf-8") as f:
        # 文件头信息
        f.write(f"! Title: {OUTPUT_TITLE}\n")
        f.write(f"! Version: {datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}\n")
        f.write(f"! Last-Modified: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}\n")
        f.write(f"! Total Rules: {len(rules)}\n")
        f.write(f"! Checksum-MD5: {checksum_md5}\n")
        f.write(f"! Checksum-SHA1: {checksum_sha1}\n")
        f.write(f"! Size-Estimated: {estimated_size / 1024:.1f} KB\n")
        f.write("! Source: https://github.com/SamaelTONY/My_DNS_Rules\n")
        f.write("\n")
        
        # 规则内容
        f.write(rules_content)
    
    logging.info(f"✓ Output saved: {len(rules)} rules, {estimated_size/1024:.1f} KB")


def print_summary(rules: list, sources: list):
    """打印执行摘要"""
    print("\n" + "=" * 50)
    print("📊 RULES AGGREGATION SUMMARY")
    print("=" * 50)
    print(f"Sources processed : {len(sources)}")
    print(f"Final rule count  : {len(rules):,}")
    print(f"Output file       : {OUTPUT_FILE}")
    
    # 域名分布统计（前10顶级域名）
    tld_count = defaultdict(int)
    for rule in rules[:1000]:  # 采样统计
        domain = extract_domain_from_rule(rule)
        tld = domain.split(".")[-1] if "." in domain else "unknown"
        tld_count[tld] += 1
    
    if tld_count:
        print(f"\nTop TLDs (sample):")
        for tld, count in sorted(tld_count.items(), key=lambda x: -x[1])[:5]:
            print(f"  .{tld}: {count}")
    
    print("=" * 50 + "\n")


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="ADG Home Rules Aggregator")
    parser.add_argument(
        "-o", "--output", 
        type=str, 
        default=OUTPUT_FILE,
        help=f"Output file path (default: {OUTPUT_FILE})"
    )
    parser.add_argument(
        "-s", "--sources", 
        type=str, 
        nargs="+",
        help="Override rule source URLs"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true",
        help="Process rules but don't write output file"
    )
    return parser.parse_args()


def main():
    """主入口函数"""
    args = parse_args()
    
    # 初始化
    setup_logging()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 应用命令行参数
    output_file = args.output
    sources = args.sources if args.sources else RULE_SOURCES
    
    logging.info("🚀 ADG Rules Aggregator started")
    logging.info(f"Python {sys.version.split()[0]} | Platform: {sys.platform}")
    
    try:
        # 1. 下载规则
        session = get_requests_session()
        raw_rules = download_rules(sources, session)
        
        if not raw_rules:
            logging.error("No rules collected! Please check sources or network.")
            sys.exit(1)
        
        # 2. 优化去重
        optimized_rules = optimize_rules(raw_rules)
        
        # 3. 合并自定义规则
        final_rules = merge_custom_rules(optimized_rules)
        
        # 4. 输出结果
        if not args.dry_run:
            generate_output(final_rules, output_file)
            print_summary(final_rules, sources)
        else:
            logging.info("🔍 Dry-run mode: skipped file output")
            print_summary(final_rules, sources)
        
        logging.info("✅ All done!")
        return 0
        
    except KeyboardInterrupt:
        logging.warning("⚠️ Interrupted by user")
        return 130
    except Exception as e:
        logging.exception(f"❌ Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

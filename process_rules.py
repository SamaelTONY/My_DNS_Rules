#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADG Home Rules Aggregator v4.0 (Pro/AdRules/Privacy Edition)
整合多源广告规则，智能去重后输出 AdGuard Home 格式规则文件
针对 GitHub Actions 环境优化：移除脆弱缓存、修复白名单 @@ 例外、强化去重

Author: SamaelTONY
Date: 2026
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

# ==================== 🔧 配置区域 ====================
# 规则源列表 - 2026 稳健组合 (Pro + AdRules + EasyPrivacy)
RULE_SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
]

# 输出配置
OUTPUT_FILE = "my_adg_rules.txt"
OUTPUT_TITLE = "OEC Master Rules (Pro/AdRules/Privacy Build)"
MAX_OUTPUT_SIZE = 15 * 1024 * 1024  # 15MB 警告阈值

# 请求配置
REQUEST_TIMEOUT = 60
REQUEST_RETRIES = 3
REQUEST_USER_AGENT = "ADG-Rules-Aggregator/4.0 (+https://github.com/SamaelTONY/My_DNS_Rules)"

# 规则过滤配置
RULE_PREFIX = "||"
RULE_SUFFIX = "^"
MIN_DOMAIN_LENGTH = 4

# 本地文件（可选）
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
    """从 AdGuard 规则中提取纯域名"""
    domain = rule.strip()
    if domain.startswith(RULE_PREFIX):
        domain = domain[len(RULE_PREFIX):]
    if domain.endswith(RULE_SUFFIX):
        domain = domain[:-len(RULE_SUFFIX)]
    return domain.split("/")[0].lower().strip()


def is_valid_rule(rule: str) -> bool:
    """验证规则格式是否有效（仅接受 ||domain^ 标准格式）"""
    if not rule.startswith(RULE_PREFIX) or not rule.endswith(RULE_SUFFIX):
        return False
    domain = extract_domain_from_rule(rule)
    if len(domain) < MIN_DOMAIN_LENGTH or "." not in domain:
        return False
    parts = domain.split(".")
    if any(len(p) == 0 or p.startswith("-") or p.endswith("-") for p in parts):
        return False
    return True


def is_valid_whitelist_domain(domain: str) -> bool:
    """
    🔒 白名单域名合法性校验
    ✅ 必须至少两级域名 (example.com, qq.com)
    ❌ 拒绝纯顶级域名 (com, cn, io)
    """
    if not domain or "." not in domain:
        return False
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    # 已修复：移除了对 qq.com/jd.com 等短域名的误判
    return all(0 < len(p) < 64 and not p.startswith("-") and not p.endswith("-") for p in parts)


def load_local_rules(filepath: str, is_whitelist: bool = False) -> set:
    """加载本地规则文件（支持白名单安全校验）"""
    rules = set()
    if not os.path.exists(filepath):
        return rules
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("!") and not line.startswith("#"):
                    if is_valid_rule(line):
                        domain = extract_domain_from_rule(line)
                        if is_whitelist and not is_valid_whitelist_domain(domain):
                            logging.warning(f"⚠️ 跳过无效白名单域名: {domain}")
                            continue
                        rules.add(line)
        logging.info(f"Loaded {len(rules)} rules from {filepath}")
    except Exception as e:
        logging.warning(f"Failed to load {filepath}: {e}")
    return rules


def download_rules_with_stats(sources: list, session: requests.Session) -> tuple:
    """
    下载并解析远程规则（纯净全量下载，移除脆弱的 304 缓存逻辑）
    返回: (raw_rules_set, source_stats_dict)
    """
    raw_rules = set()
    source_stats = {}
    
    logging.info(f"Step 1: Downloading rules from {len(sources)} sources...")
    
    for idx, url in enumerate(sources, 1):
        try:
            source_name = urlparse(url).path.split('/')[-1]
            logging.info(f"  [{idx}/{len(sources)}] Checking: {source_name}...")
            
            # 纯净的全量下载
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            rules_from_source = {
                line.strip() for line in response.text.splitlines() 
                if is_valid_rule(line.strip())
            }
            downloaded_count = len(rules_from_source)
            logging.info(f"    ✓ Downloaded {downloaded_count:,} rules")
            
            # 计算本批次唯一规则数
            unique_count = len([r for r in rules_from_source if r not in raw_rules])
            raw_rules.update(rules_from_source)
            
            source_stats[url] = {
                'downloaded': downloaded_count,
                'unique': unique_count
            }
            logging.info(f"    → {unique_count:,} new rules added")
            
        except Exception as e:
            logging.error(f"    ✗ Failed to download {url}: {e}")
            source_stats[url] = {'downloaded': 0, 'unique': 0}
    
    logging.info(f"Total raw rules collected: {len(raw_rules):,}")
    return raw_rules, source_stats


def optimize_rules(raw_rules: set) -> list:
    """
    智能去重优化：
    1. 按域名长度升序排序（短域名优先覆盖）
    2. 若某域名已被父域名覆盖，则跳过
    """
    logging.info(f"Step 2: Optimizing rules (original: {len(raw_rules):,})...")
    
    sorted_rules = sorted(raw_rules, key=lambda r: len(extract_domain_from_rule(r)))
    optimized = []
    covered_domains = set()
    
    for rule in sorted_rules:
        domain = extract_domain_from_rule(rule)
        is_covered = False
        
        # 检查所有可能的父域名
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in covered_domains:
                is_covered = True
                logging.debug(f"  Skip covered: {domain} (by {parent})")
                break
        
        if not is_covered:
            optimized.append(rule)
            covered_domains.add(domain)
    
    removed = len(raw_rules) - len(optimized)
    rate = (removed / len(raw_rules) * 100) if raw_rules else 0
    logging.info(f"Optimized: {len(optimized):,} rules (removed {removed:,}, {rate:.1f}% reduction)")
    return optimized


def is_whitelisted(domain: str, whitelist_domains: set) -> bool:
    """检查域名是否在白名单中（支持父域名精确匹配）"""
    if domain in whitelist_domains:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in whitelist_domains:
            return True
    return False


def merge_custom_rules(rules: list) -> tuple:
    """合并自定义规则与安全白名单，返回 (最终规则列表, 白名单域名集合)"""
    # 1. 合并自定义规则
    custom_rules = load_local_rules(CUSTOM_RULES_FILE)
    if custom_rules:
        rule_set = set(rules)
        rule_set.update(custom_rules)
        rules = sorted(rule_set, key=lambda r: len(extract_domain_from_rule(r)))
        logging.info(f"Merged {len(custom_rules)} custom rules")
    
    # 2. 应用白名单（安全过滤）
    whitelist = load_local_rules(WHITELIST_FILE, is_whitelist=True)
    whitelist_domains = set()
    
    if whitelist:
        whitelist_domains = {extract_domain_from_rule(r) for r in whitelist}
        original_count = len(rules)
        # 仍然保留删除逻辑以减小文件体积
        rules = [r for r in rules if not is_whitelisted(extract_domain_from_rule(r), whitelist_domains)]
        removed = original_count - len(rules)
        if removed > 0:
            logging.info(f"Whitelisted {removed} rules (including subdomains)")
    
    return rules, whitelist_domains


def generate_output(rules: list, whitelist_domains: set, output_path: str):
    """生成最终输出文件"""
    logging.info(f"Step 3: Writing output to {output_path}...")
    
    # 🔑 关键修复：将白名单转化为 @@ 例外规则追加到末尾
    # 这样即使上游源封了父域名（如 ||qq.com^），白名单中的子域名（如 @@||dns.weixin.qq.com.cn^）依然能生效
    exception_rules = []
    if whitelist_domains:
        exception_rules = [f"@@||{d}^" for d in sorted(whitelist_domains)]
        logging.info(f"Added {len(exception_rules)} whitelist exceptions (@@)")

    final_content_list = rules + exception_rules
    rules_content = "\n".join(final_content_list)
    
    checksum_md5 = hashlib.md5(rules_content.encode("utf-8")).hexdigest()[:16]
    checksum_sha1 = hashlib.sha1(rules_content.encode("utf-8")).hexdigest()[:20]
    estimated_size = len(rules_content.encode("utf-8"))
    
    if estimated_size > MAX_OUTPUT_SIZE:
        logging.warning(f"⚠️ Output size ({estimated_size/1024/1024:.2f}MB) exceeds limit!")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"! Title: {OUTPUT_TITLE}\n")
        f.write(f"! Version: {datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}\n")
        f.write(f"! Last-Modified: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}\n")
        f.write(f"! Total Rules: {len(final_content_list)}\n")
        f.write(f"! Checksum-MD5: {checksum_md5}\n")
        f.write(f"! Checksum-SHA1: {checksum_sha1}\n")
        f.write(f"! Size-Estimated: {estimated_size / 1024:.1f} KB\n")
        f.write("! Source: https://github.com/SamaelTONY/My_DNS_Rules\n\n")
        f.write(rules_content)
    
    logging.info(f"✓ Output saved: {len(final_content_list):,} total rules, {estimated_size/1024:.1f} KB")


def print_summary(rules: list, sources: list, source_stats: dict):
    """打印执行摘要与源贡献统计"""
    print("\n" + "=" * 60)
    print("📊 RULES AGGREGATION SUMMARY")
    print("=" * 60)
    print(f"Sources processed : {len(sources)}")
    print(f"Final rule count  : {len(rules):,}")
    print(f"Output file       : {OUTPUT_FILE}")
    
    if source_stats:
        print("\n📈 Source Contribution:")
        print("-" * 60)
        for url, stats in source_stats.items():
            name = urlparse(url).path.split('/')[-1]
            print(f"  {name:30} {stats['downloaded']:8,} rules ({stats['unique']:,} unique)")
        print("-" * 60)
    
    print("=" * 60 + "\n")


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="ADG Home Rules Aggregator v4.0")
    parser.add_argument("-o", "--output", type=str, default=OUTPUT_FILE, help="Output file path")
    parser.add_argument("-s", "--sources", type=str, nargs="+", help="Override rule source URLs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--dry-run", action="store_true", help="Process but don't write file")
    return parser.parse_args()


def main():
    """主入口函数"""
    args = parse_args()
    setup_logging()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    output_file = args.output
    sources = args.sources if args.sources else RULE_SOURCES
    
    logging.info("🚀 ADG Rules Aggregator v4.0 started")
    logging.info(f"Python {sys.version.split()[0]} | Platform: {sys.platform}")
    
    try:
        session = get_requests_session()
        raw_rules, source_stats = download_rules_with_stats(sources, session)
        
        if not raw_rules:
            logging.error("No rules collected! Check sources or network.")
            sys.exit(1)
        
        optimized_rules = optimize_rules(raw_rules)
        final_rules, whitelist_domains = merge_custom_rules(optimized_rules)
        
        if not args.dry_run:
            generate_output(final_rules, whitelist_domains, output_file)
            print_summary(final_rules, sources, source_stats)
        else:
            logging.info("🔍 Dry-run mode: skipped file output")
            print_summary(final_rules, sources, source_stats)
        
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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADG Home Rules Aggregator v5.0 (Pro/AdRules/TIF Edition)
整合多源广告规则，智能去重后输出 AdGuard Home 格式规则文件
针对 GitHub Actions 环境优化：移除脆弱缓存、修复白名单 @@ 例外、强化去重

v5.0 变更 (2026-09):
  - 移除 EasyPrivacy（DNS 层误杀率高，隐私拦截已由 Pro 覆盖）
  - 新增 HaGeZi TIF Medium（恶意软件/钓鱼/威胁情报防护）
  - 下载统计新增 skipped 计数，便于观察各源被过滤的非 DNS 规则

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
# 规则源列表 - 2026 稳健组合 (Pro + AdRules + TIF Mini)
RULE_SOURCES = [
    # 国际广告/追踪/遥测拦截（平衡型主力）
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    # 国内广告/流氓软件拦截（国内环境主力）
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    # 恶意软件/钓鱼/矿池/C2 防护（高置信度精华版，低误杀）
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt",
]

# 输出配置
OUTPUT_FILE = "my_adg_rules.txt"
OUTPUT_TITLE = "OEC Master Rules (Pro/AdRules/TIF Build)"
MAX_OUTPUT_SIZE = 15 * 1024 * 1024  # 15MB 警告阈值

# 请求配置
REQUEST_TIMEOUT = 60
REQUEST_RETRIES = 3
REQUEST_USER_AGENT = "ADG-Rules-Aggregator/5.0 (+https://github.com/SamaelTONY/My_DNS_Rules)"

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

            # v5.0: 统计被过滤的非标准规则（正则/修饰符规则，DNS 层无法生效）
            lines = [line.strip() for line in response.text.splitlines() if line.strip()]
            rules_from_source = {line for line in lines if is_valid_rule(line)}
            skipped_count = len(lines) - len(rules_from_source)
            downloaded_count = len(rules_from_source)
            logging.info(f"    ✓ Downloaded {downloaded_count:,} valid DNS rules "
                         f"(skipped {skipped_count:,} non-standard/regex rules)")

            # 计算本批次唯一规则数
            unique_count = len([r for r in rules_from_source if r not in raw_rules])
            raw_rules.update(rules_from_source)

            source_stats[url] = {
                'downloaded': downloaded_count,
                'unique': unique_count,
                'skipped': skipped_count
            }
            logging.info(f"    → {unique_count:,} new rules added")

        except Exception as e:
            logging.error(f"    ✗ Failed to download {url}: {e}")
            source_stats[url] = {'downloaded': 0, 'unique': 0, 'skipped': 0}

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
           

#!/usr/bin/env python3

import os
import sys
import time
import json
import random
import logging
import asyncio
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional, Tuple, Set, Iterator
import aiofiles
from aiofiles.threadpool.text import AsyncTextIOWrapper

import aiohttp
from tqdm import tqdm
from colorama import init, Fore, Style
from aiohttp.client import ClientTimeout
from aiohttp.connector import TCPConnector

init(autoreset=True)

DEFAULT_WORKERS = 25
DEFAULT_TIMEOUT = 6
DEFAULT_RATE_LIMIT = 400
DEFAULT_PER_HOST_CONNECTIONS = 20
BATCH_SIZE = 50
CONNECTION_LIMIT_MULTIPLIER = 4

VERSION = "0.0.1"
GITHUB_REPOSITORY: str = "Cybersecurity-Ethical-Hacker/lfier"
GITHUB_URL: str = f"https://github.com/{GITHUB_REPOSITORY}"

class TimeoutFilter(logging.Filter):
    """Filter out timeout-related log messages to reduce noise."""
    def filter(self, record: logging.LogRecord) -> bool:
        timeout_patterns = [
            "Timeout for URL:",
            "Error validating LFI for",
            "ClientTimeout",
            "TimeoutError"
        ]
        return not any(pattern in str(record.msg) for pattern in timeout_patterns)

class HTTPErrorHandler:
    """Centralized HTTP error handling"""
    @staticmethod
    async def handle_request_error(
        error: Exception,
        url: str,
        stats_lock: asyncio.Lock,
        stats: Dict[str, int],
        progress_bar: Optional[tqdm] = None,
        running: bool = True
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        if 'Can redirect only to http or https' in str(error):
            return False, [], {"status": "unsupported_redirect"}
        if isinstance(error, aiohttp.ClientResponseError):
            async with stats_lock:
                stats['errors'] += 1
            return False, [], {"status": "client_response_error"}
        if isinstance(error, aiohttp.ClientConnectorRedirectError):
            async with stats_lock:
                stats['errors'] += 1
            return False, [], {"status": "client_connector_redirect_error"}
        async with stats_lock:
            stats['errors'] += 1
        if running and progress_bar:
            progress_bar.write(f"{Fore.RED}Error processing URL {url}: {error}{Style.RESET_ALL}")
        return False, [], {"status": "error"}

class URLValidator:
    """Centralized URL validation logic"""
    @staticmethod
    def validate_url(url: str) -> bool:
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    @staticmethod
    def validate_url_parameters(url: str) -> Tuple[bool, str, Optional[Dict[str, List[str]]]]:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return False, "No query string found", None
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                return False, "No valid parameters parsed", None
            param_info = []
            for param, values in params.items():
                if not values or values == ['']:
                    param_info.append(f"{param} (empty)")
                else:
                    param_info.append(f"{param}={values[0]}")
            return True, f"Found parameters: {', '.join(param_info)}", params
        except Exception as e:
            return False, f"Error parsing URL parameters: {str(e)}", None

    @staticmethod
    def validate_urls_batch(urls: List[str]) -> Tuple[List[str], List[str], List[str]]:
        valid_urls = []
        invalid_urls = []
        no_param_urls = []
        for url in urls:
            if not URLValidator.validate_url(url):
                invalid_urls.append(url)
                continue
            has_params, _, _ = URLValidator.validate_url_parameters(url)
            if has_params:
                valid_urls.append(url)
            else:
                no_param_urls.append(url)
        return valid_urls, invalid_urls, no_param_urls

class PayloadGroup:
    """Represents a group of payloads and their associated validation indicators."""
    def __init__(self, payloads: Optional[List[str]] = None, 
                 indicators: Optional[List[str]] = None) -> None:
        self.payloads: List[str] = list(dict.fromkeys(payloads)) if payloads else []
        self.indicators: List[str] = indicators or []

def load_grouped_payloads(file_content: str) -> List[PayloadGroup]:
    groups: List[PayloadGroup] = []
    current_payloads: List[str] = []
    current_indicators: List[str] = []
    current_mode: Optional[str] = None
    for line in file_content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            if line.lower().startswith('# payload'):
                if current_mode == 'indicators' and current_payloads and current_indicators:
                    groups.append(PayloadGroup(current_payloads.copy(),
                                               current_indicators.copy()))
                    current_payloads.clear()
                    current_indicators.clear()
                current_mode = 'payloads'
            elif line.lower().startswith('# indicator'):
                current_mode = 'indicators'
            continue
        if current_mode == 'payloads':
            current_payloads.append(line)
        elif current_mode == 'indicators':
            current_indicators.append(line)
    if current_payloads and current_indicators:
        groups.append(PayloadGroup(current_payloads, current_indicators))
    return groups

class URLProcessor:
    """Handles URL manipulation operations."""
    @staticmethod
    def construct_payloaded_urls(base_url: str, payloads: List[str]) -> List[Tuple[str, str, int, str]]:
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        if not query_params:
            return []
        payloaded_urls = []
        for param_name, values in query_params.items():
            for line_num, payload in enumerate(payloads, start=1):
                new_params = query_params.copy()
                new_params[param_name] = [payload]
                new_query = urlencode(new_params, doseq=True)
                new_url = parsed_url._replace(query=new_query).geturl()
                payloaded_urls.append((param_name, new_url, line_num, payload))
        return payloaded_urls

class GitHandler:
    @staticmethod
    def check_git() -> Tuple[bool, str]:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', '--version'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env
                )
            return True, result.stdout.strip()
        except FileNotFoundError:
            return False, "Git is not installed"
        except subprocess.TimeoutExpired:
            return False, "Git command timed out"
        except subprocess.CalledProcessError:
            return False, "Git error"
        except Exception:
            return False, "Git check failed"

    @staticmethod
    def check_repo_status() -> Tuple[bool, str]:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'rev-parse', '--git-dir'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env
                )
            return True, "Repository OK"
        except:
            return False, "Repository not initialized"

class AutoUpdater:
    def __init__(self) -> None:
        self.current_version: str = VERSION
        self.repo_path: Path = Path(__file__).parent
        self.is_git_repo: bool = self._check_git_repo()
        self.default_branch: Optional[str] = self._detect_default_branch()

    def _check_git_repo(self) -> bool:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                subprocess.run(
                    ['git', 'rev-parse', '--git-dir'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return True
        except:
            return False

    def _detect_default_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                return result.stdout.strip() or 'main'
        except:
            return 'main'

    def _run_git_command(self, command: List[str]) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return result.stdout.strip()
        except:
            return None

    def _get_remote_changes(self) -> Tuple[bool, str]:
        if not self.default_branch:
            return False, "Check skipped"
        env = os.environ.copy()
        env["GIT_ASKPASS"] = "echo"
        env["GIT_TERMINAL_PROMPT"] = "0"
        try:
            with open(os.devnull, 'w') as devnull:
                fetch_result = subprocess.run(
                    ['git', 'fetch', '--tags', 'origin'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            if fetch_result.returncode != 0:
                return False, "Check skipped"
        except:
            return False, "Check skipped"
        try:
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0', f'origin/{self.default_branch}'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            remote_tag = result.stdout.strip()
            if not remote_tag:
                return False, "Check skipped"
        except:
            return False, "Check skipped"
        remote_version = remote_tag.lstrip('v')
        current_version = self.current_version
        try:
            has_changes = self._compare_versions(remote_version, current_version)
            return has_changes, remote_version
        except:
            return False, "Check skipped"

    def _perform_update(self) -> Dict[str, Any]:
        if not self.default_branch:
            return {
                'status': 'error',
                'message': 'No default branch detected'
            }
        if not self._run_git_command(['git', 'reset', '--hard', f'origin/{self.default_branch}']):
            return {
                'status': 'error',
                'message': 'Update failed'
            }
        pull_output = self._run_git_command(['git', 'pull', '--force', 'origin', self.default_branch])
        if not pull_output:
            return {
                'status': 'error',
                'message': 'Pull failed'
            }
        current_tag = self._run_git_command(['git', 'describe', '--tags', '--abbrev=0']) or VERSION
        return {
            'status': 'success',
            'message': 'Update successful',
            'version': current_tag.lstrip('v'),
            'changes': pull_output,
            'updated': True
        }

    def _compare_versions(self, v1: str, v2: str) -> bool:
        def to_ints(v: str):
            return list(map(int, v.split('.')))
        return to_ints(v1) > to_ints(v2)

    def check_and_update(self) -> Dict[str, Any]:
        if not self.is_git_repo:
            return {
                'status': 'error',
                'message': 'Not a git repository'
            }
        has_changes, info = self._get_remote_changes()
        if info == "Check skipped":
            return {
                'status': 'success',
                'message': 'Check skipped',
                'version': self.current_version,
                'updated': False
            }
        elif not has_changes:
            return {
                'status': 'success',
                'message': 'Already at latest version',
                'version': self.current_version,
                'updated': False
            }
        update_result = self._perform_update()
        return update_result

class BatchProcessor:
    """Handles processing of items in batches for efficient resource usage."""
    def __init__(self, batch_size: int = 50) -> None:
        self.batch_size = batch_size

    def create_batches(self, items: List[Any]) -> Iterator[List[Any]]:
        for i in range(0, len(items), self.batch_size):
            yield items[i:i + self.batch_size]

class RateLimiter:
    """Implements token bucket algorithm for rate limiting requests."""
    def __init__(self, rate_limit: int) -> None:
        self.rate_limit: int = rate_limit
        self.tokens: float = rate_limit
        self.last_update: float = time.time()
        self.lock: asyncio.Lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(self.rate_limit, self.tokens + time_passed * self.rate_limit)
            self.last_update = now
            if self.tokens < 1:
                await asyncio.sleep(1/self.rate_limit)
                self.tokens = 1
            self.tokens -= 1

class LFIScanner:
    """Main scanner class that orchestrates the LFI vulnerability scanning process."""
    def __init__(self, config: 'Config') -> None:
        self.semaphore = asyncio.Semaphore(config.max_workers)
        self.config: 'Config' = config
        self.stats: Dict[str, int] = {
            'total_urls': 0,
            'total_parameters': 0,
            'payloads_tested': 0,
            'successful_payloads': 0,
            'failed_payloads': 0,
            'errors': 0,
            'current_test': 0,
            'total_tests': 0
        }
        self.batch_processor: BatchProcessor = BatchProcessor(config.batch_size)
        self.rate_limiter: RateLimiter = RateLimiter(config.rate_limit)
        self.progress_lock: asyncio.Lock = asyncio.Lock()
        self.results_lock: asyncio.Lock = asyncio.Lock()
        self.buffer_lock: asyncio.Lock = asyncio.Lock()
        self.result_buffer: List[Dict[str, Any]] = []
        self.BUFFER_SIZE: int = 1000
        self.results: List[str] = []
        self.json_results: List[Dict[str, Any]] = []
        self.start_time: Optional[float] = None
        self.running = True
        self.pbar: Optional[tqdm] = None
        self.payload_groups: List[PayloadGroup] = []
        self.tested_payloads: Set[Tuple[str, str, str]] = set()
        self.discovered_vulnerabilities: Set[Tuple[str, str, str]] = set()
        self.found_vulnerable: Set[Tuple[str, str]] = set()
        self.vuln_lock: asyncio.Lock = asyncio.Lock()

    async def _flush_buffer(self) -> None:
        async with self.buffer_lock:
            if not self.result_buffer:
                return
            
            if self.config.json_output:
                self.json_results.extend(self.result_buffer)
                try:
                    async with aiofiles.open(self.config.output_file, 'w') as f:
                        await f.write(json.dumps(self.json_results, indent=2))
                except Exception as e:
                    print(f"\n{Fore.RED}Error saving JSON results: {e}{Style.RESET_ALL}")
            else:
                try:
                    async with aiofiles.open(self.config.output_file, 'a') as f:
                        for result in self.result_buffer:
                            formatted_result = (
                                f"LFI vulnerability found: [parameter: {result['parameter']}] "
                                f"[domain: {result['hostname']}] | [Payload #{result['payload_number']}]\n"
                                f"Patterns matched:\n"
                            )
                            for pattern in result['patterns_matched']:
                                formatted_result += f"- {pattern}\n"
                            formatted_result += f"Status code: {result['response_info']['status']}\n"
                            formatted_result += f"Url with payload: {result['url_with_payload']}\n\n"
                            await f.write(formatted_result)
                except Exception as e:
                    print(f"\n{Fore.RED}Error saving text results: {e}{Style.RESET_ALL}")
            
            self.result_buffer.clear()

    async def claim_vulnerability(self, hostname: str, param: str) -> bool:
        key = (hostname, param)
        async with self.vuln_lock:
            if key in self.found_vulnerable:
                return False
            self.found_vulnerable.add(key)
            return True

    async def is_payload_tested(self, hostname: str, param: str, payload: str) -> bool:
        normalized_payload = payload.strip()
        key = (hostname, param, normalized_payload)
        async with self.vuln_lock:
            if key in self.tested_payloads:
                return True
            self.tested_payloads.add(key)
            return False

    async def validate_lfi(
        self,
        session: aiohttp.ClientSession,
        url: str,
        indicators: List[str]
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        if not self.running:
            return False, [], {}
        try:
            await self.rate_limiter.acquire()
            timeout = ClientTimeout(
                total=self.config.timeout,
                connect=self.config.connect_timeout,
                sock_read=self.config.read_timeout
            )
            async with session.get(url, timeout=timeout, allow_redirects=True) as response:
                content = await response.text()
                matched_indicators = [pattern for pattern in indicators if pattern in content]
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location', '')
                    return False, [], {"status": response.status, "redirect_location": location}
                if matched_indicators:
                    return True, matched_indicators, {
                        "status": response.status,
                        "content_length": len(content),
                        "validation_reason": "Indicator matched"
                    }
                return False, [], {"status": response.status}
        except Exception as e:
            return await HTTPErrorHandler.handle_request_error(
                error=e,
                url=url,
                stats_lock=self.progress_lock,
                stats=self.stats,
                progress_bar=self.pbar,
                running=self.running
            )

    async def process_url(self, session: aiohttp.ClientSession, url: str) -> None:
        async with self.semaphore:
            hostname = urlparse(url).netloc
            for group in self.payload_groups:
                if not self.running:
                    break
                payloaded_urls = URLProcessor.construct_payloaded_urls(url, group.payloads)
                for param, payloaded_url, line_num, payload in payloaded_urls:
                    if not self.running:
                        break
                    if await self.is_payload_tested(hostname, param, payload):
                        continue
                    is_vulnerable, patterns_matched, response_info = await self.validate_lfi(
                        session, payloaded_url, group.indicators
                    )
                    if is_vulnerable:
                        claimed = await self.claim_vulnerability(hostname, param)
                        if claimed:
                            await self._handle_vulnerability(
                                url, param, line_num, patterns_matched,
                                payloaded_url, response_info
                            )
                            async with self.progress_lock:
                                self.stats['payloads_tested'] += 1
                                self.stats['successful_payloads'] += 1
                            break
                    else:
                        async with self.progress_lock:
                            self.stats['payloads_tested'] += 1
                            self.stats['failed_payloads'] += 1
                            self.stats['current_test'] += 1
                            if self.running and self.pbar:
                                self.pbar.update(1)

    async def _handle_vulnerability(
        self,
        url: str,
        param: str,
        line_num: int,
        patterns: List[str],
        payloaded_url: str,
        response_info: Dict[str, Any]
    ) -> None:
        hostname = urlparse(url).netloc
        indicator_count = len(patterns)
        main_indicator = patterns[0]
        indicator_display = f"{main_indicator[:40]}..." if len(main_indicator) > 40 else main_indicator
        if indicator_count > 1:
            indicator_display += f" (+{indicator_count-1} more)"
        output = (
            f"{Fore.GREEN}🎯 LFI Found!{Style.RESET_ALL}  "
            f"Domain: {Fore.YELLOW}{hostname}{Style.RESET_ALL}  |  "
            f"Parameter: {Fore.YELLOW}{param}{Style.RESET_ALL}  |  "
            f"Indicator: {Fore.YELLOW}{indicator_display}{Style.RESET_ALL} | "
            f"Payload #{Fore.YELLOW}{line_num}{Style.RESET_ALL}"
        )
        result_data = {
            "parameter": param,
            "hostname": hostname,
            "payload_number": line_num,
            "url_with_payload": payloaded_url,
            "patterns_matched": patterns,
            "response_info": response_info
        }
        async with self.buffer_lock:
            self.result_buffer.append(result_data)
            if len(self.result_buffer) >= self.BUFFER_SIZE:
                await self._flush_buffer()
        if self.running and self.pbar:
            self.pbar.write(output)

    async def run(self) -> None:
        try:
            print_banner(self.config)
            self.start_time = time.time()
            print(f"{Fore.CYAN}📦 Loading URLs...{Style.RESET_ALL}")
            urls = await load_file_async(self.config.url_list) if self.config.url_list else [self.config.domain]
            valid_urls, invalid_urls, no_param_urls = URLValidator.validate_urls_batch(urls)
            if not valid_urls:
                print(f"\n{Fore.RED}No valid URLs with parameters found to scan.{Style.RESET_ALL}")
                return
            urls = valid_urls
            try:
                with open(self.config.payload_file, 'r') as f:
                    payload_content = f.read()
            except FileNotFoundError:
                print(f"\n{Fore.RED}Payload file not found: {self.config.payload_file}{Style.RESET_ALL}")
                sys.exit(1)
            except Exception as e:
                print(f"\n{Fore.RED}Error reading payload file: {e}{Style.RESET_ALL}")
                sys.exit(1)
            self.payload_groups = load_grouped_payloads(payload_content)
            total_payloads = sum(len(group.payloads) for group in self.payload_groups)
            total_parameters = 0
            for url in urls:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                total_parameters += len(params)
            self.stats.update({
                'total_urls': len(urls),
                'total_parameters': total_parameters,
                'total_tests': total_parameters * total_payloads
            })
            if self.stats['total_tests'] > 0:
                self.pbar = tqdm(
                    total=self.stats['total_tests'],
                    desc='Progress',
                    unit='Req',
                    unit_scale=False,
                    leave=True,
                    dynamic_ncols=True,
                    colour='green',
                    bar_format='{l_bar}{bar}| [Payloads: {n_fmt}/{total_fmt}] [Time:{elapsed} - Est:{remaining}] [{rate_fmt}]'
                )
                if self.pbar:
                    self.pbar.write(f"{Fore.GREEN}🔗 Loaded {len(urls)} URLs and {total_payloads} payloads{Style.RESET_ALL}")
                    self.pbar.write(f"{Fore.YELLOW}🔍 Starting the scan...{Style.RESET_ALL}\n")
            else:
                print(f"\n{Fore.RED}No tests to perform. Exiting.{Style.RESET_ALL}")
                return
            async with aiohttp.ClientSession(
                connector=TCPConnector(**self.config.connector_kwargs),
                headers=self.config.headers,
                timeout=ClientTimeout(total=self.config.timeout),
                trust_env=True,
                raise_for_status=False
            ) as session:
                try:
                    for batch in self.batch_processor.create_batches(urls):
                        if not self.running:
                            break
                        await asyncio.gather(
                            *(self.process_url(session, url) for url in batch),
                            return_exceptions=True
                        )
                except asyncio.CancelledError:
                    raise KeyboardInterrupt
            await self._flush_buffer()
            if self.config.json_output:
                try:
                    with open(self.config.output_file, 'w') as f:
                        json.dump(self.json_results, f, indent=2)
                except Exception as e:
                    print(f"\n{Fore.RED}Error saving JSON results: {e}{Style.RESET_ALL}")
            else:
                try:
                    with open(self.config.output_file, 'w') as f:
                        f.write('\n'.join(self.results))
                except Exception as e:
                    print(f"\n{Fore.RED}Error saving text results: {e}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            self.running = False
            if self.pbar:
                self.pbar.close()
            print(f"\n{Fore.YELLOW}🚫 Scan interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Error during scan: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error during scan: {str(e)}")
        finally:
            if self.pbar:
                self.pbar.n = self.pbar.total
                self.pbar.refresh()
                self.pbar.close()
            if self.start_time:
                duration = time.time() - self.start_time
                minutes, seconds = divmod(int(duration), 60)
                print(f"\n{Fore.CYAN}🏁 Scan Complete! Summary:{Style.RESET_ALL}")
                print("="*30)
                print(f"Duration: {Fore.GREEN}{minutes}m {seconds}s{Style.RESET_ALL}")
                print(f"URLs tested: {Fore.GREEN}{self.stats['total_urls']}{Style.RESET_ALL}")
                print(f"Parameters tested: {Fore.GREEN}{self.stats['total_parameters']}{Style.RESET_ALL}")
                print(f"Payloads tested: {Fore.GREEN}{self.stats['payloads_tested']}{Style.RESET_ALL}")
                print(f"LFI found: {Fore.GREEN}{self.stats['successful_payloads']}{Style.RESET_ALL}")
                print(f"Failed payloads: {Fore.YELLOW}{self.stats['failed_payloads']}{Style.RESET_ALL}")
                print(f"Errors: {Fore.RED if self.stats['errors'] > 0 else Fore.GREEN}{self.stats['errors']}{Style.RESET_ALL}")
                print("="*30)
                if self.stats['successful_payloads'] == 0:
                    print(f"\n{Fore.YELLOW}No vulnerabilities found.{Style.RESET_ALL}")
                if self.results or self.json_results:
                    print(f"\n{Fore.CYAN}📝 Results saved to:{Style.RESET_ALL} {Fore.GREEN}{self.config.output_file.absolute()}{Style.RESET_ALL}")

class CustomHelpFormatter(argparse.HelpFormatter):
    """Custom formatter for argparse help text with improved layout."""
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if hasattr(self, '_usage_mode'):
                return action.option_strings[0]
            parts.extend(action.option_strings)
            return ', '.join(parts)

    def _format_usage(self, usage: str, actions: List[argparse.Action],
                     groups: List[argparse._ArgumentGroup], prefix: Optional[str]) -> str:
        if prefix is None:
            prefix = 'usage: '
        self._usage_mode = True
        action_usage = []
        action_usage.append("[-h HELP]")
        action_usage.append("[-d DOMAIN | -l URL_LIST]")
        for action in actions:
            if action.option_strings:
                if action.option_strings[0] not in ['-h', '-d', '-l']:
                    msg = self._format_action_invocation(action)
                    upper_dest = action.dest.upper()
                    action_usage.append(f"[{msg} {upper_dest}]")
        usage = ' '.join([x for x in action_usage if x])
        delattr(self, '_usage_mode')
        return f"{prefix}{self._prog} {usage}"

class CustomArgumentParser(argparse.ArgumentParser):
    """Custom argument parser with improved error handling and update flag support."""
    def error(self, message: str) -> None:
        """Handle parsing errors by showing the full help message."""
        args = sys.argv[1:]
        if '-u' in args or '--update' in args:
            if len(args) == 1:  # Only update flag provided
                return  # Allow execution to continue
                
        # Print full help message for any error
        self.print_help()
        
        # Add error message at the end
        if "one of the arguments -d/--domain -l/--url-list is required" in message:
            print(f"\n{Fore.RED}❌ One of the arguments is required -d/--domain or -l/--url-list{Style.RESET_ALL}")
        elif "unrecognized arguments" in message:
            print(f"\n{Fore.RED}Error: {message}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}Error: {message}{Style.RESET_ALL}")
            
        sys.exit(2)

def parse_arguments() -> argparse.Namespace:
    parser = CustomArgumentParser(
        formatter_class=lambda prog: CustomHelpFormatter(prog, max_help_position=80)
    )
    parser.add_argument('-u', '--update', action='store_true', 
                       help='Check for updates and automatically install the latest version')
    mutex_group = parser.add_mutually_exclusive_group(required=False)
    mutex_group.add_argument('-d', '--domain', 
                           help='Specify the domain with parameter(s) to scan (required unless -l is used)')
    mutex_group.add_argument('-l', '--url-list', 
                           help='Provide a file containing a list of URLs with parameters to scan')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                       help='Total request timeout in seconds')
    parser.add_argument('--connect-timeout', type=int, default=5,
                       help='Timeout for establishing connections in seconds')
    parser.add_argument('--read-timeout', type=int, default=5,
                       help='Timeout for reading responses in seconds')
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS,
                       help='Maximum number of concurrent workers')
    parser.add_argument('-r', '--rate', type=int, default=DEFAULT_RATE_LIMIT,
                       help='Request rate limit')
    parser.add_argument('-b', '--batch-size', type=int, default=50,
                       help='Number of items to process in each batch')
    parser.add_argument('-p', '--payloads', help='Custom file containing payloads')
    parser.add_argument('-o', '--output', help='Specify the output file name (supports .txt or .json)')
    parser.add_argument('-j', '--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('-H', '--header', action='append', 
                       help='Custom headers can be specified multiple times. Format: "Header: Value"')
    parser._optionals.title = "\nOptions"
    args = parser.parse_args()
    if not args.update and not (args.domain or args.url_list):
        parser.error("one of the arguments -d/--domain -l/--url-list is required")
    return args

class Config:
    """Configuration handler for the scanner."""
    def __init__(self, args: argparse.Namespace) -> None:
        self.domain = args.domain
        self.url_list: Optional[str] = args.url_list
        self.json_output = args.json
        self.timeout = args.timeout
        self.connect_timeout: int = args.connect_timeout
        self.read_timeout: int = args.read_timeout
        self.rate_limit: int = args.rate
        self.max_workers: int = args.workers
        self.batch_size: int = args.batch_size
        self.connector_kwargs: Dict[str, Any] = {
            'limit': self.max_workers * CONNECTION_LIMIT_MULTIPLIER,
            'ttl_dns_cache': 3600,
            'enable_cleanup_closed': True,
            'force_close': False,
            'limit_per_host': DEFAULT_PER_HOST_CONNECTIONS,
            'ssl': False
        }
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir: Path = Path(f"scans/{self._get_base_name()}")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.payload_file: Path = (Path(args.payloads) if args.payloads else 
                                Path(__file__).parent / "lfi_payloads.txt")
        self.output_file: Path = self._configure_output_file(args.output, timestamp)
        self.using_default_headers: bool = not bool(args.header)
        self.headers: Dict[str, str] = self.get_default_headers()
        if args.header:
            self.headers.clear()
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    self.headers[key.strip()] = value.strip()
        repo_status, repo_message = GitHandler.check_repo_status()
        if not repo_status:
            self.version_info = {
                'current': "Unknown",
                'update_available': 'Unknown (No Repository)'
            }
        else:
            self.version_info = self._check_version()

    def _get_current_version(self) -> str:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=Path(__file__).parent
                )
            version = result.stdout.strip()
            if not version:
                return "Unknown"
            return version.lstrip('v')
        except:
            return "Unknown"

    def _get_remote_version(self) -> Optional[str]:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                fetch_result = subprocess.run(
                    ['git', 'fetch', '--tags', 'origin'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=Path(__file__).parent
                )
                if fetch_result.returncode != 0:
                    return None
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0', 'origin/main'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=Path(__file__).parent
                )
            version = result.stdout.strip()
            return version.lstrip('v') if version else None
        except:
            return None

    def _check_version(self) -> Dict[str, str]:
        try:
            current_version = self._get_current_version()
            if current_version == "Unknown":
                return {
                    'current': current_version,
                    'update_available': 'Unknown'
                }
            updater = AutoUpdater()
            update_result = updater.check_and_update()
            if update_result.get('status') == 'error':
                return {
                    'current': current_version,
                    'update_available': 'Check skipped'
                }
            elif update_result.get('message') == 'Check skipped':
                return {
                    'current': current_version,
                    'update_available': 'Check skipped'
                }
            elif update_result.get('updated'):
                return {
                    'current': current_version,
                    'update_available': 'Yes'
                }
            return {
                'current': current_version,
                'update_available': 'No'
            }
        except Exception as e:
            return {
                'current': self._get_current_version(),
                'update_available': 'Check skipped'
            }

    def _get_base_name(self) -> str:
        if self.domain:
            parsed = urlparse(self.domain)
            return parsed.netloc if parsed.netloc else self.domain
        elif self.url_list:
            return Path(self.url_list).stem
        return 'scan'

    def _configure_output_file(self, output_arg: Optional[str], timestamp: str) -> Path:
        if output_arg:
            output_path = Path(output_arg)
            suffix = '.json' if self.json_output else '.txt'
            return output_path.parent / f"{output_path.stem}_{timestamp}{suffix}"
        return self.base_dir / f"lfi_results_{timestamp}.{'json' if self.json_output else 'txt'}"

    def get_default_headers(self) -> Dict[str, str]:
        major_version = random.randint(120, 122)
        build = random.randint(6200, 6300)
        patch = random.randint(100, 150)
        chrome_version = f"{major_version}.0.{build}.{patch}"
        win_versions = ['10.0', '11.0']
        win_version = random.choice(win_versions)
        languages = [
            'en-US,en;q=0.9',
            'en-US,en;q=0.9,es;q=0.8',
            'en-GB,en;q=0.9',
            'en-US,en;q=0.9,fr;q=0.8',
            'en-US,en;q=0.9,de;q=0.8'
        ]
        resolutions = ['1920', '1680', '1440', '2560']
        memories = ['4', '8', '16']
        headers = {
            'User-Agent': f'Mozilla/5.0 (Windows NT {win_version}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36',
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            ]),
            'Accept-Language': random.choice(languages),
            'Accept-Encoding': random.choice([
                'gzip, deflate, br',
                'gzip, deflate',
                'br, gzip, deflate'
            ]),
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not(A:Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': f'"Windows"',
            'Sec-Ch-Ua-Platform-Version': f'"{win_version}"',
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
            'Sec-Fetch-Mode': random.choice(['navigate', 'same-origin']),
            'Sec-Fetch-User': random.choice(['?1', '?0']),
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1',
            'Connection': random.choice(['keep-alive', 'close']),
            'Priority': random.choice(['u=0, i', 'u=1, i']),
            'Viewport-Width': random.choice(resolutions),
            'Device-Memory': random.choice(memories),
        }
        if random.random() > 0.3:
            headers['DNT'] = '1'
        if random.random() > 0.5:
            headers['Permissions-Policy'] = 'interest-cohort=()'
        if random.random() > 0.7:
            headers['TE'] = 'trailers'
        return headers

async def load_file_async(file_path: str) -> List[str]:
    try:
        async with aiofiles.open(Path(file_path), 'r') as f:
            content = await f.read()
            return [line.strip() for line in content.split('\n') if line.strip()]
    except FileNotFoundError:
        print(f"\n{Fore.RED}Error: File not found - {file_path}{Style.RESET_ALL}")
        sys.exit(1)

def setup_logging(config: Config) -> None:
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.ERROR)
    
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    error_handler = logging.FileHandler(logs_dir / 'lfier_scanner_errors.log')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s:%(message)s'))
    
    root_logger.addHandler(error_handler)

def print_banner(config: Config) -> None:
    logo_width = 40
    author_text = "By Dimitris Chatzidimitris"
    email_text = "Email: dimitris.chatzidimitris@gmail.com"
    features_text = "Async HTTP Engine / Parameter Validation / Pattern-Based Detection"
    centered_author = author_text.center(logo_width)
    centered_email = email_text.center(logo_width)
    centered_features = features_text.center(logo_width)
    payload_display = config.payload_file.name if config.payload_file.is_relative_to(Path.cwd()) \
        else str(config.payload_file)
    output_display = str(config.output_file.absolute())
    headers_status = "Default" if config.using_default_headers else "Custom"
    banner = f"""
{Fore.GREEN}
██╗     ███████╗██╗███████╗██████╗ 
██║     ██╔════╝██║██╔════╝██╔══██╗
██║     █████╗  ██║█████╗  ██████╔╝
██║     ██╔══╝  ██║██╔══╝  ██╔══██╗
███████╗██║     ██║███████╗██║  ██║
╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.GREEN}{centered_author}
{centered_email}
{centered_features}{Style.RESET_ALL}

{Fore.CYAN}🔧Configuration:{Style.RESET_ALL}
- Version: {Fore.YELLOW}{config.version_info['current']}{Style.RESET_ALL}
- Update Available: {Fore.YELLOW}{config.version_info['update_available']}{Style.RESET_ALL}
- Workers: {Fore.YELLOW}{config.max_workers}{Style.RESET_ALL}
- Timeout: {Fore.YELLOW}{config.timeout}s{Style.RESET_ALL}
- Connections per host: {Fore.YELLOW}{config.connector_kwargs['limit_per_host']}{Style.RESET_ALL}
- Global Rate Limit: {Fore.YELLOW}{config.rate_limit} req/s{Style.RESET_ALL}
- Payloads File: {Fore.YELLOW}{payload_display}{Style.RESET_ALL}
- Custom Headers: {Fore.YELLOW}{headers_status}{Style.RESET_ALL}
- Output Format: {Fore.YELLOW}{'JSON' if config.json_output else 'Text'}{Style.RESET_ALL}
- Output File: {Fore.YELLOW}{output_display}{Style.RESET_ALL}
"""
    print(banner)

def main() -> None:
    args = parse_arguments()
    if args.update:
        git_handler = GitHandler()
        if not git_handler.check_git()[0]:
            print(f"\n{Fore.RED}Cannot check for updates without Git installed.{Style.RESET_ALL}")
            sys.exit(1)
        updater = AutoUpdater()
        if not updater.is_git_repo:
            print(f"{Fore.RED}Not a git repository. Cannot update.{Style.RESET_ALL}")
            sys.exit(1)
        print(f"\n{Fore.CYAN}Checking for updates...{Style.RESET_ALL}")
        update_result = updater.check_and_update()
        if update_result.get('status') == 'error':
            print(f"{Fore.RED}Update failed: {update_result.get('message')}{Style.RESET_ALL}")
            sys.exit(1)
        elif update_result.get('updated'):
            print(f"{Fore.GREEN}Tool updated successfully to version {update_result.get('version')}!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please restart the tool...{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.GREEN}{update_result.get('message', 'Already up-to-date.')}{Style.RESET_ALL}")
            sys.exit(0)
    config = Config(args)
    setup_logging(config)
    scanner = LFIScanner(config)
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()

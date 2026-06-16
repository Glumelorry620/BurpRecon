    # BurpRecon

    **Attack Surface Intelligence from Burp Suite XML exports**

    BurpRecon parses Burp Suite proxy history (`.xml` exports) and runs an automated multi-phase analysis to surface high-value vulnerability candidates — IDORs, Host Header Injection, Privilege Escalation vectors, obfuscated paths, tech fingerprints, and CVE lookups — all from a single interactive CLI.

    Built for bug bounty hunters who want signal, not noise.

    ---

    ## Features

    | Phase | What it does |
    |-------|-------------|
    | **Phase 1 — Parse** | Extracts all endpoints, hosts, status codes, HTTP methods, and flags (IDOR, AUTH, JWT, FINANCIAL, GQL, S3, WRITE…) from a Burp XML export |
    | **Phase 2A — IDOR/BOLA** | Scores every numeric-ID endpoint (CRITICAL / HIGH / MEDIUM / LOW) and generates ready-to-run `curl` + Python PoC for each candidate |
    | **Phase 2B — Host Header Injection** | Detects password-reset, OTP, and email flows and outputs 7 inject headers + `curl` PoC per endpoint |
    | **Phase 2C — Privilege Escalation** | Flags role params, JWT-authenticated endpoints (alg:none, RS256→HS256, kid injection), and WRITE operations on user/account paths |
    | **Phase 2D — GraphQL** | Generates introspection, batch, IDOR-via-args, alias-bypass, and field-suggestion payloads for every GQL endpoint |
    | **Phase 2E — Open Redirect / SSRF** | Finds `url=`, `redirect=`, `next=` parameters and outputs 5 bypass payloads per endpoint |
    | **Phase 2F — Obfuscated Paths** | Shannon entropy analysis + UUID + hex token detection with enumeration test ideas |
    | **Phase 3 — Tech Fingerprint + CVE** | Parses `Server`, `X-Powered-By`, `Via`, `X-Cache` headers → maps to tech stack → CVE lookup chain |
    | **Phase 4 — Recon** | Subfinder + Amass passive subdomain enum → httpx live probe → 53-path API crawl (Swagger, GraphQL, health checks…) |

    ### CVE Lookup Chain (no API key required)

    1. **searchsploit** (local ExploitDB) — if installed, used exclusively, zero network calls
    2. **ExploitDB web** — public JSON API, no key, no rate limit
    3. **CIRCL CVE Search** (cve.circl.lu) — free, no key, no rate limit

    ---

    ## Prerequisites

    - **Python 3.8+** (f-strings and `pathlib` required; tested on 3.10 / 3.12)
    - **Burp Suite** (Community or Pro) — any version that can export proxy history as XML

    ---

    ## Installation

    ```bash
    git clone https://github.com/berrinche699/BurpRecon
    cd BurpRecon
    pip install -r requirements.txt
    ```

    ### External tools (optional but recommended)

    | Tool | Used for | Install |
    |------|----------|---------|
    | `searchsploit` | Local CVE/exploit lookup | `sudo apt install exploitdb` or via Kali |
    | `subfinder` | Passive subdomain enumeration | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
    | `amass` | Passive subdomain enumeration | [owasp-amass/amass](https://github.com/owasp-amass/amass) |
    | `httpx` | Live host probing | `pip install httpx` or [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |

    On Windows, run `install_tools.ps1` to download the latest `subfinder` and `amass` binaries automatically:

    ```powershell
    .\install_tools.ps1
    ```

    > **Note for Windows users:** `install_tools.ps1` places binaries in a local `tools/` folder and adds it to the session PATH. If you run BurpRecon from a new terminal, the tools will still be found automatically — the script handles discovery via both `PATH` and the local `tools/` directory.

    ---

    ## Usage

    ```bash
    python burprecon_ui.py
    ```

    ```
    MAIN MENU

    [1]  Phase 1  —  Parse Burp XML
    [2]  Phase 2  —  Deep Vulnerability Analysis
    [3]  Phase 3  —  Tech Fingerprint + CVE
    [4]  Run All  —  Phases 1 + 2 + 3 (full pipeline)
    [5]  Recon    —  Subdomains + API crawl

    [0]  Exit
    ```

    Enter the path to your Burp XML export when prompted. You can optionally scope the analysis to a single hostname (e.g. `api.target.com`).

    **WSL users:** Windows paths are auto-converted — you can paste `C:\Users\...\export.xml` directly.

    > **The tool is fully interactive** — there are no required CLI arguments. Just run it and follow the menu.

    ### How to export from Burp Suite

    1. Open Burp Suite → **Proxy → HTTP history**
    2. Select the requests you want to analyze (Ctrl+A for all, or filter by host first)
    3. Right-click → **Save items**
    4. Save as `.xml` — make sure **Base64-encode requests and responses** is checked
    5. Pass the resulting file to BurpRecon when prompted

    ### Output

    - Colored real-time output in the terminal
    - Full report saved as `<name>_burprecon.txt` next to your XML file

    ---

    ## IDOR Scoring

    | Priority | Condition |
    |----------|-----------|
    | **CRITICAL** | `GET` + `200` + numeric ID in path |
    | **HIGH** | `PUT/POST/PATCH/DELETE` + `200/201` + numeric ID |
    | **MEDIUM** | Any `2xx` + numeric ID |
    | **POTENTIAL** | `4xx` (not 403) + numeric ID — a `404` on a modified ID confirms the ID is the object identifier, classic indirect IDOR signal. Test with a second authenticated session. |
    | **INFO** | `OPTIONS` or `403` — blocked, but worth retesting with a different role |

    Each finding includes the original ID, a set of test IDs (sequential ±1, low integers, IDs seen elsewhere in the session), and a copy-paste `curl` + Python PoC.

    ---

## Python Dependencies

    ```
    colorama>=0.4.6
    ```

    Everything else uses Python standard library only (`xml.etree`, `urllib`, `json`, `subprocess`, `pathlib`…).

    ---

    ## Disclaimer

    This tool is intended for authorized security testing and bug bounty research only.  
    **Do not use against systems you do not have explicit permission to test.**  
    The author assumes no liability for misuse.

    ---

    ## License

    MIT

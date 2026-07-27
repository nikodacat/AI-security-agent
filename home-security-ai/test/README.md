# home-security-ai test lab

End-to-end test setup for cve-scanner + home-security-ai. Runs in a disposable
Windows VM so we can install software with known active CVEs without
risking the host.

## Why VM-only

The script `install-vulnerable-apps.ps1` installs four pieces of software with
KEV-listed, ransomware-or-APT-deployed vulnerabilities. Do not run this on your
day-to-day machine. Use a VirtualBox / Hyper-V snapshot you can revert.

## Step 1: get a Windows VM

Microsoft's free pre-built "Windows Dev VM" downloads have been paused since
2024. The currently-available official path is:

1. Grab **Windows 11 Enterprise Evaluation** ISO (90-day, no key required) from
   [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise).
2. Create a new VirtualBox VM:
   - Type: Microsoft Windows
   - Version: Windows 11 (64-bit)
   - RAM: 4096 MB minimum, 8192 MB recommended
   - CPU: 2+ cores
   - Disk: 60 GB dynamic
   - Enable EFI in System -> Motherboard, enable TPM 2.0 if your VirtualBox
     version supports it (>= 7.0)
3. Mount the ISO and install Windows normally. Skip the Microsoft account
   step (use Shift+F10 -> `OOBE\BYPASSNRO` if prompted).
4. Snapshot the freshly-installed VM as `clean-baseline` so you can roll back.

If your VirtualBox is older than 7.0 and can't fake TPM, install **Windows 10
Enterprise Evaluation** instead — also 90-day, same evaluation center.

## Step 2: install Python + the scanners inside the VM

```powershell
# Inside the VM, as Administrator
winget install --id Python.Python.3.12 --source winget
winget install --id Git.Git --source winget

git clone https://github.com/<your-fork>/project.git C:\project
cd C:\project\home-security-ai
.\setup.ps1
```

`setup.ps1` creates `.venv` and pulls everything from `requirements.txt`
(including `rapidfuzz` for the new KEV engine).

For the Claude CLI: install Claude Code inside the VM and run `claude` once
to sign in with your subscription. The scanner picks it up via PATH.

## Step 3: install deliberately-vulnerable apps

```powershell
cd C:\project\home-security-ai\test
$env:HOMESEC_TEST_VM_CONFIRM = "YES_I_AM_IN_A_DISPOSABLE_VM"
.\install-vulnerable-apps.ps1
```

The safety gate refuses to run without the env var. The script downloads
installers from each vendor's official archive — there's no Chocolatey
dependency because Chocolatey is unreliable for very old version pins.

What gets installed:

| Software | Version | KEV CVE | Why |
|---|---|---|---|
| 7-Zip | 22.01 | CVE-2025-0411 | Mark-of-the-Web bypass; fixed in 24.09 |
| Notepad++ | 8.6.4 | CVE-2025-15556 | WinGUp updater integrity; fixed later in 8.6 line |
| Firefox ESR | 115.5.0 | CVE-2024-9680 | UAF in animation timelines; ransomware-flagged on KEV |
| WinRAR | 6.10 | CVE-2023-38831 | Russian APT used against Ukraine; fixed in 6.23 |

Snapshot the VM again as `vulnerable-baseline` after install.

## Step 4: run cve-scanner standalone

```powershell
cd C:\project\cve-scanner
python -m cve_scanner scan --check-versions --no-explain
```

You should see (versions / counts will vary slightly with KEV updates):

```
[3/5] Matching against KEV...
      ~13 finding(s) (1 ransomware-linked)
[4/5] Checking installed versions against NVD CPE ranges (~10 unique CVEs)...
      vulnerable=4  patched=6  unknown=3
```

The four vulnerable hits are the four apps we installed. The patched + unknown
counts come from whatever else the Windows VM ships with (Edge, etc.).

## Step 5: run the full home-security-ai pipeline

```powershell
cd C:\project\home-security-ai
.\run_cli.ps1        # CLI scan -> HTML report
# or
.\run_web.ps1        # FastAPI dashboard at http://localhost:8000
```

The software scanner now uses the KEV engine by default (see `config.yaml`).
You can flip it back to legacy keyword search with `engine: keyword`.

## Step 6: clean up

Easiest: shut down the VM and revert to the `clean-baseline` snapshot.

If you want to keep the VM and just remove the four test apps:

```powershell
cd C:\project\home-security-ai\test
.\uninstall-vulnerable-apps.ps1
```

This is best-effort — silent uninstall args sometimes lag the install ones.
The snapshot revert is more reliable.

## Expected `kev_findings` from the test lab

When everything is set up, `home-security-ai` should produce a software-scanner
section containing at minimum these four findings:

| Verdict | CVE | Package | Severity (expected) |
|---|---|---|---|
| vulnerable | CVE-2024-9680 | Mozilla Firefox 115.5.0 ESR | critical (ransomware-linked) |
| vulnerable | CVE-2025-0411 | 7-Zip 22.01 | high |
| vulnerable | CVE-2025-15556 | Notepad++ 8.6.4 | high |
| vulnerable | CVE-2023-38831 | WinRAR 6.10 | high |

Plus a handful of `unknown` Edge-related entries (modern Chromium Edge can't
be cleanly matched against historical Chakra-era CVEs in NVD).

## Troubleshooting

**Firefox auto-updated to a newer version after install**
Set `app.update.enabled = false` in `about:config`, restart Firefox once,
then revert to snapshot before next test.

**KEV download fails inside the VM**
Check VM has outbound HTTPS to `www.cisa.gov`. Some corporate proxies block
the feed. You can also pre-download `kev.json` on the host and copy it to
`C:\project\cve-scanner\cache\kev.json`.

**NVD lookups are very slow**
Without an NVD_API_KEY each CVE lookup sleeps 6.5 s to respect the
unauthenticated rate limit. Apply for a free key at
<https://nvd.nist.gov/developers/request-an-api-key> and set
`$env:NVD_API_KEY = "..."` before running the scan; rate limit jumps 10x.

## Adding more test cases

To add another vulnerable target, append to the `$apps` array in
`install-vulnerable-apps.ps1`. Pick versions whose CVE IDs appear in the
current `cve-scanner\cache\kev.json` to keep the KEV engine path exercised.

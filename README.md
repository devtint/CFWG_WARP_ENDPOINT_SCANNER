# Cloudflare WARP Mass Endpoint Scanner

Author: Tint Naing Win
Telegram: @BadCodeWriter
Repository: https://github.com/devtint/CFWG_WARP_ENDPOINT_SCANNER

This repository provides automated scanner tools to discover fast Cloudflare WARP endpoints, generate WireGuard configuration profiles, and measure connection latency on Windows, Linux, and macOS.

======================================================================
ENGLISH SECTION
======================================================================

CRITICAL WARNINGS BEFORE RUNNING
1. TURN OFF ALL EXISTING VPNS FIRST
Disconnect from any active VPN services including official Cloudflare WARP app, WireGuard, or third-party proxies before starting the scanner. Existing VPN connections will block local socket probes and cause false test failures.

2. DO NOT USE THE INTERNET WHILE SCANNING
Do not play online games, join video calls, or run downloads while the scanner is running. During Step 5, the script dynamically installs and uninstalls test WireGuard tunnels to verify real connectivity, which will temporarily drop and reconnect your internet connection every few seconds.

ONE-LINE DIRECT RUN COMMANDS (FASTEST)
Method 1: Windows Administrator PowerShell (Recommended)
Open PowerShell as Administrator in your desired folder and run this command:

```powershell
iwr -useb https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/WARP-Scanner.ps1 -OutFile WARP-Scanner.ps1; .\WARP-Scanner.ps1
```

Method 2: Linux or macOS Bash Terminal
Open Terminal as root and run this command:

```bash
curl -sSL https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/warp_scanner.sh -o warp_scanner.sh && chmod +x warp_scanner.sh && sudo ./warp_scanner.sh
```

Method 3: Python (Windows, Linux, macOS)
Open Command Prompt or Terminal as Administrator / root and run this command:

```bash
curl -sSL https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/warp_scanner.py -o warp_scanner.py && python warp_scanner.py
```

MANUAL QUICK START GUIDE FOR BEGINNERS
Option A: Running on Windows (PowerShell - Primary Recommended Method)
1. Turn off any active VPN apps on your machine.
2. Open Windows Start Menu, search for PowerShell, right-click Windows PowerShell, and select Run as administrator.
3. Download or place WARP-Scanner.ps1 into any folder on your computer.
4. Open that folder in PowerShell and run:

```powershell
.\WARP-Scanner.ps1
```

5. Type 1 and press Enter when the interactive menu appears to start a Standard Scan.

Option B: Running with Python (Windows, Linux, macOS)
1. Turn off any active VPN apps on your machine.
2. Open Terminal or Command Prompt as Administrator / root.
3. Run:

```bash
python warp_scanner.py
```

4. Select choice 1 from the menu to start scanning.

Option C: Running on Linux or macOS (Bash Terminal)
1. Turn off any active VPN apps on your machine.
2. Open Terminal as root user.
3. Make script executable and run:

```bash
chmod +x warp_scanner.sh && sudo ./warp_scanner.sh
```

TOOL COMPARISON & RECOMMENDATION
If you are using Windows, WARP-Scanner.ps1 is the primary recommended tool because:
1. Zero Installation: Built directly into Windows without installing Python or extra tools.
2. Ultra Fast Pre-Scan: Uses native PowerShell multithreaded Runspaces for high speed IP discovery.
3. Direct Windows Integration: Interacts cleanly with Windows WireGuard service APIs.

If you are on Linux or macOS, use warp_scanner.py or warp_scanner.sh.

SECURITY AND TRUST NOTICE
These scripts require Administrator or root privileges because WireGuard network interfaces must be created and destroyed dynamically.

To maintain complete user trust:
1. There are zero unnecessary functions, third-party libraries, or hidden external requests.
2. All operations rely exclusively on native system commands, official wgcf, and WireGuard binaries.
3. You are strongly encouraged to inspect the source code manually or review it with an AI tool before running it with Administrator privileges.

WHERE TO FIND YOUR WORKING CONFIGURATIONS
After the scan completes, your results are saved automatically inside the script directory:
* Working_Configs folder: Contains ready-to-use .conf files. Import any file from this folder directly into your WireGuard application.
* working_endpoints.csv: Complete summary spreadsheet sorted by lowest latency.
* working_endpoints.txt: Text summary report with IP, port, latency, and datacenter location.


======================================================================
မြန်မာဘာသာ လမ်းညွှန်ချက်များ (BURMESE SECTION)
======================================================================

မစတင်မီ အထူးသတိပြုရန် အချက်များ
၁။ ချိတ်ဆက်ထားသော VPN များကို ခေတ္တပိတ်ထားပါ
စကန်မဖတ်မီ စက်ထဲတွင် ပွင့်နေသော Cloudflare WARP သို့မဟုတ် အခြား VPN များကို ခေတ္တ ပိတ်ထားပေးပါ။ VPN ဖွင့်ထားပါက စကန်ဖတ်သည့်စနစ် အလုပ်လုပ်မည် မဟုတ်ပါ။

၂။ စကန်ဖတ်နေချိန်တွင် အင်တာနက် အသုံးပြုမှု ခေတ္တရပ်နားထားပါ
စကန်ဖတ်နေစဉ်အတွင်း ဂိမ်းဆော့ခြင်း၊ ဗီဒီယို ကောလ် ပြောခြင်း သို့မဟုတ် ဖိုင်ဒေါင်းလုဒ် ဆွဲခြင်းများ မပြုလုပ်ပါနှင့်။ အစမ်းလိုင်းများကို တစ်ခုချင်း ချိတ်ဆက် စမ်းသပ်နေသည့်အတွက် အင်တာနက်လိုင်း မိနစ်ပိုင်းမျှ ခေတ္တ ခဏ ပြတ်တောက်နိုင်ပါသည်။

တစ်လိုင်းတည်းဖြင့် တိုက်ရိုက် RUN နည်း (အမြန်ဆုံးနည်းလမ်း)
နည်းလမ်း ၁ - Windows PowerShell (Admin) အတွက် (အကြံပြုချက်)
PowerShell ကို Run as administrator ဖြင့် ဖွင့်ပြီး အောက်ပါ Command ကို ကူးယူ၍ စက္ကန့်ပိုင်းအတွင်း တိုက်ရိုက် run နိုင်ပါသည်။

```powershell
iwr -useb https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/WARP-Scanner.ps1 -OutFile WARP-Scanner.ps1; .\WARP-Scanner.ps1
```

နည်းလမ်း ၂ - Linux သို့မဟုတ် macOS Terminal အတွက်
Terminal ကို root အဖြစ် ဖွင့်ပြီး အောက်ပါ Command ကို run ပါ။

```bash
curl -sSL https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/warp_scanner.sh -o warp_scanner.sh && chmod +x warp_scanner.sh && sudo ./warp_scanner.sh
```

နည်းလမ်း ၃ - Python ဖြင့် run လိုသူများအတွက်
Terminal သို့မဟုတ် Command Prompt တွင် အောက်ပါအတိုင်း run ပါ။

```bash
curl -sSL https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/warp_scanner.py -o warp_scanner.py && python warp_scanner.py
```

စတင်အသုံးပြုနည်း လမ်းညွှန်
Windows အတွက် (PowerShell)
၁။ စက်ထဲရှိ VPN များကို ပိတ်ပါ။
၂။ Windows Start Menu တွင် PowerShell ကို ရှာပြီး Run as administrator ဖြင့် ဖွင့်ပါ။
၃။ WARP-Scanner.ps1 ရှိသော Folder ထဲသို့ သွားပါ။
၄။ အောက်ပါ Command ဟု ရိုက်ထည့်ပြီး Enter နှိပ်ပါ။

```powershell
.\WARP-Scanner.ps1
```

၅။ Menu ပေါ်လာပါက 1 ဟု ရိုက်ပြီး Enter နှိပ်၍ စကန်ဖတ်ခြင်း စတင်ပါ။

အသုံးပြုနိုင်သော ရလဒ်ဖိုင်များ ရှာဖွေနည်း
စကန်ဖတ်ခြင်း ပြီးဆုံးပါက အောက်ပါ ဖိုင်များ တိုက်ရိုက် ထွက်ရှိလာမည် ဖြစ်ပါသည်။
* Working_Configs ဖိုင်တွဲ - ချိတ်ဆက်မှု အဆင်ပြေသော WireGuard .conf ဖိုင်များ သိမ်းဆည်းထားသည့် နေရာ ဖြစ်ပါသည်။ ထိုဖိုင်များကို WireGuard App ထဲသို့ တိုက်ရိုက် Import လုပ်၍ အသုံးပြုနိုင်ပါသည်။
* working_endpoints.csv - လိုင်းအမြန်နှုန်း Ping latency အလိုက် အစဉ်လိုက် စီပေးထားသော ဇယားဖိုင် ဖြစ်ပါသည်။
* working_endpoints.txt - စမ်းသပ်အောင်မြင်သော IP များနှင့် တည်နေရာ အချက်အလက်များ ပါဝင်သော စာသားဖိုင် ဖြစ်ပါသည်။

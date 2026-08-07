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
If you are already using a VPN app such as the official Cloudflare WARP app, WireGuard, or any other proxy tool, turn it off completely before running this scanner. A running VPN will interfere with the scan and cause it to produce wrong results. Your physical internet connection (WiFi or cable) must stay connected and working throughout the entire scan.

2. KEEP YOUR INTERNET ON BUT STOP HEAVY USAGE DURING SCANNING
Your internet connection must remain switched on the entire time. Do not disconnect it. What you should avoid during the scan is running anything that needs a stable connection such as online games, video calls, or large file downloads. The reason is that during Step 5, the script briefly connects to and disconnects from dozens of test WireGuard tunnels one by one. Each test connection lasts only a few seconds. This causes your connection to blink on and off rapidly, which will interrupt any active session you have open.

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
၁။ ပွင့်နေသော VPN App များကို ပိတ်ပါ (အင်တာနက်ကို မပိတ်ပါနှင့်)
ဤ Scanner မစတင်မီ သင့်စက်တွင် ဖွင့်ထားသော Cloudflare WARP App၊ WireGuard သို့မဟုတ် အခြား VPN App တစ်ခုခု ရှိပါက ထို App ကိုသာ ပိတ်ပေးပါ။ WiFi သို့မဟုတ် ကြိုး Internet ချိတ်ဆက်မှုကို မပိတ်ပါနှင့်။ Internet ချိတ်ဆက်မှု ဖွင့်ထားမှသာ Scanner အလုပ်လုပ်နိုင်မည် ဖြစ်ပါသည်။ VPN App ဖွင့်ထားပါက Scanner မှ ရလဒ်များ မှားယွင်းနိုင်ပါသည်။

၂။ Internet ဖွင့်ထားပါ သို့သော် စကန်ဖတ်နေစဉ် အသုံးများသော ကိစ္စများ ခေတ္တရပ်နားပါ
စကန်ဖတ်နေစဉ် Internet ချိတ်ဆက်မှုကို ဖွင့်ထားရပါမည်။ ပိတ်ခြင်း မပြုပါနှင့်။ သို့သော် ဂိမ်းဆော့ခြင်း၊ Video Call ပြောခြင်း သို့မဟုတ် ဖိုင်ကြီးများ ဒေါင်းလုဒ်ဆွဲခြင်းများကို ယာယီ ရပ်နားထားပါ။ အကြောင်းမှာ Step 5 တွင် Script သည် WireGuard Tunnel တစ်ခုချင်းစီကို ချိတ်ဆက် စမ်းသပ်ပြီး ဖြုတ်ကာ တစ်ခုပြီး တစ်ခု စစ်ဆေးနေမည် ဖြစ်သည်။ ထိုအချိန်တွင် Internet လိုင်း ဆက်တိုက် ခဏခဏ ပြတ်တောက်ကာ ပြန်ချိတ်ဆက်မည် ဖြစ်သဖြင့် ချိတ်ဆက်မှု မတည်ငြိမ်မှုကို မှီခိုနေသော ကိစ္စများ ကြားဖြတ်ပြတ်တောက်နိုင်ပါသည်။

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


======================================================================
WHAT THIS TOOL DOES AND DOES NOT DO (ENGLISH)
======================================================================
This scanner finds Cloudflare WARP endpoints that are currently reachable on your network and generates WireGuard configuration files for them. It does not modify your system, install persistent software, or send your data anywhere.

WHAT CLOUDFLARE WARP PROVIDES
* Free with no advertisements and no usage limits on the free tier.
* Encrypts traffic between your device and Cloudflare's nearest server.
* Bypasses ISP-level port blocking and basic traffic filtering.
* Cloudflare operates one of the largest networks in the world, meaning latency is generally low.
* Cloudflare's published privacy policy commits to not selling or sharing user traffic data with third parties.

WHAT CLOUDFLARE WARP DOES NOT PROVIDE
* Full anonymity. Cloudflare can see your connection metadata including your real IP address and the domains you visit.
* Protection against deep packet inspection that specifically targets WireGuard's protocol fingerprint.
* A guarantee that every endpoint found will remain reachable. Network conditions change and endpoints that work today may not work tomorrow.
* Protection at the device level. If your device itself is monitored, WARP does not change that.

WHO THIS IS FOR
This tool is suitable for users on networks where services are filtered at the ISP level and who need a free, low-latency solution that does not involve trusting unknown third parties or installing ad-supported applications.

WHO SHOULD CONSIDER OTHER OPTIONS
If you require strong anonymity or need to protect your identity from a sophisticated monitoring capability, a properly configured Tor setup or a paid audited VPN provider with a verified no-log policy is a more appropriate choice than WARP.


======================================================================
ဤ Tool ဖြင့် ဘာကို လုပ်နိုင်သည်၊ ဘာကို မလုပ်နိုင် (မြန်မာဘာသာ)
======================================================================
ဤ Scanner သည် ကွန်ရက်ပေါ်တွင် လက်ရှိ ချိတ်ဆက်နိုင်သော Cloudflare WARP Endpoint များကို ရှာဖွေပေးပြီး WireGuard Configuration ဖိုင်များ ထုတ်ပေးသည်။ ဤ Script သည် သင့်စနစ်ကို မည်သည့်နည်းဖြင့်မျှ မပြောင်းလဲဘဲ၊ နောက်ခံ Software တင်ခြင်း မပြုသည့်အပြင် သင့်ဒေတာများကိုလည်း မည်သည့်နေရာသို့မျှ မပို့ပါ။

Cloudflare WARP ဖြင့် ရနိုင်သည့် အကျိုးကျေးဇူးများ
* အခမဲ့ သုံးနိုင်ပြီး ကြော်ငြာ မပါဝင်ဘဲ Data Limit လည်း မရှိပါ။
* သင့်စက်မှ Cloudflare ၏ အနီးဆုံး Server အထိ Traffic ကို ကုဒ်ဝှက်ပေးပါသည်။
* ISP အဆင့်တွင် ပိတ်ဆို့ထားသော Port များနှင့် အခြေခံ Traffic Filtering များကို ကျော်ဖြတ်နိုင်ပါသည်။
* Cloudflare သည် ကြီးမားသော Network တစ်ခုကို ပိုင်ဆိုင်သောကြောင့် Latency နည်းပါသည်။
* Cloudflare ၏ Privacy Policy တွင် User ၏ Traffic ဒေတာများကို တတိယပါတီများသို့ ရောင်းချခြင်း သို့မဟုတ် မျှဝေခြင်း မပြုဟု တိတိကျကျ ဖော်ပြထားသည်။

Cloudflare WARP ဖြင့် မရနိုင်သည့် အချက်များ
* အပြည့်အဝ(Anonymity) မရပါ။ Cloudflare သည် သင့် IP Address နှင့် ဝင်ရောက်သည့် Domain များကို မြင်နိုင်ပါသည်။
* WireGuard Protocol ကို တိကျစွာ ပစ်မှတ်ထားသည့် Deep Packet Inspection ကို ကာကွယ်နိုင်ခြင်း မရှိပါ။
* ယနေ့ အလုပ်လုပ်သော Endpoint များ နောက်တစ်နေ့တွင်လည်း အလုပ်လုပ်မည်ဟု အာမမခံနိုင်ပါ။ Network အခြေအနေများ ပြောင်းလဲနေပါသည်။
* Device အဆင့် စောင့်ကြည့်မှုကို ကာကွယ်ပေးနိုင်ခြင်း မရှိပါ။ သင့်စက်ကို တိုက်ရိုက် စောင့်ကြည့်နေပါက WARP ဖြင့် ကာကွယ်ရန် မဖြစ်နိုင်ပါ။

-----------------------------

ဤ Tool ကို မည်သူများအတွက် သင့်တော်သည်

ISP အဆင့်တွင် Service များ ပိတ်ဆို့ စစ်ထုတ်ထားသော ကွန်ရက်ပေါ်ရှိ သုံးစွဲသူများနှင့် ကြော်ငြာများ ပါဝင်သော Application များ သို့မဟုတ် မသိသော တတိယပါတီများကို မှီခိုစရာ မလိုဘဲ အခမဲ့ Latency နည်းသော ဖြေရှင်းချက် လိုအပ်သူများအတွက် သင့်တော်ပါသည်။

------------------------------

အခြား နည်းလမ်းများကို စဉ်းစားသင့်သည့် အခြေအနေ

အကယ်၍ သင်သည် ခိုင်မာသော Anonymity လိုအပ်သည် သို့မဟုတ် အဆင့်မြင့် Network စောင့်ကြည့်မှုမှ ကာကွယ်ရန် လိုသည်ဆိုပါက Tor သို့မဟုတ် No-Log Policy ကို စစ်ဆေးအတည်ပြုပြီးသော ငွေပေး VPN Provider တစ်ခုသည် WARP ထက် ပိုသင့်တော်ပါသည်။

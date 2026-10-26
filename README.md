# 🛡️ Windows Security Scan Tool v4.0 — ML & CVE Edition

> 一鍵快速診斷 Windows 本機安全態勢，整合**微軟官方 MSRC CVE 弱點雷達**與**純本機 ML 基線異常偵測**，產出互動式深色主題安全報告。

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows)
![MSRC](https://img.shields.io/badge/MSRC-CVRF%20v2.0-00A4EF?logo=microsoft)
![Machine Learning](https://img.shields.io/badge/ML-In--Browser%20Z--Score-FF6F00)
[![Co-Developed with Gemini](https://img.shields.io/badge/Co--Developed%20with-Google%20Gemini-4285F4?logo=google&logoColor=white)](https://gemini.google.com)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ 核心功能特色

| 功能 | 說明 |
|------|------|
| 🔍 **16 大維度深度稽核** | 涵蓋網路連線、監聽 Port、程序簽章、Temp 檔案、防火牆、Registry 自啟動、排程任務、系統服務、PowerShell 歷程、WMI 事件、瀏覽器擴充、Prefetch、事件日誌、SMB/RDP 及微軟 CVE 比對。 |
| 🛡️ **微軟 MSRC 即時 CVE 雷達** | 主動連線微軟 MSRC CVRF 官方安全 API，拉取**近 2 個月（包含最新月份）** Windows 全量 CVE 弱點庫，精準比對本機已安裝之累積更新（LCU）與修補狀態。 |
| 🤖 **純本機 ML 基線比對** | 內建純 JavaScript ML 引擎，利用本機 `localStorage` 累積歷史掃描，以 **Z-Score** 算法動態建立主機基準線，自動標記反常指標（無須連網傳送資料，零隱私外洩）。 |
| 🆕 **增量差異追蹤（Delta）** | 智慧比對本次與上次掃描，高亮標註新出現的 Port、外部連線程序、自啟動項目與排程任務。 |
| 📈 **趨勢 Sparklines** | 各關鍵指標直觀呈現最近 10 次掃描的歷史走勢圖。 |
| 📄 **深色主題互動式 HTML 報告** | 自動於桌面產生高質感深色報告，支援動態 CVE 搜尋過濾、官方弱點技術通報直達連結。 |
| 📬 **Telegram 自動推播** | 支援設定環境變數，掃描結束後秒級將風險摘要發送至個人或群組 Telegram。 |

---

## 🚀 快速開始

### 系統需求
- **作業系統**：Windows 10 / Windows 11（支援 64 位元 x64 及 ARM64）
- **環境**：PowerShell 5.1 或更高版本
- **權限**：**系統管理員（Administrator）** 權限（腳本具備自動 UAC 提示提權機制）

### 📥 取得專案（免任何金鑰）
- **直接下載 ZIP（最推薦）**：點擊 [Download ZIP](https://github.com/kerr20801/windows-security-scan/archive/refs/heads/main.zip) 下載後解壓縮。
- **Git Clone**：
  ```bash
  git clone https://github.com/kerr20801/windows-security-scan.git
  cd windows-security-scan
  ```

### ⚡ 執行方式

**方法一：一鍵滑鼠執行（最推薦）**
> 直接滑鼠連按兩下資料夾內的 **`run.bat`**  
> （彈出 Windows UAC 系統管理員權限提示時點選「是」即可全自動掃描）

**方法二：PowerShell 指令執行**
```powershell
# 以系統管理員開啟 PowerShell，切換至本專案目錄後執行：
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\security-scan-v4.ps1
```

掃描完成後，HTML 互動報告將自動儲存於目前使用者的**桌面**並直接在預設瀏覽器中開啟。

---

## 📊 16 大檢查維度說明

| # | 檢查項目 | 核心檢測與防禦內容 |
|---|----------|-------------------|
| 1 | 系統基本資訊 | OS 版本代碼、累積更新組建版號（UBR）、連續開機運行時間 |
| 2 | 網路外部連線 | 偵測非內網的 ESTABLISHED 對外連線，自動過濾常見安全程序並警告異常連線 |
| 3 | 監聽 Port | 盤點本機開放的 TCP/UDP Port，標記敏感高危 Port（如 139、445 SMB、3389 RDP、22 SSH 等） |
| 4 | 執行中程序 | 比對常見黑客工具與惡意特徵關鍵字，檢查未簽章（Unsigned）常駐程序 |
| 5 | Temp 資料夾 | 深度掃描使用者與系統 Temp 目錄中的 EXE 可執行檔與各類腳本（PS1/VBS/BAT） |
| 6 | 防火牆與 Defender | 檢查 Windows 網域/私人/公用防火牆狀態、Defender 即時保護與特徵碼更新狀態 |
| 7 | Registry 自啟動 | 檢查 Run / RunOnce 機碼，偵測使用 PowerShell/Cmd 等命令列常駐的自啟動項 |
| 8 | 排程任務（Task） | 盤點所有排程工作，警示調用腳本直譯器或隱藏路徑的可疑排程 |
| 9 | 系統服務（Services） | 稽核所有自動啟動之系統服務，抓出非微軟官方且未具合法簽章之服務 |
| 10 | PowerShell 安全設定 | 檢查 ExecutionPolicy 原則及過去 24 小時之可疑指令記錄 |
| 11 | WMI 事件訂閱 | 偵測駭客用於 APT 持久化攻擊之 WMI `__EventFilter` 與 `CommandLineEventConsumer` |
| 12 | 瀏覽器擴充套件 | 盤點 Google Chrome 與 Microsoft Edge 已安裝之擴充插件數量與狀態 |
| 13 | Prefetch 執行記錄 | 解析 Windows 預讀檔案，比對已知滲透工具（Mimikatz、PsExec 等）之執行足跡 |
| 14 | 系統安全事件日誌 | 統計過去 24 小時登入失敗次數（Event ID 4625）、過去 7 天新安裝服務（Event ID 7045） |
| 15 | 網路共享與遠端桌面 | 稽核未受限的使用者 SMB 共享資料夾及 RDP 遠端桌面啟用狀態 |
| 16 | **微軟 MSRC CVE 弱點雷達** | **主動查詢微軟官方近 2 個月全量安全公告，精準比對本機累積修補（LCU）狀態，支援動態搜尋過濾** |

---

## 🤖 技術原理：ML 基線比對與 MSRC 雷達

### 1. 純本機前端 ML 基線（Local ML Engine）
本工具秉持**資料零上傳、隱私全本機**原則，所有機器學習計算均在產出的 HTML 報告內以純 JavaScript 完成：
- 資料存儲於本機瀏覽器的 `localStorage`（保存最近 30 次掃描歷史，歷史資料經過精簡壓縮，絕不佔用瀏覽器空間）。
- 當累積 **3 次以上** 掃描後，系統自動計算歷史平均值（$\mu$）與標準差（$\sigma$）。
- 透過 **Z-Score** 算法評估單項指標偏離程度：$Z = \frac{|x - \mu|}{\sigma}$。
- 當指標 $Z > 3.0$ 時自動觸發「嚴重異常」視覺告警，提早發現潛伏的非典型威脅。

### 2. 微軟 MSRC CVRF 實時對齊技術
- 主動調用微軟官方 MSRC CVRF v2.0 API（`https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{yyyy-MMM}`）。
- 內建 24 小時智慧本機快取（儲存於 `$env:TEMP\MsrcCache`），避免重複下載並確保離線或弱網環境下依然能極速完成比對。
- 具備 Windows 累積更新（Latest Cumulative Update, LCU）超集識別能力，能準確判斷本月最新修補是否已自動繼承涵蓋前月之弱點，杜絕誤報。

---

## ⚠️ 關鍵資安概念辨析：已修補 (Patched) ≠ 未中毒 (Clean)

很多使用者容易產生一個危險的誤區：**「我的 Windows Update 都裝滿了、CVE 都顯示已防護，那我是不是 100% 絕對沒中毒？」**

> ### 💡 答案是：這是完全不同的兩件事！
> 
> * **「已修補弱點（Patching）」就像是替家裡裝上最新、最堅固的防盜門鎖**。它能確保已知的小偷無法用舊手法橇開大門（防範微軟官方已公開的技術漏洞 CVE）。
> * **「未受感染（Infection Free）」則是屋內當前是否有不速之客潛伏**。如果使用者曾經誤點釣魚網站將帳號密碼奉送給攻擊者、或是下載執行了自製的特裝木馬（不需要利用 CVE 漏洞即可常駐）、或是遭遇微軟尚未知曉的**零日漏洞（0-Day）**，那麼就算門鎖等級再高，攻擊者依然能長驅直入。

### 兩者本質差異比較表：

| 評估面向 | 弱點修補（Vulnerability Status） | 惡意感染偵測（Compromise Assessment） |
|:---------|:--------------------------------|:-------------------------------------|
| **核心關注點** | 系統大門是否存在已知的技術破口？ | 系統內部是否已有惡意行為者取得駐留？ |
| **檢測方式** | 比對微軟已發布的 KB 編號與 CVE 漏洞資料庫 | 鑑識分析記憶體載入、流量封包、處理程序行為與異常特徵 |
| **防護範圍** | 微軟官方已公開且發布安全性修補之 CVE | 已知惡意特徵碼、異常行為模式 |
| **防護盲點** | **無法防禦 0-Day 未知漏洞**、社工憑證外洩、設定疏失 | 無法偵測高隱蔽型內核 Rootkit 或合法工具濫用（LOLBins） |
| **本工具角色** | **完整檢驗**（第 16 項：MSRC CVE 雷達比對） | **基礎衛生稽核**（第 1~15 項：監聽、連線、自啟動等基線異常偵測） |

---

## ⚖️ 免責聲明與法律保護條款 (Disclaimer & Limitations)

在下載、複製、執行或使用本工具（包括但不限於 `security-scan-v4.ps1`、`run.bat` 及生成的 HTML 報告）之前，請務必詳細閱讀以下條款：

### 1. 非安全性擔保聲明（No Warranty / "AS-IS"）
本工具以**「現狀（AS-IS）」**形式提供，不附帶任何明示或暗示之保證。作者與專案貢獻者不對本工具的精確性、完整性、時效性、特定用途之適用性提供任何保證。掃描報告顯示「0 告警」或「100% 已修補」僅代表本機在設定的檢查規則與已知微軟公告範圍內未發現明顯特徵，**絕不構成系統「絕對安全」、「未受任何惡意軟體侵害」或「未被駭客入侵」之官方認證或法律保證**。

### 2. 非商業 EDR / 專業數位鑑識工具
本工具定位為**個人與系統管理員輔助使用之開源「系統防護衛生（Security Hygiene）檢查與基線評估腳本」**。本工具不能、且不應被視為或替代企業級端點偵測與回應（EDR）、次世代防毒軟體（NGAV）或專業資安鑑識團隊（Digital Forensics & Incident Response, DFIR）之深度威脅狩獵。

### 3. 損害賠償責任之完全免除（Limitation of Liability）
在適用法律允許的最大範圍內，作者與專案貢獻者對於因使用、無法使用本工具、或因依賴本工具之掃描結果所導致之任何直接、間接、附隨、衍生性、懲罰性損害（包括但不限於系統中斷、資料遺失、硬體損毀、未偵測到之病毒勒索侵害、營收損失或法律訴訟），**概不承擔任何法律責任、合約責任或侵權損害賠償責任**。

### 4. 合法授權使用原則（Authorized Use Only）
使用者必須確保僅在**自身擁有完整合法權限**之電腦設備或經明確書面授權之環境中運行本工具。嚴禁將本工具用於未經授權之滲透測試、惡意探測或任何違反相關法規之行為。

---

## 📬 Telegram 推播設定（選填）

若希望掃描完成後自動將風險摘要推送至 Telegram，請依下列步驟設定：

1. 透過 Telegram [@BotFather](https://t.me/BotFather) 建立專屬 Bot 並取得 `Token`。
2. 取得個人或接收群組之 `Chat ID`。
3. 開啟 PowerShell 寫入使用者環境變數（僅需設定一次）：
   ```powershell
   [System.Environment]::SetEnvironmentVariable("SECSCAN_TG_TOKEN", "你的BOT_TOKEN", "User")
   [System.Environment]::SetEnvironmentVariable("SECSCAN_TG_CHAT",  "你的CHAT_ID",  "User")
   ```
4. 設定完成後重新開啟終端機執行腳本即可享有秒級推播通知。

---

## 📁 檔案結構說明

```
windows-security-scan/
├── run.bat                 # 一鍵雙擊執行批次檔（推薦使用）
├── security-scan-v4.ps1    # 主掃描腳本（含 16 項掃描、MSRC 雷達與 ML HTML 生成）
└── README.md               # 專案說明文件、資安觀念剖析與法律免責聲明
```

報告預設輸出路徑：
```
%USERPROFILE%\Desktop\SecurityScan-YYYYMMDD-HHmm.html
```

---

## 🤝 Contributors & Credits

- 👨‍💻 **[Kerr](https://github.com/kerr20801)** — 核心架構設計、需求規格、測試驗證與專案維護
- 🤖 **[Google Gemini](https://gemini.google.com)** — AI 結對編程夥伴（ML 基線架構、微軟 MSRC CVRF 串接與資安演算法優化）

---

## 📄 License

本專案採用 [MIT License](LICENSE) 授權釋出，歡迎社群自由使用、分支與優化。

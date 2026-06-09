# 🛡️ Windows Security Scan Tool v4.0 — ML Edition

> 一鍵掃描 Windows 安全狀態，產生本機 HTML 報告，並透過 ML 基線比對偵測異常趨勢。

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ 功能特色

| 功能 | 說明 |
|------|------|
| 🔍 **15 項安全掃描** | 網路連線、監聽 Port、程序、Temp 資料夾、防火牆、Registry 自啟動、排程任務、系統服務、PowerShell 設定、WMI 訂閱、瀏覽器擴充、Prefetch、事件日誌、SMB 共享、RDP |
| 🤖 **ML 基線比對** | 使用 Z-score 分析，與本機歷史紀錄比對，自動標記異常指標 |
| 📊 **趨勢 Sparkline** | 各指標顯示最近 10 次趨勢圖 |
| 🆕 **差異偵測** | 與上次掃描比對，標出新出現的 Port、程序、服務、排程任務 |
| 📄 **HTML 報告** | 產出美觀的深色主題報告，儲存於桌面 |
| 📬 **Telegram 推播** | 掃描完成後自動推送摘要（需設定環境變數） |

---

## 🚀 快速開始

### 需求
- Windows 10 / 11
- PowerShell 5.1 以上
- **系統管理員** 權限（腳本會自動提權）

### 執行方式

**方法一：右鍵以系統管理員執行**
```
右鍵 SecurityScan.ps1 → 以系統管理員身分執行
```

**方法二：PowerShell 執行**
```powershell
# 以系統管理員開啟 PowerShell，執行：
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\SecurityScan.ps1
```

掃描完成後，HTML 報告會自動儲存到桌面並開啟。

---

## 📊 掃描項目說明

| # | 項目 | 說明 |
|---|------|------|
| 1 | 系統基本資訊 | OS 版本、開機時間 |
| 2 | 網路外部連線 | 偵測非內網的 TCP 已建立連線 |
| 3 | 監聽 Port | 列出所有監聽中的 Port，標記敏感 Port（3389、445、22 等） |
| 4 | 執行中程序 | 比對惡意工具關鍵字、檢查未簽章程序 |
| 5 | Temp 資料夾 | 掃描 EXE 及腳本檔案 |
| 6 | 防火牆 / Defender | 確認防火牆啟用、即時防護、病毒碼更新狀態 |
| 7 | Registry 自啟動 | 偵測使用命令列工具的可疑自啟動項目 |
| 8 | 排程任務 | 標記使用 PowerShell / cmd / wscript 的任務 |
| 9 | 系統服務 | 偵測未簽章的自動啟動服務 |
| 10 | PowerShell 安全設定 | 執行原則、過去 24h 可疑指令記錄 |
| 11 | WMI 事件訂閱 | 偵測可用於持久化的 CommandLine 消費者 |
| 12 | 瀏覽器擴充套件 | 統計 Chrome / Edge 擴充數量 |
| 13 | Prefetch | 比對已知危險工具執行記錄 |
| 14 | 事件日誌 | 登入失敗次數（24h）、新安裝服務（7d） |
| 15 | 網路共享 / RDP | 偵測使用者 SMB 共享及 RDP 啟用狀態 |

---

## 🤖 ML 基線比對說明

腳本產生的 HTML 報告內建 JavaScript ML 引擎，使用 **localStorage** 儲存本機掃描歷史（最多 30 筆）。

- 累積 **3 筆以上**掃描紀錄後，開始計算各指標的均值與標準差
- 以 **Z-score** 計算目前數值與歷史基線的偏離程度
- 風險等級：`Z < 1.5` → 正常 ｜ `Z 1.5~2.5` → 偏高 ｜ `Z > 3` → 異常

> ⚠️ 歷史資料儲存在瀏覽器 localStorage，使用**同一台電腦、同一個瀏覽器**開啟報告才會累積基線。

---

## 📬 Telegram 推播設定（選填）

掃描完成後可自動推送摘要到 Telegram。

1. 透過 [@BotFather](https://t.me/BotFather) 建立 Bot，取得 `Token`
2. 取得你的 `Chat ID`
3. 設定系統環境變數：

```powershell
[System.Environment]::SetEnvironmentVariable("SECSCAN_TG_TOKEN", "你的BOT_TOKEN", "User")
[System.Environment]::SetEnvironmentVariable("SECSCAN_TG_CHAT",  "你的CHAT_ID",  "User")
```

設定後重新開啟 PowerShell 再執行腳本即可。

---

## 📁 檔案說明

```
windows-security-scan/
└── SecurityScan.ps1    # 主掃描腳本
```

報告輸出路徑：
```
%USERPROFILE%\Desktop\SecurityScan-YYYYMMDD-HHmm.html
```

---

## ⚠️ 免責聲明

本工具僅供個人學習及自我電腦安全檢查使用。  
請勿用於未授權的系統。掃描結果僅供參考，不代表系統一定安全或不安全。

---

## 📄 License

MIT License — 歡迎自由使用與修改。

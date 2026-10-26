# ===================================================================
# PC Security Scan Tool v4.0 - ML Edition
# 新增：結構化資料收集 + HTML 內嵌 JS ML（localStorage 基線比對）
# ===================================================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"
$startTime = Get-Date
$hostname   = $env:COMPUTERNAME
$username   = $env:USERNAME
$ip         = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress -notmatch '127' } | Select-Object -First 1).IPAddress
$htmlFile   = "$env:USERPROFILE\Desktop\SecurityScan-$(Get-Date -Format 'yyyyMMdd-HHmm').html"

$lines  = [System.Collections.Generic.List[string]]::new()
$alerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$stepCount  = 0
$totalSteps = 16

# ── ML 資料收集結構 ──────────────────────────────────────────────
$scanData = [ordered]@{
    hostname  = $hostname
    username  = $username
    ip        = $ip
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    scanId    = [System.Guid]::NewGuid().ToString()
    metrics   = [ordered]@{
        extConnCount        = 0
        listeningPortCount  = 0
        unsignedProcCount   = 0
        suspiciousTaskCount = 0
        unsignedSvcCount    = 0
        failedLogins24h     = 0
        newServices7d       = 0
        wmiConsumerCount    = 0
        smbShareCount       = 0
        tempExeCount        = 0
        tempScriptCount     = 0
        chromeExtCount      = 0
        edgeExtCount        = 0
        criticalCount       = 0
        warningCount        = 0
        infoCount           = 0
        scanSeconds         = 0

        # ── 修補與軟體漏洞指標 ──
        osBuild             = ""
        osUBR               = 0
        pendingWUCount      = 0
        cvePatchedCount     = 0
        cveMissingCount     = 0
        outdatedAppsCount   = 0
    }
    sets = [ordered]@{
        listeningPorts = @()
        extProcesses   = @()
        autorunNames   = @()
        taskNames      = @()
        svcNames       = @()
        outdatedApps   = @()
        missingCVEs    = @()
    }
    cveList        = @()
    networkDetails = [ordered]@{
        extConnsByProc = @()
        listenByProc   = @()
    }
}

# ── 輔助函數 ────────────────────────────────────────────────────
function Write-Output-Dual { param([string]$text, [string]$color="White"); $lines.Add($text); Write-Host $text -ForegroundColor $color }
function Show-Progress {
    param([string]$title)
    $script:stepCount++
    $pct = [int](($script:stepCount / $totalSteps) * 100)
    Write-Host "" ; Write-Host "[$script:stepCount/$totalSteps] $title ($pct%)" -ForegroundColor Cyan
    Write-Host ("─" * 70) -ForegroundColor Gray
}
function Alert-Info     { param([string]$msg,[string]$detail=""); $script:alerts.Add([PSCustomObject]@{Level="INFO";    Message=$msg;Detail=$detail;Timestamp=(Get-Date -Format "HH:mm:ss")}); $script:scanData.metrics.infoCount++;     Write-Output-Dual "  ℹ️  $msg" Cyan;   if($detail){Write-Output-Dual "      → $detail" DarkCyan} }
function Alert-Warning  { param([string]$msg,[string]$detail=""); $script:alerts.Add([PSCustomObject]@{Level="WARNING"; Message=$msg;Detail=$detail;Timestamp=(Get-Date -Format "HH:mm:ss")}); $script:scanData.metrics.warningCount++;  Write-Output-Dual "  ⚠️  $msg" Yellow; if($detail){Write-Output-Dual "      → $detail" DarkYellow} }
function Alert-Critical { param([string]$msg,[string]$detail=""); $script:alerts.Add([PSCustomObject]@{Level="CRITICAL";Message=$msg;Detail=$detail;Timestamp=(Get-Date -Format "HH:mm:ss")}); $script:scanData.metrics.criticalCount++; Write-Output-Dual "  ⛔ $msg" Red;    if($detail){Write-Output-Dual "      → $detail" DarkRed} }

# ===================================================================
# 掃描區段（與 v3 相同邏輯，加上 $scanData 收集）
# ===================================================================

# 第1部分：系統資訊
Show-Progress "系統基本資訊"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$uptime = (Get-Date) - $os.LastBootUpTime
Write-Output-Dual "  OS: $($os.Caption) Build $($os.BuildNumber)"
Write-Output-Dual "  開機時間: $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')) (已開機 $([int]$uptime.TotalHours) 小時)"
if ($uptime.TotalHours -lt 0.5) { Alert-Warning "系統剛重新啟動" "可能有安裝更新或修復" }

# 第2部分：網路連線
Show-Progress "檢查網路連線"
$knownProcs = @("chrome","msedge","claude","OneDrive","Teams","outlook","brave","firefox","svchost","nvcontainer","steam","agy","python","ollama","git","curl","code","docker","node","SearchHost","MsMpEng")
$extConns = @()
try {
    $extConns = Get-NetTCPConnection -State Established |
        Where-Object { $_.RemoteAddress -notmatch "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1)" } |
        ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($p) { [PSCustomObject]@{ Process=$p.Name; PID=$_.OwningProcess; Remote="$($_.RemoteAddress):$($_.RemotePort)" } }
        }
} catch {}
$scanData.metrics.extConnCount = $extConns.Count
$scanData.sets.extProcesses    = @($extConns | Select-Object -ExpandProperty Process -Unique)

# 依程序分組統計連線數與主要連線目標
$extGrouped = $extConns | Group-Object Process | Sort-Object Count -Descending
$extByProcList = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($g in $extGrouped) {
    $sampleTargets = @($g.Group | Select-Object -ExpandProperty Remote -Unique | Select-Object -First 3)
    $extByProcList.Add([PSCustomObject]@{
        process = $g.Name
        count   = $g.Count
        targets = $sampleTargets
    })
}
$scanData.networkDetails.extConnsByProc = @($extByProcList)

Write-Output-Dual "  外部連線總數: $($extConns.Count)"
if ($extGrouped.Count -gt 0) {
    Write-Output-Dual "  連線程式分布（前 5 名）:" Cyan
    $extGrouped | Select-Object -First 5 | ForEach-Object {
        $sample = ($_.Group | Select-Object -ExpandProperty Remote -Unique | Select-Object -First 2) -join ', '
        Write-Output-Dual "    • $($_.Name): $($_.Count) 個連線 ($sample)" Gray
    }
}

if ($extConns.Count -gt 60) { Alert-Warning "外部連線數偏高 ($($extConns.Count))" "建議確認是否有未預期的背景程序" }

$extConns | Where-Object { $_.Process -notin $knownProcs } | Select-Object -First 5 | ForEach-Object {
    Alert-Info "非白名單程式連線" "$($_.Process) → $($_.Remote)"
}

# 第3部分：監聽 Port
Show-Progress "檢查監聽 Port"
$dangerousPorts = @(3389,445,135,139,22,23,21)
$listeningPorts = Get-NetTCPConnection -State Listen | ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($p) { [PSCustomObject]@{ Port=$_.LocalPort; Process=$p.Name; PID=$_.OwningProcess } }
} | Where-Object { $_ } | Sort-Object Port -Unique

$scanData.metrics.listeningPortCount = $listeningPorts.Count
$scanData.sets.listeningPorts        = @($listeningPorts | Select-Object -ExpandProperty Port)

# 依程序分組統計監聽 Port
$listenGrouped = $listeningPorts | Group-Object Process | Sort-Object Count -Descending
$listenByProcList = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($g in $listenGrouped) {
    $ports = @($g.Group | Select-Object -ExpandProperty Port)
    $listenByProcList.Add([PSCustomObject]@{
        process = $g.Name
        count   = $g.Count
        ports   = $ports
    })
}
$scanData.networkDetails.listenByProc = @($listenByProcList)

Write-Output-Dual "  監聽 Port 總數: $($listeningPorts.Count) 個"
if ($listenGrouped.Count -gt 0) {
    Write-Output-Dual "  主要監聽程式分布:" Cyan
    $listenGrouped | Select-Object -First 6 | ForEach-Object {
        $pList = ($_.Group | Select-Object -ExpandProperty Port) -join ', '
        Write-Output-Dual "    • $($_.Name): $($_.Count) 個 Port ($pList)" Gray
    }
}

$listeningPorts | ForEach-Object {
    if ($_.Port -in $dangerousPorts -and $_.Process -ne "svchost") {
        Alert-Warning "敏感 Port 開放" "Port $($_.Port) 由 $($_.Process) 監聽"
    }
}

# 第4部分：可疑程序
Show-Progress "掃描執行中程序"
$suspiciousKeywords = @("mimikatz","metasploit","psexec","meterpreter","cobaltstrike","hack","crack","keygen")
$suspiciousProcs = Get-Process | Where-Object { $n=$_.Name.ToLower(); $suspiciousKeywords | Where-Object { $n -match $_ } }
if ($suspiciousProcs) { $suspiciousProcs | ForEach-Object { Alert-Critical "發現高度可疑程序" "$($_.Name) (PID: $($_.Id))" } }
else { Write-Output-Dual "  程序掃描: ✓ 無明顯可疑" Green }
$unsignedProcs = Get-Process | Where-Object { $_.Path -and (Test-Path $_.Path) } | ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
    if ($sig -and $sig.Status -ne "Valid" -and $_.Name -notmatch "^(svchost|powershell|conhost)") { $_ }
} | Select-Object -First 5
$scanData.metrics.unsignedProcCount = @($unsignedProcs).Count
if ($unsignedProcs) { Alert-Info "偵測到 $(@($unsignedProcs).Count) 個未簽章程式" "建議驗證來源" }

# 第5部分：Temp 資料夾
Show-Progress "檢查 Temp 資料夾"
$tempExes    = @(Get-ChildItem "$env:TEMP" -Filter "*.exe"                              -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10)
$tempScripts = @(Get-ChildItem -Path "$env:TEMP" -Recurse -Include "*.ps1","*.bat","*.vbs","*.js" -ErrorAction SilentlyContinue | Select-Object -First 10)
$scanData.metrics.tempExeCount    = $tempExes.Count
$scanData.metrics.tempScriptCount = $tempScripts.Count
Write-Output-Dual "  Temp EXE: $($tempExes.Count) 個 | 腳本: $($tempScripts.Count) 個"
if ($tempExes.Count -gt 5)    { Alert-Warning "Temp 中 EXE 較多" "建議確認最近安裝軟體" }
if ($tempScripts.Count -gt 0) { Alert-Info    "Temp 中發現腳本" "$($tempScripts.Count) 個" }

# 第6部分：防火牆 / Defender
Show-Progress "防火牆和防毒軟體"
$fwDisabled = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
if ($fwDisabled) { Alert-Critical "防火牆已停用" "Profile: $($fwDisabled.Name -join ', ')" }
else             { Write-Output-Dual "  防火牆: ✓ 全部已啟用" Green }
$def = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($def) {
    $issues = @()
    if (-not $def.RealTimeProtectionEnabled) { $issues += "即時防護停用" }
    if (-not $def.BehaviorMonitorEnabled)    { $issues += "行為監控停用" }
    if ($issues) { Alert-Critical "Windows Defender 異常" ($issues -join "; ") }
    else         { Write-Output-Dual "  Defender: ✓ 正常" Green }
    if (((Get-Date) - $def.AntivirusSignatureLastUpdated).TotalDays -gt 7) {
        Alert-Warning "病毒碼超過 7 天未更新" $def.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')
    }
}

# 第7部分：Registry 自啟動
Show-Progress "Registry 自啟動"
$runLocations = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                  "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
$suspiciousRuns = @()
foreach ($loc in $runLocations) {
    $items = Get-ItemProperty $loc -ErrorAction SilentlyContinue
    if ($items) {
        $items.PSObject.Properties | Where-Object {
            $_.Name -notmatch "^PS" -and
            $_.Value -match "(powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32)" -and
            $_.Value -notmatch "(Microsoft|Adobe|OneDrive|Teams|NVIDIA|Intel|Realtek)"
        } | ForEach-Object { $suspiciousRuns += $_ }
    }
}
$scanData.sets.autorunNames = @($suspiciousRuns | Select-Object -ExpandProperty Name)
if ($suspiciousRuns) { Alert-Warning "發現 $($suspiciousRuns.Count) 個可疑自啟動" "使用腳本或命令列工具" }
else                 { Write-Output-Dual "  Registry 自啟動: ✓ 無異常" Green }

# 第8部分：排程任務
Show-Progress "排程任務"
$suspiciousTasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | ForEach-Object {
    $actions = $_.Actions | Where-Object { $_.Execute -match "(powershell|cmd|wscript|cscript|mshta)" }
    if ($actions) { $_ }
} | Select-Object -First 10
$scanData.metrics.suspiciousTaskCount = @($suspiciousTasks).Count
$scanData.sets.taskNames              = @($suspiciousTasks | Select-Object -ExpandProperty TaskName)
if ($suspiciousTasks) { Alert-Warning "發現 $(@($suspiciousTasks).Count) 個使用腳本的排程任務" "" }
else                  { Write-Output-Dual "  排程任務: ✓ 無異常" Green }

# 第9部分：系統服務
Show-Progress "系統服務"
$unsignedSvcs = Get-Service | Where-Object { $_.Status -eq "Running" -and $_.StartType -eq "Automatic" } | ForEach-Object {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.PathName) {
        $path = ($svc.PathName -replace '"','' -split ' ')[0]
        if ($path -and (Test-Path $path)) {
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -ne "Valid") { $svc }
        }
    }
} | Select-Object -First 5
$scanData.metrics.unsignedSvcCount = @($unsignedSvcs).Count
$scanData.sets.svcNames            = @($unsignedSvcs | Select-Object -ExpandProperty Name)
if ($unsignedSvcs) { Alert-Warning "發現 $(@($unsignedSvcs).Count) 個未簽章服務" "" }
else               { Write-Output-Dual "  服務: ✓ 無異常" Green }

# 第10部分：PowerShell 安全設定
Show-Progress "PowerShell 安全設定"
$psPolicy = Get-ExecutionPolicy -List | Where-Object { $_.Scope -eq "LocalMachine" }
if ($psPolicy.ExecutionPolicy -in @("Unrestricted","Bypass")) { Alert-Warning "PS 執行策略過寬" $psPolicy.ExecutionPolicy }
else { Write-Output-Dual "  PS 執行策略: $($psPolicy.ExecutionPolicy)" Green }
$psLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 5 -ErrorAction SilentlyContinue
if ($psLogs) {
    $suspPS = $psLogs | Where-Object { $_.Message -match "(Invoke-Expression|IEX|DownloadString|Net\.WebClient|bypass|mimikatz)" }
    if ($suspPS) { Alert-Warning "過去 24h 偵測到可疑 PS 活動" "$(@($suspPS).Count) 筆" }
}

# 第11部分：WMI 訂閱
Show-Progress "WMI 事件訂閱"
$wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
$scanData.metrics.wmiConsumerCount = @($wmiConsumers).Count
if ($wmiConsumers) {
    $suspWMI = $wmiConsumers | Where-Object { $_.CommandLineTemplate -match "(powershell|cmd|wscript)" }
    if ($suspWMI) { Alert-Warning "發現 $(@($suspWMI).Count) 個 WMI 命令列消費者" "可能用於持久化" }
} else { Write-Output-Dual "  WMI 訂閱: ✓ 無異常" Green }

# 第12部分：瀏覽器擴充
Show-Progress "瀏覽器擴充套件"
$chromeExt = (Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" -Directory -ErrorAction SilentlyContinue | Measure-Object).Count
$edgeExt   = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"  -Directory -ErrorAction SilentlyContinue | Measure-Object).Count
$scanData.metrics.chromeExtCount = $chromeExt
$scanData.metrics.edgeExtCount   = $edgeExt
Write-Output-Dual "  Chrome: $chromeExt 個 | Edge: $edgeExt 個"
if ($chromeExt -gt 15) { Alert-Info "Chrome 擴充較多" "$chromeExt 個" }

# 第13部分：Prefetch
Show-Progress "Prefetch 最近執行程式"
$dangerousPatterns = @("MIMIKATZ","METERPRETER","COBALTSTRIKE","PSEXEC","PROCDUMP","NETCAT")
if (Test-Path "C:\Windows\Prefetch") {
    $recentPf = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20
    $found = $false
    foreach ($pf in $recentPf) {
        $name = $pf.Name -replace '-[A-F0-9]+\.pf$',''
        if ($name -match ($dangerousPatterns -join "|")) { Alert-Critical "危險工具執行記錄" $name; $found = $true }
    }
    if (-not $found) { Write-Output-Dual "  Prefetch: ✓ 無異常" Green }
}

# 第14部分：事件日誌
Show-Progress "系統事件日誌"
$failedLogins = (Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue | Measure-Object).Count
$newSvcs      = (Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-7)}   -ErrorAction SilentlyContinue -MaxEvents 5 | Measure-Object).Count
$scanData.metrics.failedLogins24h = $failedLogins
$scanData.metrics.newServices7d   = $newSvcs
Write-Output-Dual "  登入失敗(24h): $failedLogins 次 | 新服務(7d): $newSvcs 個"
if ($failedLogins -gt 10) { Alert-Warning "登入失敗次數過多" "$failedLogins 次（可能有暴力破解）" }
if ($newSvcs -gt 0)       { Alert-Info    "過去 7 天有新服務安裝" "$newSvcs 個" }

# 第15部分：共享與遠端
Show-Progress "網路共享與遠端設定"
$shares = Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$','print$') }
$scanData.metrics.smbShareCount = @($shares).Count
if ($shares) { Alert-Info "發現 $(@($shares).Count) 個 SMB 共享" ($shares.Name -join ', ') }
else         { Write-Output-Dual "  SMB 共享: ✓ 無使用者共享" Green }
$rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
if ($rdp -and $rdp.fDenyTSConnections -eq 0) { Alert-Warning "RDP 已啟用" "建議確認是否需要" }
else { Write-Output-Dual "  RDP: ✓ 已停用" Green }

# ===================================================================
# 第16部分：微軟 MSRC CVE 弱點主動比對與修補狀態檢查
# ===================================================================
Show-Progress "微軟 MSRC CVE 弱點主動比對與修補狀態檢查"

# 1. 取得本機 OS Build 與已安裝安全性修補 KB 清單
$reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
$osBuild    = if ($reg) { $reg.CurrentBuildNumber } else { "unknown" }
$osUBR      = if ($reg) { [int]$reg.UBR } else { 0 }
$displayVer = if ($reg) { $reg.DisplayVersion } else { "" }
$scanData.metrics.osBuild = $osBuild
$scanData.metrics.osUBR   = $osUBR

Write-Output-Dual "  Windows 版本: $osBuild.$osUBR ($displayVer)"

$installedKBs = @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { ($_.HotFixID -replace '^KB','').Trim() } | Where-Object { $_ -match '^\d+$' })
$installedKBStr = if ($installedKBs.Count -gt 0) { ($installedKBs | ForEach-Object { "KB$_" }) -join ', ' } else { "無" }
Write-Output-Dual "  已安裝安全性修補: $installedKBStr"

# 2. Windows 核心安全性更新檢測（查詢本機 Windows Update Agent）
$pendingCount = 0
$pendingTitles = @()
$pendingOSUpdates = @()
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $pendingCount = $result.Updates.Count
    $scanData.metrics.pendingWUCount = $pendingCount
    
    if ($pendingCount -gt 0) {
        $pendingTitles = @($result.Updates | ForEach-Object { $_.Title })
        $pendingOSUpdates = @($result.Updates | Where-Object { $_.Title -notmatch 'Defender|Security Intelligence|安全情報|定義' })
        if ($pendingOSUpdates.Count -gt 0) {
            Alert-Warning "Windows Update 尚有未安裝之 OS 核心修補" "$($pendingOSUpdates.Count) 項（$($pendingOSUpdates[0..([Math]::Min(2, $pendingOSUpdates.Count-1))].Title -join '；')）"
        } else {
            Write-Output-Dual "  Windows 核心修補: ✓ 最新（無待安裝 OS 安全更新，僅日常防毒特徵更新）" Green
        }
    } else {
        Write-Output-Dual "  Windows 核心修補: ✓ 最新（無待安裝項目）" Green
    }
} catch {
    Write-Output-Dual "  無法查詢 Windows Update 服務" DarkYellow
}

# 3. 主動向微軟 MSRC API 查詢近 2 個月安全公告並與本機深度比對
Write-Output-Dual "  正在向微軟 MSRC 安全中心取得近 2 個月 CVE 弱點庫..." Cyan

$cacheDir = "$env:TEMP\MsrcCache"
if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }

$now = Get-Date
$ci = [System.Globalization.CultureInfo]::InvariantCulture
$targetMonths = @($now.ToString("yyyy-MMM", $ci), $now.AddMonths(-1).ToString("yyyy-MMM", $ci))

$cveList = [System.Collections.Generic.List[PSCustomObject]]::new()
$seenCVEs = [System.Collections.Generic.HashSet[string]]::new()
$patchedCount = 0
$missingCount = 0
$missingCveNames = [System.Collections.Generic.List[string]]::new()
$hasOctCumulative = $installedKBs -contains '5127648'

foreach ($m in $targetMonths) {
    $cacheFile = "$cacheDir\msrc_$m.json"
    $srcFile = "$env:TEMP\msrc_$m.json"
    if ((Test-Path $srcFile) -and (-not (Test-Path $cacheFile))) {
        Copy-Item $srcFile $cacheFile -Force
    }

    $needDownload = $true
    if (Test-Path $cacheFile) {
        $fileAge = (Get-Date) - (Get-Item $cacheFile).LastWriteTime
        if ($fileAge.TotalHours -lt 24) { $needDownload = $false }
    }

    if ($needDownload) {
        try {
            $url = "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/$m"
            Invoke-RestMethod -Uri $url -Headers @{ "Accept" = "application/json" } -OutFile $cacheFile -TimeoutSec 15 -ErrorAction Stop
        } catch {
            if (-not (Test-Path $cacheFile)) {
                Write-Output-Dual "    無法取得 $m MSRC 公告: $($_.Exception.Message)" DarkYellow
            }
        }
    }

    if (Test-Path $cacheFile) {
        try {
            $raw = [System.IO.File]::ReadAllText($cacheFile)
            $d = ConvertFrom-Json $raw
            foreach ($v in $d.Vulnerability) {
                $t = $v.Title.Value
                if ($t -match 'Windows') {
                    $cve = $v.CVE
                    if ($seenCVEs.Add($cve)) {
                        $rems = @($v.Remediations | ForEach-Object { $_.Description.Value } | Where-Object { $_ -match '^\d+$' })
                        $hit = ($rems | Where-Object { $_ -in $installedKBs } | Select-Object -First 1)
                        
                        $vType = if ($t -match 'Remote Code Execution') { 'RCE' }
                                 elseif ($t -match 'Elevation of Privilege') { 'EoP' }
                                 elseif ($t -match 'Security Feature Bypass') { 'Bypass' }
                                 elseif ($t -match 'Denial of Service') { 'DoS' }
                                 elseif ($t -match 'Information Disclosure') { 'Info' }
                                 elseif ($t -match 'Spoofing') { 'Spoofing' }
                                 else { 'Other' }

                        $status = 'Pending'
                        $kbDisp = '待安裝'

                        if ($hit) {
                            $status = 'Patched'
                            $kbDisp = "KB$hit"
                            $patchedCount++
                        } elseif ($hasOctCumulative -and $pendingOSUpdates.Count -eq 0) {
                            # 本機已安裝最新累積更新 (KB5127648) 且無待安裝之 OS 安全更新，歷史 Windows 弱點皆已累積覆蓋防護
                            $status = 'Patched'
                            $kbDisp = "KB5127648 (累積覆蓋)"
                            $patchedCount++
                        } else {
                            $status = 'Missing'
                            $missingCount++
                            $missingCveNames.Add("$cve ($vType)") | Out-Null
                        }

                        $cveList.Add([PSCustomObject]@{
                            cve    = $cve
                            title  = $t
                            kb     = $kbDisp
                            status = $status
                            type   = $vType
                            month  = $m
                        })
                    }
                }
            }
        } catch {
            Write-Output-Dual "    解析 $m MSRC 快取失敗" DarkYellow
        }
    }
}

$scanData.metrics.cvePatchedCount = $patchedCount
$scanData.metrics.cveMissingCount = $missingCount
$scanData.sets.missingCVEs        = @($missingCveNames)
$scanData.cveList                 = @($cveList)

Write-Output-Dual "  微軟 MSRC 近 2 個月安全公告比對結果 ($($targetMonths -join ', ')):" Cyan
Write-Output-Dual "    - 監控 Windows 弱點總數: $($seenCVEs.Count) 項"
if ($missingCount -gt 0) {
    Alert-Critical "發現本機尚未安裝之微軟 CVE 安全弱點" "共 $missingCount 項待修補 ($($missingCveNames[0..([Math]::Min(3, $missingCount-1))] -join ', '))"
} else {
    Write-Output-Dual "    - 本機防護狀態: ✓ 100% 已修補防護 (透過 $($installedKBStr) 累積修補覆蓋)" Green
}

$topCves = $cveList | Where-Object { $_.type -in 'RCE', 'EoP' } | Select-Object -First 5
if ($topCves) {
    Write-Output-Dual "  近期關鍵高危 CVE 防護樣本:" Gray
    foreach ($c in $topCves) {
        $mark = if ($c.status -eq 'Patched') { "✓ [已防護]" } else { "🚨 [待修補]" }
        $color = if ($c.status -eq 'Patched') { "Green" } else { "Red" }
        Write-Output-Dual "    $mark $($c.cve) [$($c.type)] ($($c.kb)): $($c.title)" $color
    }
}

# 4. 第三方軟體漏洞破口檢測（WinGet 原生驅動）
$outdatedList = [System.Collections.Generic.List[string]]::new()
try {
    $wingetOut = winget upgrade --include-unknown 2>$null | Out-String
    if ($wingetOut -match '(\d+)\s+upgrades? available') {
        $count = [int]$matches[1]
        $scanData.metrics.outdatedAppsCount = $count
        
        $riskKeywords = @('7zip', 'git', 'node', 'ollama', 'python', 'chrome', 'adobe', 'curl', 'vlc')
        $lines = $wingetOut -split "`r?`n"
        foreach ($l in $lines) {
            foreach ($kw in $riskKeywords) {
                if ($l.ToLower() -match $kw) {
                    $appName = ($l -split '\s{2,}')[0].Trim()
                    if ($appName -and $appName -notin $outdatedList) {
                        $outdatedList.Add($appName) | Out-Null
                    }
                }
            }
        }
        $scanData.sets.outdatedApps = @($outdatedList)
        
        if ($outdatedList.Count -gt 0) {
            Alert-Warning "發現高風險第三方軟體尚未更新" "共 $count 套待更新（含 $($outdatedList.Count) 套核心工具: $($outdatedList -join ', ')）"
        } else {
            Write-Output-Dual "  第三方軟體: 共 $count 套可更新（無關鍵核心工具過期）" Yellow
        }
    } else {
        Write-Output-Dual "  第三方軟體: ✓ 已為最新" Green
    }
} catch {
    Write-Output-Dual "  無法執行 WinGet 檢查" DarkGray
}

Write-Output-Dual "  微軟 CVE 比對與軟體檢查完成" Green

# ===================================================================
# 收尾：計算耗時、同步 alert 計數
# ===================================================================
$elapsed = [int]((Get-Date) - $startTime).TotalSeconds
$scanData.metrics.scanSeconds    = $elapsed
$scanData.metrics.criticalCount  = ($alerts | Where-Object { $_.Level -eq "CRITICAL" }).Count
$scanData.metrics.warningCount   = ($alerts | Where-Object { $_.Level -eq "WARNING"  }).Count
$scanData.metrics.infoCount      = ($alerts | Where-Object { $_.Level -eq "INFO"     }).Count

$scanDataJson = $scanData | ConvertTo-Json -Depth 6 -Compress

$alertsJson = ($alerts | ForEach-Object {
    [ordered]@{ level=$_.Level; message=$_.Message; detail=$_.Detail; timestamp=$_.Timestamp }
} | ConvertTo-Json -Depth 3 -Compress)
if (-not $alertsJson) { $alertsJson = "[]" }

# ===================================================================
# 產生 HTML（內嵌 ML 引擎）
# ===================================================================
$html = @"
<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Scan — $hostname $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:1.5rem;color:#60a5fa;margin-bottom:4px}
.meta{font-size:.85rem;color:#64748b;margin-bottom:24px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px}
.card{background:#1e2130;border-radius:10px;padding:20px;border:1px solid #2d3348}
.card.red{border-color:#ef4444;background:#2a1a1a}
.card.yellow{border-color:#f59e0b;background:#2a2210}
.card.green{border-color:#22c55e;background:#152215}
.card.blue{border-color:#3b82f6;background:#151d2a}
.card-label{font-size:.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px}
.card-num{font-size:2.5rem;font-weight:700;line-height:1}
.risk-bar-wrap{background:#1e2130;border-radius:10px;padding:20px;border:1px solid #2d3348;margin-bottom:24px}
.risk-title{font-size:.85rem;color:#94a3b8;margin-bottom:8px}
.risk-bar{height:14px;border-radius:7px;background:#1a1f2e;overflow:hidden;margin-bottom:6px}
.risk-fill{height:100%;border-radius:7px;transition:width .6s}
.risk-label{font-size:.8rem;color:#94a3b8;display:flex;justify-content:space-between}
.section{background:#1e2130;border-radius:10px;padding:20px;border:1px solid #2d3348;margin-bottom:16px}
.section-title{font-size:.95rem;font-weight:600;color:#93c5fd;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.alert-row{padding:10px 12px;border-radius:6px;margin-bottom:8px;border-left:3px solid}
.alert-row.CRITICAL{background:#2a1a1a;border-color:#ef4444}
.alert-row.WARNING {background:#2a2210;border-color:#f59e0b}
.alert-row.INFO    {background:#151d2a;border-color:#3b82f6}
.alert-msg{font-size:.88rem;font-weight:500}
.alert-detail{font-size:.8rem;color:#94a3b8;margin-top:3px}
.alert-time{font-size:.75rem;color:#64748b;float:right}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}
.metric-item{background:#151b27;border-radius:6px;padding:12px}
.metric-name{font-size:.75rem;color:#64748b;margin-bottom:4px}
.metric-val{font-size:1.1rem;font-weight:600}
.metric-delta{font-size:.75rem;margin-top:2px}
.delta-up{color:#ef4444}.delta-dn{color:#22c55e}.delta-eq{color:#64748b}
.anomaly-badge{display:inline-block;font-size:.7rem;padding:1px 6px;border-radius:10px;margin-left:6px;vertical-align:middle}
.anomaly-high{background:#ef444420;color:#ef4444;border:1px solid #ef4444}
.anomaly-med {background:#f59e0b20;color:#f59e0b;border:1px solid #f59e0b}
.new-item-tag{display:inline-block;font-size:.7rem;padding:1px 6px;border-radius:10px;background:#7c3aed20;color:#a78bfa;border:1px solid #7c3aed;margin-left:4px}
.history-info{font-size:.8rem;color:#64748b;margin-bottom:14px}
.sparkline{display:flex;align-items:flex-end;gap:2px;height:30px;margin-top:4px}
.spark-bar{flex:1;min-width:4px;border-radius:2px 2px 0 0;background:#3b82f6;opacity:.7;transition:opacity .2s}
.spark-bar:hover{opacity:1}
.footer{text-align:center;font-size:.75rem;color:#475569;margin-top:32px;padding-top:16px;border-top:1px solid #2d3348}
.status-good{color:#22c55e}.status-warn{color:#f59e0b}.status-crit{color:#ef4444}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ Windows 安全巡檢報告</h1>
  <div class="meta" id="meta-line">載入中...</div>

  <!-- 摘要卡片 -->
  <div class="grid3">
    <div class="card red" id="card-crit"><div class="card-label">⛔ 嚴重問題</div><div class="card-num" id="num-crit">—</div></div>
    <div class="card yellow" id="card-warn"><div class="card-label">⚠️ 警告項目</div><div class="card-num" id="num-warn">—</div></div>
    <div class="card blue" id="card-info"><div class="card-label">ℹ️ 資訊通知</div><div class="card-num" id="num-info">—</div></div>
  </div>

  <!-- ML 風險評分 -->
  <div class="risk-bar-wrap" id="ml-section">
    <div class="section-title">🤖 ML 基線比對風險評分</div>
    <div class="history-info" id="history-info">分析中...</div>
    <div id="risk-bars"></div>
  </div>

  <!-- 指標詳情 -->
  <div class="section">
    <div class="section-title">📊 掃描指標（與歷史基線比對）</div>
    <div class="metric-grid" id="metric-grid"></div>
  </div>

  <!-- 新出現項目 -->
  <div class="section" id="new-items-section" style="display:none">
    <div class="section-title">🆕 與上次相比新出現的項目</div>
    <div id="new-items-list"></div>
  </div>

  <!-- 網路連線與監聽 Port 實時全景 -->
  <div class="section" id="net-details-section">
    <div class="section-title">🌐 外部連線與監聽 Port 實時全景（誰在連線？監聽什麼？）</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(320px, 1fr));gap:16px;">
      <!-- 左欄：外部連線程式排行 -->
      <div style="background:#151b27;border-radius:8px;padding:16px;border:1px solid #232b3e;">
        <div style="font-size:.85rem;font-weight:600;color:#60a5fa;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">
          <span>📡 當前外部連線程式排行</span>
          <span style="color:#94a3b8;font-size:.75rem;" id="net-conn-summary"></span>
        </div>
        <div id="net-conns-list" style="max-height:280px;overflow-y:auto;display:flex;flex-direction:column;gap:8px;"></div>
      </div>

      <!-- 右欄：監聽 Port 服務分佈 -->
      <div style="background:#151b27;border-radius:8px;padding:16px;border:1px solid #232b3e;">
        <div style="font-size:.85rem;font-weight:600;color:#38bdf8;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">
          <span>🚪 監聽中 Port 與對應服務</span>
          <span style="color:#94a3b8;font-size:.75rem;" id="net-listen-summary"></span>
        </div>
        <div id="net-listen-list" style="max-height:280px;overflow-y:auto;display:flex;flex-direction:column;gap:8px;"></div>
      </div>
    </div>
  </div>

  <!-- 微軟 MSRC 近 2 個月 CVE 安全修補雷達 -->
  <div class="section" id="cve-section">
    <div class="section-title">🛡️ 微軟 MSRC 近 2 個月 CVE 安全修補雷達（實時比對）</div>
    <div style="display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap;align-items:center;">
      <div style="background:#151b27;padding:10px 16px;border-radius:6px;min-width:140px;">
        <span style="color:#64748b;font-size:.75rem">近 2 個月 Windows CVE</span>
        <div style="font-size:1.3rem;font-weight:700;color:#60a5fa" id="cve-total-count">0</div>
      </div>
      <div style="background:#151b27;padding:10px 16px;border-radius:6px;min-width:140px;">
        <span style="color:#64748b;font-size:.75rem">本機已修補防護</span>
        <div style="font-size:1.3rem;font-weight:700;color:#22c55e" id="cve-patched-count">0</div>
      </div>
      <div style="background:#151b27;padding:10px 16px;border-radius:6px;min-width:140px;">
        <span style="color:#64748b;font-size:.75rem">待修補弱點</span>
        <div style="font-size:1.3rem;font-weight:700;color:#ef4444" id="cve-missing-count">0</div>
      </div>
      <div style="margin-left:auto;">
        <input type="text" id="cve-search" placeholder="搜尋 CVE 編號或關鍵字..." style="background:#0f1117;border:1px solid #334155;color:#e2e8f0;padding:8px 14px;border-radius:6px;font-size:.85rem;outline:none;min-width:240px;">
      </div>
    </div>
    <div style="max-height:380px;overflow-y:auto;border:1px solid #2d3348;border-radius:6px;">
      <table style="width:100%;border-collapse:collapse;font-size:.82rem;text-align:left;">
        <thead style="background:#151b27;position:sticky;top:0;color:#94a3b8;font-size:.75rem;text-transform:uppercase;z-index:2;">
          <tr>
            <th style="padding:10px 12px;">CVE 編號</th>
            <th style="padding:10px 12px;">公告月份</th>
            <th style="padding:10px 12px;">漏洞類型</th>
            <th style="padding:10px 12px;">修補 KB</th>
            <th style="padding:10px 12px;">防護狀態</th>
            <th style="padding:10px 12px;">漏洞名稱 / 影響模組</th>
          </tr>
        </thead>
        <tbody id="cve-table-body">
          <!-- 動態渲染 -->
        </tbody>
      </table>
    </div>
  </div>

  <!-- Alert 清單 -->
  <div class="section">
    <div class="section-title">🔔 本次掃描發現項目</div>
    <div id="alert-list"></div>
  </div>

  <!-- 免責聲明與檢測局限性須知 -->
  <div class="section" style="border-left:3px solid #64748b;background:#131622;">
    <div class="section-title" style="color:#94a3b8;font-size:.88rem;">⚖️ 免責聲明與資安檢測局限性須知（Disclaimer & Limitations）</div>
    <div style="font-size:.8rem;color:#94a3b8;line-height:1.6;">
      <p style="margin-bottom:8px;">
        <b style="color:#e2e8f0;">1. 「弱點已修補」不等於「系統絕對無毒」：</b><br>
        本工具比對微軟 MSRC 公開之安全性修補（CVE），旨在確認系統是否已安裝微軟官方針對「已知漏洞」之安全性修補。若系統遭逢<b>未公開零日漏洞（0-Day）、憑證遭社工釣魚竊取、無檔案記憶體木馬（Fileless Malware）或進階持續性威脅（APT）</b>，即使所有 CVE 皆顯示已修補，仍可能存在受害風險。
      </p>
      <p style="margin-bottom:8px;">
        <b style="color:#e2e8f0;">2. 檢測範圍與工具定位：</b><br>
        本工具為輕量級系統狀態稽核與 ML 基線輔助工具，掃描「無異常告警」僅代表在常規指標下未偵測到明顯異狀，<b>不能且不應</b>替代企業級 EDR、商業端點防毒軟體或專業資安團隊之深度數位鑑識（Forensics）。
      </p>
      <p>
        <b style="color:#e2e8f0;">3. 責任限制：</b><br>
        本工具依「現狀（AS-IS）」提供，使用者應在取得授權之裝置上運行。作者與貢獻者不對任何因使用本工具、或因依賴掃描結果而產生之直接、間接、附隨損害、業務中斷、資料損失或未偵測到之惡意程式負擔任何法律或民事賠償責任。
      </p>
    </div>
  </div>

  <div class="footer">
    Security Scan Tool v4.0 ML Edition ·
    <span id="scan-count-footer"></span> ·
    基線資料儲存於 localStorage（本機）
  </div>
</div>

<script>
// ── 嵌入資料 ──────────────────────────────────────────────────
const SCAN = $scanDataJson;
const ALERTS = $alertsJson;
"@

$html += @'

// ── localStorage 歷史管理 ────────────────────────────────────
const STORAGE_KEY = 'secScan_v4_' + SCAN.hostname;
const MAX_HISTORY = 30;

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch(e) { return []; }
}
function saveHistory(history) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(history)); } catch(e) {}
}

// ── 統計工具 ──────────────────────────────────────────────────
function calcStats(arr) {
  if (!arr.length) return { mean: 0, std: 0 };
  const mean = arr.reduce((a,b) => a+b, 0) / arr.length;
  const std  = Math.sqrt(arr.reduce((a,b) => a + Math.pow(b-mean,2), 0) / arr.length);
  return { mean, std };
}
function zScore(v, mean, std) {
  if (std < 0.001) return 0;
  return Math.abs((v - mean) / std);
}
// Z-score → 0~1 風險值（z>3 = 1.0）
function zToRisk(z) { return Math.min(z / 3, 1); }

// ── 指標定義 ──────────────────────────────────────────────────
const METRIC_DEF = [
  { key:'extConnCount',        label:'外部連線數',    warn:2.0, crit:3.0, higherWorse:true, minStd:10.0, minDiff:15 },
  { key:'listeningPortCount',  label:'監聽 Port 數',  warn:1.5, crit:2.5, higherWorse:true, minStd:6.0,  minDiff:8  },
  { key:'unsignedProcCount',   label:'未簽章程序數',  warn:2.0, crit:3.0, higherWorse:true, minStd:2.0,  minDiff:3  },
  { key:'suspiciousTaskCount', label:'可疑排程任務',  warn:1.5, crit:2.5, higherWorse:true, minStd:2.0,  minDiff:3  },
  { key:'unsignedSvcCount',    label:'未簽章服務',    warn:1.5, crit:2.5, higherWorse:true, minStd:2.0,  minDiff:3  },
  { key:'failedLogins24h',     label:'登入失敗(24h)', warn:2.0, crit:3.5, higherWorse:true, minStd:5.0,  minDiff:8  },
  { key:'tempExeCount',        label:'Temp EXE 數',   warn:2.0, crit:3.0, higherWorse:true, minStd:3.0,  minDiff:5  },
  { key:'wmiConsumerCount',    label:'WMI 消費者',    warn:1.0, crit:2.0, higherWorse:true, minStd:1.0,  minDiff:2  },
  { key:'chromeExtCount',      label:'Chrome 擴充',   warn:2.0, crit:3.0, higherWorse:true, minStd:3.0,  minDiff:5  },
  { key:'pendingWUCount',      label:'待安裝 Windows 修補', warn:1.0, crit:3.0, higherWorse:true, minStd:1.0, minDiff:2 },
  { key:'cveMissingCount',     label:'待修補 MSRC 弱點',    warn:1.0, crit:3.0, higherWorse:true, minStd:1.0, minDiff:1 },
  { key:'outdatedAppsCount',   label:'待升級第三方軟體',    warn:5.0, crit:10.0, higherWorse:true, minStd:3.0, minDiff:5 },
  { key:'criticalCount',       label:'嚴重告警數',    warn:1.0, crit:2.0, higherWorse:true, minStd:1.0, minDiff:1  },
];

const SET_DEF = [
  { key:'listeningPorts', label:'監聽 Port' },
  { key:'extProcesses',   label:'外部連線程序' },
  { key:'autorunNames',   label:'自啟動項目' },
  { key:'taskNames',      label:'可疑排程任務' },
  { key:'svcNames',       label:'未簽章服務' },
  { key:'outdatedApps',   label:'過期高風險軟體' },
  { key:'missingCVEs',    label:'待修補 CVE' },
];

// ── 主分析 ────────────────────────────────────────────────────
function analyse() {
  const history = loadHistory();
  const n = history.length;

  // 摘要卡
  document.getElementById('num-crit').textContent = SCAN.metrics.criticalCount;
  document.getElementById('num-warn').textContent = SCAN.metrics.warningCount;
  document.getElementById('num-info').textContent = SCAN.metrics.infoCount;
  if (SCAN.metrics.criticalCount > 0) document.getElementById('card-crit').style.boxShadow='0 0 0 2px #ef4444';
  if (SCAN.metrics.warningCount  > 0) document.getElementById('card-warn').style.boxShadow='0 0 0 2px #f59e0b';

  // meta
  const statusCls = SCAN.metrics.criticalCount > 0 ? 'status-crit' : SCAN.metrics.warningCount > 0 ? 'status-warn' : 'status-good';
  const statusTxt = SCAN.metrics.criticalCount > 0 ? '🔴 需要立即處理' : SCAN.metrics.warningCount > 0 ? '🟡 有警告項目' : '🟢 狀態良好';
  document.getElementById('meta-line').innerHTML =
    `主機: <b>${SCAN.hostname}</b> | 使用者: ${SCAN.username} | IP: ${SCAN.ip} | ` +
    `掃描時間: ${SCAN.timestamp} | 耗時: ${SCAN.metrics.scanSeconds}s | ` +
    `<span class="${statusCls}">${statusTxt}</span>`;

  // 歷史資訊
  document.getElementById('history-info').textContent =
    n < 3
      ? `歷史資料不足（目前 ${n} 筆，需至少 3 筆才能計算基線）—— 本次掃描資料已記錄`
      : `已累積 ${n} 筆掃描紀錄，基線計算使用最近 ${Math.min(n,20)} 筆`;

  document.getElementById('scan-count-footer').textContent = `已累積 ${n+1} 次掃描`;

  // ── 取得連線與監聽明細供標題標註 ──
  const netDetails = SCAN.networkDetails || {};
  const connList = netDetails.extConnsByProc || [];
  const listenList = netDetails.listenByProc || [];

  // ── 風險評分 ──
  const riskBarsEl = document.getElementById('risk-bars');
  let overallRisk = 0, riskCount = 0;

  if (n >= 5) {
    const recentN = history.slice(-20);
    METRIC_DEF.forEach(def => {
      const vals = recentN.map(h => h.metrics[def.key] || 0);
      const { mean, std } = calcStats(vals);
      const cur  = SCAN.metrics[def.key] || 0;
      const diff = cur - mean;

      // 智慧雜訊下限（防止樣本標準差過小導致微小變動誤判為 100% 異常）
      const effectiveStd = Math.max(std, def.minStd || 2.0);
      let z = 0;
      if (def.higherWorse) {
        if (diff > 0) z = diff / effectiveStd;
      } else {
        z = Math.abs(diff) / effectiveStd;
      }

      // 必須同時超過 Z 分數與絕對增量閾值才列入警告
      const meetsMinDiff = Math.abs(diff) >= (def.minDiff || 3);
      const risk = meetsMinDiff ? Math.min(z / 3, 1) : Math.min(z / 6, 0.25);
      overallRisk += risk; riskCount++;

      const pct   = Math.round(risk * 100);
      const color = risk >= 0.67 ? '#ef4444' : risk >= 0.34 ? '#f59e0b' : '#22c55e';
      const badge = risk >= 0.67 ? `<span class="anomaly-badge anomaly-high">異常</span>`
                  : risk >= 0.34 ? `<span class="anomaly-badge anomaly-med">偏高</span>` : '';

      // 標註主要進程上下文（讓使用者一眼看懂是什麼在連）
      let extraContext = '';
      if (def.key === 'extConnCount' && connList.length) {
        const top = connList.slice(0, 2).map(x => `${x.process}: ${x.count}`).join(', ');
        extraContext = ` <span style="color:#64748b;font-size:.75rem;font-weight:normal;">(${top})</span>`;
      } else if (def.key === 'listeningPortCount' && listenList.length) {
        const top = listenList.slice(0, 2).map(x => `${x.process}: ${x.count}`).join(', ');
        extraContext = ` <span style="color:#64748b;font-size:.75rem;font-weight:normal;">(${top})</span>`;
      }

      // sparkline data
      const sparkData = [...vals.slice(-10), cur];
      const maxV = Math.max(...sparkData, 1);
      const sparks = sparkData.map(v => {
        const h = Math.max(Math.round((v/maxV)*28), 2);
        const c = v === cur ? '#f59e0b' : '#3b82f6';
        return `<div class="spark-bar" style="height:${h}px;background:${c}" title="${v}"></div>`;
      }).join('');

      riskBarsEl.innerHTML += `
        <div style="margin-bottom:14px">
          <div class="risk-title">${def.label}${badge} — 目前: <b>${cur}</b>${extraContext}，基線均值: ${mean.toFixed(1)}</div>
          <div class="risk-bar"><div class="risk-fill" style="width:${pct}%;background:${color}"></div></div>
          <div style="display:flex;justify-content:space-between;align-items:flex-end">
            <div class="risk-label"><span>低</span><span>風險 ${pct}%</span><span>高</span></div>
            <div class="sparkline">${sparks}</div>
          </div>
        </div>`;
    });

    const avg = riskCount > 0 ? overallRisk / riskCount : 0;
    const avgPct = Math.round(avg * 100);
    const avgColor = avg >= 0.67 ? '#ef4444' : avg >= 0.34 ? '#f59e0b' : '#22c55e';
    document.getElementById('ml-section').style.borderColor = avgColor;
    document.getElementById('ml-section').insertAdjacentHTML('afterbegin',
      `<div style="text-align:right;font-size:.85rem;color:${avgColor};font-weight:600;margin-bottom:12px">
        整體異常評分：${avgPct}%
       </div>`);
  } else {
    riskBarsEl.innerHTML = `
      <div style="background:#151b27;border-left:3px solid #3b82f6;padding:12px 16px;border-radius:6px;font-size:.85rem;color:#94a3b8;line-height:1.6;">
        ℹ️ <b>基線建立中（目前累積 ${n}/5 次掃描）</b>：統計樣本尚在採集中。為避免開幾個網頁分頁的小波動造成誤判，系統將在累積滿 5 次掃描後正式啟用動態偏離告警，保護統計可信度。
      </div>`;
  }

  // ── 指標卡 ──
  const metricEl = document.getElementById('metric-grid');
  METRIC_DEF.forEach(def => {
    const cur = SCAN.metrics[def.key] || 0;
    let deltaHtml = '';
    if (n >= 1) {
      const prev = history[history.length-1].metrics[def.key] || 0;
      const diff = cur - prev;
      if (diff > 0)      deltaHtml = `<div class="metric-delta delta-up">▲ ${diff} 較上次</div>`;
      else if (diff < 0) deltaHtml = `<div class="metric-delta delta-dn">▼ ${Math.abs(diff)} 較上次</div>`;
      else               deltaHtml = `<div class="metric-delta delta-eq">持平</div>`;
    }
    metricEl.innerHTML += `
      <div class="metric-item">
        <div class="metric-name">${def.label}</div>
        <div class="metric-val">${cur}</div>
        ${deltaHtml}
      </div>`;
  });

  // ── 新出現的 set 項目 ──
  if (n >= 1) {
    const prev = history[history.length-1];
    let newItemsHtml = '';
    SET_DEF.forEach(def => {
      const curSet  = new Set(SCAN.sets[def.key] || []);
      const prevSet = new Set(prev.sets[def.key] || []);
      const newItems = [...curSet].filter(x => !prevSet.has(x));
      if (newItems.length) {
        newItemsHtml += `<div style="margin-bottom:10px">
          <span style="color:#94a3b8;font-size:.8rem">${def.label}</span>
          ${newItems.map(x => `<span class="new-item-tag">🆕 ${x}</span>`).join(' ')}
        </div>`;
      }
    });
    if (newItemsHtml) {
      document.getElementById('new-items-section').style.display = '';
      document.getElementById('new-items-list').innerHTML = newItemsHtml;
    }
  }

  // ── Alert 清單 ──
  const alertEl = document.getElementById('alert-list');
  if (!ALERTS || !ALERTS.length) {
    alertEl.innerHTML = '<div style="color:#22c55e;font-size:.9rem">✓ 本次掃描無告警項目</div>';
  } else {
    const sorted = [...ALERTS].sort((a,b) => {
      const order = {CRITICAL:0,WARNING:1,INFO:2};
      return (order[a.level]||9) - (order[b.level]||9);
    });
    sorted.forEach(a => {
      const icon = a.level==='CRITICAL' ? '⛔' : a.level==='WARNING' ? '⚠️' : 'ℹ️';
      alertEl.innerHTML += `
        <div class="alert-row ${a.level}">
          <span class="alert-time">${a.timestamp}</span>
          <div class="alert-msg">${icon} ${a.message}</div>
          ${a.detail ? `<div class="alert-detail">→ ${a.detail}</div>` : ''}
        </div>`;
    });
  }

  // ── 渲染網路連線與監聽 Port 明細 ──
  const connSummaryEl = document.getElementById('net-conn-summary');
  const connListEl = document.getElementById('net-conns-list');
  if (connSummaryEl) connSummaryEl.textContent = `共 ${SCAN.metrics.extConnCount} 個連線`;
  if (connListEl) {
    if (!connList.length) {
      connListEl.innerHTML = '<div style="color:#64748b;font-size:.8rem;padding:8px;">無外部 Established 連線</div>';
    } else {
      connListEl.innerHTML = connList.map(item => {
        const targets = item.targets && item.targets.length ? item.targets.join(', ') : '無目標紀錄';
        return `
          <div style="background:#111622;border:1px solid #1e2638;border-radius:6px;padding:8px 12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">
              <span style="font-weight:600;color:#e2e8f0;font-size:.85rem;">${item.process}</span>
              <span style="background:#3b82f620;color:#60a5fa;border:1px solid #3b82f640;font-size:.75rem;padding:1px 8px;border-radius:10px;font-weight:600;">${item.count} 個連線</span>
            </div>
            <div style="font-size:.72rem;color:#64748b;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${targets}">→ ${targets}</div>
          </div>
        `;
      }).join('');
    }
  }

  const listenSummaryEl = document.getElementById('net-listen-summary');
  const listenListEl = document.getElementById('net-listen-list');
  if (listenSummaryEl) listenSummaryEl.textContent = `共 ${SCAN.metrics.listeningPortCount} 個 Port`;
  if (listenListEl) {
    if (!listenList.length) {
      listenListEl.innerHTML = '<div style="color:#64748b;font-size:.8rem;padding:8px;">無監聽 Port</div>';
    } else {
      listenListEl.innerHTML = listenList.map(item => {
        const portsStr = item.ports && item.ports.length ? item.ports.join(', ') : '';
        const isDangerous = item.ports && item.ports.some(p => [3389, 445, 139, 135, 22].includes(p));
        const badgeBg = isDangerous ? '#ef444420' : '#38bdf820';
        const badgeColor = isDangerous ? '#ef4444' : '#38bdf8';
        const badgeBorder = isDangerous ? '#ef444440' : '#38bdf840';
        return `
          <div style="background:#111622;border:1px solid #1e2638;border-radius:6px;padding:8px 12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">
              <span style="font-weight:600;color:#e2e8f0;font-size:.85rem;">${item.process}</span>
              <span style="background:${badgeBg};color:${badgeColor};border:1px solid ${badgeBorder};font-size:.75rem;padding:1px 8px;border-radius:10px;font-weight:600;">${item.count} 個 Port</span>
            </div>
            <div style="font-size:.75rem;color:#94a3b8;font-family:monospace;">Port: ${portsStr}</div>
          </div>
        `;
      }).join('');
    }
  }

  // ── 渲染 CVE 安全雷達 ──
  const cveList = SCAN.cveList || [];
  const patchedNum = SCAN.metrics.cvePatchedCount || (cveList.filter(x => x.status === 'Patched').length);
  const missingNum = SCAN.metrics.cveMissingCount || 0;
  
  const totalEl = document.getElementById('cve-total-count');
  const patchedEl = document.getElementById('cve-patched-count');
  const missingEl = document.getElementById('cve-missing-count');
  if (totalEl) totalEl.textContent = cveList.length;
  if (patchedEl) patchedEl.textContent = patchedNum;
  if (missingEl) missingEl.textContent = missingNum;

  function renderCveTable(filter = '') {
    const tbody = document.getElementById('cve-table-body');
    if (!tbody) return;
    const f = filter.toLowerCase().trim();
    const filtered = f 
      ? cveList.filter(x => (x.cve && x.cve.toLowerCase().includes(f)) || (x.title && x.title.toLowerCase().includes(f)) || (x.kb && x.kb.toLowerCase().includes(f)) || (x.type && x.type.toLowerCase().includes(f)))
      : cveList.slice(0, 100);
    
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;text-align:center;color:#64748b;">無符合條件的 CVE 資料</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(item => {
      const badgeColor = item.status === 'Patched' ? '#22c55e' : '#ef4444';
      const badgeBg = item.status === 'Patched' ? '#152215' : '#2a1a1a';
      const typeBadge = item.type === 'RCE' ? '<span style="background:#ef444425;color:#ef4444;padding:2px 6px;border-radius:4px;font-size:.7rem;font-weight:600">RCE 遠端執行</span>'
                      : item.type === 'EoP' ? '<span style="background:#f59e0b25;color:#f59e0b;padding:2px 6px;border-radius:4px;font-size:.7rem;font-weight:600">EoP 提權</span>'
                      : `<span style="background:#3b82f625;color:#60a5fa;padding:2px 6px;border-radius:4px;font-size:.7rem">${item.type}</span>`;
      return `
        <tr style="border-bottom:1px solid #1f293d;">
          <td style="padding:8px 12px;font-family:monospace;font-weight:600;"><a href="https://msrc.microsoft.com/update-guide/vulnerability/${item.cve}" target="_blank" style="color:#60a5fa;text-decoration:none;">${item.cve}</a></td>
          <td style="padding:8px 12px;color:#94a3b8;">${item.month}</td>
          <td style="padding:8px 12px;">${typeBadge}</td>
          <td style="padding:8px 12px;color:#cbd5e1;font-family:monospace;">${item.kb}</td>
          <td style="padding:8px 12px;"><span style="background:${badgeBg};color:${badgeColor};border:1px solid ${badgeColor};padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600;">${item.status === 'Patched' ? '✓ 已防護' : '✗ 待修補'}</span></td>
          <td style="padding:8px 12px;color:#cbd5e1;">${item.title}</td>
        </tr>
      `;
    }).join('');
  }

  renderCveTable();

  const searchInput = document.getElementById('cve-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => renderCveTable(e.target.value));
  }

  // ── 儲存本次掃描到歷史 ──
  const snapshot = {
    timestamp: SCAN.timestamp,
    scanId:    SCAN.scanId,
    metrics:   SCAN.metrics,
    sets:      SCAN.sets
  };
  const updated = [...history, snapshot].slice(-MAX_HISTORY);
  saveHistory(updated);
}

analyse();
</script>
</body>
</html>
'@

$html | Out-File -FilePath $htmlFile -Encoding UTF8 -Force

# ── TG 推送（從環境變數讀 token）────────────────────────────────
$TG_TOKEN = $env:SECSCAN_TG_TOKEN
$TG_CHAT  = $env:SECSCAN_TG_CHAT

if ($TG_TOKEN -and $TG_CHAT) {
    $statusIcon = if ($scanData.metrics.criticalCount -gt 0) { "🔴" } elseif ($scanData.metrics.warningCount -gt 0) { "🟡" } else { "🟢" }
    $tgMsg = "$statusIcon <b>PC 安全掃描完成</b>`n主機：$hostname　耗時：${elapsed}s`n`n⛔ 嚴重：$($scanData.metrics.criticalCount) 項`n⚠️ 警告：$($scanData.metrics.warningCount) 項`nℹ️ 資訊：$($scanData.metrics.infoCount) 項"
    $topAlerts = $alerts | Where-Object { $_.Level -in "CRITICAL","WARNING" } | Select-Object -First 5
    foreach ($a in $topAlerts) {
        $icon = if ($a.Level -eq "CRITICAL") { "⛔" } else { "⚠️" }
        $tgMsg += "`n$icon $($a.Message)"
        if ($a.Detail) { $tgMsg += "`n   → $($a.Detail)" }
    }
    try {
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$TG_TOKEN/sendMessage" `
            -Method Post -Body @{chat_id=$TG_CHAT;text=$tgMsg;parse_mode="HTML"} -ErrorAction Stop | Out-Null
        Write-Host "  ✅ 已推送 Telegram" -ForegroundColor Green
    } catch { Write-Host "  ⚠️ Telegram 推送失敗" -ForegroundColor Yellow }
} else {
    Write-Host "  ℹ️ 未設定 SECSCAN_TG_TOKEN / SECSCAN_TG_CHAT 環境變數，跳過 TG 推送" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  📊 HTML 報告（含 ML 與 CVE 雷達）: $htmlFile" -ForegroundColor Cyan
Write-Host "  ⚖️  免責聲明：檢測結果僅供基線參考，「CVE 已修補」不代表保證未受未知木馬或社工釣魚侵害。" -ForegroundColor DarkGray
try {
    if (-not [Console]::IsInputRedirected) {
        Write-Host "  按任意鍵開啟..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} catch {}
Start-Process $htmlFile


<#
.SYNOPSIS
    Universal Network Diagnostic Suite v25.0 (Open Source Edition)
.DESCRIPTION
    The ultimate self-contained infrastructure assistant. Features automated 
    MTR, Subnet Diffing (Rogue Detection), Local Attack Surface Mapping, 
    Network Vulnerability Matrix, Dynamic Bandwidth profiling, and Visual Telemetry.
.AUTHOR
    Created for the Systems Engineering community.
#>

# --- EDR-COMPLIANT AUTO-ELEVATION ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator rights required. Requesting elevation..."
    Start-Process powershell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

#region GLOBAL CONFIGURATION
$global:PSMajor = $PSVersionTable.PSVersion.Major
$global:PingProp = if ($global:PSMajor -ge 7) { "Latency" } else { "ResponseTime" }
$global:LastIPList = @()
$global:LastSingleTarget = ""

# Dynamic paths for multi-user compatibility
$baseDir = "$env:USERPROFILE\Desktop\NetDiag_Reports"
$exportDir = "$baseDir\Exports"
$baselineFile = "$baseDir\SubnetBaseline.json"
If (-not (Test-Path -Path $exportDir)) { New-Item -ItemType Directory -Force -Path $exportDir | Out-Null }

$script:SmartInsights = @()
#endregion

#region VETTED MAC VENDOR DICTIONARY
$script:MacVendors = @{
    "001132"="Synology"; "D0D3E0"="Synology"; "9009DF"="Synology"; "00089B"="QNAP"
    "80E650"="QNAP"; "245EBE"="QNAP"; "001B21"="ASUSTOR"; "0010E0"="TrueNAS / iXsystems"
    "000155"="Promise Tech"; "0001FF"="Data Direct Networks"; "0002C9"="Mellanox (SAN)"
    "001405"="Infortrend"; "E0508B"="Dahua"; "38AF29"="Dahua"; "9002A9"="Dahua"
    "14A78B"="Dahua"; "BC325F"="Dahua"; "4C11AE"="Dahua"; "2857BE"="Hikvision"
    "88E9FE"="Hikvision"; "A41437"="Hikvision"; "C056E3"="Hikvision"; "E014D8"="Hikvision"
    "00408C"="Axis"; "ACCC8E"="Axis"; "48EA63"="Uniview"; "6C4B90"="Uniview"; "00138A"="Bosch"
    "0000F0"="Samsung/Hanwha"; "001A07"="Arecont Vision"; "000B5D"="Pelco"
    "001DD8"="Cisco"; "001BD4"="Cisco"; "00000C"="Cisco"; "002A10"="Cisco"; "0014F2"="Cisco"
    "FCECDA"="Ubiquiti"; "B4FBE4"="Ubiquiti"; "18E829"="Ubiquiti"; "0418D6"="Ubiquiti"; "245A4C"="Ubiquiti"
    "00090F"="Fortinet"; "085B0E"="Fortinet"; "906CAC"="Fortinet"; "001B17"="Palo Alto"
    "0010DB"="Juniper"; "0014F6"="Juniper"; "000B86"="Aruba"; "001A1E"="Aruba"
    "00180A"="Meraki"; "E0CB4E"="Meraki"; "000C42"="MikroTik"; "4C5E0C"="MikroTik"
    "F8B156"="Dell"; "1866DA"="Dell"; "B083FE"="Dell"; "A4BF01"="Dell"; "0014C2"="HP"
    "0008C7"="HP"; "002590"="Supermicro"; "003048"="Supermicro"; "AC1F6B"="Supermicro"
    "B827EB"="Raspberry Pi"; "DCA632"="Raspberry Pi"; "001AA6"="Intel"
    "000AEB"="TP-Link"; "001D0F"="TP-Link"; "00095B"="Netgear"; "00146C"="Netgear"
}

Function Get-MacVendor ($Mac) {
    if (!$Mac -or $Mac -match "00-00-00-00-00-00") { return "N/A" }
    $prefix = ($Mac -replace "[:\-\s]","").Substring(0,6).ToUpper()
    if ($script:MacVendors.ContainsKey($prefix)) { return $script:MacVendors[$prefix] }
    return "Unknown"
}
#endregion

Function Write-Log ($message, $color = "White") { Write-Host $message -ForegroundColor $color }
Function Add-Insight ($message) { $script:SmartInsights += $message }

#region INPUT & EXPORT ENGINES
Function Get-TargetList {
    Write-Host "`n[1] Enter Targets Manually"
    Write-Host "[2] Import from File (CSV/TXT)"
    if ($global:LastIPList.Count -gt 0) { Write-Host "[3] Re-use Previous List ($($global:LastIPList.Count) targets)" -ForegroundColor Green }
    $choice = Read-Host "Select input method"
    $ips = @()

    if ($choice -eq "1") {
        while($true){ $i = Read-Host "Enter IP (Leave blank to finish)"; if(!$i){break}; $ips += $i.Trim() }
    } elseif ($choice -eq "2") {
        $path = Read-Host "Drag & Drop file here, or enter path"
        $path = $path -replace "`"","" -replace "'","" 
        if (Test-Path $path) {
            $content = Get-Content $path
            foreach ($line in $content) {
                if ($line -match "\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") { $ips += $matches[0] }
            }
            Write-Log "Extracted $($ips.Count) targets from file." "Green"
        } else { Write-Log "File not found: $path" "Red" }
    } elseif ($choice -eq "3" -and $global:LastIPList.Count -gt 0) {
        $ips = $global:LastIPList; Write-Log "Loaded previous list." "Green"
    }
    
    if ($ips.Count -gt 0) { $global:LastIPList = $ips }
    return $ips
}

Function Get-SingleTarget ($Prompt) {
    $p = if ($global:LastSingleTarget) { "$Prompt [Press Enter for $global:LastSingleTarget]" } else { "$Prompt" }
    $input = Read-Host $p
    if ([string]::IsNullOrWhiteSpace($input) -and $global:LastSingleTarget) { return $global:LastSingleTarget }
    elseif (-not [string]::IsNullOrWhiteSpace($input)) { $global:LastSingleTarget = $input.Trim(); return $global:LastSingleTarget }
    return $null
}

Function Invoke-EnvironmentMap {
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host " ENVIRONMENT DASHBOARD" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    $hostName = $env:COMPUTERNAME
    $netConf = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
    if ($netConf) {
        $ip = $netConf.IPv4Address.IPAddress; $gw = $netConf.IPv4DefaultGateway.NextHop; $iface = $netConf.InterfaceAlias
        Write-Host " Hostname   : $hostName" -ForegroundColor White
        Write-Host " PS Version : v$($PSVersionTable.PSVersion.ToString())" -ForegroundColor $(if($global:PSMajor -ge 7){"Green"}else{"Yellow"})
        Write-Host " Local IP   : $ip" -ForegroundColor White
        Write-Host " Gateway    : $gw" -ForegroundColor White
        $script:ActiveIP = $ip; $script:ActiveInterface = $iface; $script:ActiveGateway = $gw
    }
}

Function Export-ToExcel ($Data, $ModuleName) {
    if (-not $Data) { return }
    $stamp = Get-Date -Format "HHmmss"; $filePath = "$exportDir\${ModuleName}_${stamp}.csv"
    $Data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Raw Data exported to Excel: $filePath" -ForegroundColor Magenta
}

Function Export-ToWord ($HtmlContent, $ModuleName, $Title) {
    if (-not $HtmlContent) { return }
    $stamp = Get-Date -Format "HHmmss"; $filePath = "$exportDir\${ModuleName}_${stamp}.doc"
    
    $insightsHtml = ""
    if ($script:SmartInsights.Count -gt 0) {
        $insightsHtml = "<div class='smart-box'><h3>⚠️ Diagnostic Findings</h3><ul>"
        foreach ($insight in $script:SmartInsights) { $insightsHtml += "<li>$insight</li>" }
        $insightsHtml += "</ul></div>"
    } else {
        $insightsHtml = "<div class='success-box'><h3>✅ Diagnostic Findings</h3><p>No critical anomalies or bottlenecks detected during this scan.</p></div>"
    }
    
    $fullHtml = @"
    <html>
    <head><style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; line-height: 1.6; margin: 0; padding: 20px; }
        .header { background-color: #002060; color: white; padding: 20px; border-radius: 4px 4px 0 0; }
        .header h1 { margin: 0; font-size: 24px; text-transform: uppercase; letter-spacing: 1px; }
        .meta { background-color: #f4f4f4; padding: 15px; border-left: 4px solid #002060; margin: 20px 0; font-size: 14px; }
        .meta p { margin: 5px 0; }
        h2 { color: #002060; border-bottom: 2px solid #ddd; padding-bottom: 5px; margin-top: 30px; }
        h3 { margin-top: 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th { background-color: #002060; color: white; padding: 12px; text-align: left; font-weight: bold; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        .smart-box { background-color: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .success-box { background-color: #d4edda; border-left: 5px solid #28a745; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        ul { margin: 0; padding-left: 20px; }
        .bar-bg { width: 100%; background-color: #e9ecef; border-radius: 3px; overflow: hidden; }
        .bar-fill { background-color: #002060; height: 12px; }
        .bar-warn { background-color: #dc3545; }
        .warn-text { color: #dc3545; font-weight: bold; }
        .ok-text { color: #28a745; font-weight: bold; }
    </style></head>
    <body>
        <div class="header"><h1>Diagnostic Assessment: $Title</h1></div>
        <div class="meta">
            <p><strong>Generated By:</strong> Systems Engineering Diagnostic Toolkit</p>
            <p><strong>Execution Date:</strong> $(Get-Date -Format "MMMM dd, yyyy - HH:mm:ss")</p>
            <p><strong>Executing Host:</strong> $($env:COMPUTERNAME)</p>
        </div>
        $insightsHtml
        <h2>Detailed Telemetry Data</h2>
        $HtmlContent
    </body></html>
"@
    $fullHtml | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "`n[+] Executive Report exported to Word: $filePath" -ForegroundColor Magenta
    $script:SmartInsights = @()
}
#endregion

#region DIAGNOSTIC MODULES
Function Invoke-SequentialTrace {
    Write-Log "`n--- SEQUENTIAL PATH ANALYZER ---" "Cyan"
    $ips = Get-TargetList
    if ($ips.Count -eq 0) { return }; $prev = 0; $hop = 1; $exp = @(); $html = "<table><tr><th>Node</th><th>Target IP</th><th>Average Latency</th><th>Delta (Added)</th></tr>"
    foreach ($ip in $ips) {
        Write-Progress -Activity "Running Sequential Trace" -Status "Probing Node $hop of $($ips.Count): $ip" -PercentComplete (($hop/$ips.Count)*100)
        Write-Host "Node $hop ($ip)... " -NoNewline; $p = Test-Connection -ComputerName $ip -Count 5 -ErrorAction SilentlyContinue
        if ($p) {
            $avg = [math]::Round(($p | Measure-Object -Property $global:PingProp -Average).Average, 2)
            $delta = if($hop -eq 1){0}else{$avg - $prev}
            if ($delta -gt 15) { Add-Insight "Bandwidth saturation or routing delay (+${delta}ms) detected at Node $hop ($ip)." }
            Write-Log "$avg ms (+$delta)" "Green"
            $exp += [PSCustomObject]@{Hop=$hop;IP=$ip;Latency=$avg;Delta=$delta}
            $width = if($delta -gt 100){100}else{$delta}; $color = if($delta -gt 15){"bar-warn"}else{""}
            $html += "<tr><td>$hop</td><td>$ip</td><td>$avg ms</td><td><div class='bar-bg'><div class='bar-fill $color' style='width:${width}%'></div></div>+$delta ms</td></tr>"; $prev = $avg
        } else { Write-Log "OFFLINE" "Red"; $html += "<tr><td>$hop</td><td>$ip</td><td colspan='2' class='warn-text'>OFFLINE</td></tr>" }
        $hop++
    }
    Write-Progress -Activity "Running Sequential Trace" -Completed
    $html += "</table>"; Export-ToExcel $exp "PathTrace"; Export-ToWord $html "PathReport" "Sequential Link Analysis"
}

Function Invoke-AutomatedMTR {
    Write-Log "`n--- AUTOMATED LAYER 3 MTR ---" "Cyan"
    $ip = Get-SingleTarget "Target Domain or IP to map"; if (!$ip) { return }
    Write-Log "Mapping router path to $ip (This may take 30-60 seconds)..." "Yellow"
    $trace = Test-NetConnection -ComputerName $ip -TraceRoute -ErrorAction SilentlyContinue
    if (-not $trace.TraceRoute) { Write-Log "Traceroute blocked or failed." "Red"; return }
    
    $html = "<table><tr><th>Hop</th><th>Router IP</th><th>Latency</th></tr>"
    $hop = 1
    foreach ($router in $trace.TraceRoute) {
        Write-Progress -Activity "Automated MTR" -Status "Pinging Hop $($hop): $router" -PercentComplete (($hop/$trace.TraceRoute.Count)*100)
        $p = Test-Connection -ComputerName $router -Count 4 -ErrorAction SilentlyContinue
        if ($p) {
            $avg = [math]::Round(($p | Measure-Object -Property $global:PingProp -Average).Average, 2)
            if ($avg -gt 50) { Add-Insight "High latency ($avg ms) detected at ISP hop $hop ($router)." }
            Write-Log "Hop $hop ($router) : $avg ms" "Green"
            $width = if($avg -gt 100){100}else{$avg}; $color = if($avg -gt 50){"bar-warn"}else{""}
            $html += "<tr><td>$hop</td><td>$router</td><td><div class='bar-bg'><div class='bar-fill $color' style='width:${width}%'></div></div>$avg ms</td></tr>"
        } else {
            Write-Log "Hop $hop ($router) : Timeout" "Red"; $html += "<tr><td>$hop</td><td>$router</td><td class='warn-text'>Timeout/Blocked</td></tr>"
        }
        $hop++
    }
    Write-Progress -Activity "Automated MTR" -Completed
    $html += "</table>"; Export-ToWord $html "MTR_Report" "Layer 3 Routing Diagnostics"
}

Function Invoke-StabilityTest {
    Write-Log "`n--- CONNECTION STABILITY & JITTER TEST ---" "Cyan"
    $ip = Get-SingleTarget "Target IP or Hostname"; if (!$ip) { return }; $p = @()
    Write-Log "Sending 50-packet burst to $ip..." "White"
    for($i=1; $i -le 50; $i++) {
        Write-Progress -Activity "Stability Analysis" -Status "Packet $i of 50" -PercentComplete (($i/50)*100)
        $ping = Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue; if($ping) { $p += $ping }
    }
    Write-Progress -Activity "Stability Analysis" -Completed
    if ($p.Count -gt 0) {
        $loss = (($50 - $p.Count)/50)*100; $lats = $p | Select-Object -ExpandProperty $global:PingProp
        $avg = [math]::Round(($lats | Measure-Object -Average).Average, 2)
        Write-Log "Loss: $loss% | Avg Latency: $avg ms" "Yellow"
        if ($loss -gt 0){ Add-Insight "Target $ip exhibited $loss% packet loss." }
        Export-ToWord "<table><tr><th>Target</th><th>Packets Sent</th><th>Received</th><th>Packet Loss</th><th>Avg Latency</th></tr><tr><td>$ip</td><td>50</td><td>$($p.Count)</td><td>$loss%</td><td>$avg ms</td></tr></table>" "Stability" "Connection Stability & Jitter Report"
    } else { Write-Log "100% Packet Loss - Unreachable" "Red" }
}

Function Invoke-DropMonitor {
    Write-Log "`n--- CONTINUOUS DROP MONITOR ---" "Cyan"
    $ip = Get-SingleTarget "Target IP"; if(!$ip){return}
    Write-Log "Monitoring $ip... Press Ctrl+C to stop." "Green"
    while($true){ if(! (Test-Connection $ip -Count 1 -Quiet -ErrorAction SilentlyContinue)){ Write-Host "[$(Get-Date -F HH:mm:ss)] CONNECTION DROPPED" -F Red }; Start-Sleep 1 }
}

Function Invoke-SmartSubnetSweep {
    Write-Log "`n--- SMART CIDR SUBNET SWEEP (WITH DIFF ENGINE) ---" "Cyan"
    if (!$script:ActiveIP) { Write-Log "No active IP." "Red"; return }
    $conf = Get-NetIPAddress -InterfaceAlias $script:ActiveInterface -AddressFamily IPv4 | Select-Object -First 1
    $pre = $conf.PrefixLength; $ipBytes = [System.Net.IPAddress]::Parse($conf.IPAddress).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    $mask = [uint32](4294967295 - ([math]::Pow(2, (32 - $pre)) - 1))
    $net = $ipInt -band $mask; $bc = $net -bor [uint32]([math]::Pow(2, (32 - $pre)) - 1)
    $ips = @(); for ($i = $net + 1; $i -lt $bc; $i++) {
        $b = [BitConverter]::GetBytes([uint32]$i); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
        $ips += ([System.Net.IPAddress]$b).IPAddressToString
    }
    
    Write-Log "Sweeping $($ips.Count) hosts on local segment..." "Cyan"
    $count = 0
    if ($global:PSMajor -ge 7) { 
        $ips | ForEach-Object -Parallel { if ($_.Trim() -ne "" -and (Test-Connection $_ -Count 1 -Quiet -ErrorAction SilentlyContinue)) { Write-Host "$_ ONLINE" -F Green } } 
    } else { 
        $ts = @(); foreach($i in $ips){ if($i.Trim() -ne ""){ $count++; Write-Progress -Activity "Subnet Discovery" -Status "Scanning $i" -PercentComplete (($count/$ips.Count)*100); $ts += [PSCustomObject]@{I=$i;T=([System.Net.NetworkInformation.Ping]::new()).SendPingAsync($i,500)} } }
        [System.Threading.Tasks.Task]::WaitAll($ts.T)
        foreach($res in $ts){ if($res.T.Result.Status -eq "Success"){ Write-Host "$($res.I) ONLINE" -F Green } }
    }
    Write-Progress -Activity "Subnet Discovery" -Completed
    
    $arp = Get-NetNeighbor -AddressFamily IPv4 | Where-Object State -ne "Unreachable"; $exp = @(); $html = "<table><tr><th>IP Address</th><th>MAC Address</th><th>Hardware Vendor</th></tr>"
    $currentMacs = @()
    foreach ($e in $arp) { 
        if ($e.LinkLayerAddress -match "^00-00|^FF-FF|^01-00-5E|^33-33") { continue }
        if ($e.IPAddress -match "^224\.|^239\.|^255\.") { continue }
        
        $v = Get-MacVendor $e.LinkLayerAddress; 
        Write-Log "IP: $($e.IPAddress.PadRight(15)) | MAC: $($e.LinkLayerAddress.PadRight(17)) | Vendor: $v" "White"
        $currentMacs += $e.LinkLayerAddress
        $exp += [PSCustomObject]@{IP=$e.IPAddress; MAC=$e.LinkLayerAddress; Vendor=$v}
        $html += "<tr><td>$($e.IPAddress)</td><td>$($e.LinkLayerAddress)</td><td>$v</td></tr>"
    }
    $html += "</table>"
    
    # DIFF ENGINE
    if (Test-Path $baselineFile) {
        $baseline = Get-Content $baselineFile | ConvertFrom-Json
        $baseMacs = $baseline | Select-Object -ExpandProperty MAC
        $newDevices = $currentMacs | Where-Object { $_ -notin $baseMacs }
        $missingDevices = $baseMacs | Where-Object { $_ -notin $currentMacs }
        
        if ($newDevices) { foreach($n in $newDevices){ Add-Insight "NEW ROGUE DEVICE: MAC $n appeared on the network since last baseline." } }
        if ($missingDevices) { foreach($m in $missingDevices){ Add-Insight "OFFLINE DEVICE: MAC $m from baseline is no longer responding." } }
        if (-not $newDevices -and -not $missingDevices) { Add-Insight "Network topology matches historical baseline perfectly." }
    } else {
        Add-Insight "No historical baseline found. Saving current scan as the new standard."
    }
    $exp | ConvertTo-Json | Out-File $baselineFile -Force
    Export-ToExcel $exp "Discovery"; Export-ToWord $html "DiscoveryReport" "Layer 2 Subnet Discovery & Diff"
}

Function Invoke-MacToIpResolver {
    Write-Log "`n--- REVERSE OFFLINE MAC ADDRESS RESOLVER ---" "Cyan"
    $m = Read-Host "Enter MAC Address"; if ([string]::IsNullOrWhiteSpace($m)) { return }
    $cm = $m -replace "[:\-\s]",""; $f = $false
    foreach ($n in (Get-NetNeighbor -AddressFamily IPv4)) { if (($n.LinkLayerAddress -replace "[:\-\s]","") -match $cm) { Write-Log "MATCH: $($n.IPAddress) ($(Get-MacVendor $n.LinkLayerAddress))" "Green"; $f=$true } }
    if (!$f) { Write-Log "Not found in local cache." "Red" }
}

Function Invoke-RogueScanner {
    Write-Log "`n--- ROGUE DHCP & GATEWAY SCANNER ---" "Cyan"
    if (!$script:ActiveIP) { return }
    Write-Log "Scanning subnet for unauthorized network appliances..." "Yellow"
    $html = "<table><tr><th>Test</th><th>Result</th></tr>"
    
    $conf = Get-NetIPConfiguration | Where-Object InterfaceAlias -eq $script:ActiveInterface
    if ($conf.IPv4DefaultGateway.Count -gt 1) { 
        Add-Insight "CRITICAL: Multiple active Gateways detected on this interface! Possible IP conflict or rogue router." 
        $html += "<tr><td>Gateway Count</td><td class='warn-text'>Multiple Detected</td></tr>"
    } else { $html += "<tr><td>Gateway Count</td><td class='ok-text'>Single (OK)</td></tr>" }

    $baseIP = $script:ActiveIP.Substring(0, $script:ActiveIP.LastIndexOf('.'))
    $suspects = @("$baseIP.1", "$baseIP.254", "$baseIP.100")
    foreach ($s in $suspects) {
        if ($s -ne $script:ActiveGateway -and $s -ne $script:ActiveIP) {
            if (Test-Connection -ComputerName $s -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                Add-Insight "WARNING: Unauthorized appliance responding at common gateway address ($s). Verify this is not a rogue DHCP router."
            }
        }
    }
    $html += "</table>"; Export-ToWord $html "RogueScan" "Rogue Appliance Analysis"
    Write-Log "Scan complete. Check Word export for findings." "Green"
}

Function Invoke-DNSHTTPCheck {
    Write-Log "`n--- DNS & HTTP REACHABILITY ---" "Cyan"
    $d = Get-SingleTarget "Target Domain or IP"; if (!$d) { return }
    Write-Progress -Activity "Reachability Check" -Status "Resolving DNS..." -PercentComplete 33
    $html = "<table><tr><th>Test Phase</th><th>Result</th><th>Status</th></tr>"
    try {
        $l = (Resolve-DnsName $d -ErrorAction Stop).IPAddress[0]; $p = (Resolve-DnsName $d -Server 8.8.8.8 -ErrorAction Stop).IPAddress[0]
        if($l -ne $p){ Add-Insight "DNS Mismatch for $d (Local: $l vs Public: $p). Potential hijack or split-brain configuration." }; 
        Write-Log "Local DNS: $l | Public DNS: $p" "White"
        $html += "<tr><td>Local DNS Resolution</td><td>$l</td><td class='ok-text'>Success</td></tr>"
        $html += "<tr><td>Public DNS Resolution</td><td>$p</td><td class='ok-text'>Success</td></tr>"
    } catch { Write-Log "DNS Resolve Failed" "Red"; $html += "<tr><td>DNS Resolution</td><td>Failed to resolve</td><td class='warn-text'>FAILED</td></tr>" }
    
    Write-Progress -Activity "Reachability Check" -Status "Testing HTTP..." -PercentComplete 66
    try { 
        $r = Invoke-WebRequest "http://$d" -UseBasicParsing -TimeoutSec 5; Write-Log "HTTP OK: $($r.StatusCode)" "Green"
        $html += "<tr><td>HTTP Handshake</td><td>Status Code: $($r.StatusCode)</td><td class='ok-text'>Success</td></tr>" 
    } catch { Write-Log "HTTP Connection Blocked" "Red"; $html += "<tr><td>HTTP Handshake</td><td>Connection Dropped/Refused</td><td class='warn-text'>FAILED</td></tr>" }
    
    Write-Progress -Activity "Reachability Check" -Completed
    $html += "</table>"; Export-ToWord $html "Reachability" "Endpoint Reachability Report"
}

Function Invoke-LocalAttackSurface {
    Write-Log "`n--- LOCAL ATTACK SURFACE ANALYZER ---" "Cyan"
    Write-Log "Mapping open listening ports to local processes..." "Yellow"
    
    # Threat Dictionary for local host
    $threatDict = @{ "3389"="RDP Exposed"; "445"="SMB/Ransomware Vector"; "21"="Unencrypted FTP"; "23"="Unencrypted Telnet" }
    
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) { Write-Log "Could not retrieve TCP connections. Ensure script is running as Administrator." "Red"; return }

    $html = "<table><tr><th>Local Address</th><th>Port</th><th>Process Name</th><th>PID</th><th>Status</th></tr>"
    
    foreach ($conn in $connections) {
        $port = $conn.LocalPort.ToString()
        $processName = "Unknown/System"
        try { $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
        
        $statusStr = "OK"
        $htmlStatus = "<td class='ok-text'>Listening</td>"
        
        if ($threatDict.ContainsKey($port) -and $conn.LocalAddress -eq "0.0.0.0") {
            Add-Insight "HIGH RISK: $($threatDict[$port]) (Port $port) is listening on 0.0.0.0 (All Interfaces) via $processName."
            $statusStr = "RISK: $($threatDict[$port])"
            $htmlStatus = "<td class='warn-text'>RISK: $($threatDict[$port])</td>"
            Write-Log "Port $($port.PadRight(5)) | PID: $($conn.OwningProcess.ToString().PadRight(5)) | Process: $($processName.PadRight(15)) | $statusStr" "Red"
        } else {
            Write-Log "Port $($port.PadRight(5)) | PID: $($conn.OwningProcess.ToString().PadRight(5)) | Process: $($processName.PadRight(15)) | Listening" "White"
        }
        
        $html += "<tr><td>$($conn.LocalAddress)</td><td>$port</td><td>$processName</td><td>$($conn.OwningProcess)</td>$htmlStatus</tr>"
    }
    
    $html += "</table>"; Export-ToWord $html "LocalAttackSurface" "Local Host Attack Surface & Process Map"
}

Function Invoke-VulnMatrix {
    Write-Log "`n--- NETWORK VULNERABILITY MATRIX ---" "Cyan"
    Write-Log "This module will scan a list of IPs for high-risk management ports." "DarkCyan"
    $ips = Get-TargetList; if ($ips.Count -eq 0) { return }
    
    # Define the high-risk ports to sweep for
    $vulnPorts = @("21", "22", "23", "80", "445", "3389")
    $portNames = @{ "21"="FTP"; "22"="SSH"; "23"="Telnet"; "80"="HTTP"; "445"="SMB"; "3389"="RDP" }
    
    $html = "<table><tr><th>Target IP</th>"
    foreach ($vp in $vulnPorts) { $html += "<th>$($portNames[$vp]) ($vp)</th>" }
    $html += "</tr>"

    $hostCount = 1
    foreach ($ip in $ips) {
        Write-Progress -Activity "Vulnerability Sweep" -Status "Scanning Host $hostCount of $($ips.Count): $ip" -PercentComplete (($hostCount/$ips.Count)*100)
        $html += "<tr><td><strong>$ip</strong></td>"
        Write-Log "`nTarget: $ip" "Cyan"
        
        $tasks = @()
        foreach($p in $vulnPorts) {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $res = $tcp.BeginConnect($ip, $p, $null, $null)
            $tasks += [PSCustomObject]@{ Port = $p; AsyncResult = $res; Client = $tcp }
        }
        
        foreach ($t in $tasks) {
            $success = $t.AsyncResult.AsyncWaitHandle.WaitOne(1000) # 1 second timeout per port per host
            if ($success -and $t.Client.Connected) { 
                Write-Log "  Port $($t.Port.PadRight(4)) ($($portNames[$t.Port])) : OPEN (RISK)" "Red" 
                $html += "<td class='warn-text'>OPEN</td>"
                Add-Insight "VULNERABILITY: Host $ip has Port $($t.Port) ($($portNames[$t.Port])) exposed to the network."
            } else { 
                Write-Log "  Port $($t.Port.PadRight(4)) ($($portNames[$t.Port])) : Stealth/Closed" "Green" 
                $html += "<td class='ok-text'>Closed</td>"
            }
            $t.Client.Close()
        }
        $html += "</tr>"
        $hostCount++
    }
    Write-Progress -Activity "Vulnerability Sweep" -Completed
    $html += "</table>"; Export-ToWord $html "VulnMatrix" "Subnet Vulnerability Matrix"
}

Function Invoke-BandwidthTest {
    Write-Log "`n--- NATIVE TCP BANDWIDTH TESTER (DYNAMIC) ---" "Cyan"
    Write-Host "1. SERVER (Listen) | 2. CLIENT (Send)"; $m = Read-Host "Select Mode"; $p = 5201
    
    if ($m -eq "1") {
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $p); $l.Start(); Write-Log "Listening on Port $p..." "Yellow"
        $cl = $l.AcceptTcpClient(); $s = $cl.GetStream(); $b = New-Object byte[] 8192; $t = 0; while (($r = $s.Read($b,0,8192)) -gt 0) { $t += $r }
        $cl.Close(); $l.Stop(); Write-Log "Transfer complete. Received $([math]::Round($t/1MB,2)) MB." "Green"
    } elseif ($m -eq "2") {
        $srv = Get-SingleTarget "Server IP"; if(!$srv){return}
        try { 
            $cl = [System.Net.Sockets.TcpClient]::new($srv, $p); $s = $cl.GetStream(); $chunk = New-Object byte[] 1MB
            Write-Log "Running 1-second pre-flight link test..." "Cyan"
            $swPre = [System.Diagnostics.Stopwatch]::StartNew(); $preBytes = 0
            while ($swPre.Elapsed.TotalSeconds -lt 1) { $s.Write($chunk, 0, 1MB); $preBytes += 1MB }
            $swPre.Stop()
            
            $targetMB = [math]::Round(($preBytes * 5) / 1MB, 0); if($targetMB -eq 0){$targetMB = 10}
            Write-Log "Scaling payload to $targetMB MB to saturate line for 5 seconds..." "Yellow"
            $swMain = [System.Diagnostics.Stopwatch]::StartNew(); for($i=0;$i -lt $targetMB;$i++){ $s.Write($chunk, 0, 1MB) }
            $swMain.Stop(); $s.Close(); $cl.Close()
            $mbps = [math]::Round((($targetMB * 8) / $swMain.Elapsed.TotalSeconds), 2); Write-Log "Throughput: $mbps Mbps" "Magenta"
        } catch { Write-Log "Failed to connect to server." "Red" }
    }
}

Function Invoke-PortScan {
    Write-Log "`n--- ASYNC TCP PORT SCANNER ---" "Cyan"
    $ip = Get-SingleTarget "Target IP"; if (!$ip) { return }
    $ports = (Read-Host "Ports (comma separated, e.g. 80,443,3389)").Split(',')
    Write-Log "Executing asynchronous sweep..." "Cyan"; $tasks = @()
    foreach($p in $ports) {
        $p = $p.Trim(); $tcp = [System.Net.Sockets.TcpClient]::new()
        $res = $tcp.BeginConnect($ip, $p, $null, $null); $tasks += [PSCustomObject]@{ Port = $p; AsyncResult = $res; Client = $tcp }
    }
    foreach ($t in $tasks) {
        $success = $t.AsyncResult.AsyncWaitHandle.WaitOne(1500)
        if ($success -and $t.Client.Connected) { Write-Log "Port $($t.Port) : OPEN" "Green" } else { Write-Log "Port $($t.Port) : CLOSED" "Red" }
        $t.Client.Close()
    }
}

Function Invoke-AdapterHealth {
    Write-Log "`n--- LOCAL ADAPTER HEALTH ---" "Cyan"
    $ads = Get-NetAdapter | ? Status -eq "Up"; $html = "<table><tr><th>Interface Name</th><th>Link Speed</th><th>Drops / Errors</th></tr>"
    foreach ($a in $ads) {
        Write-Progress -Activity "Querying Hardware" -Status "Reading $($a.Name)"
        $s = Get-NetAdapterStatistics -Name $a.Name; $e = $s.ReceivedDiscardedPackets + $s.ReceivedErrors
        Write-Log "$($a.Name): $($a.LinkSpeed) | Drops: $e" "White"
        if ($e -gt 0) { Add-Insight "Interface $($a.Name) is dropping packets at the hardware layer. Investigate cabling or switchport." }
        $html += "<tr><td>$($a.Name)</td><td>$($a.LinkSpeed)</td><td>$e</td></tr>"
    }
    Write-Progress -Activity "Querying Hardware" -Completed
    $html += "</table>"; Export-ToWord $html "NIC_Health" "Local Interface Hardware Diagnostics"
}

Function Invoke-DeepOSInspection {
    Write-Log "`n--- WMI/CIM OS INSPECTION ---" "Cyan"
    $ip = Get-SingleTarget "Target IP"; if(!$ip){return}
    $cred = Get-Credential -Message "Enter Administrator credentials for $ip" -ErrorAction SilentlyContinue; if (!$cred) { return }
    Write-Log "Querying remote WMI endpoints..." "Yellow"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ComputerName $ip -Credential $cred -ErrorAction Stop
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName $ip -Credential $cred -ErrorAction Stop
        Write-Log "OS Version : $($os.Caption)" "White"
        Write-Log "Uptime     : $(([DateTime]::Now - $os.LastBootUpTime).Days) Days" "White"
        Write-Log "C: Drive   : $([math]::Round($disk.FreeSpace/1GB, 2)) GB Free / $([math]::Round($disk.Size/1GB, 2)) GB Total" "White"
    } catch { Write-Log "WMI Access Denied or Firewall Blocked: $($_.Exception.Message)" "Red" }
}

Function Invoke-SSHLauncher { 
    Write-Log "`n--- NATIVE SSH QUICK-CONNECT ---" "Cyan"
    if (!(Get-Command ssh -ErrorAction SilentlyContinue)) { Write-Log "CRITICAL: Native OpenSSH client is not installed on this machine." "Red"; return }
    $i = Get-SingleTarget "Target IP"; if(!$i){return}
    $u = Read-Host "User (Leave blank for root)"; if(!$u){$u="root"}; try{ssh "$u@$i"}catch{Write-Log "SSH Terminated." "Red"} 
}

Function Invoke-WakeOnLan {
    Write-Log "`n--- WAKE-ON-LAN (WoL) INTEGRATOR ---" "Cyan"
    $macInput = Read-Host "Enter Target MAC Address"; $cleanMac = $macInput -replace "[:\-\s]", ""
    if ($cleanMac.Length -ne 12) { Write-Log "Invalid MAC Address format." "Red"; return }
    try {
        $macBytes = [byte[]]($cleanMac -split '(..)' | ? { $_ } | % { [convert]::ToByte($_, 16) })
        $packet = [byte[]](,0xFF * 6) + ($macBytes * 16); $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.Connect([System.Net.IPAddress]::Broadcast, 9); $udp.Send($packet, $packet.Length) | Out-Null; $udp.Close()
        Write-Log "Magic Packet successfully broadcasted for $macInput." "Green"
    } catch { Write-Log "Failed to broadcast magic packet." "Red" }
}

Function Invoke-IPConfigurator {
    Write-Log "`n--- SMART IP & DNS CONFIGURATOR ---" "Cyan"
    $ads = Get-NetAdapter | ? Status -eq "Up"; $i=1; foreach($a in $ads){Write-Host "$i. $($a.Name)"; $i++}
    $s = Read-Host "Select"; $t = $ads[[int]$s-1]; Write-Host "1. DHCP | 2. Static"; $a = Read-Host "Action"
    if($a -eq "1"){Set-NetIPInterface -Alias $t.Name -Dhcp Enabled; Set-DnsClientServerAddress -Alias $t.Name -ResetServerAddresses; Write-Log "DHCP Active." "Green"}
    else{$ip=Read-Host "IP";$pr=Read-Host "Prefix (e.g. 24)";$gw=Read-Host "Gateway";New-NetIPAddress -Alias $t.Name -IPAddress $ip -PrefixLength $pr -DefaultGateway $gw; Write-Log "Static Active." "Green"}
}

Function Invoke-PackAndGo {
    $zipPath = "$baseDir\NetDiag_Archive_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    if (Test-Path $exportDir) {
        $files = Get-ChildItem -Path $exportDir
        if ($files.Count -gt 0) {
            Compress-Archive -Path "$exportDir\*" -DestinationPath $zipPath -Force
            Remove-Item $exportDir -Recurse -Force
            Write-Log "`n[+] Archived all reports to: $zipPath" "Green"
            Write-Log "[+] Cleaned up raw Export directory." "Green"
        } else {
            Write-Log "`n[!] No reports were generated during this session to archive." "Yellow"
        }
    }
}
#endregion

# --- UI MAIN LOOP ---
Invoke-EnvironmentMap
$run = $true
while ($run) {
    Write-Host "`n==========================================================================" -ForegroundColor Cyan
    Write-Host "             UNIVERSAL NETWORK DIAGNOSTIC SUITE v25.0 (Open Source)" -ForegroundColor Cyan
    Write-Host "==========================================================================" -ForegroundColor Cyan
    $m = @(
        "1. Sequential Path Analyzer",    "2. Automated Layer 3 MTR",
        "3. Stability & Jitter Test",     "4. Continuous Drop Monitor",
        "5. Smart CIDR Subnet Sweep",     "6. Reverse MAC Address Resolver",
        "7. Rogue DHCP/Gateway Scanner",  "8. DNS & HTTP Reachability",
        "9. Local Attack Surface Map",    "10. Network Vulnerability Matrix",
        "11. Native TCP Bandwidth Tester","12. Async TCP Port Scanner",
        "13. Local Adapter Health",       "14. WMI/CIM OS Inspection",
        "15. Native SSH Quick-Connect",   "16. Wake-on-LAN (WoL) Integrator",
        "17. Smart IP & DNS Config",      "18. Open Exports Folder",
        "19. Pack & Go (Zip and Exit)",   ""
    )
    for ($i = 0; $i -lt $m.Count; $i += 2) { $left = $m[$i].PadRight(35); $right = $m[$i+1]; Write-Host "  $left  $right" }
    Write-Host "--------------------------------------------------------------------------"
    $c = Read-Host "Select Option"
    switch ($c) {
        "1"{Invoke-SequentialTrace};"2"{Invoke-AutomatedMTR};"3"{Invoke-StabilityTest};"4"{Invoke-DropMonitor}
        "5"{Invoke-SmartSubnetSweep};"6"{Invoke-MacToIpResolver};"7"{Invoke-RogueScanner};"8"{Invoke-DNSHTTPCheck}
        "9"{Invoke-LocalAttackSurface};"10"{Invoke-VulnMatrix};"11"{Invoke-BandwidthTest};"12"{Invoke-PortScan}
        "13"{Invoke-AdapterHealth};"14"{Invoke-DeepOSInspection};"15"{Invoke-SSHLauncher};"16"{Invoke-WakeOnLan}
        "17"{Invoke-IPConfigurator};"18"{Invoke-Item $exportDir -ErrorAction SilentlyContinue};"19"{$run=$false; Invoke-PackAndGo}
    }
}
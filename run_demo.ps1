$ErrorActionPreference = "Stop"
Push-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
try {
    $Build = "build"
    if (-not (Test-Path "$Build/mini_wireshark.exe")) {
        & .\build_all.ps1
    }

    Write-Host "Starting Mini-Wireshark GUI..."
    Start-Process -FilePath "$Build\mini_wireshark.exe"

    Start-Sleep -Milliseconds 600
    Write-Host "Starting Upstream Authoritative DNS (port 9153)..."
    $up = Start-Process -FilePath "$Build\dns_server.exe" -ArgumentList "--port 9153 --zones config/upstream_zones.conf --server-ip 8.8.8.8" -PassThru

    Write-Host "Starting Local Caching/Forwarding DNS (port 9053)..."
    $loc = Start-Process -FilePath "$Build\dns_server.exe" -ArgumentList "--port 9053 --zones config/local_zones.conf --upstream 127.0.0.1 --upstream-port 9153" -PassThru

    Write-Host "Starting BOOTP Server (port 9067)..."
    $bootp = Start-Process -FilePath "$Build\bootp_server.exe" -ArgumentList "--port 9067 --dns 192.168.10.2" -PassThru

    Start-Sleep -Milliseconds 500
    Write-Host "Running Zero-Config Bootstrapped Node Client (BOOTP -> DNS)..."
    & ".\$Build\node_client.exe"

    Write-Host "`nDemo sequence finished! Inspect packets in Mini-Wireshark."
    Read-Host "Press Enter to stop background servers"
    Stop-Process -Id $bootp.Id, $loc.Id, $up.Id -ErrorAction SilentlyContinue
} finally {
    Pop-Location
}


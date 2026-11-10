$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    $BuildDir = "build"
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

    $Flags = @("-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-Iinclude")

    $ConsoleTargets = @(
        "phase1_test",
        "phase2_test",
        "phase3_test",
        "phase4_test",
        "bootp_server_main:bootp_server",
        "bootp_relay_main:bootp_relay",
        "bootp_client_main:bootp_client",
        "dns_server_main:dns_server",
        "dns_client_main:dns_client",
        "node_client_main:node_client",
        "sniffer_cli_main:sniffer_cli"
    )

    foreach ($entry in $ConsoleTargets) {
        $parts = $entry.Split(":")
        $srcName = $parts[0]
        $outName = if ($parts.Length -gt 1) { $parts[1] } else { $parts[0] }
        Write-Host "Building $outName.exe..."
        & g++ @Flags "src/$srcName.cpp" -o "$BuildDir/$outName.exe" -lws2_32
        if ($LASTEXITCODE -ne 0) { throw "Build failed for $outName.exe" }
    }

    Write-Host "Building mini_wireshark.exe..."
    & g++ @Flags -mwindows "src/mini_wireshark_main.cpp" -o "$BuildDir/mini_wireshark.exe" -lws2_32 -lcomctl32 -lcomdlg32 -lgdi32
    if ($LASTEXITCODE -ne 0) { throw "Build failed for mini_wireshark.exe" }

    Write-Host "`nAll 12 targets built successfully in group_project/$BuildDir"
} finally {
    Pop-Location
}

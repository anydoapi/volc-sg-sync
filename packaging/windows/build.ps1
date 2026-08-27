param(
    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$out = Join-Path $root $OutputDir
New-Item -ItemType Directory -Force -Path $out | Out-Null

$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
Push-Location $root
try {
    $webui = Join-Path $root "webui"
    if (Test-Path (Join-Path $webui "package.json")) {
        Write-Host "Building React Web UI..."
        Push-Location $webui
        try {
            if (-not (Test-Path (Join-Path $webui "node_modules"))) { npm install --no-audit --no-fund }
            npm run build
        } finally { Pop-Location }
        $webOut = Join-Path $out "webui"
        New-Item -ItemType Directory -Force -Path $webOut | Out-Null
        Copy-Item (Join-Path $webui "dist\*") $webOut -Recurse -Force
    }
    go build -trimpath -ldflags "-s -w" -o (Join-Path $out "volc-sg-sync.exe") .
    Copy-Item (Join-Path $root "config.example.yaml") (Join-Path $out "config.example.yaml") -Force
} finally {
    Pop-Location
}

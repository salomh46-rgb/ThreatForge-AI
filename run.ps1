# ThreatForge AI - 1-Click Startup Script
$Host.UI.RawUI.WindowTitle = "ThreatForge AI Engine"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " 🛡️ ThreatForge AI - Cloud Architecture Security Engine" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Clean conflicting ports 8000 and 5173
Write-Host "[1/4] Checking and clearing ports 8000 & 5173..." -ForegroundColor Yellow
@(8000, 5173) | ForEach-Object {
    $port = $_
    $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connections) {
        $connections | ForEach-Object {
            $pidToKill = $_.OwningProcess
            if ($pidToKill -gt 0) {
                Write-Host "Terminating process PID $pidToKill using port $port..." -ForegroundColor Yellow
                Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# 2. Start Backend
Write-Host "[2/4] Starting FastAPI backend on http://localhost:8000..." -ForegroundColor Green
$backendProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "cd 'D:\ALLProjects\threatforge-ai\backend'; .\.venv\Scripts\activate; uvicorn app.main:app --reload --port 8000" -PassThru

# 3. Start Frontend
Write-Host "[3/4] Starting Vite React frontend on http://localhost:5173..." -ForegroundColor Green
$frontendProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "cd 'D:\ALLProjects\threatforge-ai\frontend'; npm run dev" -PassThru

# 4. Wait and Open Browser
Write-Host "[4/4] Opening ThreatForge AI in browser..." -ForegroundColor Cyan
Start-Sleep -Seconds 3
Start-Process "http://localhost:5173"

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  ✅ ThreatForge AI is LIVE!" -ForegroundColor Green
Write-Host "  - Frontend: http://localhost:5173" -ForegroundColor White
Write-Host "  - Backend API: http://localhost:8000" -ForegroundColor White
Write-Host "  - API Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green

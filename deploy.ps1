<#
.SYNOPSIS
    Развёртывание сервиса «Генератор моделей угроз ФСТЭК» на рабочем ПК.

.DESCRIPTION
    Вызывается CI/CD-пайплайном (GitHub Actions, self-hosted раннер)
    после успешного CI. Скрипт:

      1. регистрирует/обновляет задачу планировщика «ThreatModeler»,
         которая запускает threat-modeler\start.ps1 при входе в систему
         (сервис переживает перезагрузку и не зависит от раннера);
      2. останавливает текущий экземпляр сервиса (по задаче и по порту);
      3. запускает задачу заново — стартует свежая версия кода;
      4. ждёт ответ /health (до 120 секунд) и завершает работу
         с кодом 0 только при успешном ответе.

.PARAMETER TaskName
    Имя задачи планировщика. По умолчанию «ThreatModeler».

.PARAMETER Port
    Порт сервиса для проверки /health. По умолчанию 8080.

.EXAMPLE
    .\deploy.ps1
    .\deploy.ps1 -Port 8080
#>

param(
    [string]$TaskName = "ThreatModeler",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartScript = Join-Path $Root "threat-modeler\start.ps1"

if (-not (Test-Path $StartScript)) {
    Write-Error "Не найден $StartScript — скрипт должен лежать в корне репозитория"
    exit 1
}

# --- 1. Задача планировщика: сервис стартует при входе в систему ------------
# Если раннер работает под SYSTEM (служба), берём вошедшего в систему
# пользователя интерактивной сессии; иначе — текущего пользователя.
$interactiveUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
if (-not $interactiveUser) { $interactiveUser = "$env:USERDOMAIN\$env:USERNAME" }

Write-Host "[DEPLOY] Регистрирую задачу '$TaskName' для пользователя $interactiveUser..." -ForegroundColor Cyan

$argument = "-NoProfile -ExecutionPolicy Bypass -File `"$StartScript`""
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $interactiveUser

Register-ScheduledTask -TaskName $TaskName `
    -Action $action -Trigger $trigger `
    -User $interactiveUser `
    -Description "Сервис модели угроз ФСТЭК (uvicorn 0.0.0.0:$Port)" `
    -Force | Out-Null

# --- 2. Остановка старого экземпляра ----------------------------------------
Write-Host "[DEPLOY] Останавливаю старый экземпляр..." -ForegroundColor Cyan
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Подстраховка: процесс, который держит порт, но остался от прошлого запуска
Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object {
        Write-Host "[DEPLOY] Останавливаю процесс $_, державший порт $Port"
        Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
    }
Start-Sleep -Seconds 1

# --- 3. Запуск свежей версии ------------------------------------------------
Write-Host "[DEPLOY] Запускаю задачу '$TaskName'..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $TaskName

# --- 4. Ожидание /health ----------------------------------------------------
Write-Host "[DEPLOY] Жду ответ /health (до 120 секунд)..." -ForegroundColor Cyan
$ok = $false
for ($i = 1; $i -le 60; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" `
            -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -eq 200) {
            $ok = $true
            Write-Host "[OK] Сервис отвечает: $($resp.Content)" -ForegroundColor Green
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $ok) {
    Write-Error "Сервис не ответил на /health за 120 секунд — проверьте задачу '$TaskName'"
    exit 1
}

Write-Host "[DEPLOY] Развёртывание завершено. Сервис доступен на 0.0.0.0:$Port" -ForegroundColor Green
exit 0

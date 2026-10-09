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
      4. ждёт ответ /health (до 150 секунд, при необходимости — одна
         повторная попытка запуска) и завершает работу с кодом 0 только
         при успешном ответе.

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

# Настройки по умолчанию планировщика не годятся для сервера:
#   * DisallowStartIfOnBatteries/StopIfGoingOnBatteries — задача не стартует
#     на ноутбуке от батареи (вечное «Queued»);
#   * IdleSettings.StopOnIdleEnd — сервис выключался бы при простое;
#   * ExecutionTimeLimit по умолчанию 72 часа — сервис убивался бы через 3 суток.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName `
    -Action $action -Trigger $trigger -Settings $settings `
    -User $interactiveUser `
    -Description "Сервис модели угроз ФСТЭК (uvicorn 0.0.0.0:$Port)" `
    -Force | Out-Null

# --- 2. Остановка старого экземпляра ----------------------------------------
function Stop-ServiceInstance {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    # Подстраховка: процесс, который держит порт, но остался от прошлого запуска
    Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique |
        ForEach-Object {
            Write-Host "[DEPLOY] Останавливаю процесс $_, державший порт $Port"
            Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
        }

    # Пока планировщик считает старый запуск активным, новый остаётся в очереди
    # (Queued) и не стартует — дожидаемся освобождения экземпляра задачи.
    for ($i = 1; $i -le 15; $i++) {
        if ((Get-ScheduledTask -TaskName $TaskName).State -ne "Running") { break }
        Start-Sleep -Seconds 1
    }
}

function Wait-Health {
    param([int]$Seconds = 150)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" `
                -UseBasicParsing -TimeoutSec 3
            if ($resp.StatusCode -eq 200) { return $resp.Content }
        } catch { }
        Start-Sleep -Seconds 2
    }
    return $null
}

Write-Host "[DEPLOY] Останавливаю старый экземпляр..." -ForegroundColor Cyan
Stop-ServiceInstance

# --- 3. Запуск свежей версии ------------------------------------------------
Write-Host "[DEPLOY] Запускаю задачу '$TaskName'..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $TaskName

# --- 4. Ожидание /health ----------------------------------------------------
Write-Host "[DEPLOY] Жду ответ /health (до 150 секунд)..." -ForegroundColor Cyan
$health = Wait-Health -Seconds 150

if (-not $health) {
    # Планировщик изредка не поднимает экземпляр с первого раза — пробуем ещё раз
    Write-Host "[DEPLOY] Первый запуск не ответил — повторяю..." -ForegroundColor Yellow
    Stop-ServiceInstance
    Start-ScheduledTask -TaskName $TaskName
    $health = Wait-Health -Seconds 90
}

if (-not $health) {
    Write-Error "Сервис не ответил на /health — проверьте задачу '$TaskName'"
    exit 1
}

Write-Host "[OK] Сервис отвечает: $health" -ForegroundColor Green
Write-Host "[DEPLOY] Развёртывание завершено. Сервис доступен на 0.0.0.0:$Port" -ForegroundColor Green
exit 0

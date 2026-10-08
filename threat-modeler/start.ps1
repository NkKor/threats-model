<#
.SYNOPSIS
    Запуск сервиса «Генератор моделей угроз ФСТЭК» в обычном Python-окружении.

.DESCRIPTION
    Скрипт выполняет:
      1. поиск Python 3.11+ (py -3 либо python);
      2. создание виртуального окружения .venv, если его нет, и установку
         зависимостей из requirements.txt;
      3. инициализацию базы данных (справочники и корпус УБИ);
      4. запуск uvicorn на 0.0.0.0:<порт> — сервис доступен коллегам
         из локальной сети по адресу http://<ваш-IP>:<порт>.

.PARAMETER Port
    Порт сервиса. По умолчанию 8080.

.PARAMETER RebuildVenv
    Пересоздать .venv и переустановить зависимости.

.EXAMPLE
    .\start.ps1
    .\start.ps1 -Port 8080
    .\start.ps1 -RebuildVenv
#>

param(
    [int]$Port = 8080,
    [switch]$RebuildVenv
)

$ErrorActionPreference = "Stop"

# --- 1. Рабочий каталог и Python -------------------------------------------
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Find-Python311 {
    # Возвращает массив-аргументы для запуска Python 3.11+ либо $null.
    $variants = @(
        , @("py", "-3"),
        , @("python")
    )
    foreach ($variant in $variants) {
        $exe = $variant[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $prefix = @()
        if ($variant.Count -gt 1) { $prefix = $variant[1..($variant.Count - 1)] }
        try {
            $code = "import sys; print('%d.%d' % sys.version_info[:2])"
            $ver = & $exe @prefix -c $code 2>$null
            if ($LASTEXITCODE -eq 0 -and $ver -and [version]("$ver") -ge [version]"3.11") {
                return ($variant)
            }
        } catch { }
    }
    return $null
}

$pyVariant = Find-Python311
if (-not $pyVariant) {
    Write-Error "Python 3.11+ не найден. Установите Python с python.org и повторите запуск."
    exit 1
}
$pyName = $pyVariant[0]
$pyPrefix = @()
if ($pyVariant.Count -gt 1) { $pyPrefix = $pyVariant[1..($pyVariant.Count - 1)] }
Write-Host ("[START] Python: " + (& $pyName @pyPrefix -V)) -ForegroundColor Cyan

# --- 2. Виртуальное окружение и зависимости --------------------------------
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if ($RebuildVenv -and (Test-Path (Join-Path $Root ".venv"))) {
    Write-Host "[SETUP] Удаляю старое окружение .venv..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force (Join-Path $Root ".venv")
}
if (-not (Test-Path $VenvPython)) {
    Write-Host "[SETUP] Создаю виртуальное окружение .venv..." -ForegroundColor Yellow
    & $pyName @pyPrefix -m venv .venv
    if ($LASTEXITCODE -ne 0) { Write-Error "Не удалось создать .venv"; exit 1 }
}
Write-Host "[SETUP] Проверяю зависимости..." -ForegroundColor Yellow
& $VenvPython -m pip install --disable-pip-version-check -q -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Error "Не удалось установить зависимости"; exit 1 }

# --- 3. Окружение приложения (.env необязателен: есть настройки по умолчанию)
if (-not (Test-Path (Join-Path $Root ".env")) -and (Test-Path (Join-Path $Root ".env.example"))) {
    Copy-Item (Join-Path $Root ".env.example") (Join-Path $Root ".env")
    Write-Host "[SETUP] Создан .env из .env.example (при необходимости задайте SESSION_SECRET)" -ForegroundColor Yellow
}

# --- 4. База данных: схема и данные -----------------------------------------
& $VenvPython -m app.db.init
if ($LASTEXITCODE -ne 0) { Write-Error "Инициализация БД не удалась"; exit 1 }

# --- 5. Адреса для коллег из локальной сети ---------------------------------
$lanIps = @()
if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
    $lanIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
        Select-Object -ExpandProperty IPAddress)
}

Write-Host ""
Write-Host ("[START] Запуск сервиса на 0.0.0.0:" + $Port) -ForegroundColor Green
Write-Host ("        Локально:      http://127.0.0.1:" + $Port)
foreach ($ip in $lanIps) {
    Write-Host ("        В локальной сети: http://" + $ip + ":" + $Port)
}
Write-Host ("        Swagger:       http://127.0.0.1:" + $Port + "/docs")
Write-Host ("        Health:        http://127.0.0.1:" + $Port + "/health")
if ($lanIps.Count -gt 0) {
    Write-Host ""
    Write-Host "        Если коллеги не открывают страницу, разрешите входящие" -ForegroundColor Yellow
    Write-Host ("        подключения к порту " + $Port + " (от имени администратора):") -ForegroundColor Yellow
    Write-Host ("        netsh advfirewall firewall add rule name=`"Threat Modeler " + $Port + "`" dir=in action=allow protocol=TCP localport=" + $Port) -ForegroundColor Yellow
}
Write-Host "        Остановка: Ctrl+C" -ForegroundColor Gray
Write-Host ""

# --- 6. Запуск ---------------------------------------------------------------
& $VenvPython -m uvicorn app.main:app --host 0.0.0.0 --port $Port

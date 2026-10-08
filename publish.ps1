<#
.SYNOPSIS
    Быстрая выкладка изменений в GitHub: add → commit → push одной командой.

.DESCRIPTION
    Скрипт добавляет все изменённые файлы, создаёт коммит с сообщением
    и выгружает в origin/main. После push CI на GitHub автоматически
    прогонит тесты и HTTP-смоук (смотреть: вкладка Actions в репозитории).

.PARAMETER Message
    Сообщение коммита. Если не указано — генерируется из текущей даты.

.PARAMETER Pull
    Сначала выполнить git pull --rebase (обновиться перед выкладкой).

.EXAMPLE
    .\publish.ps1 -Message "Исправил форму шага 2"
    .\publish.ps1 -Pull
#>

param(
    [string]$Message = "",
    [switch]$Pull
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# --- Что изменилось? --------------------------------------------------------
$changed = git status --porcelain
if (-not $changed) {
    Write-Host "[GIT] Изменений нет — выкладывать нечего." -ForegroundColor Yellow
    exit 0
}

# --- Опциональное обновление ------------------------------------------------
if ($Pull) {
    Write-Host "[GIT] git pull --rebase..." -ForegroundColor Cyan
    git pull --rebase origin main
    if ($LASTEXITCODE -ne 0) { Write-Error "pull --rebase не удался; разрешите конфликты и повторите"; exit 1 }
}

# --- add --------------------------------------------------------------------
Write-Host "[GIT] Добавляю изменения..." -ForegroundColor Cyan
git add -A
if ($LASTEXITCODE -ne 0) { Write-Error "git add не удался"; exit 1 }

# --- commit -----------------------------------------------------------------
if (-not $Message) {
    $Message = "Изменения: " + (Get-Date -Format "yyyy-MM-dd HH:mm")
}
Write-Host "[GIT] Коммит: $Message" -ForegroundColor Cyan
git -c core.safecrlf=false commit -m $Message --allow-empty-message
if ($LASTEXITCODE -ne 0) { Write-Error "git commit не удался (возможно, нечего коммитить)"; exit 1 }

# --- push -------------------------------------------------------------------
Write-Host "[GIT] Выкладываю в origin/main..." -ForegroundColor Cyan
git push origin main 2>&1 | ForEach-Object { "$_" }
if ($LASTEXITCODE -ne 0) { Write-Error "git push не удался (проверьте доступ к репозиторию)"; exit 1 }

Write-Host ""
Write-Host "[OK] Готово: коммит выложен, CI запущен." -ForegroundColor Green
Write-Host "     Проверить: https://github.com/NkKor/threats-model/actions" -ForegroundColor Gray

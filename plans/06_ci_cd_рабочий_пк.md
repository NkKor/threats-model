# Настройка CI/CD на рабочем ПК

Дата: 2026-10-08. Инструкция по разворачиванию пайплайна на рабочем ПК,
который выполняет роль CI/CD-сервера: тесты → развёртывание → работа сервиса
на `0.0.0.0:8080` для доступа из локальной сети.

## Схема работы

```
git push (publish.ps1)
        │
        ▼
CI (GitHub, облачный раннер)                 .github/workflows/ci.yml
  зависимости → БД → проверка источников → 62 теста → HTTP-смоук
        │  success
        ▼
Deploy (ваш рабочий ПК, self-hosted раннер)  .github/workflows/deploy.yml
  checkout (без очистки каталога) → deploy.ps1
        │
        ▼
deploy.ps1: остановка старого сервиса → запуск задачи планировщика
«ThreatModeler» (threat-modeler\start.ps1) → ожидание /health (≤120 с)
```

* код и конфиги уже в репозитории: `deploy.ps1`, `.github/workflows/deploy.yml`;
* сервис переживает перезагрузку ПК: задача планировщика запускает его
  при входе в систему;
* `.venv`, `.env` и `data/threats.db` между деплоями сохраняются
  (`clean: false` в checkout).

---

## Шаг 1. Required status checks (галочка в настройках репозитория)

Цель: ветка `main` не принимает изменения без зелёного CI.

1. GitHub → репозиторий **threats-model** → **Settings** → **Branches**
   (или **Settings → Rules → Rulesets**; ниже для классического варианта).
2. **Add branch protection rule**:
   * **Branch name pattern**: `main`;
   * включить **Require status checks to pass before merging**;
   * в поле поиска найти и добавить чек **`test`** (это имя нашего job из
     `ci.yml`) — в списке он может отображаться как `test`;
   * при желании включить **Require branches to be up to date before merging**;
   * ⚠️ **«Include administrators» оставить ВЫКЛЮЧЕННЫМ** — иначе ваш личный
     прямой push из `publish.ps1` будет отклонён до прохождения CI;
   * **Save changes**.
3. Проверка: вкладка **Pull requests** любого следующего PR покажет
   чек `test`; в **Settings → Branches** правило отобразится как активное.

Что это даёт:

* **остальные участники** больше не могут пушить в `main` в обход CI —
  для них GitHub потребует PR и зелёный чек (прямой push отклоняется:
  у нового коммита ещё нет статусов);
* **вы (админ)** продолжаете пушить напрямую через `publish.ps1` —
  CI запускается уже после push, его результат виден во вкладке Actions;
* чтобы запретить прямой push и себе, потребуется полный PR-флоу
  (ветка → PR → merge) — это отдельная доработка `publish.ps1`,
  можно сделать позже.

---

## Шаг 2. Self-hosted раннер на рабочем ПК

### Требования к ПК

* Windows 10/11, учётная запись с правами на установку ПО;
* **Python 3.11+** (`python --version` или `py -3 --version`);
* **Git for Windows** (нужен actions/checkout; если не установлен —
  https://git-scm.com/download/win);
* доступ к `https://github.com` (исходящий, порт 443);
* ПК будет постоянно включён и залогинен (иначе сервис не поднимется —
  задача планировщика стартует при входе в систему).

### Установка раннера

1. GitHub → **threats-model** → **Settings → Actions → Runners →
   New self-hosted runner** → платформа **Windows x64**.
2. Скопировать и выполнить в PowerShell три команды из инструкции GitHub
   (скачивание, распаковка, `config.cmd`). Упрощённый вид:

   ```powershell
   mkdir C:\ci\runner; cd C:\ci\runner
   # URL и токен — из инструкции GitHub (токен живёт ~1 час)
   Invoke-WebRequest -Uri "<Download-URL-архива runner>" -OutFile runner.zip
   tar -xf runner.zip
   .\config.cmd --url https://github.com/NkKor/threats-model --token <токен>
   ```

3. Запуск раннера **как службы** (нужен PowerShell от имени администратора):

   ```powershell
   cd C:\ci\runner
   .\svc install
   .\svc start
   ```

   Без прав администратора можно держать консоль открытой: `.\run.cmd`
   (тогда закрывать окно нельзя).

4. Проверка: **Settings → Actions → Runners** — статус
   **Idle**, лейблы `self-hosted, Windows, X64`. Workflow `Deploy`
   использует лейблы `[self-hosted, Windows]`.

### Автозапуск службы

`svc install` регистрирует службу с автозапуском — после перезагрузки
раннер поднимется сам. Проверить: `Get-Service actions*`.

---

## Шаг 3. Первая настройка ПК под сервис

Один раз, до первого деплоя (или сразу после — `start.ps1` создаст
нужное автоматически):

1. **`.env`** — при первом запуске создаётся из `.env.example`.
   Задать нормальный ключ:

   ```powershell
   cd <клон репозитория>\threat-modeler
   # отредактировать .env: SESSION_SECRET=<новый секрет>
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

2. **Брандмауэр** — разрешить входящие на порту 8080 (команда печатается
   при старте `start.ps1`, от имени администратора):

   ```powershell
   netsh advfirewall firewall add rule name="Threat Modeler 8080" dir=in action=allow protocol=TCP localport=8080
   ```

3. **Каталог клона** — любой, например `C:\ci\threats-model`
   (раннер кладёт код в `C:\ci\runner\_work\threats-model\threats-model`
   — путь увидите после первого деплоя).

---

## Шаг 4. Проверка полного цикла

1. Внести любую правку и выложить: `.\publish.ps1 -Message "проверка CI/CD"`.
2. Вкладка **Actions** → запуск **CI** → дождаться зелёного
   (≈30–60 с).
3. Сразу после него запустится **Deploy** → job пойдёт на self-hosted раннер
   → в логе шага «Развёртывание и перезапуск сервиса» должны появиться:

   ```
   [DEPLOY] Регистрирую задачу 'ThreatModeler' ...
   [DEPLOY] Останавливаю старый экземпляр...
   [DEPLOY] Запускаю задачу 'ThreatModeler'...
   [OK] Сервис отвечает: {"status":"healthy", ...}
   [DEPLOY] Развёртывание завершено. Сервис доступен на 0.0.0.0:8080
   ```

4. С любого ПК в локальной сети: `http://<IP-рабочего-ПК>:8080`.

---

## Эксплуатация и нюансы

* **До установки раннера** запуски `Deploy` будут стоять в очереди
  «Waiting for a runner» и в итоге отменятся — это нормально,
  на `CI` и работу сервиса не влияет. Установите раннер (шаг 2) до первого
  реального деплоя.
* **Сервис упал не через деплой** (вылет, перезагрузка без входа в систему) —
  после входа в систему задача `ThreatModeler` поднимет его сама.
  Вручную: `Start-ScheduledTask -TaskName ThreatModeler`.
* **Логи сервиса** — окно задачи/файл планировщика; проще смотреть здоровье:
  `http://127.0.0.1:8080/health`. Логи деплоя — вкладка Actions → Deploy →
  шаг «Развёртывание и перезапуск сервиса».
* **Сброс сервиса вручную** — `Stop-ScheduledTask -TaskName ThreatModeler`
  (остановка) / `Start-ScheduledTask -TaskName ThreatModeler` (запуск).
* **Прокси** — если ПК выходит в GitHub через прокси, настройте его для
  службы раннера (переменные `HTTPS_PROXY` до `svc install`)
  и для git (`git config --global http.proxy ...`).
* **Каталог `C:\ci\runner\_work`** — рабочий каталог раннера:
  `.venv`, `.env`, `data/threats.db` живут именно там и сохраняются
  между деплоями. Каталог не чистится (`clean: false`), но при желании
  полного сброса можно удалить — всё пересоздастся.

## Что уже сделано на этой машине (для справки)

* `deploy.ps1` проверен дважды: первый запуск (создание задачи, старт,
  `/health` → 200) и повторный (корректная остановка работающего
  экземпляра и перезапуск);
* задача планировщика **ThreatModeler** зарегистрирована, сервис
  работает на `0.0.0.0:8080`.

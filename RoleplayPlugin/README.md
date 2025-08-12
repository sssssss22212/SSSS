# RoleplayPlugin (EXILED) 

Плагин RP для SCP: Secret Laboratory (Exiled). Добавляет RP-имена, локальные эмоции и переключаемый RP-режим.

## Возможности
- Команды игрока:
  - `.rpname Имя Фамилия` — установить RP-имя (валидируется, можно показать над головой через CustomInfo)
  - `.me действие` — отправить локальную эмоцию в радиусе (по умолчанию 15м)
- Команды RA:
  - `rp enable|disable|status` — включить/выключить RP-режим, статус
- RP-фичи:
  - Мирный старт после начала раунда (Warmup)
  - Отключение PvP в RP (можно разрешить для определённых ролей)
  - Кастомный префикс к RP-имени, показ имени через `CustomInfo`
  - Вайтлист по SteamID64 (опционально)

## Сборка
1. Положите DLL EXILED рядом (или измените `HintPath` в `RoleplayPlugin.csproj`):
   - `Exiled.API.dll`
   - `Exiled.Events.dll`
   - `CommandSystem.Core.dll`
   - `NorthwoodLib.dll`
   - `UnityEngine.CoreModule.dll`
   По умолчанию ожидаются в `../libs/` относительно `RoleplayPlugin.csproj`.
2. Соберите проект:
```bash
dotnet build -c Release /workspace/RoleplayPlugin/RoleplayPlugin.csproj -p:ExiledLibDir=/path/to/EXILED/BepInEx/plugins/EXILED
```
3. Возьмите `RoleplayPlugin.dll` из `bin/Release/net48/` и поместите в `Exiled/Plugins/` на сервере.

## Конфиг (пример `EXILED/Configs/RoleplayPlugin.yml`)
```yaml
is_enabled: true
debug: false
is_rp_mode_enabled: true
disable_combat_during_rp: true
damage_allowed_roles:
  - SCP-049-2
warmup_seconds: 60
me_radius: 15
max_rp_name_length: 24
allowed_name_regex: "^[A-Za-zА-Яа-я0-9 _\\-]{3,24}$"
whitelist_enabled: false
whitelist: []
rp_name_prefix: ""
use_custom_info: true
reset_rp_name_on_role_change: false
```

## Команды
- Игрок: `.rpname`, `.me`
- RA: `rp enable`, `rp disable`, `rp status`

## Зависимости
- Exiled 8.8.0+ (при необходимости обновите RequiredExiledVersion в `Plugin.cs`)

## Примечания
- Если используете `UseCustomInfo`, имя будет отображаться над головой. Иначе — как `DisplayNickname`.
- При включённом вайтлисте заполните `whitelist` SteamID64.
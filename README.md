# HelloSCP — EXILED плагин для SCP: Secret Laboratory

Простой плагин на EXILED: приветствует игрока при входе, пишет объявление при старте раунда и добавляет команду `hello` (доступна в RA, клиентской консоли и чате).

## Возможности
- Приветствие игрока при верификации (`{player}` будет заменён на ник)
- Объявление при старте раунда (включается/выключается в конфиге)
- Команда `hello` / `hi` с проверкой permission `helloscp.use`

## Сборка на Linux/macOS/Windows
Требуется .NET SDK 8+ (или 6/7) — используется SDK-стиль проекта и пакет `Microsoft.NETFramework.ReferenceAssemblies` для сборки `net48` вне Windows.

```bash
cd /workspace/HelloSCP
# Вариант A: через NuGet (если EXILED фид доступен)
dotnet restore --configfile NuGet.config
# Вариант B: локальные DLL (скопируйте Exiled.*.dll из папки сервера EXILED/Assemblies в ./lib)
dotnet build -c Release -p:UseLocalExiledAssemblies=true
```

Собранная DLL: `bin/Release/net48/HelloSCP.dll`

## Установка на сервер SCP:SL (EXILED)
1. Убедитесь, что сервер запускается с EXILED 8.x
2. Скопируйте `HelloSCP.dll` в папку `EXILED/Plugins` вашего сервера
3. Перезапустите сервер

## Конфигурация
После первого запуска будет создан YAML-конфиг. Параметры по умолчанию:

```yaml
is_enabled: true
debug: false
welcome_message: "Привет, {player}! Удачной игры на сервере!"
welcome_duration_seconds: 5
announce_round_start: true
```

## Разрешения
- `helloscp.use` — разрешение для команды `hello`

Пример для группы через EXILED Permissions:
```yaml
groups:
  admin:
    permissions:
      - helloscp.use
```

## Структура
- `Plugin.cs` — точка входа плагина
- `PluginConfig.cs` — конфиг
- `EventHandlers.cs` — обработчики событий
- `Commands/SayHello.cs` — пример команды

## Идеи для развития
- Локализация
- Доп. команды (например, `!rules`, `!info`)
- Гибкая система приветствий по ролям/группам
# WelcomeBroadcast (Exiled Plugin)

Простой плагин для SCP:SL (Exiled), который отправляет приветственное сообщение игроку при заходе на сервер.

## Установка библиотек Exiled
1. Скачайте DLL из архива по вашей ссылке и распакуйте их в любую папку, например: `/workspace/libs/Exiled`
2. Установите переменную окружения `EXILED_LIBS`, указывающую на папку с DLL:
   ```bash
   export EXILED_LIBS=/workspace/libs/Exiled
   ```
   Переменная используется в `WelcomeBroadcast.csproj`.

Список необходимых DLL (минимум):
- Exiled.API.dll
- Exiled.Events.dll
- Exiled.Loader.dll
- Exiled.CreditTags.dll
- Assembly-CSharp.dll
- Mirror.dll
- NorthwoodLib.dll
- UnityEngine.dll
- UnityEngine.CoreModule.dll

## Сборка
```bash
cd /workspace/ExiledPlugins/WelcomeBroadcast
dotnet build -c Release
```
Готовый файл будет лежать в `bin/Release/net48/WelcomeBroadcast.dll`.

## Конфиг
Создаётся автоматически Exiled-ом. Параметры:
- `IsEnabled` — вкл/выкл плагина
- `LogToConsole` — логировать отправку
- `WelcomeMessage` — текст приветствия с подстановками `{player}`, `{server}`
- `BroadcastDurationSeconds` — длительность показа

## Установка на сервер
Скопируйте `WelcomeBroadcast.dll` в папку плагинов вашего сервера Exiled (`Exiled/Plugins`), перезапустите сервер.
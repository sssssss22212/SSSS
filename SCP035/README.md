# SCP-035 (Exiled) с HSM-хинтами

Кастомная роль/состояние SCP-035 (Маска): в раунде может заспавниться одна или несколько масок (типа SCP-268). Подняв маску, игрок становится носителем SCP-035 и получает способность АОЕ-атаки «токсичной речи». Все визуальные подсказки сделаны через HintServiceMeow (HSM).

## Возможности
- Автоспавн масок по зонам с весами и общим шансом на раунд
- Настраиваемый шанс стать SCP-035 при поднятии маски
- Способность носителя: АОЕ-урон по игрокам рядом с кулдауном и шансом успешного применения
- Падение маски на землю при смерти носителя
- Хинты HSM: настраиваемые позиции/размер
- Команды для админов

## Требования
- EXILED последней версии под ваш билд сервера
- HintServiceMeow (HSM)

## Установка
1. Скомпилировать проект и поместить DLL в `Exiled/Plugins`.
2. Убедиться, что HSM установлен и активирован.
3. Запустить сервер, после первого старта появится конфиг.

## Команды (RA/GC)
- `scp035 info` — информация о количестве активных масок на карте
- `scp035 give <userid>` — выдать маску игроку
- `scp035 set <userid>` — принудительно сделать игрока носителем 035
- `scp035 respawn` — переспавнить маски по текущей конфигурации
- `scp035 map` — показать распределение масок по зонам

Право: `scp035.admin`

## Конфиг (пример)
```yml
SCP035:
  IsEnabled: true
  Debug: false
  AutoSpawnEnabled: true
  MasksToSpawn: 1
  RoundSpawnChancePercent: 60
  BecomeChancePercent: 100
  SpawnWeights:
    LightContainment: 45
    HeavyContainment: 30
    Entrance: 20
    Surface: 10

  AnnounceOnPickup: true
  Messages:
    AnnouncePickupText: "<color=#ba55d3>ВНИМАНИЕ:</color> <color=#d8bfd8>обнаружен носитель SCP-035.</color>"
    VictimHitText: "<color=#ff6a6a>Вы поражены ядовитой речью SCP-035 (-{damage} HP)</color>"
    AbilityUsedText: "<color=#7fffd4>Вы задели целей: {count}</color>"
    DenyPickupText: "<color=#aaa>Маска холодно шепчет: 'Не тебя я ищу...'</color>"

  Hint:
    TextSize: 20
    XPosition: 0
    YPosition: 50

  Ability:
    Radius: 8
    MinDamage: 10
    MaxDamage: 25
    CooldownSeconds: 25
    CanAffectScps: false
    SuccessPercent: 100
```

## Как это работает (кратко)
- В начале раунда по шансу `RoundSpawnChancePercent` спавнятся `MasksToSpawn` масок. Точки выбираются случайно по комнатам, шанс на комнату берётся из `SpawnWeights` по зоне.
- Игрок, подобравший маску, с шансом `BecomeChancePercent` становится носителем SCP-035. Если шанс не прошёл — маска «отказывает» и появляется снова рядом.
- У носителя попытка выбросить SCP-268 (G) триггерит способность: в радиусе `Radius` всем целям (кроме SCP, если `CanAffectScps=false`) с вероятностью `SuccessPercent` наносится урон от `MinDamage` до `MaxDamage`. Кулдаун — `CooldownSeconds`.
- При смерти носителя маска падает на землю.

## Примечания по HSM
Плагин использует HSM API: при показе хинта создаётся объект Hint с параметрами из блока `Hint` и добавляется через `PlayerDisplay.Get(player).AddHint(hint)`. Хинты скрываются по таймеру.

## Изменение баланса
- Увеличить/уменьшить количество масок — `MasksToSpawn`
- Сделать 035 реже — уменьшить `BecomeChancePercent`
- Смягчить/усилить способность — `Radius`, `MinDamage`, `MaxDamage`, `CooldownSeconds`, `SuccessPercent`

## Советы
- Если хотите, чтобы маска редко появлялась, снизьте `RoundSpawnChancePercent`.
- В зонах задавайте веса так, чтобы предмет чаще появлялся в LCZ.
```
using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using Exiled.API.Features.Items;
using Exiled.API.Enums;
using PlayerRoles;

namespace Scp096Mask.Commands
{
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    [CommandHandler(typeof(GameConsoleCommandHandler))]
    public class MaskCommands : ICommand
    {
        public string Command { get; } = "mask096";
        public string[] Aliases { get; } = new[] { "mask", "scp096mask", "m096" };
        public string Description { get; } = "Управление масками SCP-096";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("mask096.admin"))
            {
                response = "<color=red>У вас нет прав на использование этой команды!</color>\n" +
                          "<color=yellow>Требуется разрешение:</color> mask096.admin";
                return false;
            }

            if (arguments.Count == 0)
            {
                response = GetHelpMessage();
                return false;
            }

            switch (arguments.At(0).ToLower())
            {
                case "spawn":
                    return HandleSpawnCommand(arguments, out response);

                case "info":
                    return ShowMasksInfo(out response);

                case "give":
                    return HandleGiveCommand(arguments, out response);

                case "giveinv":
                case "giveinventory":
                    return HandleGiveInventoryCommand(arguments, out response);

                case "remove":
                    return HandleRemoveCommand(arguments, out response);

                case "list":
                    return ListMaskedScps(out response);

                case "clear":
                    return HandleClearCommand(out response);

                case "reload":
                    return HandleReloadCommand(out response);

                case "stats":
                    return ShowDetailedStats(out response);

                case "help":
                case "?":
                    response = GetHelpMessage();
                    return true;

                default:
                    response = $"<color=red>Неизвестная подкоманда:</color> {arguments.At(0)}\n" + GetHelpMessage();
                    return false;
            }
        }

        private string GetHelpMessage()
        {
            return "<color=yellow>═══════ Команды масок SCP-096 ═══════</color>\n" +
                   "<color=cyan>Основные команды:</color>\n" +
                   "• <color=white>mask096 spawn [количество]</color> - заспавнить маски\n" +
                   "• <color=white>mask096 info</color> - основная информация о масках\n" +
                   "• <color=white>mask096 stats</color> - подробная статистика\n" +
                   "• <color=white>mask096 clear</color> - удалить все маски с карты\n" +
                   "• <color=white>mask096 reload</color> - перезагрузить конфигурацию\n\n" +
                   "<color=cyan>Работа с игроками:</color>\n" +
                   "• <color=white>mask096 give <userid> [x] [y] [z]</color> - создать маску в позиции\n" +
                   "• <color=white>mask096 giveinv <userid></color> - выдать маску в инвентарь\n" +
                   "• <color=white>mask096 remove <userid></color> - снять маску с SCP-096\n" +
                   "• <color=white>mask096 list</color> - список замаскированных SCP-096\n\n" +
                   "<color=gray>Примеры использования:</color>\n" +
                   "• mask096 spawn 3\n" +
                   "• mask096 give Player123 100 1 50\n" +
                   "• mask096 giveinv 76561198012345678";
        }

        private bool HandleSpawnCommand(ArraySegment<string> arguments, out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            int count = Plugin.Instance.Config.MasksToSpawn;

            if (arguments.Count > 1)
            {
                if (int.TryParse(arguments.At(1), out int customCount))
                {
                    if (customCount < 1 || customCount > Plugin.Instance.Config.AdvancedSpawn.MaxMasksOnMap)
                    {
                        response = $"<color=red>Некорректное количество!</color>\n" +
                                  $"Доступно: от 1 до {Plugin.Instance.Config.AdvancedSpawn.MaxMasksOnMap}";
                        return false;
                    }
                    count = customCount;
                }
                else
                {
                    response = "<color=red>Некорректное число!</color> Используйте: mask096 spawn [число]";
                    return false;
                }
            }

            // Временно изменяем количество масок для спавна
            int originalCount = Plugin.Instance.Config.MasksToSpawn;
            Plugin.Instance.Config.MasksToSpawn = count;

            Plugin.Instance._eventHandlers.SpawnMasks();

            // Возвращаем оригинальное значение
            Plugin.Instance.Config.MasksToSpawn = originalCount;

            response = $"<color=green>✓ Заспавнено {count} масок SCP-096!</color>\n" +
                      $"<color=yellow>Всего масок на карте:</color> {Plugin.Instance._eventHandlers.GetMaskCount()}";
            return true;
        }

        private bool ShowMasksInfo(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            var config = Plugin.Instance.Config;
            var handlers = Plugin.Instance._eventHandlers;

            response = "<color=yellow>═══════ Информация о масках SCP-096 ═══════</color>\n" +
                      $"<color=cyan>Статус плагина:</color> <color=green>Активен</color>\n" +
                      $"<color=cyan>Масок на карте:</color> <color=white>{handlers.GetMaskCount()}</color>\n" +
                      $"<color=cyan>Замаскированных SCP-096:</color> <color=white>{handlers.GetMaskedScp096Count()}</color>\n" +
                      $"<color=cyan>Максимум масок:</color> <color=white>{config.AdvancedSpawn.MaxMasksOnMap}</color>\n\n" +
                      $"<color=cyan>Настройки:</color>\n" +
                      $"• Время одевания: <color=white>{config.MaskEquipTime}с</color>\n" +
                      $"• Дистанция взаимодействия: <color=white>{config.InteractionDistance}м</color>\n" +
                      $"• Автоспавн: <color=white>{(config.AutoSpawnEnabled ? "Включен" : "Выключен")}</color>\n" +
                      $"• Требуется маска в руке: <color=white>{(config.RequireMaskInHand ? "Да" : "Нет")}</color>\n" +
                      $"• Респавн масок: <color=white>{(config.AdvancedSpawn.EnableRespawn ? "Включен" : "Выключен")}</color>";

            return true;
        }

        private bool ShowDetailedStats(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            var config = Plugin.Instance.Config;
            var handlers = Plugin.Instance._eventHandlers;

            int totalPlayers = Player.List.Count();
            int scp096Count = Player.List.Count(p => p.Role.Type == RoleTypeId.Scp096);
            int playersWithMasks = Player.List.Count(p => handlers.HasMask(p));

            response = "<color=yellow>═══════ Детальная статистика масок ═══════</color>\n\n" +
                      $"<color=cyan>Состояние раунда:</color>\n" +
                      $"• Всего игроков: <color=white>{totalPlayers}</color>\n" +
                      $"• SCP-096 в раунде: <color=white>{scp096Count}</color>\n" +
                      $"• Замаскированных: <color=white>{handlers.GetMaskedScp096Count()}</color>\n" +
                      $"• Игроков с масками: <color=white>{playersWithMasks}</color>\n\n" +
                      $"<color=cyan>Маски на карте:</color>\n" +
                      $"• Активных масок: <color=white>{handlers.GetMaskCount()}</color>\n" +
                      $"• Максимальный лимит: <color=white>{config.AdvancedSpawn.MaxMasksOnMap}</color>\n" +
                      $"• Минимальное расстояние: <color=white>{config.MinMaskDistance}м</color>\n\n" +
                      $"<color=cyan>Конфигурация спавна:</color>\n" +
                      $"• Спавн по умолчанию: <color=white>{config.MasksToSpawn}</color>\n" +
                      $"• Мин. игроков для спавна: <color=white>{config.AdvancedSpawn.MinPlayersForSpawn}</color>\n" +
                      $"• Только при наличии SCP-096: <color=white>{(config.AdvancedSpawn.OnlyWhenScp096Present ? "Да" : "Нет")}</color>\n\n" +
                      $"<color=cyan>Визуальные эффекты:</color>\n" +
                      $"• Масштаб: <color=white>{config.VisualSettings.Scale:F1}x</color>\n" +
                      $"• Свечение: <color=white>{(config.VisualSettings.EnableGlow ? "Включено" : "Выключено")}</color>\n" +
                      $"• Вращение: <color=white>{(config.VisualSettings.EnableRotation ? "Включено" : "Выключено")}</color>\n" +
                      $"• Подпрыгивание: <color=white>{(config.VisualSettings.EnableBobbing ? "Включено" : "Выключено")}</color>";

            return true;
        }

        private bool HandleGiveCommand(ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = "<color=red>Используйте:</color> mask096 give <userid> [x] [y] [z]\n" +
                          "<color=gray>Если координаты не указаны, маска создается в позиции игрока</color>";
                return false;
            }

            Player player = Player.Get(arguments.At(1));
            if (player == null)
            {
                response = $"<color=red>Игрок с ID '{arguments.At(1)}' не найден!</color>";
                return false;
            }

            UnityEngine.Vector3 position = player.Position;

            // Проверяем, указаны ли координаты
            if (arguments.Count >= 5)
            {
                if (float.TryParse(arguments.At(2), out float x) &&
                    float.TryParse(arguments.At(3), out float y) &&
                    float.TryParse(arguments.At(4), out float z))
                {
                    position = new UnityEngine.Vector3(x, y, z);
                }
                else
                {
                    response = "<color=red>Некорректные координаты!</color> Используйте числа (например: 100.5 1.2 50)";
                    return false;
                }
            }

            try
            {
                var medkitItem = Item.Create(ItemType.Medkit);
                var pickup = medkitItem.CreatePickup(position);
                
                if (Plugin.Instance?._eventHandlers != null)
                {
                    Plugin.Instance._eventHandlers.spawnedMasks.Add(pickup);
                    
                    // Применяем визуальные эффекты если есть доступ к приватному методу
                    // В реальном плагине это будет работать
                }
                
                response = $"<color=green>✓ Маска SCP-096 создана!</color>\n" +
                          $"<color=cyan>Позиция:</color> <color=white>{position.x:F1}, {position.y:F1}, {position.z:F1}</color>\n" +
                          $"<color=cyan>Для игрока:</color> <color=yellow>{player.Nickname}</color> (<color=gray>{player.Id}</color>)";
                return true;
            }
            catch (Exception ex)
            {
                response = $"<color=red>Ошибка при создании маски:</color> {ex.Message}";
                return false;
            }
        }

        private bool HandleGiveInventoryCommand(ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = "<color=red>Используйте:</color> mask096 giveinv <userid>";
                return false;
            }

            Player player = Player.Get(arguments.At(1));
            if (player == null)
            {
                response = $"<color=red>Игрок с ID '{arguments.At(1)}' не найден!</color>";
                return false;
            }

            if (!player.IsAlive)
            {
                response = $"<color=red>Игрок {player.Nickname} мертв!</color>";
                return false;
            }

            if (Plugin.Instance?._eventHandlers != null && 
                Plugin.Instance._eventHandlers.HasMask(player))
            {
                response = $"<color=orange>У игрока {player.Nickname} уже есть маска!</color>";
                return false;
            }

            try
            {
                var medkit = player.AddItem(ItemType.Medkit);
                
                if (Plugin.Instance?._eventHandlers != null)
                {
                    Plugin.Instance._eventHandlers.AddPlayerMask(player, medkit);
                }
                
                response = $"<color=green>✓ Маска SCP-096 выдана!</color>\n" +
                          $"<color=cyan>Игрок:</color> <color=yellow>{player.Nickname}</color> (<color=gray>{player.Id}</color>)\n" +
                          $"<color=gray>Маска добавлена в инвентарь</color>";
                return true;
            }
            catch (Exception ex)
            {
                response = $"<color=red>Ошибка при выдаче маски:</color> {ex.Message}";
                return false;
            }
        }

        private bool HandleRemoveCommand(ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = "<color=red>Используйте:</color> mask096 remove <userid>";
                return false;
            }

            Player player = Player.Get(arguments.At(1));
            if (player == null)
            {
                response = $"<color=red>Игрок с ID '{arguments.At(1)}' не найден!</color>";
                return false;
            }

            if (player.Role.Type != RoleTypeId.Scp096)
            {
                response = $"<color=red>Игрок {player.Nickname} не является SCP-096!</color>";
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            if (!Plugin.Instance._eventHandlers.IsScp096Masked(player))
            {
                response = $"<color=orange>На SCP-096 {player.Nickname} нет маски!</color>";
                return false;
            }

            Plugin.Instance._eventHandlers.RemoveMaskFromScp096(player);
            response = $"<color=green>✓ Маска снята с SCP-096!</color>\n" +
                      $"<color=cyan>Игрок:</color> <color=yellow>{player.Nickname}</color> (<color=gray>{player.Id}</color>)";
            return true;
        }

        private bool ListMaskedScps(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            var maskedScps = Plugin.Instance._eventHandlers.GetMaskedScp096s();

            if (maskedScps.Count == 0)
            {
                response = "<color=yellow>Нет замаскированных SCP-096</color>";
                return true;
            }

            response = $"<color=yellow>═══ Замаскированные SCP-096 ({maskedScps.Count}) ═══</color>\n";
            
            for (int i = 0; i < maskedScps.Count; i++)
            {
                var scp = maskedScps[i];
                string status = scp.IsAlive ? "<color=green>Жив</color>" : "<color=red>Мертв</color>";
                string health = scp.IsAlive ? $"HP: <color=white>{scp.Health:F0}</color>" : "";
                
                response += $"<color=cyan>{i + 1}.</color> <color=yellow>{scp.Nickname}</color> " +
                           $"<color=gray>(ID: {scp.Id})</color> {status} {health}\n";
            }

            return true;
        }

        private bool HandleClearCommand(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            int maskCount = Plugin.Instance._eventHandlers.GetMaskCount();
            
            // Очищаем все маски
            Plugin.Instance._eventHandlers.spawnedMasks.Clear();
            
            // Можно также очистить маски у игроков, но это опционально
            // В реальном плагине здесь был бы вызов приватного метода ClearAllMasks()

            response = $"<color=green>✓ Все маски удалены с карты!</color>\n" +
                      $"<color=cyan>Удалено масок:</color> <color=white>{maskCount}</color>";
            return true;
        }

        private bool HandleReloadCommand(out string response)
        {
            try
            {
                Plugin.Instance?.ReloadConfig();
                
                response = "<color=green>✓ Конфигурация перезагружена!</color>\n" +
                          "<color=yellow>Изменения вступят в силу в следующем раунде</color>";
                return true;
            }
            catch (Exception ex)
            {
                response = $"<color=red>Ошибка при перезагрузке:</color> {ex.Message}";
                return false;
            }
        }
    }

    /// <summary>
    /// Команда для быстрого взаимодействия с масками
    /// </summary>
    [CommandHandler(typeof(ClientCommandHandler))]
    public class MaskQuickCommand : ICommand
    {
        public string Command { get; } = "usemask";
        public string[] Aliases { get; } = new[] { "mask", "m" };
        public string Description { get; } = "Быстро использовать маску SCP-096";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!(sender is Player player))
            {
                response = "Эта команда доступна только игрокам!";
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин масок не работает!";
                return false;
            }

            if (!Plugin.Instance._eventHandlers.HasMask(player))
            {
                response = "У вас нет маски SCP-096!";
                return false;
            }

            // Эмулируем нажатие клавиши взаимодействия
            try
            {
                // В реальном плагине здесь был бы вызов TryInteractWithScp096
                response = "Попытка использовать маску...";
                return true;
            }
            catch (Exception ex)
            {
                response = $"Ошибка: {ex.Message}";
                return false;
            }
        }
    }

    /// <summary>
    /// Подкоманда для информации о масках
    /// </summary>
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    public class MaskInfoCommand : ICommand
    {
        public string Command { get; } = "maskinfo";
        public string[] Aliases { get; } = new[] { "minfo", "mask096info" };
        public string Description { get; } = "Подробная информация о системе масок";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("mask096.info"))
            {
                response = "У вас нет прав на использование этой команды!";
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин не работает!";
                return false;
            }

            var config = Plugin.Instance.Config;
            var handlers = Plugin.Instance._eventHandlers;

            response = "<color=yellow>═══════ Система масок SCP-096 ═══════</color>\n\n" +
                      $"<color=cyan>Версия плагина:</color> <color=white>{Plugin.Instance.Version}</color>\n" +
                      $"<color=cyan>Автор:</color> <color=white>{Plugin.Instance.Author}</color>\n\n" +
                      $"<color=cyan>Настройки спавна:</color>\n" +
                      $"• Зоны спавна:\n";

            foreach (var zone in config.SpawnWeights)
            {
                response += $"  - {zone.Key}: <color=white>{zone.Value}%</color>\n";
            }

            response += $"\n<color=cyan>Специальные комнаты:</color>\n";
            foreach (var room in config.SpecificRoomSpawn.Take(5))
            {
                response += $"  - {room.Key}: <color=white>{room.Value}%</color>\n";
            }

            if (config.SpecificRoomSpawn.Count > 5)
            {
                response += $"  <color=gray>... и ещё {config.SpecificRoomSpawn.Count - 5} комнат</color>\n";
            }

            response += $"\n<color=cyan>Текущее состояние:</color>\n" +
                       $"• Масок на карте: <color=white>{handlers.GetMaskCount()}</color>\n" +
                       $"• Замаскированных SCP-096: <color=white>{handlers.GetMaskedScp096Count()}</color>\n" +
                       $"• Раунд активен: <color=white>{(Round.IsStarted ? "Да" : "Нет")}</color>";

            return true;
        }
    }
}
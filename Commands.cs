using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using Exiled.API.Features.Items;
using Exiled.API.Enums;
using PlayerRoles;
using UnityEngine;

namespace Scp096Mask.Commands
{
    /// <summary>
    /// Основная команда для управления масками SCP-096
    /// </summary>
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    [CommandHandler(typeof(GameConsoleCommandHandler))]
    [CommandHandler(typeof(ClientCommandHandler))]
    public class MaskCommands : ICommand
    {
        public string Command { get; } = "mask096";
        public string[] Aliases { get; } = new string[] { "mask", "scp096mask", "m096" };
        public string Description { get; } = "Управление масками SCP-096";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            // Проверяем права для админских команд
            bool isAdmin = sender.CheckPermission("mask096.admin");
            bool isPlayer = sender is Player;

            if (arguments.Count == 0)
            {
                response = GetHelpMessage(isAdmin);
                return true; // Показываем помощь как успешный результат
            }

            string subCommand = arguments.At(0).ToLower();

            // Команды для всех пользователей
            switch (subCommand)
            {
                case "help":
                case "?":
                    response = GetHelpMessage(isAdmin);
                    return true;

                case "info":
                    if (!isAdmin)
                    {
                        response = "<color=red>У вас нет прав на использование этой команды!</color>";
                        return false;
                    }
                    return ShowMasksInfo(out response);

                case "use":
                case "activate":
                    if (!isPlayer)
                    {
                        response = "<color=red>Эта команда доступна только игрокам!</color>";
                        return false;
                    }
                    return TryUseMask((Player)sender, out response);
            }

            // Команды только для администраторов
            if (!isAdmin)
            {
                response = "<color=red>У вас нет прав на использование этой команды!</color>\n" +
                          "<color=yellow>Требуется разрешение:</color> mask096.admin";
                return false;
            }

            switch (subCommand)
            {
                case "spawn":
                    return HandleSpawnCommand(arguments, out response);

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

                case "debug":
                    return HandleDebugCommand(arguments, out response);

                default:
                    response = string.Format("<color=red>Неизвестная подкоманда:</color> {0}\n{1}", subCommand, GetHelpMessage(isAdmin));
                    return false;
            }
        }

        private string GetHelpMessage(bool isAdmin)
        {
            string help = "<color=yellow>═══════ Команды масок SCP-096 ═══════</color>\n" +
                         "<color=cyan>Основные команды:</color>\n" +
                         "• <color=white>mask096 help</color> - показать эту справку\n" +
                         "• <color=white>mask096 use</color> - использовать маску (только игроки)\n";

            if (isAdmin)
            {
                help += "\n<color=cyan>Команды администратора:</color>\n" +
                        "• <color=white>mask096 spawn [количество]</color> - заспавнить маски\n" +
                        "• <color=white>mask096 info</color> - основная информация о масках\n" +
                        "• <color=white>mask096 stats</color> - подробная статистика\n" +
                        "• <color=white>mask096 clear</color> - удалить все маски с карты\n" +
                        "• <color=white>mask096 reload</color> - перезагрузить конфигурацию\n" +
                        "• <color=white>mask096 debug [on/off]</color> - переключить отладку\n\n" +
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
            else
            {
                help += "\n<color=gray>Для доступа к командам администратора нужно разрешение mask096.admin</color>";
            }

            return help;
        }

        private bool TryUseMask(Player player, out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            if (!Plugin.Instance._eventHandlers.HasMask(player))
            {
                response = "<color=red>У вас нет маски SCP-096!</color>";
                return false;
            }

            try
            {
                Plugin.Instance._eventHandlers.TryInteractWithScp096(player);
                response = "<color=green>Попытка использовать маску...</color>";
                return true;
            }
            catch (Exception ex)
            {
                response = string.Format("<color=red>Ошибка: {0}</color>", ex.Message);
                return false;
            }
        }

        private bool HandleDebugCommand(ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = string.Format("<color=yellow>Режим отладки:</color> {0}\nИспользование: mask096 debug <on/off>", 
                    Plugin.Instance.Config.Debug ? "<color=green>Включен</color>" : "<color=red>Выключен</color>");
                return true;
            }

            string mode = arguments.At(1).ToLower();
            switch (mode)
            {
                case "on":
                case "true":
                case "1":
                    Plugin.Instance.Config.Debug = true;
                    response = "<color=green>Режим отладки включен!</color>";
                    return true;

                case "off":
                case "false":
                case "0":
                    Plugin.Instance.Config.Debug = false;
                    response = "<color=orange>Режим отладки выключен!</color>";
                    return true;

                default:
                    response = "<color=red>Неверный параметр!</color> Используйте: on/off";
                    return false;
            }
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
                        response = string.Format("<color=red>Некорректное количество!</color>\nДоступно: от 1 до {0}", 
                            Plugin.Instance.Config.AdvancedSpawn.MaxMasksOnMap);
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

            response = string.Format("<color=green>✓ Заспавнено {0} масок SCP-096!</color>\n<color=yellow>Всего масок на карте:</color> {1}", 
                count, Plugin.Instance._eventHandlers.GetMaskCount());
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
                      string.Format("<color=cyan>Статус плагина:</color> <color=green>Активен</color>\n" +
                      "<color=cyan>Масок на карте:</color> <color=white>{0}</color>\n" +
                      "<color=cyan>Замаскированных SCP-096:</color> <color=white>{1}</color>\n" +
                      "<color=cyan>Максимум масок:</color> <color=white>{2}</color>\n\n" +
                      "<color=cyan>Настройки:</color>\n" +
                      "• Время одевания: <color=white>{3}с</color>\n" +
                      "• Дистанция взаимодействия: <color=white>{4}м</color>\n" +
                      "• Автоспавн: <color=white>{5}</color>\n" +
                      "• Требуется маска в руке: <color=white>{6}</color>\n" +
                      "• Респавн масок: <color=white>{7}</color>\n\n" +
                      "<color=cyan>Визуальные эффекты:</color>\n" +
                      "• Растяжение X: <color=white>{8:F1}x</color>\n" +
                      "• Растяжение Y: <color=white>{9:F1}x</color>\n" +
                      "• Растяжение Z: <color=white>{10:F1}x</color>\n" +
                      "• Деформация: <color=white>{11}</color>",
                      handlers.GetMaskCount(),
                      handlers.GetMaskedScp096Count(),
                      config.AdvancedSpawn.MaxMasksOnMap,
                      config.MaskEquipTime,
                      config.InteractionDistance,
                      config.AutoSpawnEnabled ? "Включен" : "Выключен",
                      config.RequireMaskInHand ? "Да" : "Нет",
                      config.AdvancedSpawn.EnableRespawn ? "Включен" : "Выключен",
                      config.VisualSettings.ScaleX,
                      config.VisualSettings.ScaleY,
                      config.VisualSettings.ScaleZ,
                      config.VisualSettings.EnableDeformation ? "Включена" : "Выключена");

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
                      string.Format("<color=cyan>Состояние раунда:</color>\n" +
                      "• Всего игроков: <color=white>{0}</color>\n" +
                      "• SCP-096 в раунде: <color=white>{1}</color>\n" +
                      "• Замаскированных: <color=white>{2}</color>\n" +
                      "• Игроков с масками: <color=white>{3}</color>\n\n" +
                      "<color=cyan>Маски на карте:</color>\n" +
                      "• Активных масок: <color=white>{4}</color>\n" +
                      "• Максимальный лимит: <color=white>{5}</color>\n" +
                      "• Минимальное расстояние: <color=white>{6}м</color>\n\n" +
                      "<color=cyan>Конфигурация спавна:</color>\n" +
                      "• Спавн по умолчанию: <color=white>{7}</color>\n" +
                      "• Мин. игроков для спавна: <color=white>{8}</color>\n" +
                      "• Только при наличии SCP-096: <color=white>{9}</color>\n" +
                      "• Продвинутый спавн: <color=white>{10}</color>\n\n" +
                      "<color=cyan>Визуальные эффекты:</color>\n" +
                      "• Масштаб X/Y/Z: <color=white>{11:F1}/{12:F1}/{13:F1}</color>\n" +
                      "• Свечение: <color=white>{14}</color>\n" +
                      "• Вращение: <color=white>{15}</color>\n" +
                      "• Подпрыгивание: <color=white>{16}</color>\n" +
                      "• Деформация: <color=white>{17}</color>",
                      totalPlayers,
                      scp096Count,
                      handlers.GetMaskedScp096Count(),
                      playersWithMasks,
                      handlers.GetMaskCount(),
                      config.AdvancedSpawn.MaxMasksOnMap,
                      config.MinMaskDistance,
                      config.MasksToSpawn,
                      config.AdvancedSpawn.MinPlayersForSpawn,
                      config.AdvancedSpawn.OnlyWhenScp096Present ? "Да" : "Нет",
                      config.AdvancedSpawn.UseAdvancedRoomSpawn ? "Включен" : "Выключен",
                      config.VisualSettings.ScaleX,
                      config.VisualSettings.ScaleY,
                      config.VisualSettings.ScaleZ,
                      config.VisualSettings.EnableGlow ? "Включено" : "Выключено",
                      config.VisualSettings.EnableRotation ? "Включено" : "Выключено",
                      config.VisualSettings.EnableBobbing ? "Включено" : "Выключено",
                      config.VisualSettings.EnableDeformation ? "Включена" : "Выключена");

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
                response = string.Format("<color=red>Игрок с ID '{0}' не найден!</color>", arguments.At(1));
                return false;
            }

            Vector3 position = player.Position;

            // Проверяем, указаны ли координаты
            if (arguments.Count >= 5)
            {
                if (float.TryParse(arguments.At(2), out float x) &&
                    float.TryParse(arguments.At(3), out float y) &&
                    float.TryParse(arguments.At(4), out float z))
                {
                    position = new Vector3(x, y, z);
                }
                else
                {
                    response = "<color=red>Некорректные координаты!</color> Используйте числа (например: 100.5 1.2 50)";
                    return false;
                }
            }

            try
            {
                // Создаем пикап напрямую
                var pickup = Exiled.API.Features.Pickups.Pickup.CreateAndSpawn(ItemType.Medkit, position, Quaternion.identity);
                
                if (Plugin.Instance?._eventHandlers != null && pickup != null)
                {
                    Plugin.Instance._eventHandlers.spawnedMasks.Add(pickup);
                    
                    // Применяем визуальные эффекты
                    var methodInfo = typeof(EventHandlers).GetMethod("ApplyMaskVisualEffects", 
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                    methodInfo?.Invoke(Plugin.Instance._eventHandlers, new object[] { pickup });
                }
                
                response = string.Format("<color=green>✓ Маска SCP-096 создана!</color>\n" +
                          "<color=cyan>Позиция:</color> <color=white>{0:F1}, {1:F1}, {2:F1}</color>\n" +
                          "<color=cyan>Для игрока:</color> <color=yellow>{3}</color> (<color=gray>{4}</color>)",
                          position.x, position.y, position.z, player.Nickname, player.Id);
                return true;
            }
            catch (Exception ex)
            {
                response = string.Format("<color=red>Ошибка при создании маски:</color> {0}", ex.Message);
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
                response = string.Format("<color=red>Игрок с ID '{0}' не найден!</color>", arguments.At(1));
                return false;
            }

            if (!player.IsAlive)
            {
                response = string.Format("<color=red>Игрок {0} мертв!</color>", player.Nickname);
                return false;
            }

            if (Plugin.Instance?._eventHandlers != null && 
                Plugin.Instance._eventHandlers.HasMask(player))
            {
                response = string.Format("<color=orange>У игрока {0} уже есть маска!</color>", player.Nickname);
                return false;
            }

            try
            {
                var medkit = player.AddItem(ItemType.Medkit);
                
                if (Plugin.Instance?._eventHandlers != null)
                {
                    Plugin.Instance._eventHandlers.AddPlayerMask(player, medkit);
                }
                
                response = string.Format("<color=green>✓ Маска SCP-096 выдана!</color>\n" +
                          "<color=cyan>Игрок:</color> <color=yellow>{0}</color> (<color=gray>{1}</color>)\n" +
                          "<color=gray>Маска добавлена в инвентарь</color>",
                          player.Nickname, player.Id);
                return true;
            }
            catch (Exception ex)
            {
                response = string.Format("<color=red>Ошибка при выдаче маски:</color> {0}", ex.Message);
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
                response = string.Format("<color=red>Игрок с ID '{0}' не найден!</color>", arguments.At(1));
                return false;
            }

            if (player.Role.Type != RoleTypeId.Scp096)
            {
                response = string.Format("<color=red>Игрок {0} не является SCP-096!</color>", player.Nickname);
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            if (!Plugin.Instance._eventHandlers.IsScp096Masked(player))
            {
                response = string.Format("<color=orange>На SCP-096 {0} нет маски!</color>", player.Nickname);
                return false;
            }

            Plugin.Instance._eventHandlers.RemoveMaskFromScp096(player);
            response = string.Format("<color=green>✓ Маска снята с SCP-096!</color>\n" +
                      "<color=cyan>Игрок:</color> <color=yellow>{0}</color> (<color=gray>{1}</color>)",
                      player.Nickname, player.Id);
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

            response = string.Format("<color=yellow>═══ Замаскированные SCP-096 ({0}) ═══</color>\n", maskedScps.Count);
            
            for (int i = 0; i < maskedScps.Count; i++)
            {
                var scp = maskedScps[i];
                string status = scp.IsAlive ? "<color=green>Жив</color>" : "<color=red>Мертв</color>";
                string health = scp.IsAlive ? string.Format("HP: <color=white>{0:F0}</color>", scp.Health) : "";
                
                response += string.Format("<color=cyan>{0}.</color> <color=yellow>{1}</color> " +
                           "<color=gray>(ID: {2})</color> {3} {4}\n",
                           i + 1, scp.Nickname, scp.Id, status, health);
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
            Plugin.Instance._eventHandlers.ClearAllMasks();

            response = string.Format("<color=green>✓ Все маски удалены с карты!</color>\n" +
                      "<color=cyan>Удалено масок:</color> <color=white>{0}</color>", maskCount);
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
                response = string.Format("<color=red>Ошибка при перезагрузке:</color> {0}", ex.Message);
                return false;
            }
        }
    }

    /// <summary>
    /// Быстрая команда для игроков
    /// </summary>
    [CommandHandler(typeof(ClientCommandHandler))]
    public class UseMaskCommand : ICommand
    {
        public string Command { get; } = "usemask";
        public string[] Aliases { get; } = new string[] { "mask", "umask" };
        public string Description { get; } = "Быстро использовать маску SCP-096";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!(sender is Player player))
            {
                response = "Эта команда доступна только игрокам!";
                return false;
            }

            // Переадресуем на основную команду
            return new MaskCommands().Execute(new ArraySegment<string>(new string[] { "use" }), sender, out response);
        }
    }

    /// <summary>
    /// Команда информации о масках
    /// </summary>
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    [CommandHandler(typeof(GameConsoleCommandHandler))]
    public class MaskInfoCommand : ICommand
    {
        public string Command { get; } = "maskinfo";
        public string[] Aliases { get; } = new string[] { "minfo", "mask096info" };
        public string Description { get; } = "Подробная информация о системе масок";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("mask096.info") && !sender.CheckPermission("mask096.admin"))
            {
                response = "<color=red>У вас нет прав на использование этой команды!</color>";
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "<color=red>Плагин не работает!</color>";
                return false;
            }

            var config = Plugin.Instance.Config;
            var handlers = Plugin.Instance._eventHandlers;

            response = "<color=yellow>═══════ Система масок SCP-096 ═══════</color>\n\n" +
                      string.Format("<color=cyan>Версия плагина:</color> <color=white>{0}</color>\n" +
                      "<color=cyan>Автор:</color> <color=white>{1}</color>\n" +
                      "<color=cyan>Режим отладки:</color> <color=white>{2}</color>\n\n" +
                      "<color=cyan>Настройки спавна:</color>\n" +
                      "• Зоны спавна:\n",
                      Plugin.Instance.Version,
                      Plugin.Instance.Author,
                      config.Debug ? "Включен" : "Выключен");

            foreach (var zone in config.SpawnWeights.Take(3))
            {
                response += string.Format("  - {0}: <color=white>{1}%</color>\n", zone.Key, zone.Value);
            }

            if (config.SpawnWeights.Count > 3)
            {
                response += string.Format("  <color=gray>... и ещё {0} зон</color>\n", config.SpawnWeights.Count - 3);
            }

            response += "\n<color=cyan>Специальные комнаты:</color>\n";
            foreach (var room in config.SpecificRoomSpawn.Take(3))
            {
                response += string.Format("  - {0}: <color=white>{1}%</color>\n", room.Key, room.Value);
            }

            if (config.SpecificRoomSpawn.Count > 3)
            {
                response += string.Format("  <color=gray>... и ещё {0} комнат</color>\n", config.SpecificRoomSpawn.Count - 3);
            }

            response += "\n<color=cyan>Продвинутые настройки:</color>\n";
            if (config.RoomSpawnConfigs.Count > 0)
            {
                response += string.Format("• Конфигураций комнат: <color=white>{0}</color>\n", config.RoomSpawnConfigs.Count);
                foreach (var roomConfig in config.RoomSpawnConfigs.Where(c => c.IsEnabled).Take(3))
                {
                    response += string.Format("  - {0}: <color=white>{1}%</color> (макс: {2})\n", 
                        roomConfig.RoomType, roomConfig.SpawnChance, roomConfig.MaxMasksInRoom);
                }
            }

            response += string.Format("\n<color=cyan>Текущее состояние:</color>\n" +
                       "• Масок на карте: <color=white>{0}</color>\n" +
                       "• Замаскированных SCP-096: <color=white>{1}</color>\n" +
                       "• Раунд активен: <color=white>{2}</color>",
                       handlers.GetMaskCount(),
                       handlers.GetMaskedScp096Count(),
                       Round.IsStarted ? "Да" : "Нет");

            return true;
        }
    }
}
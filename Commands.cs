using System;
using System.Linq;
using System.Collections.Generic;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using Exiled.API.Features.Items;
using Exiled.API.Features.Pickups;
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
            try
            {
                // Проверяем права для админских команд
                bool isAdmin = sender.CheckPermission("mask096.admin");
                bool isPlayer = sender is Player;

                if (arguments.Count == 0)
                {
                    response = GetHelpMessage(isAdmin);
                    return true;
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
                        response = "<color=red>Неизвестная подкоманда:</color> " + subCommand + "\n" + GetHelpMessage(isAdmin);
                        return false;
                }
            }
            catch (Exception ex)
            {
                response = "<color=red>Критическая ошибка команды:</color> " + ex.Message;
                if (Plugin.Instance != null && Plugin.Instance.Config.Debug)
                {
                    Log.Error("Ошибка в команде mask096: " + ex);
                }
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
            try
            {
                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
                {
                    response = "<color=red>Плагин не работает!</color>";
                    return false;
                }

                if (!Plugin.Instance._eventHandlers.HasMask(player))
                {
                    response = "<color=red>У вас нет маски SCP-096!</color>";
                    return false;
                }

                Plugin.Instance._eventHandlers.TryInteractWithScp096(player);
                response = "<color=green>Попытка использовать маску...</color>";
                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool HandleDebugCommand(ArraySegment<string> arguments, out string response)
        {
            try
            {
                if (Plugin.Instance == null)
                {
                    response = "<color=red>Плагин не загружен!</color>";
                    return false;
                }

                if (arguments.Count < 2)
                {
                    string debugStatus = Plugin.Instance.Config.Debug ? "<color=green>Включен</color>" : "<color=red>Выключен</color>";
                    response = "<color=yellow>Режим отладки:</color> " + debugStatus + "\nИспользование: mask096 debug <on/off>";
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
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды debug: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool HandleSpawnCommand(ArraySegment<string> arguments, out string response)
        {
            try
            {
                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
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
                            response = "<color=red>Некорректное количество!</color>\nДоступно: от 1 до " + 
                                Plugin.Instance.Config.AdvancedSpawn.MaxMasksOnMap.ToString();
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

                response = "<color=green>✓ Заспавнено " + count.ToString() + " масок SCP-096!</color>\n" +
                          "<color=yellow>Всего масок на карте:</color> " + Plugin.Instance._eventHandlers.GetMaskCount().ToString();
                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды spawn: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool ShowMasksInfo(out string response)
        {
            try
            {
                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
                {
                    response = "<color=red>Плагин не работает!</color>";
                    return false;
                }

                var config = Plugin.Instance.Config;
                var handlers = Plugin.Instance._eventHandlers;

                response = "<color=yellow>═══════ Информация о масках SCP-096 ═══════</color>\n" +
                          "<color=cyan>Статус плагина:</color> <color=green>Активен</color>\n" +
                          "<color=cyan>Масок на карте:</color> <color=white>" + handlers.GetMaskCount().ToString() + "</color>\n" +
                          "<color=cyan>Замаскированных SCP-096:</color> <color=white>" + handlers.GetMaskedScp096Count().ToString() + "</color>\n" +
                          "<color=cyan>Максимум масок:</color> <color=white>" + config.AdvancedSpawn.MaxMasksOnMap.ToString() + "</color>\n\n" +
                          "<color=cyan>Настройки:</color>\n" +
                          "• Время одевания: <color=white>" + config.MaskEquipTime.ToString("F1") + "с</color>\n" +
                          "• Дистанция взаимодействия: <color=white>" + config.InteractionDistance.ToString("F1") + "м</color>\n" +
                          "• Автоспавн: <color=white>" + (config.AutoSpawnEnabled ? "Включен" : "Выключен") + "</color>\n" +
                          "• Требуется маска в руке: <color=white>" + (config.RequireMaskInHand ? "Да" : "Нет") + "</color>\n" +
                          "• Респавн масок: <color=white>" + (config.AdvancedSpawn.EnableRespawn ? "Включен" : "Выключен") + "</color>\n\n" +
                          "<color=cyan>Визуальные эффекты:</color>\n" +
                          "• Растяжение X: <color=white>" + config.VisualSettings.ScaleX.ToString("F1") + "x</color>\n" +
                          "• Растяжение Y: <color=white>" + config.VisualSettings.ScaleY.ToString("F1") + "x</color>\n" +
                          "• Растяжение Z: <color=white>" + config.VisualSettings.ScaleZ.ToString("F1") + "x</color>\n" +
                          "• Деформация: <color=white>" + (config.VisualSettings.EnableDeformation ? "Включена" : "Выключена") + "</color>";

                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды info: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool ShowDetailedStats(out string response)
        {
            try
            {
                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
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
                          "<color=cyan>Состояние раунда:</color>\n" +
                          "• Всего игроков: <color=white>" + totalPlayers.ToString() + "</color>\n" +
                          "• SCP-096 в раунде: <color=white>" + scp096Count.ToString() + "</color>\n" +
                          "• Замаскированных: <color=white>" + handlers.GetMaskedScp096Count().ToString() + "</color>\n" +
                          "• Игроков с масками: <color=white>" + playersWithMasks.ToString() + "</color>\n\n" +
                          "<color=cyan>Маски на карте:</color>\n" +
                          "• Активных масок: <color=white>" + handlers.GetMaskCount().ToString() + "</color>\n" +
                          "• Максимальный лимит: <color=white>" + config.AdvancedSpawn.MaxMasksOnMap.ToString() + "</color>\n" +
                          "• Минимальное расстояние: <color=white>" + config.MinMaskDistance.ToString("F1") + "м</color>\n\n" +
                          "<color=cyan>Конфигурация спавна:</color>\n" +
                          "• Спавн по умолчанию: <color=white>" + config.MasksToSpawn.ToString() + "</color>\n" +
                          "• Мин. игроков для спавна: <color=white>" + config.AdvancedSpawn.MinPlayersForSpawn.ToString() + "</color>\n" +
                          "• Только при наличии SCP-096: <color=white>" + (config.AdvancedSpawn.OnlyWhenScp096Present ? "Да" : "Нет") + "</color>\n" +
                          "• Продвинутый спавн: <color=white>" + (config.AdvancedSpawn.UseAdvancedRoomSpawn ? "Включен" : "Выключен") + "</color>\n\n" +
                          "<color=cyan>Визуальные эффекты:</color>\n" +
                          "• Масштаб X/Y/Z: <color=white>" + config.VisualSettings.ScaleX.ToString("F1") + "/" + config.VisualSettings.ScaleY.ToString("F1") + "/" + config.VisualSettings.ScaleZ.ToString("F1") + "</color>\n" +
                          "• Свечение: <color=white>" + (config.VisualSettings.EnableGlow ? "Включено" : "Выключено") + "</color>\n" +
                          "• Вращение: <color=white>" + (config.VisualSettings.EnableRotation ? "Включено" : "Выключено") + "</color>\n" +
                          "• Подпрыгивание: <color=white>" + (config.VisualSettings.EnableBobbing ? "Включено" : "Выключено") + "</color>\n" +
                          "• Деформация: <color=white>" + (config.VisualSettings.EnableDeformation ? "Включена" : "Выключена") + "</color>";

                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды stats: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool HandleGiveCommand(ArraySegment<string> arguments, out string response)
        {
            try
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
                    response = "<color=red>Игрок с ID '" + arguments.At(1) + "' не найден!</color>";
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

                // Создаем пикап напрямую
                var pickup = Pickup.CreateAndSpawn(ItemType.Medkit, position, Quaternion.identity);
                
                if (Plugin.Instance != null && Plugin.Instance._eventHandlers != null && pickup != null)
                {
                    Plugin.Instance._eventHandlers.spawnedMasks.Add(pickup);
                    
                    // Применяем визуальные эффекты через рефлексию
                    var methodInfo = typeof(EventHandlers).GetMethod("ApplyMaskVisualEffects", 
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                    methodInfo?.Invoke(Plugin.Instance._eventHandlers, new object[] { pickup });
                }
                
                response = "<color=green>✓ Маска SCP-096 создана!</color>\n" +
                          "<color=cyan>Позиция:</color> <color=white>" + position.x.ToString("F1") + ", " + position.y.ToString("F1") + ", " + position.z.ToString("F1") + "</color>\n" +
                          "<color=cyan>Для игрока:</color> <color=yellow>" + player.Nickname + "</color> (<color=gray>" + player.Id.ToString() + "</color>)";
                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка при создании маски: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool HandleGiveInventoryCommand(ArraySegment<string> arguments, out string response)
        {
            try
            {
                if (arguments.Count < 2)
                {
                    response = "<color=red>Используйте:</color> mask096 giveinv <userid>";
                    return false;
                }

                Player player = Player.Get(arguments.At(1));
                if (player == null)
                {
                    response = "<color=red>Игрок с ID '" + arguments.At(1) + "' не найден!</color>";
                    return false;
                }

                if (!player.IsAlive)
                {
                    response = "<color=red>Игрок " + player.Nickname + " мертв!</color>";
                    return false;
                }

                if (Plugin.Instance != null && Plugin.Instance._eventHandlers != null && 
                    Plugin.Instance._eventHandlers.HasMask(player))
                {
                    response = "<color=orange>У игрока " + player.Nickname + " уже есть маска!</color>";
                    return false;
                }

                var medkit = player.AddItem(ItemType.Medkit);
                
                if (Plugin.Instance != null && Plugin.Instance._eventHandlers != null)
                {
                    Plugin.Instance._eventHandlers.AddPlayerMask(player, medkit);
                }
                
                response = "<color=green>✓ Маска SCP-096 выдана!</color>\n" +
                          "<color=cyan>Игрок:</color> <color=yellow>" + player.Nickname + "</color> (<color=gray>" + player.Id.ToString() + "</color>)\n" +
                          "<color=gray>Маска добавлена в инвентарь</color>";
                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка при выдаче маски: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool HandleRemoveCommand(ArraySegment<string> arguments, out string response)
        {
            try
            {
                if (arguments.Count < 2)
                {
                    response = "<color=red>Используйте:</color> mask096 remove <userid>";
                    return false;
                }

                Player player = Player.Get(arguments.At(1));
                if (player == null)
                {
                    response = "<color=red>Игрок с ID '" + arguments.At(1) + "' не найден!</color>";
                    return false;
                }

                if (player.Role.Type != RoleTypeId.Scp096)
                {
                    response = "<color=red>Игрок " + player.Nickname + " не является SCP-096!</color>";
                    return false;
                }

                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
                {
                    response = "<color=red>Плагин не работает!</color>";
                    return false;
                }

                if (!Plugin.Instance._eventHandlers.IsScp096Masked(player))
                {
                    response = "<color=orange>На SCP-096 " + player.Nickname + " нет маски!</color>";
                    return false;
                }

                Plugin.Instance._eventHandlers.RemoveMaskFromScp096(player);
                response = "<color=green>✓ Маска снята с SCP-096!</color>\n" +
                          "<color=cyan>Игрок:</color> <color=yellow>" + player.Nickname + "</color> (<color=gray>" + player.Id.ToString() + "</color>)";
                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды remove: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool ListMaskedScps(out string response)
        {
            try
            {
                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
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

                response = "<color=yellow>═══ Замаскированные SCP-096 (" + maskedScps.Count.ToString() + ") ═══</color>\n";
                
                for (int i = 0; i < maskedScps.Count; i++)
                {
                    var scp = maskedScps[i];
                    string status = scp.IsAlive ? "<color=green>Жив</color>" : "<color=red>Мертв</color>";
                    string health = scp.IsAlive ? ("HP: <color=white>" + scp.Health.ToString("F0") + "</color>") : "";
                    
                    response += "<color=cyan>" + (i + 1).ToString() + ".</color> <color=yellow>" + scp.Nickname + "</color> " +
                               "<color=gray>(ID: " + scp.Id.ToString() + ")</color> " + status + " " + health + "\n";
                }

                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды list: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool HandleClearCommand(out string response)
        {
            try
            {
                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
                {
                    response = "<color=red>Плагин не работает!</color>";
                    return false;
                }

                int maskCount = Plugin.Instance._eventHandlers.GetMaskCount();
                
                // Очищаем все маски
                Plugin.Instance._eventHandlers.ClearAllMasks();

                response = "<color=green>✓ Все маски удалены с карты!</color>\n" +
                          "<color=cyan>Удалено масок:</color> <color=white>" + maskCount.ToString() + "</color>";
                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды clear: " + ex.Message + "</color>";
                return false;
            }
        }

        private bool HandleReloadCommand(out string response)
        {
            try
            {
                if (Plugin.Instance == null)
                {
                    response = "<color=red>Плагин не загружен!</color>";
                    return false;
                }

                Plugin.Instance.ReloadConfig();
                
                response = "<color=green>✓ Конфигурация перезагружена!</color>\n" +
                          "<color=yellow>Изменения вступят в силу в следующем раунде</color>";
                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка при перезагрузке: " + ex.Message + "</color>";
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
            try
            {
                if (!(sender is Player player))
                {
                    response = "Эта команда доступна только игрокам!";
                    return false;
                }

                // Переадресуем на основную команду
                return new MaskCommands().Execute(new ArraySegment<string>(new string[] { "use" }), sender, out response);
            }
            catch (Exception ex)
            {
                response = "Ошибка команды: " + ex.Message;
                return false;
            }
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
            try
            {
                if (!sender.CheckPermission("mask096.info") && !sender.CheckPermission("mask096.admin"))
                {
                    response = "<color=red>У вас нет прав на использование этой команды!</color>";
                    return false;
                }

                if (Plugin.Instance == null || Plugin.Instance._eventHandlers == null)
                {
                    response = "<color=red>Плагин не работает!</color>";
                    return false;
                }

                var config = Plugin.Instance.Config;
                var handlers = Plugin.Instance._eventHandlers;

                response = "<color=yellow>═══════ Система масок SCP-096 ═══════</color>\n\n" +
                          "<color=cyan>Версия плагина:</color> <color=white>" + Plugin.Instance.Version.ToString() + "</color>\n" +
                          "<color=cyan>Автор:</color> <color=white>" + Plugin.Instance.Author + "</color>\n" +
                          "<color=cyan>Режим отладки:</color> <color=white>" + (config.Debug ? "Включен" : "Выключен") + "</color>\n\n" +
                          "<color=cyan>Настройки спавна:</color>\n" +
                          "• Зоны спавна:\n";

                foreach (var zone in config.SpawnWeights.Take(3))
                {
                    response += "  - " + zone.Key.ToString() + ": <color=white>" + zone.Value.ToString() + "%</color>\n";
                }

                if (config.SpawnWeights.Count > 3)
                {
                    response += "  <color=gray>... и ещё " + (config.SpawnWeights.Count - 3).ToString() + " зон</color>\n";
                }

                response += "\n<color=cyan>Специальные комнаты:</color>\n";
                foreach (var room in config.SpecificRoomSpawn.Take(3))
                {
                    response += "  - " + room.Key.ToString() + ": <color=white>" + room.Value.ToString() + "%</color>\n";
                }

                if (config.SpecificRoomSpawn.Count > 3)
                {
                    response += "  <color=gray>... и ещё " + (config.SpecificRoomSpawn.Count - 3).ToString() + " комнат</color>\n";
                }

                response += "\n<color=cyan>Продвинутые настройки:</color>\n";
                if (config.RoomSpawnConfigs.Count > 0)
                {
                    response += "• Конфигураций комнат: <color=white>" + config.RoomSpawnConfigs.Count.ToString() + "</color>\n";
                    foreach (var roomConfig in config.RoomSpawnConfigs.Where(c => c.IsEnabled).Take(3))
                    {
                        response += "  - " + roomConfig.RoomType.ToString() + ": <color=white>" + roomConfig.SpawnChance.ToString() + "%</color> (макс: " + roomConfig.MaxMasksInRoom.ToString() + ")\n";
                    }
                }

                response += "\n<color=cyan>Текущее состояние:</color>\n" +
                           "• Масок на карте: <color=white>" + handlers.GetMaskCount().ToString() + "</color>\n" +
                           "• Замаскированных SCP-096: <color=white>" + handlers.GetMaskedScp096Count().ToString() + "</color>\n" +
                           "• Раунд активен: <color=white>" + (Round.IsStarted ? "Да" : "Нет") + "</color>";

                return true;
            }
            catch (Exception ex)
            {
                response = "<color=red>Ошибка команды maskinfo: " + ex.Message + "</color>";
                return false;
            }
        }
    }
}
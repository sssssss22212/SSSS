using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using Exiled.API.Features.Items;

namespace Scp096Mask.Commands
{
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    [CommandHandler(typeof(GameConsoleCommandHandler))]
    public class MaskCommands : ICommand
    {
        public string Command { get; } = "mask096";
        public string[] Aliases { get; } = new[] { "mask", "scp096mask" };
        public string Description { get; } = "Управление масками SCP-096";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("mask096.admin"))
            {
                response = "У вас нет прав на использование этой команды!";
                return false;
            }

            if (arguments.Count == 0)
            {
                response = "Использование:\n" +
                          "mask096 spawn - заспавнить маски\n" +
                          "mask096 info - информация о масках\n" +
                          "mask096 give <userid> - выдать маску в инвентарь\n" +
                          "mask096 create <userid> - создать маску рядом с игроком\n" +
                          "mask096 remove <userid> - снять маску с SCP-096\n" +
                          "mask096 list - список замаскированных SCP-096\n" +
                          "mask096 clear - очистить все маски";
                return false;
            }

            switch (arguments.At(0).ToLower())
            {
                case "spawn":
                    return SpawnMasks(out response);

                case "info":
                    return ShowMasksInfo(out response);

                case "give":
                    if (arguments.Count < 2)
                    {
                        response = "Используйте: mask096 give <userid>";
                        return false;
                    }
                    return GiveMaskInventory(arguments.At(1), out response);

                case "create":
                    if (arguments.Count < 2)
                    {
                        response = "Используйте: mask096 create <userid>";
                        return false;
                    }
                    return CreateMaskNearPlayer(arguments.At(1), out response);

                case "remove":
                    if (arguments.Count < 2)
                    {
                        response = "Используйте: mask096 remove <userid>";
                        return false;
                    }
                    return RemoveMask(arguments.At(1), out response);

                case "list":
                    return ListMaskedScps(out response);

                case "clear":
                    return ClearAllMasks(out response);

                default:
                    response = "Неизвестная подкоманда. Доступно: spawn, info, give, create, remove, list, clear";
                    return false;
            }
        }

        private bool SpawnMasks(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин не работает";
                return false;
            }

            Plugin.Instance._eventHandlers.SpawnMasks();
            response = $"{Plugin.Instance.Config.MasksToSpawn} масок SCP-096 заспавнено!";
            return true;
        }

        private bool ShowMasksInfo(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин не работает";
                return false;
            }

            var masks = Plugin.Instance._eventHandlers.spawnedMasks;
            var maskedScps = Player.List.Where(p => p.Role.Type == PlayerRoles.RoleTypeId.Scp096 && 
                                                   Plugin.Instance._eventHandlers.IsScp096Masked(p)).Count();

            response = $"<color=yellow>Информация о масках SCP-096:</color>\n" +
                      $"Заспавнено масок в мире: {masks.Count}\n" +
                      $"SCP-096 с масками: {maskedScps}\n" +
                      $"Время одевания: {Plugin.Instance.Config.MaskEquipTime} сек\n" +
                      $"Дистанция взаимодействия: {Plugin.Instance.Config.InteractionDistance} м\n" +
                      $"Автоспавн: {(Plugin.Instance.Config.AutoSpawnEnabled ? "да" : "нет")}\n" +
                      $"Визуальные эффекты: {(Plugin.Instance.Config.MaskDisplay.GlowEffect ? "включены" : "выключены")}";

            return true;
        }

        private bool CreateMaskNearPlayer(string userId, out string response)
        {
            Player player = Player.Get(userId);
            if (player == null)
            {
                response = $"Игрок с ID {userId} не найден!";
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин не работает";
                return false;
            }

            // Создаем маску рядом с игроком
            var medkitItem = Item.Create(ItemType.Medkit);
            var pickup = medkitItem.CreatePickup(player.Position + player.Transform.forward * 2f);
            
            // Модифицируем внешний вид и добавляем в список масок
            Plugin.Instance._eventHandlers.spawnedMasks.Add(pickup);
            
            response = $"Создана маска SCP-096 рядом с игроком <color=green>{player.Nickname}</color> (<color=#aaaaaa>{player.Id}</color>)";
            return true;
        }

        private bool GiveMaskInventory(string userId, out string response)
        {
            Player player = Player.Get(userId);
            if (player == null)
            {
                response = $"Игрок с ID {userId} не найден!";
                return false;
            }

            // Проверяем, есть ли уже маска у игрока
            if (Plugin.Instance?._eventHandlers != null && 
                Plugin.Instance._eventHandlers.HasMask(player))
            {
                response = $"У игрока {player.Nickname} уже есть маска!";
                return false;
            }

            // Добавляем аптечку в инвентарь
            var medkit = player.AddItem(ItemType.Medkit);
            
            // Регистрируем как маску
            if (Plugin.Instance?._eventHandlers != null)
            {
                Plugin.Instance._eventHandlers.AddPlayerMask(player, medkit);
            }
            
            response = $"Выдана маска SCP-096 в инвентарь игроку <color=green>{player.Nickname}</color> (<color=#aaaaaa>{player.Id}</color>)";
            return true;
        }

        private bool RemoveMask(string userId, out string response)
        {
            Player player = Player.Get(userId);
            if (player == null)
            {
                response = $"Игрок с ID {userId} не найден!";
                return false;
            }

            if (player.Role.Type != PlayerRoles.RoleTypeId.Scp096)
            {
                response = $"Игрок {player.Nickname} не является SCP-096!";
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин не работает";
                return false;
            }

            if (!Plugin.Instance._eventHandlers.IsScp096Masked(player))
            {
                response = $"На SCP-096 {player.Nickname} нет маски!";
                return false;
            }

            Plugin.Instance._eventHandlers.RemoveMaskFromScp096(player);
            response = $"Маска снята с SCP-096 <color=green>{player.Nickname}</color>";
            return true;
        }

        private bool ListMaskedScps(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин не работает";
                return false;
            }

            var maskedScps = Player.List
                .Where(p => p.Role.Type == PlayerRoles.RoleTypeId.Scp096 && 
                           Plugin.Instance._eventHandlers.IsScp096Masked(p))
                .ToList();

            if (maskedScps.Count == 0)
            {
                response = "Нет SCP-096 с масками";
                return true;
            }

            response = $"<color=yellow>SCP-096 с масками ({maskedScps.Count}):</color>\n";
            foreach (var scp in maskedScps)
            {
                response += $"• <color=green>{scp.Nickname}</color> (ID: {scp.Id})\n";
            }

            return true;
        }

        private bool ClearAllMasks(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "Плагин не работает";
                return false;
            }

            int maskCount = Plugin.Instance._eventHandlers.spawnedMasks.Count;
            
            // Очищаем все маски из мира
            foreach (var mask in Plugin.Instance._eventHandlers.spawnedMasks.ToList())
            {
                try
                {
                    if (mask != null && mask.IsSpawned)
                        mask.Destroy();
                }
                catch (Exception ex)
                {
                    Log.Debug($"Ошибка при удалении маски: {ex}");
                }
            }
            
            Plugin.Instance._eventHandlers.spawnedMasks.Clear();
            
            response = $"Удалено {maskCount} масок SCP-096 из мира";
            return true;
        }
    }
}
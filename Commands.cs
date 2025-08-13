using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using Exiled.API.Features.Pickups;
using Exiled.API.Enums;
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
                response = "❌ У вас нет прав на использование этой команды!";
                return false;
            }

            if (arguments.Count == 0)
            {
                response = "ℹ Использование:\n" +
                          "mask096 spawn - заспавнить маски\n" +
                          "mask096 info - информация о масках\n" +
                          "mask096 give <userid> - выдать маску игроку\n" +
                          "mask096 remove <userid> - снять маску с SCP-096\n" +
                          "mask096 list - список замаскированных SCP-096";
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
                        response = "ℹ Используйте: mask096 give <userid>";
                        return false;
                    }
                    return GiveMask(arguments.At(1), out response);

                case "remove":
                    if (arguments.Count < 2)
                    {
                        response = "ℹ Используйте: mask096 remove <userid>";
                        return false;
                    }
                    return RemoveMask(arguments.At(1), out response);

                case "list":
                    return ListMaskedScps(out response);

                default:
                    response = "❌ Неизвестная подкоманда. Доступно: spawn, info, give, remove, list";
                    return false;
            }
        }

        private bool SpawnMasks(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "❌ Плагин не инициализирован!";
                return false;
            }

            Plugin.Instance._eventHandlers.SpawnMasks();
            response = $"♻ {Plugin.Instance.Config.MasksToSpawn} масок SCP-096 заспавнено!";
            return true;
        }

        private bool ShowMasksInfo(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "❌ Плагин не инициализирован!";
                return false;
            }

            var masks = Plugin.Instance._eventHandlers.spawnedMasks;
            response = $"<color=yellow>🎭 Информация о масках SCP-096:</color>\n" +
                      $"Заспавнено масок: {masks.Count}\n" +
                      $"Время одевания: {Plugin.Instance.Config.MaskEquipTime} сек\n" +
                      $"Дистанция взаимодействия: {Plugin.Instance.Config.InteractionDistance} м\n" +
                      $"Автоспавн: {(Plugin.Instance.Config.AutoSpawnEnabled ? "✅" : "❌")}";

            return true;
        }

        private bool GiveMask(string userId, out string response)
        {
            Player player = Player.Get(userId);
            if (player == null)
            {
                response = $"❌ Игрок с ID {userId} не найден!";
                return false;
            }

            // Создаем pickup рядом с игроком
            var medkitItem = Item.Create(ItemType.Medkit);
            var pickup = medkitItem.CreatePickup(player.Position);
            
            response = $"✅ Создали маску SCP-096 рядом с игроком <color=green>{player.Nickname}</color> (<color=#aaaaaa>{player.Id}</color>)";
            return true;
        }

        private bool RemoveMask(string userId, out string response)
        {
            Player player = Player.Get(userId);
            if (player == null)
            {
                response = $"❌ Игрок с ID {userId} не найден!";
                return false;
            }

            if (player.Role.Type != PlayerRoles.RoleTypeId.Scp096)
            {
                response = $"❌ Игрок {player.Nickname} не является SCP-096!";
                return false;
            }

            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "❌ Плагин не инициализирован!";
                return false;
            }

            if (!Plugin.Instance._eventHandlers.IsScp096Masked(player))
            {
                response = $"❌ На SCP-096 {player.Nickname} нет маски!";
                return false;
            }

            Plugin.Instance._eventHandlers.RemoveMaskFromScp096(player);
            response = $"✅ Маска снята с SCP-096 <color=green>{player.Nickname}</color>";
            return true;
        }

        private bool ListMaskedScps(out string response)
        {
            if (Plugin.Instance?._eventHandlers == null)
            {
                response = "❌ Плагин не инициализирован!";
                return false;
            }

            var maskedScps = Player.List
                .Where(p => p.Role.Type == PlayerRoles.RoleTypeId.Scp096 && 
                           Plugin.Instance._eventHandlers.IsScp096Masked(p))
                .ToList();

            if (maskedScps.Count == 0)
            {
                response = "ℹ Нет замаскированных SCP-096";
                return true;
            }

            response = $"<color=yellow>🎭 Замаскированные SCP-096 ({maskedScps.Count}):</color>\n";
            foreach (var scp in maskedScps)
            {
                response += $"• <color=green>{scp.Nickname}</color> (ID: {scp.Id})\n";
            }

            return true;
        }
    }
}
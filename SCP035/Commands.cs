using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;

namespace SCP035
{
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    [CommandHandler(typeof(GameConsoleCommandHandler))]
    public class Scp035Command : ICommand
    {
        public string Command => "scp035";
        public string[] Aliases => new[] { "035" };
        public string Description => "Управление SCP-035: info, give <userid>, respawn, set <userid>, map";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("scp035.admin"))
            {
                response = "❌ Нет прав.";
                return false;
            }

            if (arguments.Count == 0)
            {
                response = "Использование: scp035 info | scp035 give <userid> | scp035 respawn";
                return false;
            }

            switch (arguments.At(0).ToLower())
            {
                case "info":
                    response = $"Активных масок на карте: {Plugin.Instance.spawnedMasks.Count(m => m != null && m.IsSpawned)}";
                    return true;

                case "give":
                    if (arguments.Count < 2)
                    {
                        response = "Использование: scp035 give <userid>";
                        return false;
                    }
                    var player = Player.Get(arguments.At(1));
                    if (player == null)
                    {
                        response = "Игрок не найден.";
                        return false;
                    }
                    player.AddItem(Exiled.API.Enums.ItemType.SCP268);
                    response = $"Выдана маска SCP-035 игроку {player.Nickname}.";
                    return true;

                case "respawn":
                    Plugin.Instance.TrySpawnMasksAtRoundStart();
                    response = "Маски перезаспавнены по текущим настройкам.";
                    return true;

                case "set":
                    if (arguments.Count < 2)
                    {
                        response = "Использование: scp035 set <userid>";
                        return false;
                    }
                    var p2 = Player.Get(arguments.At(1));
                    if (p2 == null)
                    {
                        response = "Игрок не найден.";
                        return false;
                    }
                    PluginUtils.ForceBecome035(p2);
                    response = $"Игрок {p2.Nickname} стал носителем SCP-035.";
                    return true;

                case "map":
                    var groups = Plugin.Instance.spawnedMasks
                        .Where(pk => pk != null && pk.IsSpawned)
                        .GroupBy(pk =>
                        {
                            var room = Exiled.API.Features.Room.FindParentRoom(pk.GameObject);
                            return room != null ? room.Zone : Exiled.API.Enums.ZoneType.Unspecified;
                        })
                        .OrderBy(g => g.Key);

                    response = "Маски SCP-035 по зонам:\n";
                    foreach (var g in groups)
                        response += $"{g.Key}: {g.Count()}\n";
                    return true;
            }

            response = "Неизвестная подкоманда.";
            return false;
        }
    }
}
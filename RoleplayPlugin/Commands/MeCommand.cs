using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;

namespace RpPlugin.Commands
{
    [CommandHandler(typeof(ClientCommandHandler))]
    public class MeCommand : ICommand
    {
        public string Command => "me";
        public string[] Aliases => Array.Empty<string>();
        public string Description => "Эмоция в радиусе (по умолчанию 15м): /me действие";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!RoleplayPlugin.Instance.Config.IsEnabled)
            {
                response = "Плагин отключён";
                return false;
            }

            if (!Player.TryGet(sender, out var player))
            {
                response = "Команда только для игрока";
                return false;
            }

            if (arguments.Count == 0)
            {
                response = "Использование: .me действие";
                return false;
            }

            string text = string.Join(" ", arguments);
            string msg = $"<i><color=#c2c2c2>{player.Nickname} {text}</color></i>";
            int recipients = RpPlugin.EventHandlers.SendProximityMessage(player, RoleplayPlugin.Instance.Config.MeRadius, msg);

            response = $"Отправлено игрокам поблизости: {recipients}";
            return true;
        }
    }
}
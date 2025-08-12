using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;

namespace RpPlugin.Commands
{
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    public class RpCommand : ICommand
    {
        public string Command => "rp";
        public string[] Aliases => new[] { "roleplay" };
        public string Description => "Управление RP режимом: enable|disable|status";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (arguments.Count == 0)
            {
                response = "Использование: rp enable|disable|status";
                return false;
            }

            string sub = arguments.ElementAt(0).ToLowerInvariant();
            switch (sub)
            {
                case "enable":
                    RoleplayPlugin.Instance.IsRpModeEnabled = true;
                    response = "RP режим: ВКЛ";
                    Map.Broadcast(6, "<b><color=#9df291>RP режим включён</color></b>");
                    return true;
                case "disable":
                    RoleplayPlugin.Instance.IsRpModeEnabled = false;
                    response = "RP режим: ВЫКЛ";
                    Map.Broadcast(6, "<b><color=#f29d9d>RP режим выключен</color></b>");
                    return true;
                case "status":
                    response = $"RP режим: {(RoleplayPlugin.Instance.IsRpModeEnabled ? "ВКЛ" : "ВЫКЛ")}";
                    return true;
                default:
                    response = "Неизвестная подкоманда. Используйте: enable|disable|status";
                    return false;
            }
        }
    }
}
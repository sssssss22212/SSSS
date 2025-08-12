using System;
using System.Collections.Generic;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;

namespace HelloSCP.Commands
{
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    [CommandHandler(typeof(GameConsoleCommandHandler))]
    [CommandHandler(typeof(ClientCommandHandler))]
    public sealed class HelloCommand : ICommand
    {
        public string Command => "hello";
        public string[] Aliases => new[] { "hi" };
        public string Description => "Отправляет приветствие. Требуется разрешение 'helloscp.use'.";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            // Permission check (works for RA and clients)
            if (!sender.CheckPermission("helloscp.use"))
            {
                response = "Недостаточно прав. Требуется permission: helloscp.use";
                return false;
            }

            string targetName = sender is PlayerCommandSender pSender ? pSender.ReferenceHub.nicknameSync.Network_myNickSync : sender.Nickname;

            string message = Plugin.Instance?.Config?.WelcomeMessage?.Replace("{player}", targetName) ?? $"Привет, {targetName}!";

            // If a player executes from client, also show them a hint
            if (sender is PlayerCommandSender pcs)
            {
                var player = Player.Get(pcs.ReferenceHub);
                player.ShowHint(message, 5);
            }

            response = message;
            return true;
        }
    }
}
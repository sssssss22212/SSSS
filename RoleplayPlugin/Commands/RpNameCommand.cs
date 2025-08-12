using System;
using System.Linq;
using System.Text.RegularExpressions;
using CommandSystem;
using Exiled.API.Features;

namespace RpPlugin.Commands
{
    [CommandHandler(typeof(ClientCommandHandler))]
    public class RpNameCommand : ICommand
    {
        public string Command => "rpname";
        public string[] Aliases => new[] { "name", "nick" };
        public string Description => "Установить RP-имя (/rpname Имя Фамилия)";

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
                response = "Использование: .rpname Имя Фамилия";
                return false;
            }

            string requested = string.Join(" ", arguments);
            var cfg = RoleplayPlugin.Instance.Config;

            if (requested.Length > cfg.MaxRpNameLength)
            {
                response = $"Слишком длинно (>{cfg.MaxRpNameLength})";
                return false;
            }

            if (!Regex.IsMatch(requested, cfg.AllowedNameRegex))
            {
                response = "Недопустимые символы или длина";
                return false;
            }

            // Применяем имя через обработчик
            RoleplayPlugin.Instance.Handlers.TryApplyDisplayName(player, requested);

            response = $"RP-имя установлено: {requested}";
            player.ShowHint($"Имя установлено: {requested}", 5f);
            return true;
        }
    }
}
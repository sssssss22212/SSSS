using System;
using System.Text;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using System.Linq;

namespace PlayerManagerPlugin.Commands
{
    /// <summary>
    /// Команда для просмотра очков игроков
    /// </summary>
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    public class PointsCommand : ICommand
    {
        /// <summary>
        /// Название команды
        /// </summary>
        public string Command => "points";

        /// <summary>
        /// Алиасы команды
        /// </summary>
        public string[] Aliases => new[] { "pts", "очки" };

        /// <summary>
        /// Описание команды
        /// </summary>
        public string Description => "Показывает очки игроков или очки конкретного игрока";

        /// <summary>
        /// Выполнение команды
        /// </summary>
        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("pm.points"))
            {
                response = "У вас нет разрешения на использование этой команды!";
                return false;
            }

            if (!PlayerManagerPlugin.Instance.Config.EnablePointSystem)
            {
                response = "Система очков отключена в конфигурации плагина!";
                return false;
            }

            // Если указан конкретный игрок
            if (arguments.Count > 0)
            {
                string playerName = string.Join(" ", arguments);
                Player targetPlayer = Player.Get(playerName);

                if (targetPlayer == null)
                {
                    response = $"Игрок '{playerName}' не найден!";
                    return false;
                }

                var eventHandlers = PlayerManagerPlugin.Instance.EventHandlers;
                var pointsField = eventHandlers.GetType().GetField("_playerPoints", 
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                
                if (pointsField != null)
                {
                    var playerPoints = (System.Collections.Generic.Dictionary<string, int>)pointsField.GetValue(eventHandlers);
                    int points = playerPoints.ContainsKey(targetPlayer.UserId) ? playerPoints[targetPlayer.UserId] : 0;
                    response = $"Игрок {targetPlayer.Nickname} имеет {points} очков.";
                    return true;
                }
            }

            // Показать всех игроков с очками
            var sb = new StringBuilder();
            sb.AppendLine("=== ОЧКИ ИГРОКОВ ===");

            var eventHandlersInstance = PlayerManagerPlugin.Instance.EventHandlers;
            var pointsFieldAll = eventHandlersInstance.GetType().GetField("_playerPoints", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (pointsFieldAll != null)
            {
                var allPlayerPoints = (System.Collections.Generic.Dictionary<string, int>)pointsFieldAll.GetValue(eventHandlersInstance);
                
                if (allPlayerPoints.Count == 0)
                {
                    sb.AppendLine("Нет данных об очках игроков.");
                }
                else
                {
                    var sortedPoints = new System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<string, int>>(allPlayerPoints);
                    sortedPoints.Sort((x, y) => y.Value.CompareTo(x.Value));

                    foreach (var kvp in sortedPoints)
                    {
                        Player player = Player.List.FirstOrDefault(p => p.UserId == kvp.Key);
                        string playerName = player?.Nickname ?? "Неизвестный игрок";
                        sb.AppendLine($"{playerName}: {kvp.Value} очков");
                    }
                }
            }

            response = sb.ToString();
            return true;
        }
    }
}
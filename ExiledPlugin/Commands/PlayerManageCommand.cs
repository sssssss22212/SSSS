using System;
using System.Linq;
using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using UnityEngine;

namespace PlayerManagerPlugin.Commands
{
    /// <summary>
    /// Команда для управления игроками
    /// </summary>
    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    public class PlayerManageCommand : ICommand
    {
        /// <summary>
        /// Название команды
        /// </summary>
        public string Command => "pm";

        /// <summary>
        /// Алиасы команды
        /// </summary>
        public string[] Aliases => new[] { "playermanager", "пм" };

        /// <summary>
        /// Описание команды
        /// </summary>
        public string Description => "Команды управления игроками (heal/tp/item/info)";

        /// <summary>
        /// Выполнение команды
        /// </summary>
        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (arguments.Count < 1)
            {
                response = GetHelpText();
                return false;
            }

            string action = arguments.At(0).ToLower();

            switch (action)
            {
                case "heal":
                case "хил":
                    return ExecuteHeal(arguments, sender, out response);

                case "tp":
                case "teleport":
                case "тп":
                    return ExecuteTeleport(arguments, sender, out response);

                case "item":
                case "предмет":
                    return ExecuteGiveItem(arguments, sender, out response);

                case "info":
                case "инфо":
                    return ExecutePlayerInfo(arguments, sender, out response);

                case "kick":
                case "кик":
                    return ExecuteKick(arguments, sender, out response);

                case "kill":
                case "убить":
                    return ExecuteKill(arguments, sender, out response);

                default:
                    response = $"Неизвестная команда: {action}\n{GetHelpText()}";
                    return false;
            }
        }

        /// <summary>
        /// Команда лечения игрока
        /// </summary>
        private bool ExecuteHeal(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("pm.heal"))
            {
                response = "У вас нет разрешения на использование команды heal!";
                return false;
            }

            if (arguments.Count < 2)
            {
                response = "Использование: pm heal <игрок> [количество_хп]";
                return false;
            }

            string playerName = arguments.At(1);
            Player targetPlayer = Player.Get(playerName);

            if (targetPlayer == null)
            {
                response = $"Игрок '{playerName}' не найден!";
                return false;
            }

            float healAmount = 100f;
            if (arguments.Count > 2 && float.TryParse(arguments.At(2), out float customAmount))
            {
                healAmount = customAmount;
            }

            targetPlayer.Health = healAmount;
            response = $"Игрок {targetPlayer.Nickname} вылечен на {healAmount} ХП.";
            targetPlayer.ShowHint($"<color=green>Вы были вылечены администратором!</color>", 3);
            return true;
        }

        /// <summary>
        /// Команда телепортации игрока
        /// </summary>
        private bool ExecuteTeleport(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("pm.teleport"))
            {
                response = "У вас нет разрешения на использование команды teleport!";
                return false;
            }

            if (arguments.Count < 3)
            {
                response = "Использование: pm tp <игрок1> <игрок2> - телепортирует игрока1 к игроку2";
                return false;
            }

            string player1Name = arguments.At(1);
            string player2Name = arguments.At(2);

            Player player1 = Player.Get(player1Name);
            Player player2 = Player.Get(player2Name);

            if (player1 == null)
            {
                response = $"Игрок '{player1Name}' не найден!";
                return false;
            }

            if (player2 == null)
            {
                response = $"Игрок '{player2Name}' не найден!";
                return false;
            }

            player1.Teleport(player2.Position);
            response = $"Игрок {player1.Nickname} телепортирован к {player2.Nickname}.";
            player1.ShowHint($"<color=cyan>Вы были телепортированы к {player2.Nickname}!</color>", 3);
            return true;
        }

        /// <summary>
        /// Команда выдачи предмета игроку
        /// </summary>
        private bool ExecuteGiveItem(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("pm.item"))
            {
                response = "У вас нет разрешения на использование команды item!";
                return false;
            }

            if (arguments.Count < 3)
            {
                response = "Использование: pm item <игрок> <предмет> [количество]";
                return false;
            }

            string playerName = arguments.At(1);
            string itemName = arguments.At(2);

            Player targetPlayer = Player.Get(playerName);

            if (targetPlayer == null)
            {
                response = $"Игрок '{playerName}' не найден!";
                return false;
            }

            if (!Enum.TryParse<ItemType>(itemName, true, out ItemType itemType))
            {
                response = $"Предмет '{itemName}' не найден!";
                return false;
            }

            int quantity = 1;
            if (arguments.Count > 3 && int.TryParse(arguments.At(3), out int customQuantity))
            {
                quantity = Math.Max(1, customQuantity);
            }

            for (int i = 0; i < quantity; i++)
            {
                targetPlayer.AddItem(itemType);
            }

            response = $"Игроку {targetPlayer.Nickname} выдано {quantity}x {itemType}.";
            targetPlayer.ShowHint($"<color=green>Вам выдан предмет: {itemType} x{quantity}</color>", 3);
            return true;
        }

        /// <summary>
        /// Команда получения информации об игроке
        /// </summary>
        private bool ExecutePlayerInfo(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("pm.info"))
            {
                response = "У вас нет разрешения на использование команды info!";
                return false;
            }

            if (arguments.Count < 2)
            {
                response = "Использование: pm info <игрок>";
                return false;
            }

            string playerName = arguments.At(1);
            Player targetPlayer = Player.Get(playerName);

            if (targetPlayer == null)
            {
                response = $"Игрок '{playerName}' не найден!";
                return false;
            }

            response = $"=== ИНФОРМАЦИЯ ОБ ИГРОКЕ ===\n" +
                      $"Ник: {targetPlayer.Nickname}\n" +
                      $"ID: {targetPlayer.Id}\n" +
                      $"UserID: {targetPlayer.UserId}\n" +
                      $"IP: {targetPlayer.IPAddress}\n" +
                      $"Роль: {targetPlayer.Role}\n" +
                      $"Команда: {targetPlayer.Role.Team}\n" +
                      $"Здоровье: {targetPlayer.Health}/{targetPlayer.MaxHealth}\n" +
                      $"Позиция: {targetPlayer.Position}\n" +
                      $"Комната: {targetPlayer.CurrentRoom?.Type}\n" +
                      $"Зона: {targetPlayer.Zone}\n" +
                      $"Жив: {(targetPlayer.IsAlive ? "Да" : "Нет")}\n" +
                      $"Связан: {(targetPlayer.IsConnected ? "Да" : "Нет")}";

            return true;
        }

        /// <summary>
        /// Команда кика игрока
        /// </summary>
        private bool ExecuteKick(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("pm.kick"))
            {
                response = "У вас нет разрешения на использование команды kick!";
                return false;
            }

            if (arguments.Count < 2)
            {
                response = "Использование: pm kick <игрок> [причина]";
                return false;
            }

            string playerName = arguments.At(1);
            string reason = arguments.Count > 2 ? string.Join(" ", arguments.Skip(2)) : "Кик администратором";

            Player targetPlayer = Player.Get(playerName);

            if (targetPlayer == null)
            {
                response = $"Игрок '{playerName}' не найден!";
                return false;
            }

            targetPlayer.Kick(reason);
            response = $"Игрок {targetPlayer.Nickname} кикнут. Причина: {reason}";
            return true;
        }

        /// <summary>
        /// Команда убийства игрока
        /// </summary>
        private bool ExecuteKill(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("pm.kill"))
            {
                response = "У вас нет разрешения на использование команды kill!";
                return false;
            }

            if (arguments.Count < 2)
            {
                response = "Использование: pm kill <игрок>";
                return false;
            }

            string playerName = arguments.At(1);
            Player targetPlayer = Player.Get(playerName);

            if (targetPlayer == null)
            {
                response = $"Игрок '{playerName}' не найден!";
                return false;
            }

            if (!targetPlayer.IsAlive)
            {
                response = $"Игрок {targetPlayer.Nickname} уже мертв!";
                return false;
            }

            targetPlayer.Kill("Убит администратором");
            response = $"Игрок {targetPlayer.Nickname} убит администратором.";
            return true;
        }

        /// <summary>
        /// Получает текст справки
        /// </summary>
        private string GetHelpText()
        {
            return "=== КОМАНДЫ PLAYER MANAGER ===\n" +
                   "pm heal <игрок> [хп] - Лечит игрока\n" +
                   "pm tp <игрок1> <игрок2> - Телепортирует игрока1 к игроку2\n" +
                   "pm item <игрок> <предмет> [кол-во] - Выдает предмет игроку\n" +
                   "pm info <игрок> - Показывает информацию об игроке\n" +
                   "pm kick <игрок> [причина] - Кикает игрока\n" +
                   "pm kill <игрок> - Убивает игрока";
        }
    }
}
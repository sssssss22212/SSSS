using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using System;
using System.Linq;

namespace SCPRoleplayPlugin.Commands
{
    /// <summary>
    /// Команда для управления деньгами
    /// </summary>
    [CommandHandler(typeof(ClientCommandHandler))]
    public class MoneyCommand : ICommand
    {
        public string Command => "money";
        public string[] Aliases => new[] { "m", "деньги", "баланс" };
        public string Description => "Управление денежной системой";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            try
            {
                var player = Player.Get(sender);
                if (player == null)
                {
                    response = "Эта команда доступна только игрокам!";
                    return false;
                }

                if (!Plugin.PluginConfig.EnableMoneySystem)
                {
                    response = "Денежная система отключена!";
                    return false;
                }

                if (Plugin.Instance.MoneySystem == null)
                {
                    response = "Денежная система недоступна!";
                    return false;
                }

                if (arguments.Count == 0)
                {
                    response = GetMoneyHelp();
                    return true;
                }

                var action = arguments.At(0).ToLower();

                switch (action)
                {
                    case "balance":
                    case "баланс":
                        return HandleBalance(player, arguments, out response);

                    case "transfer":
                    case "перевод":
                        return HandleTransfer(player, arguments, out response);

                    case "top":
                    case "топ":
                        return HandleTop(player, out response);

                    case "history":
                    case "история":
                        return HandleHistory(player, out response);

                    case "give":
                    case "дать":
                        return HandleGive(player, arguments, out response);

                    case "take":
                    case "забрать":
                        return HandleTake(player, arguments, out response);

                    case "set":
                    case "установить":
                        return HandleSet(player, arguments, out response);

                    default:
                        response = "Неизвестное действие! Используйте: !money для помощи";
                        return false;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в команде money: {ex}");
                response = "Произошла ошибка при выполнении команды!";
                return false;
            }
        }

        /// <summary>
        /// Получить справку по команде
        /// </summary>
        private string GetMoneyHelp()
        {
            return "=== КОМАНДЫ ДЕНЕЖНОЙ СИСТЕМЫ ===\n" +
                   "!money balance [игрок] - баланс игрока\n" +
                   "!money transfer <игрок> <сумма> - перевести деньги\n" +
                   "!money top - топ богатых игроков\n" +
                   "!money history - история транзакций\n" +
                   "=== КОМАНДЫ АДМИНИСТРАТОРА ===\n" +
                   "!money give <игрок> <сумма> [причина] - дать деньги\n" +
                   "!money take <игрок> <сумма> [причина] - забрать деньги\n" +
                   "!money set <игрок> <сумма> [причина] - установить баланс\n" +
                   "==================================";
        }

        /// <summary>
        /// Обработать баланс
        /// </summary>
        private bool HandleBalance(Player player, ArraySegment<string> arguments, out string response)
        {
            Player target = player;

            if (arguments.Count > 1)
            {
                var targetName = arguments.At(1);
                target = Player.Get(targetName);
                
                if (target == null)
                {
                    response = $"Игрок '{targetName}' не найден!";
                    return false;
                }

                // Проверка прав на просмотр чужого баланса
                if (target != player && !player.CheckPermission("scp_rp.money.balance.others"))
                {
                    response = "У вас нет прав для просмотра баланса других игроков!";
                    return false;
                }
            }

            var balance = Plugin.Instance.MoneySystem.GetBalance(target);
            
            if (target == player)
            {
                response = $"Ваш баланс: {balance}₽";
            }
            else
            {
                response = $"Баланс игрока {target.Nickname}: {balance}₽";
            }
            
            return true;
        }

        /// <summary>
        /// Обработать перевод
        /// </summary>
        private bool HandleTransfer(Player player, ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 3)
            {
                response = "Использование: !money transfer <игрок> <сумма>";
                return false;
            }

            var targetName = arguments.At(1);
            if (!int.TryParse(arguments.At(2), out int amount))
            {
                response = "Некорректная сумма!";
                return false;
            }

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            var success = Plugin.Instance.MoneySystem.TransferMoney(player, target, amount);
            if (success)
            {
                response = $"Успешно переведено {amount}₽ игроку {target.Nickname}!";
                return true;
            }
            else
            {
                response = "Не удалось выполнить перевод! Проверьте баланс.";
                return false;
            }
        }

        /// <summary>
        /// Обработать топ игроков
        /// </summary>
        private bool HandleTop(Player player, out string response)
        {
            var topPlayers = Plugin.Instance.MoneySystem.GetTopRichPlayers(10);
            
            if (!topPlayers.Any())
            {
                response = "Нет данных о балансах игроков!";
                return false;
            }

            response = "=== ТОП БОГАТЫХ ИГРОКОВ ===\n";
            for (int i = 0; i < topPlayers.Count; i++)
            {
                var playerMoney = topPlayers[i];
                response += $"{i + 1}. {playerMoney.PlayerName}: {playerMoney.Balance}₽\n";
            }

            return true;
        }

        /// <summary>
        /// Обработать историю транзакций
        /// </summary>
        private bool HandleHistory(Player player, out string response)
        {
            var transactions = Plugin.Instance.MoneySystem.GetTransactions(player, 5);
            
            if (!transactions.Any())
            {
                response = "История транзакций пуста!";
                return true;
            }

            response = "=== ИСТОРИЯ ТРАНЗАКЦИЙ ===\n";
            foreach (var transaction in transactions.OrderByDescending(t => t.Timestamp))
            {
                var sign = transaction.Type == TransactionType.Income ? "+" : "-";
                var color = transaction.Type == TransactionType.Income ? "green" : "red";
                response += $"{transaction.Timestamp:dd.MM.yyyy HH:mm} | {sign}{transaction.Amount}₽ | {transaction.Reason}\n";
            }

            return true;
        }

        /// <summary>
        /// Обработать выдачу денег (админ)
        /// </summary>
        private bool HandleGive(Player player, ArraySegment<string> arguments, out string response)
        {
            if (!player.CheckPermission("scp_rp.money.give"))
            {
                response = "У вас нет прав для выдачи денег!";
                return false;
            }

            if (arguments.Count < 3)
            {
                response = "Использование: !money give <игрок> <сумма> [причина]";
                return false;
            }

            var targetName = arguments.At(1);
            if (!int.TryParse(arguments.At(2), out int amount))
            {
                response = "Некорректная сумма!";
                return false;
            }

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            var reason = arguments.Count > 3 ? string.Join(" ", arguments.Skip(3)) : "Административная выдача";
            
            var success = Plugin.Instance.MoneySystem.AddMoney(target, amount, reason);
            if (success)
            {
                response = $"Успешно выдано {amount}₽ игроку {target.Nickname}! Причина: {reason}";
                return true;
            }
            else
            {
                response = "Не удалось выдать деньги!";
                return false;
            }
        }

        /// <summary>
        /// Обработать снятие денег (админ)
        /// </summary>
        private bool HandleTake(Player player, ArraySegment<string> arguments, out string response)
        {
            if (!player.CheckPermission("scp_rp.money.take"))
            {
                response = "У вас нет прав для снятия денег!";
                return false;
            }

            if (arguments.Count < 3)
            {
                response = "Использование: !money take <игрок> <сумма> [причина]";
                return false;
            }

            var targetName = arguments.At(1);
            if (!int.TryParse(arguments.At(2), out int amount))
            {
                response = "Некорректная сумма!";
                return false;
            }

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            var reason = arguments.Count > 3 ? string.Join(" ", arguments.Skip(3)) : "Административное снятие";
            
            var success = Plugin.Instance.MoneySystem.RemoveMoney(target, amount, reason);
            if (success)
            {
                response = $"Успешно снято {amount}₽ у игрока {target.Nickname}! Причина: {reason}";
                return true;
            }
            else
            {
                response = "Не удалось снять деньги! Проверьте баланс игрока.";
                return false;
            }
        }

        /// <summary>
        /// Обработать установку баланса (админ)
        /// </summary>
        private bool HandleSet(Player player, ArraySegment<string> arguments, out string response)
        {
            if (!player.CheckPermission("scp_rp.money.set"))
            {
                response = "У вас нет прав для установки баланса!";
                return false;
            }

            if (arguments.Count < 3)
            {
                response = "Использование: !money set <игрок> <сумма> [причина]";
                return false;
            }

            var targetName = arguments.At(1);
            if (!int.TryParse(arguments.At(2), out int amount))
            {
                response = "Некорректная сумма!";
                return false;
            }

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            var reason = arguments.Count > 3 ? string.Join(" ", arguments.Skip(3)) : "Административная установка";
            
            var success = Plugin.Instance.MoneySystem.SetBalance(target, amount, player, reason);
            if (success)
            {
                response = $"Баланс игрока {target.Nickname} установлен на {amount}₽! Причина: {reason}";
                return true;
            }
            else
            {
                response = "Не удалось установить баланс!";
                return false;
            }
        }
    }
}
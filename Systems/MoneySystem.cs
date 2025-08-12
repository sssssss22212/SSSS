using Exiled.API.Features;
using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;

namespace SCPRoleplayPlugin
{
    /// <summary>
    /// Система управления деньгами игроков на RP сервере
    /// </summary>
    public class MoneySystem
    {
        private Dictionary<string, PlayerMoney> playerMoney = new Dictionary<string, PlayerMoney>();
        private readonly string dataPath = Path.Combine(Paths.Configs, "SCPRoleplay", "money.json");

        public MoneySystem()
        {
            LoadData();
        }

        /// <summary>
        /// Получить баланс игрока
        /// </summary>
        public int GetBalance(Player player)
        {
            var key = player.UserId;
            if (!playerMoney.ContainsKey(key))
            {
                CreateAccount(player);
            }
            return playerMoney[key].Balance;
        }

        /// <summary>
        /// Создать аккаунт для нового игрока
        /// </summary>
        private void CreateAccount(Player player)
        {
            var key = player.UserId;
            if (!playerMoney.ContainsKey(key))
            {
                playerMoney[key] = new PlayerMoney
                {
                    UserId = key,
                    PlayerName = player.Nickname,
                    Balance = Plugin.PluginConfig.StartingMoney,
                    LastUpdated = DateTime.Now
                };
                
                player.ShowHint($"Создан банковский аккаунт! Стартовый баланс: {Plugin.PluginConfig.StartingMoney}₽", 5);
                Log.Debug($"Создан аккаунт для {player.Nickname} с балансом {Plugin.PluginConfig.StartingMoney}");
            }
        }

        /// <summary>
        /// Добавить деньги игроку
        /// </summary>
        public bool AddMoney(Player player, int amount, string reason = "Неизвестно")
        {
            try
            {
                if (amount <= 0)
                    return false;

                var key = player.UserId;
                if (!playerMoney.ContainsKey(key))
                {
                    CreateAccount(player);
                }

                playerMoney[key].Balance += amount;
                playerMoney[key].LastUpdated = DateTime.Now;
                
                // Записываем транзакцию
                playerMoney[key].Transactions.Add(new Transaction
                {
                    Amount = amount,
                    Type = TransactionType.Income,
                    Reason = reason,
                    Timestamp = DateTime.Now
                });

                player.ShowHint($"<color=green>+{amount}₽</color> ({reason})\nБаланс: {playerMoney[key].Balance}₽", 4);
                
                SaveData();
                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при добавлении денег: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Снять деньги у игрока
        /// </summary>
        public bool RemoveMoney(Player player, int amount, string reason = "Неизвестно")
        {
            try
            {
                if (amount <= 0)
                    return false;

                var key = player.UserId;
                if (!playerMoney.ContainsKey(key))
                {
                    CreateAccount(player);
                }

                if (playerMoney[key].Balance < amount)
                {
                    player.ShowHint("Недостаточно средств!", 3);
                    return false;
                }

                playerMoney[key].Balance -= amount;
                playerMoney[key].LastUpdated = DateTime.Now;
                
                // Записываем транзакцию
                playerMoney[key].Transactions.Add(new Transaction
                {
                    Amount = amount,
                    Type = TransactionType.Expense,
                    Reason = reason,
                    Timestamp = DateTime.Now
                });

                player.ShowHint($"<color=red>-{amount}₽</color> ({reason})\nБаланс: {playerMoney[key].Balance}₽", 4);
                
                SaveData();
                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при снятии денег: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Перевести деньги между игроками
        /// </summary>
        public bool TransferMoney(Player from, Player to, int amount, string reason = "Перевод")
        {
            try
            {
                if (amount <= 0)
                {
                    from.ShowHint("Сумма перевода должна быть положительной!", 3);
                    return false;
                }

                if (from.UserId == to.UserId)
                {
                    from.ShowHint("Нельзя переводить деньги самому себе!", 3);
                    return false;
                }

                // Проверяем баланс отправителя
                if (GetBalance(from) < amount)
                {
                    from.ShowHint("Недостаточно средств для перевода!", 3);
                    return false;
                }

                // Выполняем перевод
                if (RemoveMoney(from, amount, $"Перевод игроку {to.Nickname}") && 
                    AddMoney(to, amount, $"Перевод от {from.Nickname}"))
                {
                    from.ShowHint($"Переведено {amount}₽ игроку {to.Nickname}", 4);
                    to.ShowHint($"Получен перевод {amount}₽ от {from.Nickname}", 4);
                    
                    Log.Info($"Перевод: {from.Nickname} → {to.Nickname}: {amount}₽");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при переводе денег: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Установить баланс игрока (только для администраторов)
        /// </summary>
        public bool SetBalance(Player player, int amount, Player admin, string reason = "Административное действие")
        {
            try
            {
                if (amount < 0)
                    return false;

                var key = player.UserId;
                if (!playerMoney.ContainsKey(key))
                {
                    CreateAccount(player);
                }

                int oldBalance = playerMoney[key].Balance;
                playerMoney[key].Balance = amount;
                playerMoney[key].LastUpdated = DateTime.Now;
                
                // Записываем транзакцию
                playerMoney[key].Transactions.Add(new Transaction
                {
                    Amount = amount - oldBalance,
                    Type = amount > oldBalance ? TransactionType.Income : TransactionType.Expense,
                    Reason = $"{reason} (Администратор: {admin.Nickname})",
                    Timestamp = DateTime.Now
                });

                player.ShowHint($"Ваш баланс установлен на {amount}₽", 5);
                admin.ShowHint($"Баланс игрока {player.Nickname} установлен на {amount}₽", 3);
                
                SaveData();
                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при установке баланса: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Получить топ богатых игроков
        /// </summary>
        public List<PlayerMoney> GetTopRichPlayers(int count = 10)
        {
            var topPlayers = new List<PlayerMoney>();
            
            foreach (var money in playerMoney.Values)
            {
                topPlayers.Add(money);
            }
            
            topPlayers.Sort((x, y) => y.Balance.CompareTo(x.Balance));
            
            if (topPlayers.Count > count)
            {
                topPlayers = topPlayers.GetRange(0, count);
            }
            
            return topPlayers;
        }

        /// <summary>
        /// Получить историю транзакций игрока
        /// </summary>
        public List<Transaction> GetTransactions(Player player, int count = 10)
        {
            var key = player.UserId;
            if (!playerMoney.ContainsKey(key))
            {
                return new List<Transaction>();
            }

            var transactions = playerMoney[key].Transactions;
            if (transactions.Count > count)
            {
                return transactions.GetRange(transactions.Count - count, count);
            }
            
            return transactions;
        }

        /// <summary>
        /// Сохранить данные в файл
        /// </summary>
        private void SaveData()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(dataPath));
                var json = JsonConvert.SerializeObject(playerMoney, Formatting.Indented);
                File.WriteAllText(dataPath, json);
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при сохранении данных денег: {ex}");
            }
        }

        /// <summary>
        /// Загрузить данные из файла
        /// </summary>
        private void LoadData()
        {
            try
            {
                if (File.Exists(dataPath))
                {
                    var json = File.ReadAllText(dataPath);
                    playerMoney = JsonConvert.DeserializeObject<Dictionary<string, PlayerMoney>>(json) ?? new Dictionary<string, PlayerMoney>();
                    Log.Debug($"Загружено {playerMoney.Count} банковских аккаунтов");
                }
                else
                {
                    playerMoney = new Dictionary<string, PlayerMoney>();
                    Log.Debug("Создана новая база данных денег");
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при загрузке данных денег: {ex}");
                playerMoney = new Dictionary<string, PlayerMoney>();
            }
        }

        /// <summary>
        /// Очистка системы
        /// </summary>
        public void Cleanup()
        {
            SaveData();
            playerMoney.Clear();
        }
    }

    /// <summary>
    /// Данные о деньгах игрока
    /// </summary>
    public class PlayerMoney
    {
        public string UserId { get; set; }
        public string PlayerName { get; set; }
        public int Balance { get; set; }
        public DateTime LastUpdated { get; set; }
        public List<Transaction> Transactions { get; set; } = new List<Transaction>();
    }

    /// <summary>
    /// Транзакция
    /// </summary>
    public class Transaction
    {
        public int Amount { get; set; }
        public TransactionType Type { get; set; }
        public string Reason { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Тип транзакции
    /// </summary>
    public enum TransactionType
    {
        Income,   // Доход
        Expense   // Расход
    }
}
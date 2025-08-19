using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Libraries.Covalence;
using Oxide.Core.Plugins;
using Oxide.Game.Rust.Cui;
using UnityEngine;
using System.Text;

namespace Oxide.Plugins
{
    [Info("RustAdminPro", "YourName", "1.0.0")]
    [Description("Профессиональная админ панель с красивым интерфейсом")]
    public class RustAdminPro : RustPlugin
    {
        #region Configuration

        private Configuration config;

        public class Configuration
        {
            [JsonProperty("Префикс чата")]
            public string ChatPrefix = "[<color=#ff6b6b>AdminPro</color>]";

            [JsonProperty("Команды")]
            public CommandSettings Commands = new CommandSettings();

            [JsonProperty("Настройки UI")]
            public UISettings UI = new UISettings();

            [JsonProperty("Права доступа")]
            public PermissionSettings Permissions = new PermissionSettings();

            [JsonProperty("Магазин")]
            public ShopSettings Shop = new ShopSettings();
        }

        public class CommandSettings
        {
            [JsonProperty("Команда админ панели")]
            public string AdminPanelCommand = "admin";

            [JsonProperty("Команда телепорта")]
            public string TeleportCommand = "tp";

            [JsonProperty("Команда кита")]
            public string KitCommand = "kit";
        }

        public class UISettings
        {
            [JsonProperty("Основной цвет")]
            public string PrimaryColor = "#1a1a2e";

            [JsonProperty("Вторичный цвет")]
            public string SecondaryColor = "#16213e";

            [JsonProperty("Цвет кнопок")]
            public string ButtonColor = "#0f3460";

            [JsonProperty("Цвет успеха")]
            public string SuccessColor = "#27ae60";

            [JsonProperty("Цвет опасности")]
            public string DangerColor = "#e74c3c";

            [JsonProperty("Цвет предупреждения")]
            public string WarningColor = "#f39c12";

            [JsonProperty("Цвет информации")]
            public string InfoColor = "#3498db";

            [JsonProperty("Градиент основной")]
            public string GradientPrimary = "#1a1a2e";

            [JsonProperty("Градиент вторичный")]
            public string GradientSecondary = "#16213e";

            [JsonProperty("Цвет текста")]
            public string TextColor = "#ecf0f1";

            [JsonProperty("Цвет акцента")]
            public string AccentColor = "#e67e22";
        }

        public class PermissionSettings
        {
            [JsonProperty("Админ панель")]
            public string AdminPanel = "rustadminpro.admin";

            [JsonProperty("Модератор")]
            public string Moderator = "rustadminpro.moderator";

            [JsonProperty("VIP")]
            public string VIP = "rustadminpro.vip";

            [JsonProperty("Премиум")]
            public string Premium = "rustadminpro.premium";

            [JsonProperty("Донатер")]
            public string Donator = "rustadminpro.donator";

            [JsonProperty("Элита")]
            public string Elite = "rustadminpro.elite";

            [JsonProperty("Погода")]
            public string Weather = "rustadminpro.weather";

            [JsonProperty("Время")]
            public string Time = "rustadminpro.time";

            [JsonProperty("Ноклип")]
            public string Noclip = "rustadminpro.noclip";

            [JsonProperty("Бог режим")]
            public string Godmode = "rustadminpro.godmode";
        }

        public class ShopSettings
        {
            [JsonProperty("Включить магазин")]
            public bool EnableShop = true;

            [JsonProperty("Валюта")]
            public string Currency = "RP";

            [JsonProperty("Товары")]
            public List<ShopItem> Items = new List<ShopItem>
            {
                // Оружие
                new ShopItem { Name = "АК-47", ShortName = "rifle.ak", Price = 1500, Category = "Оружие" },
                new ShopItem { Name = "LR-300", ShortName = "rifle.lr300", Price = 2000, Category = "Оружие" },
                new ShopItem { Name = "Болтовка", ShortName = "rifle.bolt", Price = 1200, Category = "Оружие" },
                new ShopItem { Name = "MP5", ShortName = "smg.mp5", Price = 800, Category = "Оружие" },
                new ShopItem { Name = "Python", ShortName = "pistol.python", Price = 600, Category = "Оружие" },
                
                // Броня
                new ShopItem { Name = "Металлическая броня", ShortName = "metal.plate.torso", Price = 500, Category = "Броня" },
                new ShopItem { Name = "Металлическая маска", ShortName = "metal.facemask", Price = 300, Category = "Броня" },
                new ShopItem { Name = "Дорожные штаны", ShortName = "roadsign.kilt", Price = 250, Category = "Броня" },
                new ShopItem { Name = "Дорожная куртка", ShortName = "roadsign.jacket", Price = 300, Category = "Броня" },
                new ShopItem { Name = "Хазмат костюм", ShortName = "hazmatsuit", Price = 800, Category = "Броня" },
                
                // Медицина
                new ShopItem { Name = "Медицинский шприц", ShortName = "syringe.medical", Price = 100, Category = "Медицина" },
                new ShopItem { Name = "Бинт", ShortName = "bandage", Price = 25, Category = "Медицина" },
                new ShopItem { Name = "Большой медкит", ShortName = "largemedkit", Price = 200, Category = "Медицина" },
                
                // Инструменты
                new ShopItem { Name = "Топор", ShortName = "hatchet", Price = 150, Category = "Инструменты" },
                new ShopItem { Name = "Кирка", ShortName = "pickaxe", Price = 150, Category = "Инструменты" },
                new ShopItem { Name = "Строительный молоток", ShortName = "hammer", Price = 100, Category = "Инструменты" },
                
                // Ресурсы
                new ShopItem { Name = "Дерево", ShortName = "wood", Price = 1, Category = "Ресурсы", Amount = 1000 },
                new ShopItem { Name = "Камень", ShortName = "stones", Price = 1, Category = "Ресурсы", Amount = 1000 },
                new ShopItem { Name = "Металлолом", ShortName = "metal.fragments", Price = 2, Category = "Ресурсы", Amount = 500 },
                new ShopItem { Name = "Качественный металл", ShortName = "metal.refined", Price = 10, Category = "Ресурсы", Amount = 100 }
            };
        }

        public class ShopItem
        {
            [JsonProperty("Название")]
            public string Name { get; set; }

            [JsonProperty("Короткое имя")]
            public string ShortName { get; set; }

            [JsonProperty("Цена")]
            public int Price { get; set; }

            [JsonProperty("Категория")]
            public string Category { get; set; }

            [JsonProperty("Количество")]
            public int Amount { get; set; } = 1;
        }

        #endregion

        #region Data

        private StoredData storedData;

        public class StoredData
        {
            public Dictionary<ulong, PlayerData> Players = new Dictionary<ulong, PlayerData>();
            public List<TeleportLocation> TeleportLocations = new List<TeleportLocation>();
            public List<Kit> Kits = new List<Kit>();
        }

        public class PlayerData
        {
            public string Name { get; set; }
            public int Balance { get; set; }
            public DateTime LastSeen { get; set; }
            public List<string> Warnings = new List<string>();
            public bool IsMuted { get; set; }
            public DateTime MuteExpiry { get; set; }
            public bool IsGodMode { get; set; }
            public bool IsNoclip { get; set; }
            public Dictionary<string, DateTime> KitCooldowns = new Dictionary<string, DateTime>();
            public int TotalPlayTime { get; set; }
            public Vector3 LastPosition { get; set; }
        }

        public class TeleportLocation
        {
            public string Name { get; set; }
            public Vector3 Position { get; set; }
            public bool IsPublic { get; set; }
            public ulong OwnerId { get; set; }
        }

        public class Kit
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public List<KitItem> Items = new List<KitItem>();
            public int Cooldown { get; set; }
            public string Permission { get; set; }
        }

        public class KitItem
        {
            public string ShortName { get; set; }
            public int Amount { get; set; }
            public ulong SkinId { get; set; }
        }

        #endregion

        #region Hooks

        void Init()
        {
            LoadConfig();
            LoadData();
            RegisterPermissions();
            
            cmd.AddChatCommand(config.Commands.AdminPanelCommand, this, "AdminPanelCommand");
            cmd.AddChatCommand(config.Commands.TeleportCommand, this, "TeleportCommand");
            cmd.AddChatCommand(config.Commands.KitCommand, this, "KitCommand");
            cmd.AddChatCommand("shop", this, "ShopCommand");
            cmd.AddChatCommand("balance", this, "BalanceCommand");
            cmd.AddChatCommand("weather", this, "WeatherCommand");
            cmd.AddChatCommand("time", this, "TimeCommand");
            cmd.AddChatCommand("god", this, "GodModeCommand");
            cmd.AddChatCommand("noclip", this, "NoclipCommand");
            cmd.AddChatCommand("heal", this, "HealCommand");
            cmd.AddChatCommand("feed", this, "FeedCommand");
            cmd.AddChatCommand("fly", this, "FlyCommand");
            cmd.AddChatCommand("online", this, "OnlineCommand");
            cmd.AddChatCommand("players", this, "PlayersCommand");

            // Инициализация стандартных китов
            if (storedData.Kits.Count == 0)
            {
                CreateDefaultKits();
            }

            timer.Every(300f, () => SaveData()); // Автосохранение каждые 5 минут
        }

        void OnPlayerConnected(BasePlayer player)
        {
            if (!storedData.Players.ContainsKey(player.userID))
            {
                storedData.Players[player.userID] = new PlayerData
                {
                    Name = player.displayName,
                    Balance = 1000, // Стартовый баланс
                    LastSeen = DateTime.Now
                };
            }
            else
            {
                storedData.Players[player.userID].Name = player.displayName;
                storedData.Players[player.userID].LastSeen = DateTime.Now;
            }
        }

        void OnPlayerDisconnected(BasePlayer player)
        {
            if (storedData.Players.ContainsKey(player.userID))
            {
                storedData.Players[player.userID].LastSeen = DateTime.Now;
            }
        }

        void Unload()
        {
            SaveData();
            
            // Закрываем все открытые UI
            foreach (var player in BasePlayer.activePlayerList)
            {
                CloseAllPanels(player);
            }
        }

        #endregion

        #region Configuration Methods

        protected override void LoadConfig()
        {
            base.LoadConfig();
            try
            {
                config = Config.ReadObject<Configuration>();
                if (config == null) throw new Exception();
            }
            catch
            {
                PrintWarning("Создание нового файла конфигурации...");
                config = new Configuration();
            }
            SaveConfig();
        }

        protected override void SaveConfig() => Config.WriteObject(config);

        protected override void LoadDefaultConfig() => config = new Configuration();

        #endregion

        #region Data Methods

        void LoadData()
        {
            storedData = Interface.Oxide.DataFileSystem.ReadObject<StoredData>("RustAdminPro");
            if (storedData == null)
            {
                storedData = new StoredData();
                SaveData();
            }
        }

        void SaveData()
        {
            Interface.Oxide.DataFileSystem.WriteObject("RustAdminPro", storedData);
        }

        #endregion

        #region Permissions

        void RegisterPermissions()
        {
            permission.RegisterPermission(config.Permissions.AdminPanel, this);
            permission.RegisterPermission(config.Permissions.Moderator, this);
            permission.RegisterPermission(config.Permissions.VIP, this);
            permission.RegisterPermission(config.Permissions.Premium, this);
            permission.RegisterPermission(config.Permissions.Donator, this);
            permission.RegisterPermission(config.Permissions.Elite, this);
            permission.RegisterPermission(config.Permissions.Weather, this);
            permission.RegisterPermission(config.Permissions.Time, this);
            permission.RegisterPermission(config.Permissions.Noclip, this);
            permission.RegisterPermission(config.Permissions.Godmode, this);
        }

        bool HasPermission(BasePlayer player, string perm)
        {
            return permission.UserHasPermission(player.UserIDString, perm);
        }

        #endregion

        #region Chat Commands

        [ChatCommand("admin")]
        void AdminPanelCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.AdminPanel))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на использование админ панели!");
                return;
            }

            OpenAdminPanel(player);
        }

        [ChatCommand("tp")]
        void TeleportCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Moderator))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на телепорт!");
                return;
            }

            if (args.Length == 0)
            {
                OpenTeleportMenu(player);
                return;
            }

            // Логика телепорта
            HandleTeleportCommand(player, args);
        }

        [ChatCommand("kit")]
        void KitCommand(BasePlayer player, string command, string[] args)
        {
            if (args.Length == 0)
            {
                OpenKitMenu(player);
                return;
            }

            GiveKit(player, args[0]);
        }

        [ChatCommand("shop")]
        void ShopCommand(BasePlayer player, string command, string[] args)
        {
            if (!config.Shop.EnableShop)
            {
                SendReply(player, $"{config.ChatPrefix} Магазин отключен!");
                return;
            }

            OpenShopPanel(player);
        }

        [ChatCommand("balance")]
        void BalanceCommand(BasePlayer player, string command, string[] args)
        {
            var playerData = GetPlayerData(player.userID);
            SendReply(player, $"{config.ChatPrefix} Ваш баланс: <color=#27ae60>{playerData.Balance}</color> {config.Shop.Currency}");
        }

        [ChatCommand("weather")]
        void WeatherCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Weather))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на управление погодой!");
                return;
            }

            if (args.Length == 0)
            {
                SendReply(player, $"{config.ChatPrefix} Использование: /weather <clear/rain/storm/fog>");
                return;
            }

            string weatherType = args[0].ToLower();
            switch (weatherType)
            {
                case "clear":
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.rain 0");
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.fog 0");
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.wind 0");
                    SendReply(player, $"{config.ChatPrefix} ☀️ Установлена ясная погода!");
                    Server.Broadcast($"{config.ChatPrefix} <color=#f1c40f>☀️ Администратор {player.displayName} установил ясную погоду!</color>");
                    break;

                case "rain":
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.rain 1");
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.fog 0.3");
                    SendReply(player, $"{config.ChatPrefix} 🌧️ Установлен дождь!");
                    Server.Broadcast($"{config.ChatPrefix} <color=#3498db>🌧️ Администратор {player.displayName} вызвал дождь!</color>");
                    break;

                case "storm":
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.rain 1");
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.wind 1");
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.fog 0.5");
                    SendReply(player, $"{config.ChatPrefix} ⛈️ Установлена буря!");
                    Server.Broadcast($"{config.ChatPrefix} <color=#e74c3c>⛈️ Администратор {player.displayName} вызвал бурю!</color>");
                    break;

                case "fog":
                    ConsoleSystem.Run(ConsoleSystem.Option.Server, "weather.fog 1");
                    SendReply(player, $"{config.ChatPrefix} 🌫️ Установлен туман!");
                    Server.Broadcast($"{config.ChatPrefix} <color=#95a5a6>🌫️ Администратор {player.displayName} вызвал туман!</color>");
                    break;
            }
        }

        [ChatCommand("time")]
        void TimeCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Time))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на управление временем!");
                return;
            }

            if (args.Length == 0)
            {
                SendReply(player, $"{config.ChatPrefix} Использование: /time <0-24> или /time <day/night>");
                return;
            }

            string timeArg = args[0].ToLower();
            
            if (timeArg == "day")
            {
                ConsoleSystem.Run(ConsoleSystem.Option.Server, "env.time 12");
                SendReply(player, $"{config.ChatPrefix} ☀️ Установлен день!");
                Server.Broadcast($"{config.ChatPrefix} <color=#f1c40f>☀️ Администратор {player.displayName} установил день!</color>");
            }
            else if (timeArg == "night")
            {
                ConsoleSystem.Run(ConsoleSystem.Option.Server, "env.time 0");
                SendReply(player, $"{config.ChatPrefix} 🌙 Установлена ночь!");
                Server.Broadcast($"{config.ChatPrefix} <color=#9b59b6>🌙 Администратор {player.displayName} установил ночь!</color>");
            }
            else if (float.TryParse(timeArg, out float time) && time >= 0 && time <= 24)
            {
                ConsoleSystem.Run(ConsoleSystem.Option.Server, $"env.time {time}");
                SendReply(player, $"{config.ChatPrefix} 🕐 Время установлено на {time}:00!");
                Server.Broadcast($"{config.ChatPrefix} <color=#3498db>🕐 Администратор {player.displayName} установил время {time}:00!</color>");
            }
            else
            {
                SendReply(player, $"{config.ChatPrefix} Неверное время! Используйте 0-24 или day/night");
            }
        }

        [ChatCommand("god")]
        void GodModeCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Godmode))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на режим бога!");
                return;
            }

            var playerData = GetPlayerData(player.userID);
            playerData.IsGodMode = !playerData.IsGodMode;

            if (playerData.IsGodMode)
            {
                player.metabolism.bleeding.value = 0;
                player.metabolism.radiation_poison.value = 0;
                player.health = player.MaxHealth();
                SendReply(player, $"{config.ChatPrefix} 👼 Режим бога включен!");
            }
            else
            {
                SendReply(player, $"{config.ChatPrefix} 👤 Режим бога выключен!");
            }
        }

        [ChatCommand("noclip")]
        void NoclipCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Noclip))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на ноклип!");
                return;
            }

            var playerData = GetPlayerData(player.userID);
            playerData.IsNoclip = !playerData.IsNoclip;

            if (playerData.IsNoclip)
            {
                player.SendConsoleCommand("noclip");
                SendReply(player, $"{config.ChatPrefix} 👻 Ноклип включен!");
            }
            else
            {
                player.SendConsoleCommand("noclip");
                SendReply(player, $"{config.ChatPrefix} 🚶 Ноклип выключен!");
            }
        }

        [ChatCommand("heal")]
        void HealCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Moderator))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на лечение!");
                return;
            }

            BasePlayer target = player;
            if (args.Length > 0)
            {
                target = BasePlayer.Find(args[0]);
                if (target == null)
                {
                    SendReply(player, $"{config.ChatPrefix} Игрок не найден!");
                    return;
                }
            }

            target.health = target.MaxHealth();
            target.metabolism.bleeding.value = 0;
            target.metabolism.radiation_poison.value = 0;
            target.metabolism.poison.value = 0;

            if (target == player)
            {
                SendReply(player, $"{config.ChatPrefix} ❤️ Вы полностью восстановили здоровье!");
            }
            else
            {
                SendReply(player, $"{config.ChatPrefix} ❤️ Игрок {target.displayName} вылечен!");
                SendReply(target, $"{config.ChatPrefix} ❤️ Вас вылечил администратор {player.displayName}!");
            }
        }

        [ChatCommand("feed")]
        void FeedCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Moderator))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на кормление!");
                return;
            }

            BasePlayer target = player;
            if (args.Length > 0)
            {
                target = BasePlayer.Find(args[0]);
                if (target == null)
                {
                    SendReply(player, $"{config.ChatPrefix} Игрок не найден!");
                    return;
                }
            }

            target.metabolism.calories.value = target.metabolism.calories.max;
            target.metabolism.hydration.value = target.metabolism.hydration.max;

            if (target == player)
            {
                SendReply(player, $"{config.ChatPrefix} 🍖 Вы утолили голод и жажду!");
            }
            else
            {
                SendReply(player, $"{config.ChatPrefix} 🍖 Игрок {target.displayName} накормлен!");
                SendReply(target, $"{config.ChatPrefix} 🍖 Вас накормил администратор {player.displayName}!");
            }
        }

        [ChatCommand("fly")]
        void FlyCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.AdminPanel))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на полёт!");
                return;
            }

            if (player.IsFlying)
            {
                player.SendConsoleCommand("noclip");
                SendReply(player, $"{config.ChatPrefix} 🚶 Режим полёта выключен!");
            }
            else
            {
                player.SendConsoleCommand("noclip");
                SendReply(player, $"{config.ChatPrefix} 🦅 Режим полёта включен!");
            }
        }

        [ChatCommand("online")]
        void OnlineCommand(BasePlayer player, string command, string[] args)
        {
            var onlineCount = BasePlayer.activePlayerList.Count;
            var sleepingCount = BasePlayer.sleepingPlayerList.Count;
            
            var sb = new StringBuilder();
            sb.AppendLine($"{config.ChatPrefix} 📊 <color=#3498db>СТАТИСТИКА СЕРВЕРА</color>");
            sb.AppendLine($"🟢 Онлайн игроков: <color=#27ae60>{onlineCount}</color>");
            sb.AppendLine($"😴 Спящих игроков: <color=#f39c12>{sleepingCount}</color>");
            sb.AppendLine($"📈 Всего игроков: <color=#e67e22>{onlineCount + sleepingCount}</color>");
            sb.AppendLine($"🕒 Время сервера: <color=#9b59b6>{DateTime.Now:HH:mm:ss}</color>");
            
            SendReply(player, sb.ToString());
        }

        [ChatCommand("players")]
        void PlayersCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Moderator))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на просмотр списка игроков!");
                return;
            }

            var sb = new StringBuilder();
            sb.AppendLine($"{config.ChatPrefix} 👥 <color=#3498db>СПИСОК ОНЛАЙН ИГРОКОВ</color>");
            
            foreach (var targetPlayer in BasePlayer.activePlayerList.Take(10))
            {
                string status = "🟢";
                if (HasPermission(targetPlayer, config.Permissions.AdminPanel)) status = "👑";
                else if (HasPermission(targetPlayer, config.Permissions.VIP)) status = "💎";
                else if (HasPermission(targetPlayer, config.Permissions.Moderator)) status = "🛡️";

                var targetData = GetPlayerData(targetPlayer.userID);
                sb.AppendLine($"{status} <color=#ecf0f1>{targetPlayer.displayName}</color> | 💰 {targetData.Balance} {config.Shop.Currency}");
            }
            
            SendReply(player, sb.ToString());
        }

        #endregion

        #region UI Helper Methods

        void CloseAllPanels(BasePlayer player)
        {
            CuiHelper.DestroyUi(player, "AdminPanel");
            CuiHelper.DestroyUi(player, "ShopPanel");
            CuiHelper.DestroyUi(player, "KitPanel");
            CuiHelper.DestroyUi(player, "TeleportPanel");
            CuiHelper.DestroyUi(player, "WeatherPanel");
            CuiHelper.DestroyUi(player, "TimePanel");
            CuiHelper.DestroyUi(player, "ServerPanel");
            CuiHelper.DestroyUi(player, "InventoryPanel");
            CuiHelper.DestroyUi(player, "NotificationPanel");
        }

        void ShowNotification(BasePlayer player, string message, string color = "#27ae60", float duration = 3f)
        {
            CuiHelper.DestroyUi(player, "NotificationPanel");
            
            var container = new CuiElementContainer();

            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(color, 0.9f) },
                RectTransform = { AnchorMin = "0.3 0.85", AnchorMax = "0.7 0.95" },
                CursorEnabled = false
            }, "Overlay", "NotificationPanel");

            container.Add(new CuiLabel
            {
                Text = { Text = message, FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "1 1" }
            }, "NotificationPanel");

            CuiHelper.AddUi(player, container);
            
            timer.Once(duration, () => CuiHelper.DestroyUi(player, "NotificationPanel"));
        }

        #endregion

        #region UI Creation

        void OpenAdminPanel(BasePlayer player)
        {
            // Сначала закрываем все существующие панели
            CloseAllPanels(player);
            
            var container = new CuiElementContainer();

            // Основная панель без фонового затемнения
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.98f) },
                RectTransform = { AnchorMin = "0.05 0.05", AnchorMax = "0.95 0.95" },
                CursorEnabled = true
            }, "Overlay", "AdminPanel");

            // Декоративная рамка
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.6f) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "1 0.005" }
            }, "AdminPanel");

            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.6f) },
                RectTransform = { AnchorMin = "0 0.995", AnchorMax = "1 1" }
            }, "AdminPanel");

            // Заголовок с градиентом
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0 0.9", AnchorMax = "1 1" }
            }, "AdminPanel", "AdminHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = "🛡️ RUST ADMIN PRO - ПАНЕЛЬ УПРАВЛЕНИЯ 🛡️", FontSize = 20, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "0.9 1" }
            }, "AdminHeader");

            // Кнопка закрытия с эффектом
            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor, 0.8f) },
                RectTransform = { AnchorMin = "0.92 0.02", AnchorMax = "0.98 0.08" },
                Text = { Text = "✕", FontSize = 18, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "AdminHeader");

            // Информационная панель
            var playerData = GetPlayerData(player.userID);
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.InfoColor, 0.3f) },
                RectTransform = { AnchorMin = "0.02 0.85", AnchorMax = "0.98 0.89" }
            }, "AdminPanel", "InfoPanel");

            container.Add(new CuiLabel
            {
                Text = { Text = $"👤 {player.displayName} | 💰 {playerData.Balance} {config.Shop.Currency} | 🌐 Онлайн: {BasePlayer.activePlayerList.Count} | 🕒 {DateTime.Now:HH:mm:ss}", FontSize = 12, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "1 1" }
            }, "InfoPanel");

            // Улучшенное навигационное меню
            string[] menuItems = { "👥 Игроки", "🌍 Телепорт", "📦 Киты", "🎒 Предметы", "🖥️ Сервер", "⚙️ Настройки", "🌤️ Погода", "🕐 Время" };
            string[] menuCommands = { "players", "teleport", "kits", "items", "server", "settings", "weather", "time" };
            
            for (int i = 0; i < menuItems.Length; i++)
            {
                int row = i / 4;
                int col = i % 4;
                
                float xMin = 0.02f + (col * 0.24f);
                float xMax = xMin + 0.22f;
                float yMax = 0.82f - (row * 0.08f);
                float yMin = yMax - 0.06f;

                container.Add(new CuiButton
                {
                    Button = { Command = $"adminpanel.section {menuCommands[i]}", Color = HexToRustFormat(config.UI.ButtonColor, 0.8f) },
                    RectTransform = { AnchorMin = $"{xMin} {yMin}", AnchorMax = $"{xMax} {yMax}" },
                    Text = { Text = menuItems[i], FontSize = 11, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) }
                }, "AdminPanel");
            }

            // Область контента с красивой рамкой
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0.02 0.05", AnchorMax = "0.98 0.68" }
            }, "AdminPanel", "ContentArea");

            // Добавляем содержимое по умолчанию (список игроков)
            AddPlayersContent(container);

            CuiHelper.AddUi(player, container);
        }

        void AddPlayersContent(CuiElementContainer container)
        {
            // Заголовок секции с иконкой
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.4f) },
                RectTransform = { AnchorMin = "0.02 0.9", AnchorMax = "0.98 0.98" }
            }, "ContentArea", "PlayersHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = "👥 УПРАВЛЕНИЕ ИГРОКАМИ", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "1 1" }
            }, "PlayersHeader");

            // Статистика игроков
            var onlineCount = BasePlayer.activePlayerList.Count;
            var sleepingCount = BasePlayer.sleepingPlayerList.Count;
            
            container.Add(new CuiLabel
            {
                Text = { Text = $"🟢 Онлайн: {onlineCount} | 😴 Спят: {sleepingCount} | 📊 Всего: {onlineCount + sleepingCount}", FontSize = 11, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.InfoColor) },
                RectTransform = { AnchorMin = "0.02 0.86", AnchorMax = "0.98 0.9" }
            }, "ContentArea");

            // Список онлайн игроков с улучшенным дизайном
            var onlinePlayers = BasePlayer.activePlayerList.Take(7).ToList();
            for (int i = 0; i < onlinePlayers.Count; i++)
            {
                var targetPlayer = onlinePlayers[i];
                var targetData = GetPlayerData(targetPlayer.userID);
                float yMax = 0.82f - (i * 0.11f);
                float yMin = yMax - 0.1f;

                // Панель игрока с градиентом
                container.Add(new CuiPanel
                {
                    Image = { Color = HexToRustFormat(config.UI.ButtonColor, 0.3f) },
                    RectTransform = { AnchorMin = $"0.02 {yMin}", AnchorMax = $"0.98 {yMax}" }
                }, "ContentArea", $"Player_{i}");

                // Статус игрока (онлайн/админ/VIP)
                string statusIcon = "🟢";
                if (HasPermission(targetPlayer, config.Permissions.AdminPanel)) statusIcon = "👑";
                else if (HasPermission(targetPlayer, config.Permissions.VIP)) statusIcon = "💎";
                else if (HasPermission(targetPlayer, config.Permissions.Moderator)) statusIcon = "🛡️";

                // Информация об игроке
                container.Add(new CuiLabel
                {
                    Text = { Text = $"{statusIcon} {targetPlayer.displayName}", FontSize = 13, Align = TextAnchor.MiddleLeft, Color = HexToRustFormat(config.UI.TextColor) },
                    RectTransform = { AnchorMin = "0.02 0.5", AnchorMax = "0.35 1" }
                }, $"Player_{i}");

                container.Add(new CuiLabel
                {
                    Text = { Text = $"💰 {targetData.Balance} {config.Shop.Currency} | ⚠️ {targetData.Warnings.Count}", FontSize = 10, Align = TextAnchor.MiddleLeft, Color = HexToRustFormat(config.UI.InfoColor) },
                    RectTransform = { AnchorMin = "0.02 0", AnchorMax = "0.35 0.5" }
                }, $"Player_{i}");

                // Улучшенные кнопки действий
                string[] actions = { "👢 Кик", "🔨 Бан", "🔇 Мут", "📍 ТП к", "📌 ТП сюда", "💰 Деньги", "📦 Инвентарь" };
                string[] commands = { "кик", "бан", "мут", "тп", "игрока", "money", "inventory" };
                string[] colors = { config.UI.DangerColor, config.UI.DangerColor, config.UI.WarningColor, config.UI.ButtonColor, config.UI.ButtonColor, config.UI.SuccessColor, config.UI.InfoColor };
                
                for (int j = 0; j < actions.Length; j++)
                {
                    float btnXMin = 0.37f + (j * 0.088f);
                    float btnXMax = btnXMin + 0.085f;

                    container.Add(new CuiButton
                    {
                        Button = { Command = $"adminpanel.player {commands[j]} {targetPlayer.userID}", Color = HexToRustFormat(colors[j], 0.8f) },
                        RectTransform = { AnchorMin = $"{btnXMin} 0.1", AnchorMax = $"{btnXMax} 0.9" },
                        Text = { Text = actions[j], FontSize = 8, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                    }, $"Player_{i}");
                }
            }
        }

        void OpenShopPanel(BasePlayer player, string category = "")
        {
            CloseAllPanels(player);
            
            var container = new CuiElementContainer();

            // Основная панель магазина без фонового затемнения
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.98f) },
                RectTransform = { AnchorMin = "0.1 0.05", AnchorMax = "0.9 0.95" },
                CursorEnabled = true
            }, "Overlay", "ShopPanel");

            // Декоративные рамки
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.8f) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "1 0.008" }
            }, "ShopPanel");

            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.8f) },
                RectTransform = { AnchorMin = "0 0.992", AnchorMax = "1 1" }
            }, "ShopPanel");

            // Заголовок с градиентом
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0 0.9", AnchorMax = "1 1" }
            }, "ShopPanel", "ShopHeader");

            var playerData = GetPlayerData(player.userID);
            container.Add(new CuiLabel
            {
                Text = { Text = $"🏪 ПРЕМИУМ МАГАЗИН 🏪", FontSize = 18, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0.3", AnchorMax = "0.85 1" }
            }, "ShopHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = $"💰 {playerData.Balance} {config.Shop.Currency}", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.SuccessColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "0.85 0.3" }
            }, "ShopHeader");

            // Кнопка "Назад"
            container.Add(new CuiButton
            {
                Button = { Command = "adminpanel.section players", Color = HexToRustFormat(config.UI.InfoColor, 0.8f) },
                RectTransform = { AnchorMin = "0.85 0.02", AnchorMax = "0.91 0.08" },
                Text = { Text = "⬅", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "ShopHeader");

            // Кнопка закрытия
            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor, 0.8f) },
                RectTransform = { AnchorMin = "0.92 0.02", AnchorMax = "0.98 0.08" },
                Text = { Text = "✕", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "ShopHeader");

            // Категории товаров с иконками
            var categories = config.Shop.Items.Select(x => x.Category).Distinct().ToList();
            var categoryData = new Dictionary<string, string>
            {
                ["Оружие"] = "⚔️",
                ["Броня"] = "🛡️", 
                ["Медицина"] = "💊",
                ["Инструменты"] = "🔧",
                ["Ресурсы"] = "🏗️"
            };

            // Кнопка "Все товары"
            container.Add(new CuiButton
            {
                Button = { Command = "shop.category all", Color = string.IsNullOrEmpty(category) ? HexToRustFormat(config.UI.SuccessColor, 0.8f) : HexToRustFormat(config.UI.ButtonColor, 0.7f) },
                RectTransform = { AnchorMin = "0.02 0.82", AnchorMax = "0.18 0.88" },
                Text = { Text = "📦 Все товары", FontSize = 10, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) }
            }, "ShopPanel");
            
            for (int i = 0; i < categories.Count && i < 4; i++)
            {
                float xMin = 0.2f + (i * 0.19f);
                float xMax = xMin + 0.18f;
                string icon = categoryData.ContainsKey(categories[i]) ? categoryData[categories[i]] : "📦";
                bool isSelected = category == categories[i];

                container.Add(new CuiButton
                {
                    Button = { Command = $"shop.category {categories[i]}", Color = isSelected ? HexToRustFormat(config.UI.SuccessColor, 0.8f) : HexToRustFormat(config.UI.ButtonColor, 0.7f) },
                    RectTransform = { AnchorMin = $"{xMin} 0.82", AnchorMax = $"{xMax} 0.88" },
                    Text = { Text = $"{icon} {categories[i]}", FontSize = 10, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) }
                }, "ShopPanel");
            }

            // Фильтруем товары по категории
            var items = string.IsNullOrEmpty(category) || category == "all" 
                ? config.Shop.Items.Take(15).ToList()
                : config.Shop.Items.Where(x => x.Category == category).Take(15).ToList();
            for (int i = 0; i < items.Count; i++)
            {
                int row = i / 5;
                int col = i % 5;
                
                float xMin = 0.02f + (col * 0.19f);
                float xMax = xMin + 0.18f;
                float yMax = 0.78f - (row * 0.24f);
                float yMin = yMax - 0.22f;

                var item = items[i];

                // Панель товара с тенью
                container.Add(new CuiPanel
                {
                    Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                    RectTransform = { AnchorMin = $"{xMin} {yMin}", AnchorMax = $"{xMax} {yMax}" }
                }, "ShopPanel", $"ShopItem_{i}");

                // Рамка товара
                container.Add(new CuiPanel
                {
                    Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.5f) },
                    RectTransform = { AnchorMin = "0 0", AnchorMax = "1 0.02" }
                }, $"ShopItem_{i}");

                // Название товара
                container.Add(new CuiLabel
                {
                    Text = { Text = item.Name, FontSize = 10, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                    RectTransform = { AnchorMin = "0.05 0.7", AnchorMax = "0.95 0.95" }
                }, $"ShopItem_{i}");

                // Категория
                container.Add(new CuiLabel
                {
                    Text = { Text = item.Category, FontSize = 8, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.InfoColor) },
                    RectTransform = { AnchorMin = "0.05 0.55", AnchorMax = "0.95 0.7" }
                }, $"ShopItem_{i}");

                // Цена с эффектом
                container.Add(new CuiPanel
                {
                    Image = { Color = HexToRustFormat(config.UI.WarningColor, 0.3f) },
                    RectTransform = { AnchorMin = "0.1 0.35", AnchorMax = "0.9 0.55" }
                }, $"ShopItem_{i}", $"PricePanel_{i}");

                container.Add(new CuiLabel
                {
                    Text = { Text = $"💰 {item.Price} {config.Shop.Currency}", FontSize = 9, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                    RectTransform = { AnchorMin = "0 0", AnchorMax = "1 1" }
                }, $"PricePanel_{i}");

                // Кнопка покупки с анимацией
                bool canBuy = playerData.Balance >= item.Price;
                string buttonColor = canBuy ? config.UI.SuccessColor : config.UI.DangerColor;
                string buttonText = canBuy ? "✅ КУПИТЬ" : "❌ НЕТ СРЕДСТВ";
                
                container.Add(new CuiButton
                {
                    Button = { Command = canBuy ? $"shop.buy {item.ShortName}" : "", Color = HexToRustFormat(buttonColor, 0.8f) },
                    RectTransform = { AnchorMin = "0.05 0.05", AnchorMax = "0.95 0.3" },
                    Text = { Text = buttonText, FontSize = 8, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                }, $"ShopItem_{i}");
            }

            CuiHelper.AddUi(player, container);
        }

        void OpenKitMenu(BasePlayer player)
        {
            CloseAllPanels(player);
            
            var container = new CuiElementContainer();

            // Основная панель без фонового затемнения
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.98f) },
                RectTransform = { AnchorMin = "0.15 0.1", AnchorMax = "0.85 0.9" },
                CursorEnabled = true
            }, "Overlay", "KitPanel");

            // Декоративные элементы
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.8f) },
                RectTransform = { AnchorMin = "0 0.95", AnchorMax = "1 1" }
            }, "KitPanel");

            // Заголовок с градиентом
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0 0.85", AnchorMax = "1 0.95" }
            }, "KitPanel", "KitHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = "📦 НАБОРЫ И КИТЫ 📦", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "0.9 1" }
            }, "KitHeader");

            // Кнопка "Назад"
            container.Add(new CuiButton
            {
                Button = { Command = "adminpanel.section players", Color = HexToRustFormat(config.UI.InfoColor, 0.8f) },
                RectTransform = { AnchorMin = "0.85 0.02", AnchorMax = "0.91 0.08" },
                Text = { Text = "⬅", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "KitHeader");

            // Кнопка закрытия
            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor, 0.8f) },
                RectTransform = { AnchorMin = "0.92 0.02", AnchorMax = "0.98 0.08" },
                Text = { Text = "✕", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "KitHeader");

            // Список китов с улучшенным дизайном
            var playerData = GetPlayerData(player.userID);
            for (int i = 0; i < storedData.Kits.Count && i < 10; i++)
            {
                var kit = storedData.Kits[i];
                float yMax = 0.8f - (i * 0.075f);
                float yMin = yMax - 0.065f;

                bool canUse = string.IsNullOrEmpty(kit.Permission) || HasPermission(player, kit.Permission);
                
                // Проверка кулдауна
                bool onCooldown = false;
                if (playerData.KitCooldowns.ContainsKey(kit.Name))
                {
                    onCooldown = DateTime.Now < playerData.KitCooldowns[kit.Name];
                }

                string buttonColor;
                string statusText = "";
                
                if (!canUse)
                {
                    buttonColor = config.UI.DangerColor;
                    statusText = "🔒 НЕТ ДОСТУПА";
                }
                else if (onCooldown)
                {
                    buttonColor = config.UI.WarningColor;
                    var timeLeft = playerData.KitCooldowns[kit.Name] - DateTime.Now;
                    statusText = $"⏰ {timeLeft.Minutes}м {timeLeft.Seconds}с";
                }
                else
                {
                    buttonColor = config.UI.SuccessColor;
                    statusText = "✅ ДОСТУПЕН";
                }

                // Панель кита
                container.Add(new CuiPanel
                {
                    Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.8f) },
                    RectTransform = { AnchorMin = $"0.05 {yMin}", AnchorMax = $"0.95 {yMax}" }
                }, "KitPanel", $"Kit_{i}");

                // Название и описание кита
                container.Add(new CuiLabel
                {
                    Text = { Text = $"📦 {kit.Name}", FontSize = 12, Align = TextAnchor.MiddleLeft, Color = HexToRustFormat(config.UI.TextColor) },
                    RectTransform = { AnchorMin = "0.02 0.5", AnchorMax = "0.4 1" }
                }, $"Kit_{i}");

                container.Add(new CuiLabel
                {
                    Text = { Text = kit.Description, FontSize = 9, Align = TextAnchor.MiddleLeft, Color = HexToRustFormat(config.UI.InfoColor) },
                    RectTransform = { AnchorMin = "0.02 0", AnchorMax = "0.4 0.5" }
                }, $"Kit_{i}");

                // Статус кита
                container.Add(new CuiLabel
                {
                    Text = { Text = statusText, FontSize = 10, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                    RectTransform = { AnchorMin = "0.42 0", AnchorMax = "0.7 1" }
                }, $"Kit_{i}");

                // Кнопка получения кита
                container.Add(new CuiButton
                {
                    Button = { Command = canUse && !onCooldown ? $"kit.give {kit.Name}" : "", Color = HexToRustFormat(buttonColor, 0.8f) },
                    RectTransform = { AnchorMin = "0.72 0.1", AnchorMax = "0.95 0.9" },
                    Text = { Text = "ПОЛУЧИТЬ", FontSize = 10, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                }, $"Kit_{i}");
            }

            CuiHelper.AddUi(player, container);
        }

        void OpenTeleportMenu(BasePlayer player)
        {
            CloseAllPanels(player);
            
            var container = new CuiElementContainer();

            // Основная панель без фонового затемнения
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.98f) },
                RectTransform = { AnchorMin = "0.25 0.15", AnchorMax = "0.75 0.85" },
                CursorEnabled = true
            }, "Overlay", "TeleportPanel");

            // Декоративная рамка
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.AccentColor, 0.8f) },
                RectTransform = { AnchorMin = "0 0.95", AnchorMax = "1 1" }
            }, "TeleportPanel");

            // Заголовок
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0 0.85", AnchorMax = "1 0.95" }
            }, "TeleportPanel", "TeleportHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = "🌍 СИСТЕМА ТЕЛЕПОРТА 🌍", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "0.9 1" }
            }, "TeleportHeader");

            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor, 0.8f) },
                RectTransform = { AnchorMin = "0.9 0.02", AnchorMax = "0.98 0.08" },
                Text = { Text = "✕", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "TeleportHeader");

            // Популярные локации с иконками
            string[] locations = { "🏠 Спавн", "🏴‍☠️ Bandit Camp", "🏛️ Outpost", "🚀 Launch Site", "🛢️ Dome", "⛽ Gas Station", "🏭 Power Plant", "🌊 Water Treatment" };
            string[] locationIds = { "spawn", "bandit", "outpost", "launch", "dome", "gas", "power", "water" };
            
            for (int i = 0; i < locations.Length && i < 8; i++)
            {
                float yMax = 0.8f - (i * 0.09f);
                float yMin = yMax - 0.08f;

                container.Add(new CuiPanel
                {
                    Image = { Color = HexToRustFormat(config.UI.ButtonColor, 0.6f) },
                    RectTransform = { AnchorMin = $"0.05 {yMin}", AnchorMax = $"0.95 {yMax}" }
                }, "TeleportPanel", $"Location_{i}");

                container.Add(new CuiButton
                {
                    Button = { Command = $"teleport.location {locationIds[i]}", Color = "0 0 0 0" },
                    RectTransform = { AnchorMin = "0 0", AnchorMax = "1 1" },
                    Text = { Text = locations[i], FontSize = 12, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) }
                }, $"Location_{i}");
            }

            CuiHelper.AddUi(player, container);
        }

        void OpenWeatherPanel(BasePlayer player)
        {
            CloseAllPanels(player);
            
            var container = new CuiElementContainer();

            // Основная панель без фонового затемнения
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.98f) },
                RectTransform = { AnchorMin = "0.3 0.2", AnchorMax = "0.7 0.8" },
                CursorEnabled = true
            }, "Overlay", "WeatherPanel");

            // Заголовок
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0 0.85", AnchorMax = "1 1" }
            }, "WeatherPanel", "WeatherHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = "🌤️ УПРАВЛЕНИЕ ПОГОДОЙ 🌤️", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "0.9 1" }
            }, "WeatherHeader");

            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor, 0.8f) },
                RectTransform = { AnchorMin = "0.9 0.02", AnchorMax = "0.98 0.08" },
                Text = { Text = "✕", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "WeatherHeader");

            // Кнопки погоды
            string[] weatherTypes = { "☀️ Ясно", "🌧️ Дождь", "⛈️ Буря", "🌫️ Туман" };
            string[] weatherCommands = { "clear", "rain", "storm", "fog" };
            
            for (int i = 0; i < weatherTypes.Length; i++)
            {
                float yMax = 0.75f - (i * 0.15f);
                float yMin = yMax - 0.12f;

                container.Add(new CuiButton
                {
                    Button = { Command = $"weather.set {weatherCommands[i]}", Color = HexToRustFormat(config.UI.ButtonColor, 0.8f) },
                    RectTransform = { AnchorMin = $"0.1 {yMin}", AnchorMax = $"0.9 {yMax}" },
                    Text = { Text = weatherTypes[i], FontSize = 12, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) }
                }, "WeatherPanel");
            }

            CuiHelper.AddUi(player, container);
        }

        void OpenTimePanel(BasePlayer player)
        {
            CloseAllPanels(player);
            
            var container = new CuiElementContainer();

            // Основная панель без фонового затемнения
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.98f) },
                RectTransform = { AnchorMin = "0.3 0.2", AnchorMax = "0.7 0.8" },
                CursorEnabled = true
            }, "Overlay", "TimePanel");

            // Заголовок
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0 0.85", AnchorMax = "1 1" }
            }, "TimePanel", "TimeHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = "🕐 УПРАВЛЕНИЕ ВРЕМЕНЕМ 🕐", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "0.9 1" }
            }, "TimeHeader");

            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor, 0.8f) },
                RectTransform = { AnchorMin = "0.9 0.02", AnchorMax = "0.98 0.08" },
                Text = { Text = "✕", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "TimeHeader");

            // Кнопки времени
            string[] timeTypes = { "🌅 Рассвет (6:00)", "☀️ День (12:00)", "🌆 Закат (18:00)", "🌙 Ночь (0:00)" };
            string[] timeCommands = { "6", "12", "18", "0" };
            
            for (int i = 0; i < timeTypes.Length; i++)
            {
                float yMax = 0.75f - (i * 0.15f);
                float yMin = yMax - 0.12f;

                container.Add(new CuiButton
                {
                    Button = { Command = $"time.set {timeCommands[i]}", Color = HexToRustFormat(config.UI.ButtonColor, 0.8f) },
                    RectTransform = { AnchorMin = $"0.1 {yMin}", AnchorMax = $"0.9 {yMax}" },
                    Text = { Text = timeTypes[i], FontSize = 12, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) }
                }, "TimePanel");
            }

            CuiHelper.AddUi(player, container);
        }

        void OpenServerPanel(BasePlayer player)
        {
            CloseAllPanels(player);
            
            var container = new CuiElementContainer();

            // Основная панель без фонового затемнения
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.98f) },
                RectTransform = { AnchorMin = "0.25 0.15", AnchorMax = "0.75 0.85" },
                CursorEnabled = true
            }, "Overlay", "ServerPanel");

            // Заголовок
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.9f) },
                RectTransform = { AnchorMin = "0 0.85", AnchorMax = "1 1" }
            }, "ServerPanel", "ServerHeader");

            container.Add(new CuiLabel
            {
                Text = { Text = "🖥️ УПРАВЛЕНИЕ СЕРВЕРОМ 🖥️", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) },
                RectTransform = { AnchorMin = "0 0", AnchorMax = "0.9 1" }
            }, "ServerHeader");

            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor, 0.8f) },
                RectTransform = { AnchorMin = "0.9 0.02", AnchorMax = "0.98 0.08" },
                Text = { Text = "✕", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "ServerHeader");

            // Кнопки управления сервером
            string[] serverActions = { "💾 Сохранить", "🔄 Перезагрузка", "📊 Статистика", "🧹 Очистить", "📢 Объявление" };
            string[] serverCommands = { "save", "restart", "stats", "cleanup", "announce" };
            
            for (int i = 0; i < serverActions.Length; i++)
            {
                float yMax = 0.75f - (i * 0.12f);
                float yMin = yMax - 0.1f;

                string buttonColor = i == 1 ? config.UI.DangerColor : config.UI.ButtonColor; // Перезагрузка красная

                container.Add(new CuiButton
                {
                    Button = { Command = $"server.action {serverCommands[i]}", Color = HexToRustFormat(buttonColor, 0.8f) },
                    RectTransform = { AnchorMin = $"0.1 {yMin}", AnchorMax = $"0.9 {yMax}" },
                    Text = { Text = serverActions[i], FontSize = 12, Align = TextAnchor.MiddleCenter, Color = HexToRustFormat(config.UI.TextColor) }
                }, "ServerPanel");
            }

            CuiHelper.AddUi(player, container);
        }

        #endregion

        #region Console Commands

        [ConsoleCommand("ui.close")]
        void CloseUI(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            CloseAllPanels(player);
        }

        [ConsoleCommand("adminpanel.player")]
        void PlayerAction(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null || !HasPermission(player, config.Permissions.AdminPanel)) return;

            if (arg.Args == null || arg.Args.Length < 2) return;

            string action = arg.Args[0];
            if (!ulong.TryParse(arg.Args[1], out ulong targetId)) return;

            var targetPlayer = BasePlayer.FindByID(targetId);
            if (targetPlayer == null)
            {
                SendReply(player, $"{config.ChatPrefix} Игрок не найден!");
                return;
            }

            ExecutePlayerAction(player, targetPlayer, action);
        }

        [ConsoleCommand("adminpanel.section")]
        void ChangeAdminSection(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null || !HasPermission(player, config.Permissions.AdminPanel)) return;

            string section = arg.Args?[0]?.ToLower();
            
            // Закрываем текущую панель и открываем новую секцию
            CuiHelper.DestroyUi(player, "AdminPanel");
            CuiHelper.DestroyUi(player, "AdminPanelBackground");
            
            timer.Once(0.1f, () =>
            {
                switch (section)
                {
                    case "players":
                    case "игроки":
                        OpenAdminPanel(player);
                        break;
                    case "teleport":
                    case "телепорт":
                        OpenTeleportMenu(player);
                        break;
                    case "kits":
                    case "киты":
                        OpenKitMenu(player);
                        break;
                    case "weather":
                    case "погода":
                        OpenWeatherPanel(player);
                        break;
                    case "time":
                    case "время":
                        OpenTimePanel(player);
                        break;
                    case "server":
                    case "сервер":
                        OpenServerPanel(player);
                        break;
                    default:
                        OpenAdminPanel(player);
                        break;
                }
            });
        }

        [ConsoleCommand("shop.category")]
        void ShopCategory(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            string category = arg.Args?[0];
            if (category == "all") category = "";
            
            OpenShopPanel(player, category);
        }

        [ConsoleCommand("shop.buy")]
        void BuyItem(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            string shortName = arg.Args?[0];
            if (string.IsNullOrEmpty(shortName)) return;

            var item = config.Shop.Items.FirstOrDefault(x => x.ShortName == shortName);
            if (item == null)
            {
                SendReply(player, $"{config.ChatPrefix} Товар не найден!");
                return;
            }

            var playerData = GetPlayerData(player.userID);
            if (playerData.Balance < item.Price)
            {
                SendReply(player, $"{config.ChatPrefix} Недостаточно средств! Нужно: {item.Price} {config.Shop.Currency}");
                ShowNotification(player, $"❌ Недостаточно средств!", config.UI.DangerColor);
                return;
            }

            // Выдаем предмет
            var gameItem = ItemManager.CreateByName(item.ShortName, item.Amount);
            if (gameItem == null)
            {
                SendReply(player, $"{config.ChatPrefix} Ошибка создания предмета!");
                return;
            }

            if (!player.inventory.GiveItem(gameItem))
            {
                gameItem.Drop(player.transform.position, Vector3.up * 2f);
            }

            // Списываем средства
            playerData.Balance -= item.Price;
            SendReply(player, $"{config.ChatPrefix} Вы купили <color=#27ae60>{item.Name}</color> за {item.Price} {config.Shop.Currency}!");
            ShowNotification(player, $"✅ Куплено: {item.Name}", config.UI.SuccessColor);
            
            // Обновляем UI магазина
            timer.Once(0.1f, () => OpenShopPanel(player));
        }



        [ConsoleCommand("kit.give")]
        void GiveKitFromUI(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            string kitName = arg.Args?[0];
            if (string.IsNullOrEmpty(kitName)) return;

            GiveKit(player, kitName);
            CloseAllPanels(player);
        }



        [ConsoleCommand("teleport.location")]
        void TeleportToLocation(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null || !HasPermission(player, config.Permissions.Moderator)) return;

            string locationName = arg.Args?[0];
            if (string.IsNullOrEmpty(locationName)) return;

            Vector3 position = GetLocationPosition(locationName);
            if (position != Vector3.zero)
            {
                player.Teleport(position);
                SendReply(player, $"{config.ChatPrefix} 🌍 Телепорт в: {locationName}");
                ShowNotification(player, $"🌍 Телепорт: {locationName}", config.UI.InfoColor);
                CloseAllPanels(player);
                
                // Уведомляем администраторов
                foreach (var admin in BasePlayer.activePlayerList)
                {
                    if (HasPermission(admin, config.Permissions.AdminPanel) && admin != player)
                    {
                        SendReply(admin, $"{config.ChatPrefix} 📍 <color=#3498db>{player.displayName}</color> телепортировался в <color=#27ae60>{locationName}</color>");
                    }
                }
            }
            else
            {
                SendReply(player, $"{config.ChatPrefix} Локация не найдена!");
            }
        }



        [ConsoleCommand("weather.set")]
        void SetWeatherFromUI(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null || !HasPermission(player, config.Permissions.Weather)) return;

            string weatherType = arg.Args?[0];
            if (string.IsNullOrEmpty(weatherType)) return;

            WeatherCommand(player, "weather", new[] { weatherType });
            CloseAllPanels(player);
        }



        [ConsoleCommand("time.set")]
        void SetTimeFromUI(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null || !HasPermission(player, config.Permissions.Time)) return;

            string time = arg.Args?[0];
            if (string.IsNullOrEmpty(time)) return;

            TimeCommand(player, "time", new[] { time });
            CloseAllPanels(player);
        }



        [ConsoleCommand("server.action")]
        void ServerActionFromUI(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null || !HasPermission(player, config.Permissions.AdminPanel)) return;

            string action = arg.Args?[0];
            if (string.IsNullOrEmpty(action)) return;

            switch (action.ToLower())
            {
                case "save":
                    SaveAllCommand(player, "saveall", new string[0]);
                    break;
                case "restart":
                    RestartCommand(player, "restart", new[] { "60" });
                    break;
                case "stats":
                    OnlineCommand(player, "online", new string[0]);
                    break;
                case "cleanup":
                    Server.Command("entity.deleteby !player");
                    SendReply(player, $"{config.ChatPrefix} 🧹 Очистка мусора выполнена!");
                    Server.Broadcast($"{config.ChatPrefix} <color=#27ae60>🧹 Администратор {player.displayName} выполнил очистку сервера!</color>");
                    break;
            }

            CloseAllPanels(player);
        }

        #endregion

        #region Helper Methods

        PlayerData GetPlayerData(ulong userId)
        {
            if (!storedData.Players.ContainsKey(userId))
            {
                storedData.Players[userId] = new PlayerData
                {
                    Name = "Unknown",
                    Balance = 1000,
                    LastSeen = DateTime.Now
                };
            }
            return storedData.Players[userId];
        }

        void ExecutePlayerAction(BasePlayer admin, BasePlayer target, string action)
        {
            switch (action.ToLower())
            {
                case "кик":
                    target.Kick($"Вы были исключены администратором {admin.displayName}");
                    SendReply(admin, $"{config.ChatPrefix} 👢 Игрок {target.displayName} исключен");
                    Server.Broadcast($"{config.ChatPrefix} <color=#e74c3c>👢 Игрок {target.displayName} исключен администратором {admin.displayName}</color>");
                    break;

                case "бан":
                    Server.Command($"ban {target.userID} \"Забанен администратором {admin.displayName}\"");
                    target.Kick($"Вы забанены администратором {admin.displayName}");
                    SendReply(admin, $"{config.ChatPrefix} 🔨 Игрок {target.displayName} забанен");
                    Server.Broadcast($"{config.ChatPrefix} <color=#e74c3c>🔨 Игрок {target.displayName} забанен администратором {admin.displayName}</color>");
                    break;

                case "мут":
                    var playerData = GetPlayerData(target.userID);
                    playerData.IsMuted = true;
                    playerData.MuteExpiry = DateTime.Now.AddHours(1);
                    SendReply(admin, $"{config.ChatPrefix} 🔇 Игрок {target.displayName} заглушен на 1 час");
                    SendReply(target, $"{config.ChatPrefix} 🔇 Вы заглушены на 1 час администратором {admin.displayName}");
                    Server.Broadcast($"{config.ChatPrefix} <color=#f39c12>🔇 Игрок {target.displayName} заглушен администратором {admin.displayName}</color>");
                    break;

                case "тп":
                    admin.Teleport(target.transform.position);
                    SendReply(admin, $"{config.ChatPrefix} 📍 Телепорт к игроку {target.displayName}");
                    foreach (var otherAdmin in BasePlayer.activePlayerList)
                    {
                        if (HasPermission(otherAdmin, config.Permissions.AdminPanel) && otherAdmin != admin)
                        {
                            SendReply(otherAdmin, $"{config.ChatPrefix} 📍 <color=#3498db>{admin.displayName}</color> телепортировался к <color=#27ae60>{target.displayName}</color>");
                        }
                    }
                    break;

                case "игрока":
                    target.Teleport(admin.transform.position);
                    SendReply(admin, $"{config.ChatPrefix} 📌 Игрок {target.displayName} телепортирован к вам");
                    SendReply(target, $"{config.ChatPrefix} 📌 Вы телепортированы к администратору {admin.displayName}");
                    foreach (var otherAdmin in BasePlayer.activePlayerList)
                    {
                        if (HasPermission(otherAdmin, config.Permissions.AdminPanel) && otherAdmin != admin)
                        {
                            SendReply(otherAdmin, $"{config.ChatPrefix} 📌 <color=#3498db>{admin.displayName}</color> телепортировал <color=#27ae60>{target.displayName}</color> к себе");
                        }
                    }
                    break;

                case "money":
                    // Открываем меню управления деньгами
                    SendReply(admin, $"{config.ChatPrefix} 💰 Управление деньгами игрока {target.displayName}:");
                    SendReply(admin, $"{config.ChatPrefix} /money give {target.displayName} <сумма> - Выдать деньги");
                    SendReply(admin, $"{config.ChatPrefix} /money take {target.displayName} <сумма> - Забрать деньги");
                    SendReply(admin, $"{config.ChatPrefix} /money set {target.displayName} <сумма> - Установить баланс");
                    break;

                case "inventory":
                    ShowPlayerInventory(admin, target);
                    break;
            }
        }

        void GiveKit(BasePlayer player, string kitName)
        {
            var kit = storedData.Kits.FirstOrDefault(x => x.Name.ToLower() == kitName.ToLower());
            if (kit == null)
            {
                SendReply(player, $"{config.ChatPrefix} Кит не найден!");
                return;
            }

            if (!string.IsNullOrEmpty(kit.Permission) && !HasPermission(player, kit.Permission))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет доступа к этому киту!");
                return;
            }

            var playerData = GetPlayerData(player.userID);
            
            // Проверка кулдауна
            if (kit.Cooldown > 0 && playerData.KitCooldowns.ContainsKey(kit.Name))
            {
                if (DateTime.Now < playerData.KitCooldowns[kit.Name])
                {
                    var timeLeft = playerData.KitCooldowns[kit.Name] - DateTime.Now;
                    SendReply(player, $"{config.ChatPrefix} ⏰ Кит будет доступен через {timeLeft.Hours}ч {timeLeft.Minutes}м {timeLeft.Seconds}с");
                    return;
                }
            }

            // Выдаем предметы из кита
            int itemsGiven = 0;
            foreach (var kitItem in kit.Items)
            {
                var item = ItemManager.CreateByName(kitItem.ShortName, kitItem.Amount, kitItem.SkinId);
                if (item != null)
                {
                    if (!player.inventory.GiveItem(item))
                    {
                        item.Drop(player.transform.position + Vector3.up * 2f, Vector3.up * 2f);
                    }
                    itemsGiven++;
                }
            }

            // Устанавливаем кулдаун
            if (kit.Cooldown > 0)
            {
                playerData.KitCooldowns[kit.Name] = DateTime.Now.AddSeconds(kit.Cooldown);
            }

            SendReply(player, $"{config.ChatPrefix} ✅ Вы получили кит: <color=#27ae60>{kit.Name}</color>");
            SendReply(player, $"{config.ChatPrefix} 📦 Выдано предметов: <color=#3498db>{itemsGiven}</color>");
            ShowNotification(player, $"📦 Получен кит: {kit.Name}", config.UI.SuccessColor);
            
            // Уведомляем администраторов о получении кита
            foreach (var admin in BasePlayer.activePlayerList)
            {
                if (HasPermission(admin, config.Permissions.AdminPanel) && admin != player)
                {
                    SendReply(admin, $"{config.ChatPrefix} 📦 <color=#3498db>{player.displayName}</color> получил кит <color=#27ae60>{kit.Name}</color>");
                }
            }
        }

        Vector3 GetLocationPosition(string locationName)
        {
            switch (locationName.ToLower())
            {
                case "spawn":
                case "спавн":
                    var spawnPoint = UnityEngine.Object.FindObjectOfType<SpawnHandler>();
                    return spawnPoint?.transform.position ?? new Vector3(0, 0, 0);

                case "bandit":
                case "bandit camp":
                    var monuments = UnityEngine.Object.FindObjectsOfType<MonumentInfo>();
                    var bandit = monuments.FirstOrDefault(x => x.name.Contains("bandit"));
                    return bandit?.transform.position ?? Vector3.zero;

                case "outpost":
                    var outpostMonuments = UnityEngine.Object.FindObjectsOfType<MonumentInfo>();
                    var outpost = outpostMonuments.FirstOrDefault(x => x.name.Contains("compound"));
                    return outpost?.transform.position ?? Vector3.zero;

                case "launch":
                case "launch site":
                    var launchMonuments = UnityEngine.Object.FindObjectsOfType<MonumentInfo>();
                    var launch = launchMonuments.FirstOrDefault(x => x.name.Contains("launch_site"));
                    return launch?.transform.position ?? Vector3.zero;

                case "dome":
                    var domeMonuments = UnityEngine.Object.FindObjectsOfType<MonumentInfo>();
                    var dome = domeMonuments.FirstOrDefault(x => x.name.Contains("sphere_tank"));
                    return dome?.transform.position ?? Vector3.zero;

                case "gas":
                case "gas station":
                    var gasMonuments = UnityEngine.Object.FindObjectsOfType<MonumentInfo>();
                    var gas = gasMonuments.FirstOrDefault(x => x.name.Contains("gas_station"));
                    return gas?.transform.position ?? Vector3.zero;

                case "power":
                case "power plant":
                    var powerMonuments = UnityEngine.Object.FindObjectsOfType<MonumentInfo>();
                    var power = powerMonuments.FirstOrDefault(x => x.name.Contains("powerplant"));
                    return power?.transform.position ?? Vector3.zero;

                case "water":
                case "water treatment":
                    var waterMonuments = UnityEngine.Object.FindObjectsOfType<MonumentInfo>();
                    var water = waterMonuments.FirstOrDefault(x => x.name.Contains("water_treatment"));
                    return water?.transform.position ?? Vector3.zero;

                default:
                    var customLocation = storedData.TeleportLocations.FirstOrDefault(x => x.Name.ToLower() == locationName.ToLower());
                    return customLocation?.Position ?? Vector3.zero;
            }
        }

        void HandleTeleportCommand(BasePlayer player, string[] args)
        {
            if (args.Length == 1)
            {
                // Телепорт к игроку
                var targetPlayer = BasePlayer.Find(args[0]);
                if (targetPlayer == null)
                {
                    SendReply(player, $"{config.ChatPrefix} Игрок не найден!");
                    return;
                }

                player.Teleport(targetPlayer.transform.position);
                SendReply(player, $"{config.ChatPrefix} Телепорт к игроку {targetPlayer.displayName}");
            }
            else if (args.Length == 2)
            {
                // Телепорт игрока к игроку
                var player1 = BasePlayer.Find(args[0]);
                var player2 = BasePlayer.Find(args[1]);

                if (player1 == null || player2 == null)
                {
                    SendReply(player, $"{config.ChatPrefix} Один из игроков не найден!");
                    return;
                }

                player1.Teleport(player2.transform.position);
                SendReply(player, $"{config.ChatPrefix} {player1.displayName} телепортирован к {player2.displayName}");
            }
            else if (args.Length == 3)
            {
                // Телепорт по координатам
                if (float.TryParse(args[0], out float x) && 
                    float.TryParse(args[1], out float y) && 
                    float.TryParse(args[2], out float z))
                {
                    player.Teleport(new Vector3(x, y, z));
                    SendReply(player, $"{config.ChatPrefix} Телепорт по координатам: {x}, {y}, {z}");
                }
                else
                {
                    SendReply(player, $"{config.ChatPrefix} Неверные координаты!");
                }
            }
        }

        void CreateDefaultKits()
        {
            // Стартовый кит
            storedData.Kits.Add(new Kit
            {
                Name = "Старт",
                Description = "Стартовый набор для новичков",
                Cooldown = 3600, // 1 час
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "wood", Amount = 2000 },
                    new KitItem { ShortName = "stones", Amount = 2000 },
                    new KitItem { ShortName = "metal.fragments", Amount = 1000 },
                    new KitItem { ShortName = "cloth", Amount = 200 },
                    new KitItem { ShortName = "bandage", Amount = 10 },
                    new KitItem { ShortName = "apple", Amount = 20 },
                    new KitItem { ShortName = "water.salt", Amount = 10 },
                    new KitItem { ShortName = "hatchet", Amount = 1 },
                    new KitItem { ShortName = "pickaxe", Amount = 1 }
                }
            });

            // VIP кит
            storedData.Kits.Add(new Kit
            {
                Name = "VIP",
                Description = "VIP набор с оружием и броней",
                Permission = config.Permissions.VIP,
                Cooldown = 7200, // 2 часа
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "rifle.ak", Amount = 1 },
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 256 },
                    new KitItem { ShortName = "metal.plate.torso", Amount = 1 },
                    new KitItem { ShortName = "metal.facemask", Amount = 1 },
                    new KitItem { ShortName = "pants", Amount = 1 },
                    new KitItem { ShortName = "syringe.medical", Amount = 15 },
                    new KitItem { ShortName = "lowgradefuel", Amount = 500 },
                    new KitItem { ShortName = "gunpowder", Amount = 1000 }
                }
            });

            // Премиум кит
            storedData.Kits.Add(new Kit
            {
                Name = "Премиум",
                Description = "Премиум набор для донатеров",
                Permission = config.Permissions.Premium,
                Cooldown = 5400, // 1.5 часа
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "rifle.lr300", Amount = 1 },
                    new KitItem { ShortName = "pistol.python", Amount = 1 },
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 200 },
                    new KitItem { ShortName = "ammo.pistol.hv", Amount = 100 },
                    new KitItem { ShortName = "hoodie", Amount = 1 },
                    new KitItem { ShortName = "pants.shorts", Amount = 1 },
                    new KitItem { ShortName = "shoes.boots", Amount = 1 },
                    new KitItem { ShortName = "syringe.medical", Amount = 12 }
                }
            });

            // Элитный кит
            storedData.Kits.Add(new Kit
            {
                Name = "Элита",
                Description = "Элитный набор для особых игроков",
                Permission = config.Permissions.Elite,
                Cooldown = 3600, // 1 час
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "rifle.m39", Amount = 1 },
                    new KitItem { ShortName = "smg.mp5", Amount = 1 },
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 300 },
                    new KitItem { ShortName = "ammo.pistol.hv", Amount = 200 },
                    new KitItem { ShortName = "hazmatsuit", Amount = 1 },
                    new KitItem { ShortName = "syringe.medical", Amount = 20 },
                    new KitItem { ShortName = "explosives", Amount = 5 },
                    new KitItem { ShortName = "supply.signal", Amount = 2 }
                }
            });

            // Админ кит
            storedData.Kits.Add(new Kit
            {
                Name = "Админ",
                Description = "Админский супер-набор",
                Permission = config.Permissions.AdminPanel,
                Cooldown = 0,
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "rifle.lr300", Amount = 1 },
                    new KitItem { ShortName = "pistol.m92", Amount = 1 },
                    new KitItem { ShortName = "rifle.l96", Amount = 1 },
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 1000 },
                    new KitItem { ShortName = "ammo.pistol.hv", Amount = 500 },
                    new KitItem { ShortName = "hazmatsuit", Amount = 1 },
                    new KitItem { ShortName = "syringe.medical", Amount = 50 },
                    new KitItem { ShortName = "explosives", Amount = 20 },
                    new KitItem { ShortName = "rocket.launcher", Amount = 1 },
                    new KitItem { ShortName = "ammo.rocket.basic", Amount = 10 }
                }
            });

            // ПВП кит
            storedData.Kits.Add(new Kit
            {
                Name = "ПВП",
                Description = "Набор для PvP сражений",
                Cooldown = 1800, // 30 минут
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "rifle.bolt", Amount = 1 },
                    new KitItem { ShortName = "pistol.semiauto", Amount = 1 },
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 128 },
                    new KitItem { ShortName = "ammo.pistol.hv", Amount = 64 },
                    new KitItem { ShortName = "roadsign.kilt", Amount = 1 },
                    new KitItem { ShortName = "roadsign.jacket", Amount = 1 },
                    new KitItem { ShortName = "metal.facemask", Amount = 1 },
                    new KitItem { ShortName = "bandage", Amount = 30 },
                    new KitItem { ShortName = "syringe.medical", Amount = 8 }
                }
            });

            // Строительный кит
            storedData.Kits.Add(new Kit
            {
                Name = "Строитель",
                Description = "Набор для строительства",
                Permission = config.Permissions.Donator,
                Cooldown = 2700, // 45 минут
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "building.planner", Amount = 1 },
                    new KitItem { ShortName = "hammer", Amount = 1 },
                    new KitItem { ShortName = "wood", Amount = 5000 },
                    new KitItem { ShortName = "stones", Amount = 3000 },
                    new KitItem { ShortName = "metal.fragments", Amount = 2000 },
                    new KitItem { ShortName = "metal.refined", Amount = 100 },
                    new KitItem { ShortName = "door.hinged.metal", Amount = 5 },
                    new KitItem { ShortName = "lock.code", Amount = 5 }
                }
            });

            // Рейдерский кит
            storedData.Kits.Add(new Kit
            {
                Name = "Рейдер",
                Description = "Набор для рейдов",
                Permission = config.Permissions.Elite,
                Cooldown = 10800, // 3 часа
                Items = new List<KitItem>
                {
                    new KitItem { ShortName = "explosive.timed", Amount = 10 },
                    new KitItem { ShortName = "explosives", Amount = 50 },
                    new KitItem { ShortName = "gunpowder", Amount = 2000 },
                    new KitItem { ShortName = "sulfur", Amount = 3000 },
                    new KitItem { ShortName = "charcoal", Amount = 1500 },
                    new KitItem { ShortName = "rocket.launcher", Amount = 1 },
                    new KitItem { ShortName = "ammo.rocket.basic", Amount = 8 },
                    new KitItem { ShortName = "rifle.ak", Amount = 1 },
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 256 }
                }
            });

            SaveData();
        }

        string HexToRustFormat(string hex, float alpha = 1f)
        {
            hex = hex.Replace("#", "");
            
            if (hex.Length == 6)
            {
                var r = Convert.ToInt32(hex.Substring(0, 2), 16) / 255f;
                var g = Convert.ToInt32(hex.Substring(2, 2), 16) / 255f;
                var b = Convert.ToInt32(hex.Substring(4, 2), 16) / 255f;
                return $"{r} {g} {b} {alpha}";
            }
            
            return "1 1 1 1";
        }

        // Fixed method to get all items from player inventory
        List<Item> GetAllPlayerItems(BasePlayer player)
        {
            var allItems = new List<Item>();
            
            // Main inventory items
            if (player.inventory.containerMain?.itemList != null)
                allItems.AddRange(player.inventory.containerMain.itemList);
                
            // Belt items
            if (player.inventory.containerBelt?.itemList != null)
                allItems.AddRange(player.inventory.containerBelt.itemList);
                
            // Wear items
            if (player.inventory.containerWear?.itemList != null)
                allItems.AddRange(player.inventory.containerWear.itemList);
            
            return allItems;
        }

        #endregion

        #region Advanced Features

        [ChatCommand("money")]
        void MoneyCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.AdminPanel))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на управление деньгами!");
                return;
            }

            if (args.Length < 3)
            {
                SendReply(player, $"{config.ChatPrefix} Использование: /money <give/take/set> <игрок> <сумма>");
                return;
            }

            string action = args[0].ToLower();
            var targetPlayer = BasePlayer.Find(args[1]);
            if (targetPlayer == null)
            {
                SendReply(player, $"{config.ChatPrefix} Игрок не найден!");
                return;
            }

            if (!int.TryParse(args[2], out int amount))
            {
                SendReply(player, $"{config.ChatPrefix} Неверная сумма!");
                return;
            }

            var targetData = GetPlayerData(targetPlayer.userID);

            switch (action)
            {
                case "give":
                    targetData.Balance += amount;
                    SendReply(player, $"{config.ChatPrefix} Выдано {amount} {config.Shop.Currency} игроку {targetPlayer.displayName}");
                    SendReply(targetPlayer, $"{config.ChatPrefix} Вам выдано {amount} {config.Shop.Currency}!");
                    break;

                case "take":
                    targetData.Balance = Math.Max(0, targetData.Balance - amount);
                    SendReply(player, $"{config.ChatPrefix} Снято {amount} {config.Shop.Currency} у игрока {targetPlayer.displayName}");
                    SendReply(targetPlayer, $"{config.ChatPrefix} С вас снято {amount} {config.Shop.Currency}!");
                    break;

                case "set":
                    targetData.Balance = amount;
                    SendReply(player, $"{config.ChatPrefix} Баланс игрока {targetPlayer.displayName} установлен на {amount} {config.Shop.Currency}");
                    SendReply(targetPlayer, $"{config.ChatPrefix} Ваш баланс установлен на {amount} {config.Shop.Currency}!");
                    break;
            }
        }

        [ChatCommand("warn")]
        void WarnCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.Moderator))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на выдачу предупреждений!");
                return;
            }

            if (args.Length < 2)
            {
                SendReply(player, $"{config.ChatPrefix} Использование: /warn <игрок> <причина>");
                return;
            }

            var targetPlayer = BasePlayer.Find(args[0]);
            if (targetPlayer == null)
            {
                SendReply(player, $"{config.ChatPrefix} Игрок не найден!");
                return;
            }

            string reason = string.Join(" ", args.Skip(1));
            var targetData = GetPlayerData(targetPlayer.userID);
            targetData.Warnings.Add($"{DateTime.Now:dd.MM.yyyy HH:mm} - {reason} (Модератор: {player.displayName})");

            // Уведомляем модератора
            SendReply(player, $"{config.ChatPrefix} ⚠️ Предупреждение выдано игроку {targetPlayer.displayName}");
            
            // Уведомляем игрока
            SendReply(targetPlayer, $"{config.ChatPrefix} <color=#e74c3c>⚠️ ПРЕДУПРЕЖДЕНИЕ #{targetData.Warnings.Count}:</color> {reason}");
            SendReply(targetPlayer, $"{config.ChatPrefix} <color=#f39c12>Модератор: {player.displayName}</color>");

            // Уведомляем всех администраторов
            foreach (var admin in BasePlayer.activePlayerList)
            {
                if (HasPermission(admin, config.Permissions.AdminPanel) && admin != player)
                {
                    SendReply(admin, $"{config.ChatPrefix} 📢 <color=#f39c12>ПРЕДУПРЕЖДЕНИЕ ВЫДАНО</color>");
                    SendReply(admin, $"👤 Игрок: <color=#ecf0f1>{targetPlayer.displayName}</color>");
                    SendReply(admin, $"👮 Модератор: <color=#3498db>{player.displayName}</color>");
                    SendReply(admin, $"📝 Причина: <color=#e74c3c>{reason}</color>");
                    SendReply(admin, $"🔢 Предупреждений: <color=#e67e22>{targetData.Warnings.Count}/3</color>");
                }
            }

            // Глобальное уведомление для всех игроков
            Server.Broadcast($"{config.ChatPrefix} <color=#f39c12>⚠️ Игрок {targetPlayer.displayName} получил предупреждение от модератора {player.displayName}</color>");

            // Автобан при 3 предупреждениях
            if (targetData.Warnings.Count >= 3)
            {
                Server.Command($"ban {targetPlayer.userID} \"Автобан за 3 предупреждения\"");
                targetPlayer.Kick("Автобан за 3 предупреждения");
                
                // Уведомляем всех о бане
                Server.Broadcast($"{config.ChatPrefix} <color=#e74c3c>🔨 Игрок {targetPlayer.displayName} автоматически забанен за 3 предупреждения!</color>");
                Puts($"Игрок {targetPlayer.displayName} автоматически забанен за 3 предупреждения");
            }
        }

        [ChatCommand("inventory")]
        void InventoryCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.AdminPanel))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на просмотр инвентаря!");
                return;
            }

            if (args.Length == 0)
            {
                SendReply(player, $"{config.ChatPrefix} Использование: /inventory <игрок>");
                return;
            }

            var targetPlayer = BasePlayer.Find(args[0]);
            if (targetPlayer == null)
            {
                SendReply(player, $"{config.ChatPrefix} Игрок не найден!");
                return;
            }

            ShowPlayerInventory(player, targetPlayer);
        }

        void ShowPlayerInventory(BasePlayer viewer, BasePlayer target)
        {
            CloseAllPanels(viewer);
            
            var container = new CuiElementContainer();

            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.95f) },
                RectTransform = { AnchorMin = "0.1 0.1", AnchorMax = "0.9 0.9" },
                CursorEnabled = true
            }, "Overlay", "InventoryPanel");

            container.Add(new CuiLabel
            {
                Text = { Text = $"📦 ИНВЕНТАРЬ ИГРОКА: {target.displayName}", FontSize = 18, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0 0.9", AnchorMax = "1 1" }
            }, "InventoryPanel");

            container.Add(new CuiButton
            {
                Button = { Command = "ui.close", Color = HexToRustFormat(config.UI.DangerColor) },
                RectTransform = { AnchorMin = "0.92 0.92", AnchorMax = "0.98 0.98" },
                Text = { Text = "✕", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "InventoryPanel");

            // Отображение предметов в инвентаре
            var items = GetAllPlayerItems(target).Take(30).ToList();
            int itemsPerRow = 6;

            for (int i = 0; i < items.Count; i++)
            {
                int row = i / itemsPerRow;
                int col = i % itemsPerRow;

                float xMin = 0.05f + (col * 0.15f);
                float xMax = xMin + 0.12f;
                float yMax = 0.8f - (row * 0.15f);
                float yMin = yMax - 0.12f;

                var item = items[i];

                container.Add(new CuiPanel
                {
                    Image = { Color = "0.2 0.2 0.2 0.8" },
                    RectTransform = { AnchorMin = $"{xMin} {yMin}", AnchorMax = $"{xMax} {yMax}" }
                }, "InventoryPanel", $"Item_{i}");

                container.Add(new CuiLabel
                {
                    Text = { Text = $"{item.info.displayName.translated}", FontSize = 8, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                    RectTransform = { AnchorMin = "0 0.7", AnchorMax = "1 1" }
                }, $"Item_{i}");

                container.Add(new CuiLabel
                {
                    Text = { Text = $"x{item.amount}", FontSize = 10, Align = TextAnchor.MiddleCenter, Color = "#f1c40f 1" },
                    RectTransform = { AnchorMin = "0 0", AnchorMax = "1 0.3" }
                }, $"Item_{i}");
            }

            CuiHelper.AddUi(viewer, container);
        }



        #endregion

        #region Chat Filters

        object OnUserChat(IPlayer player, string message)
        {
            var basePlayer = player.Object as BasePlayer;
            if (basePlayer == null) return null;

            var playerData = GetPlayerData(basePlayer.userID);
            
            // Проверка мута
            if (playerData.IsMuted)
            {
                if (DateTime.Now < playerData.MuteExpiry)
                {
                    var timeLeft = playerData.MuteExpiry - DateTime.Now;
                    SendReply(basePlayer, $"{config.ChatPrefix} 🔇 Вы заглушены еще на {timeLeft.Minutes} мин. {timeLeft.Seconds} сек.");
                    return false;
                }
                else
                {
                    playerData.IsMuted = false;
                }
            }

            return null;
        }

        object OnEntityTakeDamage(BaseCombatEntity entity, HitInfo info)
        {
            var player = entity as BasePlayer;
            if (player == null) return null;

            var playerData = GetPlayerData(player.userID);
            if (playerData.IsGodMode)
            {
                return true; // Блокируем урон
            }

            return null;
        }

        void OnPlayerTick(BasePlayer player)
        {
            var playerData = GetPlayerData(player.userID);
            
            // Поддержание режима бога
            if (playerData.IsGodMode)
            {
                if (player.health < player.MaxHealth())
                {
                    player.health = player.MaxHealth();
                }
                
                player.metabolism.bleeding.value = 0;
                player.metabolism.radiation_poison.value = 0;
                player.metabolism.poison.value = 0;
                player.metabolism.calories.value = player.metabolism.calories.max;
                player.metabolism.hydration.value = player.metabolism.hydration.max;
            }
        }

        #endregion

        #region Server Management

        [ChatCommand("restart")]
        void RestartCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.AdminPanel))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на перезагрузку сервера!");
                return;
            }

            int delay = 60; // По умолчанию 60 секунд
            if (args.Length > 0 && int.TryParse(args[0], out int customDelay))
            {
                delay = customDelay;
            }

            Server.Broadcast($"{config.ChatPrefix} <color=#e74c3c>СЕРВЕР БУДЕТ ПЕРЕЗАГРУЖЕН ЧЕРЕЗ {delay} СЕКУНД!</color>");
            
            timer.Once(delay, () =>
            {
                Server.Command("quit");
            });
        }

        [ChatCommand("saveall")]
        void SaveAllCommand(BasePlayer player, string command, string[] args)
        {
            if (!HasPermission(player, config.Permissions.AdminPanel))
            {
                SendReply(player, $"{config.ChatPrefix} У вас нет прав на сохранение!");
                return;
            }

            Server.Command("save");
            SaveData();
            SendReply(player, $"{config.ChatPrefix} Сервер и данные плагина сохранены!");
        }

        #endregion
    }
}
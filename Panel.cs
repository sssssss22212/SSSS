using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Libraries.Covalence;
using Oxide.Core.Plugins;
using Oxide.Game.Rust.Cui;
using UnityEngine;

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
            public string PrimaryColor = "#2c3e50";

            [JsonProperty("Вторичный цвет")]
            public string SecondaryColor = "#34495e";

            [JsonProperty("Цвет кнопок")]
            public string ButtonColor = "#3498db";

            [JsonProperty("Цвет успеха")]
            public string SuccessColor = "#27ae60";

            [JsonProperty("Цвет опасности")]
            public string DangerColor = "#e74c3c";
        }

        public class PermissionSettings
        {
            [JsonProperty("Админ панель")]
            public string AdminPanel = "rustadminpro.admin";

            [JsonProperty("Модератор")]
            public string Moderator = "rustadminpro.moderator";

            [JsonProperty("VIP")]
            public string VIP = "rustadminpro.vip";
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
                new ShopItem { Name = "АК-47", ShortName = "rifle.ak", Price = 1000, Category = "Оружие" },
                new ShopItem { Name = "Металлическая броня", ShortName = "metal.plate.torso", Price = 500, Category = "Броня" },
                new ShopItem { Name = "Медицинский шприц", ShortName = "syringe.medical", Price = 100, Category = "Медицина" }
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
                CuiHelper.DestroyUi(player, "AdminPanel");
                CuiHelper.DestroyUi(player, "ShopPanel");
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

        #endregion

        #region UI Creation

        void OpenAdminPanel(BasePlayer player)
        {
            var container = new CuiElementContainer();

            // Основная панель
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.95f) },
                RectTransform = { AnchorMin = "0.1 0.1", AnchorMax = "0.9 0.9" },
                CursorEnabled = true
            }, "Overlay", "AdminPanel");

            // Заголовок
            container.Add(new CuiLabel
            {
                Text = { Text = "🛡️ АДМИН ПАНЕЛЬ", FontSize = 24, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0 0.9", AnchorMax = "1 1" }
            }, "AdminPanel");

            // Кнопка закрытия
            container.Add(new CuiButton
            {
                Button = { Command = "adminpanel.close", Color = HexToRustFormat(config.UI.DangerColor) },
                RectTransform = { AnchorMin = "0.92 0.92", AnchorMax = "0.98 0.98" },
                Text = { Text = "✕", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "AdminPanel");

            // Навигационное меню
            string[] menuItems = { "Игроки", "Телепорт", "Киты", "Предметы", "Сервер", "Настройки" };
            for (int i = 0; i < menuItems.Length; i++)
            {
                float xMin = 0.02f + (i * 0.16f);
                float xMax = xMin + 0.15f;

                container.Add(new CuiButton
                {
                    Button = { Command = $"adminpanel.section {menuItems[i].ToLower()}", Color = HexToRustFormat(config.UI.ButtonColor) },
                    RectTransform = { AnchorMin = $"{xMin} 0.82", AnchorMax = $"{xMax} 0.88" },
                    Text = { Text = menuItems[i], FontSize = 12, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                }, "AdminPanel");
            }

            // Область контента
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.SecondaryColor, 0.8f) },
                RectTransform = { AnchorMin = "0.02 0.05", AnchorMax = "0.98 0.8" }
            }, "AdminPanel", "ContentArea");

            // Добавляем содержимое по умолчанию (список игроков)
            AddPlayersContent(container);

            CuiHelper.AddUi(player, container);
        }

        void AddPlayersContent(CuiElementContainer container)
        {
            // Заголовок секции
            container.Add(new CuiLabel
            {
                Text = { Text = "👥 УПРАВЛЕНИЕ ИГРОКАМИ", FontSize = 18, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0 0.9", AnchorMax = "1 1" }
            }, "ContentArea");

            // Список онлайн игроков
            var onlinePlayers = BasePlayer.activePlayerList.Take(8).ToList();
            for (int i = 0; i < onlinePlayers.Count; i++)
            {
                var targetPlayer = onlinePlayers[i];
                float yMax = 0.85f - (i * 0.1f);
                float yMin = yMax - 0.08f;

                // Панель игрока
                container.Add(new CuiPanel
                {
                    Image = { Color = "0.2 0.2 0.2 0.8" },
                    RectTransform = { AnchorMin = $"0.02 {yMin}", AnchorMax = $"0.98 {yMax}" }
                }, "ContentArea", $"Player_{i}");

                // Имя игрока
                container.Add(new CuiLabel
                {
                    Text = { Text = $"{targetPlayer.displayName} ({targetPlayer.userID})", FontSize = 12, Align = TextAnchor.MiddleLeft, Color = "1 1 1 1" },
                    RectTransform = { AnchorMin = "0.02 0", AnchorMax = "0.4 1" }
                }, $"Player_{i}");

                // Кнопки действий
                string[] actions = { "Кик", "Бан", "Мут", "ТП к игроку", "ТП игрока" };
                string[] colors = { config.UI.DangerColor, config.UI.DangerColor, "#f39c12", config.UI.ButtonColor, config.UI.ButtonColor };
                
                for (int j = 0; j < actions.Length; j++)
                {
                    float btnXMin = 0.42f + (j * 0.11f);
                    float btnXMax = btnXMin + 0.1f;

                    container.Add(new CuiButton
                    {
                        Button = { Command = $"adminpanel.player {actions[j].ToLower()} {targetPlayer.userID}", Color = HexToRustFormat(colors[j]) },
                        RectTransform = { AnchorMin = $"{btnXMin} 0.1", AnchorMax = $"{btnXMax} 0.9" },
                        Text = { Text = actions[j], FontSize = 10, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                    }, $"Player_{i}");
                }
            }
        }

        void OpenShopPanel(BasePlayer player)
        {
            var container = new CuiElementContainer();

            // Основная панель магазина
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.95f) },
                RectTransform = { AnchorMin = "0.15 0.1", AnchorMax = "0.85 0.9" },
                CursorEnabled = true
            }, "Overlay", "ShopPanel");

            // Заголовок
            var playerData = GetPlayerData(player.userID);
            container.Add(new CuiLabel
            {
                Text = { Text = $"🏪 МАГАЗИН | Баланс: {playerData.Balance} {config.Shop.Currency}", FontSize = 20, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0 0.9", AnchorMax = "1 1" }
            }, "ShopPanel");

            // Кнопка закрытия
            container.Add(new CuiButton
            {
                Button = { Command = "shop.close", Color = HexToRustFormat(config.UI.DangerColor) },
                RectTransform = { AnchorMin = "0.92 0.92", AnchorMax = "0.98 0.98" },
                Text = { Text = "✕", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "ShopPanel");

            // Категории товаров
            var categories = config.Shop.Items.Select(x => x.Category).Distinct().ToList();
            for (int i = 0; i < categories.Count; i++)
            {
                float xMin = 0.02f + (i * 0.2f);
                float xMax = xMin + 0.18f;

                container.Add(new CuiButton
                {
                    Button = { Command = $"shop.category {categories[i]}", Color = HexToRustFormat(config.UI.ButtonColor) },
                    RectTransform = { AnchorMin = $"{xMin} 0.82", AnchorMax = $"{xMax} 0.88" },
                    Text = { Text = categories[i], FontSize = 12, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                }, "ShopPanel");
            }

            // Товары (показываем первые 12)
            var items = config.Shop.Items.Take(12).ToList();
            for (int i = 0; i < items.Count; i++)
            {
                int row = i / 4;
                int col = i % 4;
                
                float xMin = 0.02f + (col * 0.24f);
                float xMax = xMin + 0.22f;
                float yMax = 0.75f - (row * 0.22f);
                float yMin = yMax - 0.2f;

                var item = items[i];

                // Панель товара
                container.Add(new CuiPanel
                {
                    Image = { Color = "0.2 0.2 0.2 0.9" },
                    RectTransform = { AnchorMin = $"{xMin} {yMin}", AnchorMax = $"{xMax} {yMax}" }
                }, "ShopPanel", $"ShopItem_{i}");

                // Название товара
                container.Add(new CuiLabel
                {
                    Text = { Text = item.Name, FontSize = 11, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                    RectTransform = { AnchorMin = "0 0.7", AnchorMax = "1 0.9" }
                }, $"ShopItem_{i}");

                // Цена
                container.Add(new CuiLabel
                {
                    Text = { Text = $"{item.Price} {config.Shop.Currency}", FontSize = 10, Align = TextAnchor.MiddleCenter, Color = "#f1c40f 1" },
                    RectTransform = { AnchorMin = "0 0.5", AnchorMax = "1 0.7" }
                }, $"ShopItem_{i}");

                // Кнопка покупки
                string buttonColor = playerData.Balance >= item.Price ? config.UI.SuccessColor : config.UI.DangerColor;
                container.Add(new CuiButton
                {
                    Button = { Command = $"shop.buy {item.ShortName}", Color = HexToRustFormat(buttonColor) },
                    RectTransform = { AnchorMin = "0.1 0.1", AnchorMax = "0.9 0.4" },
                    Text = { Text = "КУПИТЬ", FontSize = 10, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                }, $"ShopItem_{i}");
            }

            CuiHelper.AddUi(player, container);
        }

        void OpenKitMenu(BasePlayer player)
        {
            var container = new CuiElementContainer();

            // Основная панель
            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.95f) },
                RectTransform = { AnchorMin = "0.2 0.2", AnchorMax = "0.8 0.8" },
                CursorEnabled = true
            }, "Overlay", "KitPanel");

            // Заголовок
            container.Add(new CuiLabel
            {
                Text = { Text = "📦 НАБОРЫ (КИТЫ)", FontSize = 18, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0 0.9", AnchorMax = "1 1" }
            }, "KitPanel");

            // Кнопка закрытия
            container.Add(new CuiButton
            {
                Button = { Command = "kit.close", Color = HexToRustFormat(config.UI.DangerColor) },
                RectTransform = { AnchorMin = "0.92 0.92", AnchorMax = "0.98 0.98" },
                Text = { Text = "✕", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "KitPanel");

            // Список китов
            for (int i = 0; i < storedData.Kits.Count && i < 8; i++)
            {
                var kit = storedData.Kits[i];
                float yMax = 0.8f - (i * 0.1f);
                float yMin = yMax - 0.08f;

                bool canUse = string.IsNullOrEmpty(kit.Permission) || HasPermission(player, kit.Permission);
                string buttonColor = canUse ? config.UI.SuccessColor : config.UI.DangerColor;

                container.Add(new CuiButton
                {
                    Button = { Command = $"kit.give {kit.Name}", Color = HexToRustFormat(buttonColor, 0.8f) },
                    RectTransform = { AnchorMin = $"0.05 {yMin}", AnchorMax = $"0.95 {yMax}" },
                    Text = { Text = $"{kit.Name} - {kit.Description}", FontSize = 12, Align = TextAnchor.MiddleLeft, Color = "1 1 1 1" }
                }, "KitPanel");
            }

            CuiHelper.AddUi(player, container);
        }

        void OpenTeleportMenu(BasePlayer player)
        {
            var container = new CuiElementContainer();

            container.Add(new CuiPanel
            {
                Image = { Color = HexToRustFormat(config.UI.PrimaryColor, 0.95f) },
                RectTransform = { AnchorMin = "0.3 0.3", AnchorMax = "0.7 0.7" },
                CursorEnabled = true
            }, "Overlay", "TeleportPanel");

            container.Add(new CuiLabel
            {
                Text = { Text = "🌍 ТЕЛЕПОРТ", FontSize = 18, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0 0.85", AnchorMax = "1 1" }
            }, "TeleportPanel");

            container.Add(new CuiButton
            {
                Button = { Command = "teleport.close", Color = HexToRustFormat(config.UI.DangerColor) },
                RectTransform = { AnchorMin = "0.9 0.9", AnchorMax = "0.98 0.98" },
                Text = { Text = "✕", FontSize = 14, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "TeleportPanel");

            // Популярные локации
            string[] locations = { "Спавн", "Bandit Camp", "Outpost", "Launch Site" };
            for (int i = 0; i < locations.Length; i++)
            {
                float yMax = 0.75f - (i * 0.15f);
                float yMin = yMax - 0.12f;

                container.Add(new CuiButton
                {
                    Button = { Command = $"teleport.location {locations[i]}", Color = HexToRustFormat(config.UI.ButtonColor) },
                    RectTransform = { AnchorMin = $"0.1 {yMin}", AnchorMax = $"0.9 {yMax}" },
                    Text = { Text = locations[i], FontSize = 12, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
                }, "TeleportPanel");
            }

            CuiHelper.AddUi(player, container);
        }

        #endregion

        #region Console Commands

        [ConsoleCommand("adminpanel.close")]
        void CloseAdminPanel(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            CuiHelper.DestroyUi(player, "AdminPanel");
        }

        [ConsoleCommand("adminpanel.section")]
        void ChangeAdminSection(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null || !HasPermission(player, config.Permissions.AdminPanel)) return;

            string section = arg.Args?[0]?.ToLower();
            // Здесь можно добавить логику переключения разделов
            SendReply(player, $"{config.ChatPrefix} Переключение на раздел: {section}");
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

        [ConsoleCommand("shop.close")]
        void CloseShop(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            CuiHelper.DestroyUi(player, "ShopPanel");
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
            
            // Обновляем UI магазина
            CuiHelper.DestroyUi(player, "ShopPanel");
            timer.Once(0.1f, () => OpenShopPanel(player));
        }

        [ConsoleCommand("kit.close")]
        void CloseKitMenu(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            CuiHelper.DestroyUi(player, "KitPanel");
        }

        [ConsoleCommand("kit.give")]
        void GiveKitFromUI(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            string kitName = arg.Args?[0];
            if (string.IsNullOrEmpty(kitName)) return;

            GiveKit(player, kitName);
            CuiHelper.DestroyUi(player, "KitPanel");
        }

        [ConsoleCommand("teleport.close")]
        void CloseTeleportMenu(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            CuiHelper.DestroyUi(player, "TeleportPanel");
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
                SendReply(player, $"{config.ChatPrefix} Телепорт в: {locationName}");
                CuiHelper.DestroyUi(player, "TeleportPanel");
            }
            else
            {
                SendReply(player, $"{config.ChatPrefix} Локация не найдена!");
            }
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
                    SendReply(admin, $"{config.ChatPrefix} Игрок {target.displayName} исключен");
                    break;

                case "бан":
                    // Используем правильный метод для бана через сервер
                    Server.Command($"ban {target.userID} \"Забанен администратором {admin.displayName}\"");
                    target.Kick($"Вы забанены администратором {admin.displayName}");
                    SendReply(admin, $"{config.ChatPrefix} Игрок {target.displayName} забанен");
                    break;

                case "мут":
                    var playerData = GetPlayerData(target.userID);
                    playerData.IsMuted = true;
                    playerData.MuteExpiry = DateTime.Now.AddHours(1);
                    SendReply(admin, $"{config.ChatPrefix} Игрок {target.displayName} заглушен на 1 час");
                    SendReply(target, $"{config.ChatPrefix} Вы заглушены на 1 час администратором {admin.displayName}");
                    break;

                case "тп":
                    admin.Teleport(target.transform.position);
                    SendReply(admin, $"{config.ChatPrefix} Телепорт к игроку {target.displayName}");
                    break;

                case "игрока":
                    target.Teleport(admin.transform.position);
                    SendReply(admin, $"{config.ChatPrefix} Игрок {target.displayName} телепортирован к вам");
                    SendReply(target, $"{config.ChatPrefix} Вы телепортированы к администратору {admin.displayName}");
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

            // Выдаем предметы из кита
            foreach (var kitItem in kit.Items)
            {
                var item = ItemManager.CreateByName(kitItem.ShortName, kitItem.Amount, kitItem.SkinId);
                if (item != null)
                {
                    if (!player.inventory.GiveItem(item))
                    {
                        item.Drop(player.transform.position, Vector3.up * 2f);
                    }
                }
            }

            SendReply(player, $"{config.ChatPrefix} Вы получили кит: <color=#27ae60>{kit.Name}</color>");
        }

        Vector3 GetLocationPosition(string locationName)
        {
            switch (locationName.ToLower())
            {
                case "спавн":
                    var spawnPoint = UnityEngine.Object.FindObjectOfType<SpawnHandler>();
                    return spawnPoint?.transform.position ?? new Vector3(0, 0, 0);

                case "bandit camp":
                    var bandit = GameObject.Find("assets/bundled/prefabs/autospawn/monument/medium/bandit_town.prefab");
                    return bandit?.transform.position ?? Vector3.zero;

                case "outpost":
                    var outpost = GameObject.Find("assets/bundled/prefabs/autospawn/monument/medium/compound.prefab");
                    return outpost?.transform.position ?? Vector3.zero;

                case "launch site":
                    var launch = GameObject.Find("assets/bundled/prefabs/autospawn/monument/large/launch_site_1.prefab");
                    return launch?.transform.position ?? Vector3.zero;

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
                    new KitItem { ShortName = "wood", Amount = 1000 },
                    new KitItem { ShortName = "stones", Amount = 1000 },
                    new KitItem { ShortName = "metal.fragments", Amount = 500 },
                    new KitItem { ShortName = "cloth", Amount = 100 },
                    new KitItem { ShortName = "bandage", Amount = 5 },
                    new KitItem { ShortName = "apple", Amount = 10 }
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
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 128 },
                    new KitItem { ShortName = "metal.plate.torso", Amount = 1 },
                    new KitItem { ShortName = "metal.facemask", Amount = 1 },
                    new KitItem { ShortName = "pants", Amount = 1 },
                    new KitItem { ShortName = "syringe.medical", Amount = 10 }
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
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 512 },
                    new KitItem { ShortName = "ammo.pistol.hv", Amount = 256 },
                    new KitItem { ShortName = "hazmatsuit", Amount = 1 },
                    new KitItem { ShortName = "syringe.medical", Amount = 20 },
                    new KitItem { ShortName = "explosives", Amount = 10 }
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
                    new KitItem { ShortName = "ammo.rifle.hv", Amount = 64 },
                    new KitItem { ShortName = "roadsign.kilt", Amount = 1 },
                    new KitItem { ShortName = "roadsign.jacket", Amount = 1 },
                    new KitItem { ShortName = "metal.facemask", Amount = 1 },
                    new KitItem { ShortName = "bandage", Amount = 20 }
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

            SendReply(player, $"{config.ChatPrefix} Предупреждение выдано игроку {targetPlayer.displayName}");
            SendReply(targetPlayer, $"{config.ChatPrefix} <color=#e74c3c>ПРЕДУПРЕЖДЕНИЕ:</color> {reason}");

            // Автобан при 3 предупреждениях
            if (targetData.Warnings.Count >= 3)
            {
                Server.Command($"ban {targetPlayer.userID} \"Автобан за 3 предупреждения\"");
                targetPlayer.Kick("Автобан за 3 предупреждения");
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
                Button = { Command = "inventory.close", Color = HexToRustFormat(config.UI.DangerColor) },
                RectTransform = { AnchorMin = "0.92 0.92", AnchorMax = "0.98 0.98" },
                Text = { Text = "✕", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" }
            }, "InventoryPanel");

            // Отображение предметов в инвентаре
            var items = target.inventory.AllItems().Take(30).ToList();
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

        [ConsoleCommand("inventory.close")]
        void CloseInventoryPanel(ConsoleSystem.Arg arg)
        {
            var player = arg.Player();
            if (player == null) return;

            CuiHelper.DestroyUi(player, "InventoryPanel");
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
                    SendReply(basePlayer, $"{config.ChatPrefix} Вы заглушены еще на {timeLeft.Minutes} мин. {timeLeft.Seconds} сек.");
                    return false;
                }
                else
                {
                    playerData.IsMuted = false;
                }
            }

            return null;
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
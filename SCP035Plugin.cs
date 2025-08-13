using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Exiled.API.Enums;
using Exiled.API.Features;
using Exiled.API.Features.Items;
using Exiled.API.Interfaces;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using MEC;
using PlayerRoles;
using UnityEngine;
using Hint = HintServiceMeow.Core.Models.Hints.Hint;
using HintServiceMeow.Core.Enum;
using HintServiceMeow.Core.Utilities;
using CommandSystem;
using Exiled.Permissions.Extensions;
using Exiled.API.Features.Pickups;
using Exiled.API.Extensions;
using Exiled.Events.EventArgs.Scp914;
using Mirror;

namespace SCP035Plugin
{
    /// <summary>
    /// Плагин SCP-035 "Одержимая Маска" для SCP Secret Laboratory
    /// Добавляет кастомную роль SCP-035 с механикой контроля других игроков
    /// </summary>
    public class Plugin : Plugin<Config>
    {
        public override string Name => "SCP-035 Одержимая Маска";
        public override string Author => "SteamTime";
        public override Version Version => new Version(1, 0, 0);
        public string[] RequiredPermissions { get; } = new[] { "scp035.admin" };

        public static Plugin Instance;
        
        // Словари для отслеживания состояний игроков
        private Dictionary<Player, Hint> playerHints = new Dictionary<Player, Hint>();
        public Dictionary<Player, Player> possessedPlayers = new Dictionary<Player, Player>(); // SCP-035 -> Контролируемый игрок
        private Dictionary<Player, DateTime> lastPossessionAttempt = new Dictionary<Player, DateTime>();
        private Dictionary<Player, float> corrosionDamage = new Dictionary<Player, float>();
        private Dictionary<Player, CoroutineHandle> activeCoroutines = new Dictionary<Player, CoroutineHandle>();
        
        // Список активных SCP-035
        public HashSet<Player> scp035Players = new HashSet<Player>();
        
        private System.Random random = new System.Random();

        public override void OnEnabled()
        {
            Instance = this;
            
            // Подписка на события
            Exiled.Events.Handlers.Server.RoundStarted += OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded += OnRoundEnded;
            Exiled.Events.Handlers.Player.Spawning += OnPlayerSpawning;
            Exiled.Events.Handlers.Player.Dying += OnPlayerDying;
            Exiled.Events.Handlers.Player.Destroying += OnPlayerLeaving;
            Exiled.Events.Handlers.Player.Hurting += OnPlayerHurting;
            Exiled.Events.Handlers.Player.InteractingDoor += OnInteractingDoor;
            Exiled.Events.Handlers.Player.UsingItem += OnUsingItem;
            Exiled.Events.Handlers.Player.TogglingFlashlight += OnTogglingFlashlight;
            
            Log.Info($"✅ {Name} v{Version} загружен и готов к работе!");
            Log.Info("🎭 SCP-035 ждёт своих жертв...");
            
            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            // Отписка от событий
            Exiled.Events.Handlers.Server.RoundStarted -= OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded -= OnRoundEnded;
            Exiled.Events.Handlers.Player.Spawning -= OnPlayerSpawning;
            Exiled.Events.Handlers.Player.Dying -= OnPlayerDying;
            Exiled.Events.Handlers.Player.Destroying -= OnPlayerLeaving;
            Exiled.Events.Handlers.Player.Hurting -= OnPlayerHurting;
            Exiled.Events.Handlers.Player.InteractingDoor -= OnInteractingDoor;
            Exiled.Events.Handlers.Player.UsingItem -= OnUsingItem;
            Exiled.Events.Handlers.Player.TogglingFlashlight -= OnTogglingFlashlight;
            
            // Очистка всех данных
            CleanupAllData();
            
            Instance = null;
            Log.Info("❌ SCP-035 плагин выключен");
            base.OnDisabled();
        }

        #region Обработчики событий

        private void OnRoundStarted()
        {
            CleanupAllData();
            
            if (Config.EnableSCP035Spawn && Player.List.Count() >= Config.MinPlayersForSpawn)
            {
                Timing.CallDelayed(Config.SpawnDelay, () => SpawnSCP035());
            }
            
            if (Config.Debug)
                Log.Debug("🔄 Новый раунд начался, SCP-035 готов к появлению");
        }

        private void OnRoundEnded(RoundEndedEventArgs ev)
        {
            CleanupAllData();
            
            if (Config.Debug)
                Log.Debug("🏁 Раунд завершён, очистка данных SCP-035");
        }

        private void OnPlayerSpawning(SpawningEventArgs ev)
        {
            if (scp035Players.Contains(ev.Player))
            {
                // Если это SCP-035, настраиваем его роль
                Timing.CallDelayed(0.5f, () => SetupSCP035Player(ev.Player));
            }
        }

        private void OnPlayerDying(DyingEventArgs ev)
        {
            if (scp035Players.Contains(ev.Player))
            {
                // SCP-035 умер, пытаемся переместить его в другое тело
                if (Config.AllowPossessionOnDeath)
                {
                    Timing.CallDelayed(1f, () => TryPossessNearbyPlayer(ev.Player));
                }
                else
                {
                    RemoveSCP035(ev.Player);
                }
            }
            
            // Если умер контролируемый игрок
            if (possessedPlayers.ContainsValue(ev.Player))
            {
                var scp035 = possessedPlayers.FirstOrDefault(x => x.Value == ev.Player).Key;
                if (scp035 != null)
                {
                    possessedPlayers.Remove(scp035);
                    ShowHint(scp035, "<color=red>💀 Ваш контролируемый субъект погиб!\nВы снова можете искать новую жертву.</color>", 5f);
                }
            }
        }

        private void OnPlayerLeaving(DestroyingEventArgs ev)
        {
            CleanupPlayerData(ev.Player);
        }

        private void OnPlayerHurting(HurtingEventArgs ev)
        {
            // SCP-035 получает уменьшенный урон от некоторых источников
            if (scp035Players.Contains(ev.Player))
            {
                if (Config.SCP035DamageMultipliers.TryGetValue(ev.DamageHandler.Type, out float multiplier))
                {
                    ev.Amount *= multiplier;
                    
                    if (Config.Debug)
                        Log.Debug($"🛡️ SCP-035 получил {ev.Amount} урона (множитель: {multiplier})");
                }
            }
        }

        private void OnInteractingDoor(InteractingDoorEventArgs ev)
        {
            if (scp035Players.Contains(ev.Player) && Config.SCP035CanOpenDoors)
            {
                // SCP-035 может открывать некоторые двери без карт доступа
                if (ev.Door.RequiredPermissions.RequiredPermissions != KeycardPermissions.None)
                {
                    ev.IsAllowed = true;
                    ShowHint(ev.Player, "<color=yellow>🚪 Ваши психические способности открыли дверь</color>", 2f);
                }
            }
        }

        private void OnUsingItem(UsingItemEventArgs ev)
        {
            if (scp035Players.Contains(ev.Player))
            {
                // Обработка использования предметов SCP-035
                HandleSCP035ItemUse(ev);
            }
        }

        private void OnTogglingFlashlight(TogglingFlashlightEventArgs ev)
        {
            // Используем фонарик как кнопку для контроля
            if (scp035Players.Contains(ev.Player) && !ev.IsEnabled)
            {
                TryPossessPlayer(ev.Player);
                ev.IsAllowed = false; // Не включаем фонарик
            }
        }

        #endregion

        #region Основная логика SCP-035

        /// <summary>
        /// Спавн SCP-035 в начале раунда
        /// </summary>
        private void SpawnSCP035()
        {
            var eligiblePlayers = Player.List
                .Where(p => p.IsAlive && p.Role.Team != Team.RoundSummary)
                .ToList();
            
            if (eligiblePlayers.Count == 0) return;
            
            int scp035Count = Mathf.Min(
                Config.MaxSCP035Count, 
                Mathf.FloorToInt(eligiblePlayers.Count * Config.SCP035SpawnChance / 100f)
            );
            
            for (int i = 0; i < scp035Count; i++)
            {
                if (eligiblePlayers.Count == 0) break;
                
                var selectedPlayer = eligiblePlayers[random.Next(eligiblePlayers.Count)];
                eligiblePlayers.Remove(selectedPlayer);
                
                MakePlayerSCP035(selectedPlayer);
            }
        }

        /// <summary>
        /// Превращает игрока в SCP-035
        /// </summary>
        public void MakePlayerSCP035(Player player)
        {
            if (scp035Players.Contains(player)) return;
            
            scp035Players.Add(player);
            
            // Меняем роль на Tutorial для кастомизации
            player.Role.Set(RoleTypeId.Tutorial, SpawnReason.ForceClass);
            
            Timing.CallDelayed(1f, () => SetupSCP035Player(player));
            
            ShowHint(player, 
                "<color=red>🎭 ВЫ СТАЛИ SCP-035 \"ОДЕРЖИМАЯ МАСКА\"!</color>\n" +
                "<color=yellow>• Используйте фонарик для контроля игроков\n" +
                "• Вы медленно коррозируете, но можете лечиться\n" +
                "• Ваша цель - выжить и распространить хаос</color>", 
                10f);
            
            if (Config.Debug)
                Log.Debug($"🎭 {player.Nickname} стал SCP-035");
        }

        /// <summary>
        /// Настройка игрока SCP-035 после спавна
        /// </summary>
        private void SetupSCP035Player(Player player)
        {
            if (!scp035Players.Contains(player)) return;
            
            // Устанавливаем здоровье
            player.Health = Config.SCP035Health;
            player.MaxHealth = Config.SCP035Health;
            
            // Выдаём предметы
            player.ClearInventory();
            foreach (var item in Config.SCP035StartItems)
            {
                player.AddItem(item);
            }
            
            // Устанавливаем размер и скорость
            player.Scale = Config.SCP035Scale;
            
            // Запускаем коррозию
            if (Config.EnableCorrosion)
            {
                StartCorrosion(player);
            }
            
            // Показываем информацию
            ShowSCP035Info(player);
        }

        /// <summary>
        /// Попытка контроля игрока
        /// </summary>
        private void TryPossessPlayer(Player scp035)
        {
            if (!scp035Players.Contains(scp035)) return;
            
            // Проверяем кулдаун
            if (lastPossessionAttempt.TryGetValue(scp035, out DateTime lastAttempt))
            {
                var timeSince = DateTime.Now - lastAttempt;
                if (timeSince.TotalSeconds < Config.PossessionCooldown)
                {
                    ShowHint(scp035, 
                        $"<color=red>⏰ Подождите {Config.PossessionCooldown - (int)timeSince.TotalSeconds} сек. перед следующей попыткой</color>", 
                        3f);
                    return;
                }
            }
            
            lastPossessionAttempt[scp035] = DateTime.Now;
            
            // Ищем ближайшего игрока
            var nearbyPlayers = Player.List
                .Where(p => p != scp035 && 
                           p.IsAlive && 
                           Vector3.Distance(p.Position, scp035.Position) <= Config.PossessionRange &&
                           !scp035Players.Contains(p))
                .OrderBy(p => Vector3.Distance(p.Position, scp035.Position))
                .ToList();
            
            if (nearbyPlayers.Count == 0)
            {
                ShowHint(scp035, "<color=red>❌ Поблизости нет подходящих целей для контроля</color>", 3f);
                return;
            }
            
            var target = nearbyPlayers.First();
            
            // Проверяем шанс успеха
            float successChance = Config.BasePossessionChance;
            
            // Модификаторы шанса в зависимости от роли цели
            if (Config.PossessionChanceByRole.TryGetValue(target.Role.Type, out float roleModifier))
            {
                successChance *= roleModifier;
            }
            
            if (random.NextDouble() * 100 <= successChance)
            {
                // Успешный контроль
                StartPossession(scp035, target);
            }
            else
            {
                // Неудачная попытка
                ShowHint(scp035, "<color=red>❌ Цель сопротивляется вашему контролю!</color>", 3f);
                ShowHint(target, "<color=yellow>⚠️ Вы чувствуете странное давление в голове...</color>", 3f);
            }
        }

        /// <summary>
        /// Начинает контроль игрока
        /// </summary>
        private void StartPossession(Player scp035, Player target)
        {
            possessedPlayers[scp035] = target;
            
            ShowHint(scp035, 
                $"<color=green>✅ Вы контролируете {target.Nickname}!\n" +
                $"Контроль продлится {Config.PossessionDuration} секунд</color>", 
                5f);
                
            ShowHint(target, 
                "<color=red>🎭 ВАС КОНТРОЛИРУЕТ SCP-035!\n" +
                "Вы не можете управлять своими действиями!</color>", 
                Config.PossessionDuration);
            
            // Запускаем корутину контроля
            var coroutine = Timing.RunCoroutine(PossessionCoroutine(scp035, target));
            activeCoroutines[scp035] = coroutine;
            
            if (Config.Debug)
                Log.Debug($"🎭 SCP-035 ({scp035.Nickname}) контролирует {target.Nickname}");
        }

        /// <summary>
        /// Корутина для обработки контроля
        /// </summary>
        private IEnumerator<float> PossessionCoroutine(Player scp035, Player target)
        {
            float timeLeft = Config.PossessionDuration;
            
            while (timeLeft > 0 && scp035Players.Contains(scp035) && target.IsAlive)
            {
                yield return Timing.WaitForSeconds(1f);
                timeLeft--;
                
                // Обновляем подсказки
                ShowHint(scp035, 
                    $"<color=yellow>🎭 Контролируете: {target.Nickname}\n" +
                    $"⏰ Осталось: {timeLeft:F0} сек.</color>", 
                    1.5f);
                    
                // Эффект коррозии на контролируемого
                if (Config.PossessionCausesCorrosion && timeLeft % 3 == 0)
                {
                    target.Hurt(Config.CorrosionDamagePerTick, "SCP-035 Коррозия");
                }
            }
            
            // Завершение контроля
            EndPossession(scp035);
        }

        /// <summary>
        /// Завершает контроль игрока
        /// </summary>
        private void EndPossession(Player scp035)
        {
            if (possessedPlayers.TryGetValue(scp035, out Player target))
            {
                possessedPlayers.Remove(scp035);
                
                ShowHint(scp035, "<color=yellow>⏰ Контроль завершён</color>", 3f);
                
                if (target != null && target.IsConnected)
                {
                    ShowHint(target, "<color=green>✅ Вы снова контролируете своё тело!</color>", 3f);
                }
            }
            
            if (activeCoroutines.TryGetValue(scp035, out CoroutineHandle coroutine))
            {
                Timing.KillCoroutines(coroutine);
                activeCoroutines.Remove(scp035);
            }
        }

        /// <summary>
        /// Попытка вселения в ближайшего игрока при смерти
        /// </summary>
        private void TryPossessNearbyPlayer(Player deadSCP035)
        {
            var nearbyPlayers = Player.List
                .Where(p => p.IsAlive && 
                           Vector3.Distance(p.Position, deadSCP035.Position) <= Config.DeathPossessionRange &&
                           !scp035Players.Contains(p))
                .OrderBy(p => Vector3.Distance(p.Position, deadSCP035.Position))
                .ToList();
            
            if (nearbyPlayers.Count > 0)
            {
                var newHost = nearbyPlayers.First();
                
                if (random.NextDouble() * 100 <= Config.DeathPossessionChance)
                {
                    // Успешное вселение
                    RemoveSCP035(deadSCP035);
                    MakePlayerSCP035(newHost);
                    
                    ShowHint(newHost, 
                        "<color=red>💀 SCP-035 вселился в ваше тело!\n" +
                        "Маска нашла нового хозяина...</color>", 
                        8f);
                        
                    if (Config.Debug)
                        Log.Debug($"💀 SCP-035 переместился из {deadSCP035.Nickname} в {newHost.Nickname}");
                }
            }
            
            RemoveSCP035(deadSCP035);
        }

        /// <summary>
        /// Запускает эффект коррозии
        /// </summary>
        private void StartCorrosion(Player scp035)
        {
            if (!corrosionDamage.ContainsKey(scp035))
            {
                corrosionDamage[scp035] = 0f;
            }
            
            var coroutine = Timing.RunCoroutine(CorrosionCoroutine(scp035));
            if (activeCoroutines.ContainsKey(scp035))
            {
                Timing.KillCoroutines(activeCoroutines[scp035]);
            }
            activeCoroutines[scp035] = coroutine;
        }

        /// <summary>
        /// Корутина коррозии
        /// </summary>
        private IEnumerator<float> CorrosionCoroutine(Player scp035)
        {
            while (scp035Players.Contains(scp035) && scp035.IsAlive)
            {
                yield return Timing.WaitForSeconds(Config.CorrosionInterval);
                
                if (!scp035Players.Contains(scp035) || !scp035.IsAlive) break;
                
                // Наносим урон от коррозии
                scp035.Hurt(Config.CorrosionDamagePerTick, "SCP-035 Коррозия");
                
                corrosionDamage[scp035] += Config.CorrosionDamagePerTick;
                
                // Показываем эффект
                ShowHint(scp035, 
                    $"<color=#ff6666>🧪 Коррозия: -{Config.CorrosionDamagePerTick} HP\n" +
                    $"Общий урон: {corrosionDamage[scp035]:F0}</color>", 
                    2f);
                
                if (Config.Debug)
                    Log.Debug($"🧪 SCP-035 ({scp035.Nickname}) получил {Config.CorrosionDamagePerTick} урона от коррозии");
            }
        }

        /// <summary>
        /// Обработка использования предметов SCP-035
        /// </summary>
        private void HandleSCP035ItemUse(UsingItemEventArgs ev)
        {
            switch (ev.Item.Type)
            {
                case ItemType.Medkit:
                case ItemType.Painkillers:
                case ItemType.Adrenaline:
                    // SCP-035 может лечиться, но менее эффективно
                    ev.IsAllowed = false;
                    
                    float healAmount = ev.Item.Type switch
                    {
                        ItemType.Medkit => Config.SCP035HealingEfficiency * 100f,
                        ItemType.Painkillers => Config.SCP035HealingEfficiency * 70f,
                        ItemType.Adrenaline => Config.SCP035HealingEfficiency * 30f,
                        _ => 0f
                    };
                    
                    ev.Player.Heal(healAmount);
                    ev.Player.RemoveItem(ev.Item);
                    
                    ShowHint(ev.Player, 
                        $"<color=green>💉 Восстановлено {healAmount:F0} HP\n" +
                        "Коррозия временно замедлена</color>", 
                        3f);
                    break;
            }
        }

        #endregion

        #region Утилиты

        /// <summary>
        /// Удаляет игрока из списка SCP-035
        /// </summary>
        public void RemoveSCP035(Player player)
        {
            scp035Players.Remove(player);
            CleanupPlayerData(player);
        }

        /// <summary>
        /// Очищает данные игрока
        /// </summary>
        private void CleanupPlayerData(Player player)
        {
            if (playerHints.TryGetValue(player, out var hint))
            {
                hint.Hide = true;
                playerHints.Remove(player);
            }
            
            if (possessedPlayers.ContainsKey(player))
            {
                EndPossession(player);
            }
            
            if (possessedPlayers.ContainsValue(player))
            {
                var scp035 = possessedPlayers.FirstOrDefault(x => x.Value == player).Key;
                if (scp035 != null)
                {
                    possessedPlayers.Remove(scp035);
                }
            }
            
            lastPossessionAttempt.Remove(player);
            corrosionDamage.Remove(player);
            
            if (activeCoroutines.TryGetValue(player, out var coroutine))
            {
                Timing.KillCoroutines(coroutine);
                activeCoroutines.Remove(player);
            }
        }

        /// <summary>
        /// Очищает все данные плагина
        /// </summary>
        private void CleanupAllData()
        {
            foreach (var hint in playerHints.Values)
                hint.Hide = true;
            
            playerHints.Clear();
            possessedPlayers.Clear();
            lastPossessionAttempt.Clear();
            corrosionDamage.Clear();
            scp035Players.Clear();
            
            foreach (var coroutine in activeCoroutines.Values)
                Timing.KillCoroutines(coroutine);
            
            activeCoroutines.Clear();
        }

        /// <summary>
        /// Показывает подсказку игроку
        /// </summary>
        private void ShowHint(Player player, string message, float duration)
        {
            try
            {
                if (!playerHints.TryGetValue(player, out var hint))
                {
                    hint = new Hint
                    {
                        FontSize = Config.HintSettings.TextSize,
                        XCoordinate = Config.HintSettings.XPosition,
                        YCoordinate = Config.HintSettings.YPosition,
                        Alignment = HintAlignment.Center,
                        SyncSpeed = HintSyncSpeed.Fast,
                        Hide = false
                    };
                    PlayerDisplay.Get(player).AddHint(hint);
                    playerHints[player] = hint;
                }

                hint.Text = message;
                Timing.CallDelayed(duration, () => 
                {
                    if (playerHints.TryGetValue(player, out var h) && h.Text == message)
                    {
                        h.Hide = true;
                        playerHints.Remove(player);
                    }
                });
            }
            catch (Exception ex)
            {
                Log.Error($"❌ Ошибка при показе подсказки: {ex}");
            }
        }

        /// <summary>
        /// Показывает информацию о SCP-035
        /// </summary>
        private void ShowSCP035Info(Player player)
        {
            string info = "<color=red>═══ SCP-035 \"ОДЕРЖИМАЯ МАСКА\" ═══</color>\n\n" +
                         "<color=yellow>🎭 СПОСОБНОСТИ:</color>\n" +
                         $"• <color=cyan>Контроль игроков</color> (ПКМ фонариком, дальность: {Config.PossessionRange}м)\n" +
                         $"• <color=green>Регенерация</color> при использовании медикаментов\n" +
                         $"• <color=orange>Открытие дверей</color> без карт доступа\n\n" +
                         "<color=red>⚠️ ОПАСНОСТИ:</color>\n" +
                         $"• <color=#ff6666>Коррозия</color> (-{Config.CorrosionDamagePerTick} HP каждые {Config.CorrosionInterval}с)\n" +
                         $"• Уязвимость к некоторым типам урона\n\n" +
                         "<color=yellow>🎯 ЦЕЛЬ:</color>\n" +
                         "Выжить и посеять хаос в комплексе";
            
            ShowHint(player, info, 15f);
        }

        #endregion
    }

    #region Команды администратора

    [CommandHandler(typeof(RemoteAdminCommandHandler))]
    [CommandHandler(typeof(GameConsoleCommandHandler))]
    public class SCP035Commands : ICommand
    {
        public string Command { get; } = "scp035";
        public string[] Aliases { get; } = new[] { "035", "mask" };
        public string Description { get; } = "Команды управления SCP-035";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            if (!sender.CheckPermission("scp035.admin"))
            {
                response = "❌ У вас нет прав на использование этой команды!";
                return false;
            }

            if (arguments.Count == 0)
            {
                response = "ℹ️ Команды SCP-035:\n" +
                          "scp035 spawn <игрок> - превратить игрока в SCP-035\n" +
                          "scp035 remove <игрок> - убрать роль SCP-035\n" +
                          "scp035 list - показать всех активных SCP-035\n" +
                          "scp035 info - информация о плагине\n" +
                          "scp035 reload - перезагрузить конфигурацию";
                return false;
            }

            switch (arguments.At(0).ToLower())
            {
                case "spawn":
                    return HandleSpawnCommand(arguments, out response);
                
                case "remove":
                    return HandleRemoveCommand(arguments, out response);
                
                case "list":
                    return HandleListCommand(out response);
                
                case "info":
                    return HandleInfoCommand(out response);
                
                case "reload":
                    return HandleReloadCommand(out response);
                
                default:
                    response = "❌ Неизвестная подкоманда. Используйте 'scp035' для помощи.";
                    return false;
            }
        }

        private bool HandleSpawnCommand(ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = "ℹ️ Использование: scp035 spawn <игрок>";
                return false;
            }

            Player target = Player.Get(arguments.At(1));
            if (target == null)
            {
                response = $"❌ Игрок '{arguments.At(1)}' не найден!";
                return false;
            }

            if (Plugin.Instance.scp035Players.Contains(target))
            {
                response = $"⚠️ {target.Nickname} уже является SCP-035!";
                return false;
            }

            Plugin.Instance.MakePlayerSCP035(target);
            response = $"✅ {target.Nickname} превращён в SCP-035!";
            return true;
        }

        private bool HandleRemoveCommand(ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = "ℹ️ Использование: scp035 remove <игрок>";
                return false;
            }

            Player target = Player.Get(arguments.At(1));
            if (target == null)
            {
                response = $"❌ Игрок '{arguments.At(1)}' не найден!";
                return false;
            }

            if (!Plugin.Instance.scp035Players.Contains(target))
            {
                response = $"⚠️ {target.Nickname} не является SCP-035!";
                return false;
            }

            Plugin.Instance.RemoveSCP035(target);
            target.Role.Set(RoleTypeId.ClassD); // Возвращаем базовую роль
            response = $"✅ Роль SCP-035 убрана с {target.Nickname}!";
            return true;
        }

        private bool HandleListCommand(out string response)
        {
            var scp035List = Plugin.Instance.scp035Players.ToList();
            
            if (scp035List.Count == 0)
            {
                response = "ℹ️ В настоящее время нет активных SCP-035";
                return true;
            }

            response = $"🎭 Активные SCP-035 ({scp035List.Count}):\n";
            foreach (var scp in scp035List)
            {
                string status = scp.IsAlive ? "✅ Живой" : "💀 Мёртвый";
                string possessing = "";
                
                if (Plugin.Instance.possessedPlayers.TryGetValue(scp, out Player possessed))
                {
                    possessing = $" (контролирует: {possessed.Nickname})";
                }
                
                response += $"• {scp.Nickname} ({scp.Id}) - {status}{possessing}\n";
            }
            
            return true;
        }

        private bool HandleInfoCommand(out string response)
        {
            var config = Plugin.Instance.Config;
            
            response = $"🎭 SCP-035 Плагин v{Plugin.Instance.Version}\n\n" +
                      $"📊 Настройки:\n" +
                      $"• Шанс спавна: {config.SCP035SpawnChance}%\n" +
                      $"• Максимум SCP-035: {config.MaxSCP035Count}\n" +
                      $"• Здоровье: {config.SCP035Health} HP\n" +
                      $"• Дальность контроля: {config.PossessionRange}м\n" +
                      $"• Длительность контроля: {config.PossessionDuration}с\n" +
                      $"• Урон коррозии: {config.CorrosionDamagePerTick} HP/{config.CorrosionInterval}с\n" +
                      $"• Активных SCP-035: {Plugin.Instance.scp035Players.Count}";
            
            return true;
        }

        private bool HandleReloadCommand(out string response)
        {
            try
            {
                Plugin.Instance.Config.Reload();
                response = "✅ Конфигурация SCP-035 перезагружена!";
                return true;
            }
            catch (Exception ex)
            {
                response = $"❌ Ошибка при перезагрузке конфигурации: {ex.Message}";
                return false;
            }
        }
    }

    #endregion
}
using System;
using System.Collections.Generic;
using System.Linq;
using Exiled.API.Enums;
using Exiled.API.Features;
using Exiled.API.Features.Items;
using Exiled.API.Features.Pickups;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using MEC;
using PlayerRoles;
using UnityEngine;
using UserSettings.ServerSpecific;
using Scp096Mask.Enums;
using HintServiceMeow.Core.Models.Hints;
using HintServiceMeow.Core.Enum;
using HintServiceMeow.Core.Utilities;

namespace Scp096Mask
{
    internal class EventHandlers
    {
        private readonly Config _config;
        private System.Random random = new System.Random();
        
        // Спавненные маски
        public List<Pickup> spawnedMasks = new List<Pickup>();
        
        // Игроки с масками
        private HashSet<Player> playersWithMasks = new HashSet<Player>();
        
        // SCP-096 с масками
        private HashSet<Player> maskedScp096s = new HashSet<Player>();
        
        // Процессы одевания масок
        private Dictionary<Player, CoroutineHandle> equipProcesses = new Dictionary<Player, CoroutineHandle>();
        
        // Хинты игроков
        private Dictionary<Player, Hint> playerHints = new Dictionary<Player, Hint>();

        internal EventHandlers(Config config)
        {
            _config = config;
        }

        internal void RegisterEvents()
        {
            Exiled.Events.Handlers.Server.RoundStarted += OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded += OnRoundEnded;
            Exiled.Events.Handlers.Player.PickingUpItem += OnPickingUpItem;
            Exiled.Events.Handlers.Player.ChangingRole += OnChangingRole;
            Exiled.Events.Handlers.Player.Destroying += OnPlayerLeave;
            Exiled.Events.Handlers.Player.Left += OnPlayerLeft;

            switch (_config.ActivationType)
            {
                case ActivationType.ServerSpecificSettings:
                    ServerSpecificSettingsSync.ServerOnSettingValueReceived += OnSettingValueReceived;
                    Exiled.Events.Handlers.Player.Verified += OnVerified;
                    break;
                case ActivationType.NoClip:
                    Exiled.Events.Handlers.Player.TogglingNoClip += OnTogglingNoClip;
                    break;
            }
        }

        internal void UnregisterEvents()
        {
            Exiled.Events.Handlers.Server.RoundStarted -= OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded -= OnRoundEnded;
            Exiled.Events.Handlers.Player.PickingUpItem -= OnPickingUpItem;
            Exiled.Events.Handlers.Player.ChangingRole -= OnChangingRole;
            Exiled.Events.Handlers.Player.Destroying -= OnPlayerLeave;
            Exiled.Events.Handlers.Player.Left -= OnPlayerLeft;

            switch (_config.ActivationType)
            {
                case ActivationType.ServerSpecificSettings:
                    ServerSpecificSettingsSync.ServerOnSettingValueReceived -= OnSettingValueReceived;
                    Exiled.Events.Handlers.Player.Verified -= OnVerified;
                    break;
                case ActivationType.NoClip:
                    Exiled.Events.Handlers.Player.TogglingNoClip -= OnTogglingNoClip;
                    break;
            }
        }

        private void OnRoundStarted()
        {
            spawnedMasks.Clear();
            playersWithMasks.Clear();
            maskedScp096s.Clear();
            equipProcesses.Clear();
            playerHints.Clear();

            if (_config.AutoSpawnEnabled)
            {
                Timing.CallDelayed(2f, () => SpawnMasks());
            }

            // Показать инструкции всем игрокам
            Timing.CallDelayed(5f, () =>
            {
                foreach (var player in Player.List)
                {
                    ShowHint(player, _config.Messages.Instructions, 10f);
                }
            });

            if (_config.Debug)
                Log.Debug("Начало раунда, маски SCP-096 готовы к спавну");
        }

        private void OnRoundEnded(RoundEndedEventArgs ev)
        {
            ClearAllMasks();
            playersWithMasks.Clear();
            maskedScp096s.Clear();
            
            foreach (var process in equipProcesses.Values)
            {
                if (process.IsRunning)
                    Timing.KillCoroutines(process);
            }
            equipProcesses.Clear();
            
            ClearAllHints();
        }

        private void OnPickingUpItem(PickingUpItemEventArgs ev)
        {
            if (ev.Pickup.Type != ItemType.Medkit || !spawnedMasks.Contains(ev.Pickup))
                return;

            if (playersWithMasks.Contains(ev.Player))
            {
                ev.IsAllowed = false;
                ShowHint(ev.Player, "<color=orange>⚠ У вас уже есть маска SCP-096!</color>", 3f);
                return;
            }

            spawnedMasks.Remove(ev.Pickup);
            playersWithMasks.Add(ev.Player);
            
            ShowHint(ev.Player, _config.Messages.MaskPickedUp, 6f);

            if (_config.Debug)
                Log.Debug($"Игрок {ev.Player.Nickname} подобрал маску SCP-096");
        }

        private void OnChangingRole(ChangingRoleEventArgs ev)
        {
            if (playersWithMasks.Contains(ev.Player))
                playersWithMasks.Remove(ev.Player);

            if (maskedScp096s.Contains(ev.Player))
                maskedScp096s.Remove(ev.Player);

            if (equipProcesses.TryGetValue(ev.Player, out var process))
            {
                if (process.IsRunning)
                    Timing.KillCoroutines(process);
                equipProcesses.Remove(ev.Player);
            }

            ClearPlayerHint(ev.Player);
        }

        private void OnPlayerLeave(DestroyingEventArgs ev)
        {
            CleanupPlayer(ev.Player);
        }

        private void OnPlayerLeft(LeftEventArgs ev)
        {
            CleanupPlayer(ev.Player);
        }

        private void CleanupPlayer(Player player)
        {
            if (playersWithMasks.Contains(player))
                playersWithMasks.Remove(player);

            if (maskedScp096s.Contains(player))
                maskedScp096s.Remove(player);

            if (equipProcesses.TryGetValue(player, out var process))
            {
                if (process.IsRunning)
                    Timing.KillCoroutines(process);
                equipProcesses.Remove(player);
            }

            ClearPlayerHint(player);
        }

        private void OnVerified(VerifiedEventArgs ev)
        {
            ServerSpecificSettingsSync.SendToPlayer(ev.Player.ReferenceHub);
        }

        private void OnSettingValueReceived(ReferenceHub hub, ServerSpecificSettingBase settingBase)
        {
            if (!Player.TryGet(hub, out Player player))
                return;

            if (settingBase is SSKeybindSetting keybindSetting && 
                keybindSetting.SettingId == _config.KeybindId && 
                keybindSetting.SyncIsPressed)
            {
                TryInteractWithScp096(player);
            }
        }

        private void OnTogglingNoClip(TogglingNoClipEventArgs ev)
        {
            if (!playersWithMasks.Contains(ev.Player))
                return;

            TryInteractWithScp096(ev.Player);
            ev.IsAllowed = false;
        }

        private void TryInteractWithScp096(Player player)
        {
            if (!playersWithMasks.Contains(player))
            {
                ShowHint(player, _config.Messages.NoMask, 3f);
                return;
            }

            if (equipProcesses.ContainsKey(player))
            {
                ShowHint(player, "<color=orange>⚠ Вы уже одеваете маску!</color>", 3f);
                return;
            }

            // Найти ближайший SCP-096
            Player nearestScp096 = null;
            float nearestDistance = float.MaxValue;

            foreach (var scp in Player.List.Where(p => p.Role.Type == RoleTypeId.Scp096))
            {
                float distance = Vector3.Distance(player.Position, scp.Position);
                if (distance < nearestDistance && distance <= _config.InteractionDistance)
                {
                    nearestDistance = distance;
                    nearestScp096 = scp;
                }
            }

            if (nearestScp096 == null)
            {
                ShowHint(player, _config.Messages.TooFarAway, 3f);
                return;
            }

            if (maskedScp096s.Contains(nearestScp096))
            {
                ShowHint(player, _config.Messages.AlreadyMasked, 3f);
                return;
            }

            // Начать процесс одевания маски
            var equipProcess = Timing.RunCoroutine(EquipMaskProcess(player, nearestScp096));
            equipProcesses[player] = equipProcess;
        }

        private IEnumerator<float> EquipMaskProcess(Player player, Player scp096)
        {
            float equipTime = _config.MaskEquipTime;
            float elapsed = 0f;

            ShowHint(player, _config.Messages.MaskEquipping, equipTime + 1f);

            while (elapsed < equipTime)
            {
                if (player == null || !player.IsConnected || !player.IsAlive ||
                    scp096 == null || !scp096.IsConnected || !scp096.IsAlive ||
                    Vector3.Distance(player.Position, scp096.Position) > _config.InteractionDistance)
                {
                    ShowHint(player, "<color=red>❌ Процесс прерван!</color>", 3f);
                    equipProcesses.Remove(player);
                    yield break;
                }

                // Обновить прогресс
                float progress = elapsed / equipTime;
                int progressBars = Mathf.RoundToInt(progress * 10);
                string progressBar = $"<color=yellow>[{"█".PadRight(progressBars, '█')}{"░".PadRight(10 - progressBars, '░')}] {(progress * 100):F0}%</color>";
                
                ShowHint(player, $"{_config.Messages.MaskEquipping}\n{progressBar}", 0.5f);

                elapsed += 0.2f;
                yield return Timing.WaitForSeconds(0.2f);
            }

            // Успешно надето
            playersWithMasks.Remove(player);
            maskedScp096s.Add(scp096);
            equipProcesses.Remove(player);

            // Удалить аптечку из инвентаря
            var medkit = player.Items.FirstOrDefault(item => item.Type == ItemType.Medkit);
            if (medkit != null)
                player.RemoveItem(medkit);

            ShowHint(player, _config.Messages.MaskEquipped, 5f);
            ShowHint(scp096, "<color=green>🎭 На вас надели маску!\nВы больше не агритесь при взгляде</color>", 5f);

            if (_config.Debug)
                Log.Debug($"Игрок {player.Nickname} успешно надел маску на SCP-096 {scp096.Nickname}");
        }

        public void SpawnMasks()
        {
            ClearAllMasks();

            for (int i = 0; i < _config.MasksToSpawn; i++)
            {
                Timing.CallDelayed(0.3f * i, () =>
                {
                    if (TryFindSpawnPosition(out Vector3 position))
                    {
                        var medkit = Item.Create(ItemType.Medkit);
                        var pickup = medkit.CreatePickup(position);
                        spawnedMasks.Add(pickup);

                        if (_config.Debug)
                            Log.Debug($"Создана маска SCP-096 в {position}");
                    }
                });
            }
        }

        private bool TryFindSpawnPosition(out Vector3 position)
        {
            position = Vector3.zero;

            var availableRooms = Room.List.Where(r => _config.SpawnWeights.ContainsKey(r.Zone)).ToList();
            
            foreach (var room in availableRooms.OrderBy(r => random.Next()))
            {
                if (_config.SpawnWeights.TryGetValue(room.Zone, out float weight) && 
                    random.NextDouble() * 100 < weight)
                {
                    for (int i = 0; i < 10; i++)
                    {
                        Vector3 testPos = room.Position + new Vector3(
                            (float)(random.NextDouble() * 6 - 3),
                            1f,
                            (float)(random.NextDouble() * 6 - 3));

                        if (IsValidSpawnPosition(testPos))
                        {
                            position = testPos;
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private bool IsValidSpawnPosition(Vector3 position)
        {
            return !Physics.CheckSphere(position, 0.5f, LayerMask.GetMask("Default", "Player", "Ragdoll")) &&
                   position.y > -10f;
        }

        private void ClearAllMasks()
        {
            foreach (var mask in spawnedMasks.ToList())
            {
                try
                {
                    if (mask != null && mask.IsSpawned)
                        mask.Destroy();
                }
                catch (Exception ex)
                {
                    if (_config.Debug)
                        Log.Debug($"Ошибка при удалении маски: {ex}");
                }
            }
            spawnedMasks.Clear();
        }

        private void ShowHint(Player player, string message, float duration)
        {
            try
            {
                if (!playerHints.TryGetValue(player, out var hint))
                {
                    hint = new Hint
                    {
                        FontSize = _config.HintSettings.TextSize,
                        XCoordinate = _config.HintSettings.XPosition,
                        YCoordinate = _config.HintSettings.YPosition,
                        Alignment = HintAlignment.Center,
                        SyncSpeed = HintSyncSpeed.Fast,
                        Hide = false
                    };
                    PlayerDisplay.Get(player).AddHint(hint);
                    playerHints[player] = hint;
                }

                hint.Text = message;
                hint.Hide = false;
                
                Timing.CallDelayed(duration, () =>
                {
                    if (playerHints.TryGetValue(player, out var h) && h.Text == message)
                    {
                        h.Hide = true;
                    }
                });
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Error($"Не удалось показать хинт: {ex}");
            }
        }

        private void ClearPlayerHint(Player player)
        {
            if (playerHints.TryGetValue(player, out var hint))
            {
                hint.Hide = true;
                playerHints.Remove(player);
            }
        }

        private void ClearAllHints()
        {
            foreach (var hint in playerHints.Values)
            {
                hint.Hide = true;
            }
            playerHints.Clear();
        }

        public bool IsScp096Masked(Player scp096)
        {
            return maskedScp096s.Contains(scp096);
        }

        public void RemoveMaskFromScp096(Player scp096)
        {
            if (maskedScp096s.Contains(scp096))
            {
                maskedScp096s.Remove(scp096);
                ShowHint(scp096, _config.Messages.MaskRemoved, 3f);
                
                if (_config.Debug)
                    Log.Debug($"Маска снята с SCP-096 {scp096.Nickname}");
            }
        }
    }
}
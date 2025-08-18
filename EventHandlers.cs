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
        
        // Список заспавненных масок
        public List<Pickup> spawnedMasks = new List<Pickup>();
        
        // Игроки с масками в инвентаре
        private Dictionary<Player, Item> playersWithMasks = new Dictionary<Player, Item>();
        
        // SCP-096 с надетыми масками
        private HashSet<Player> maskedScp096s = new HashSet<Player>();
        
        // Процессы одевания масок
        private Dictionary<Player, CoroutineHandle> equipProcesses = new Dictionary<Player, CoroutineHandle>();
        
        // Хинты игроков
        private Dictionary<Player, Hint> playerHints = new Dictionary<Player, Hint>();

        // Корутины для визуальных эффектов масок
        private Dictionary<Pickup, CoroutineHandle> maskEffectCoroutines = new Dictionary<Pickup, CoroutineHandle>();

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
            Exiled.Events.Handlers.Player.DroppingItem += OnDroppingItem;

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
            Exiled.Events.Handlers.Player.DroppingItem -= OnDroppingItem;

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
            maskEffectCoroutines.Clear();

            if (_config.AutoSpawnEnabled)
            {
                Timing.CallDelayed(2f, () => SpawnMasks());
            }

            if (_config.Debug)
                Log.Debug("Начало раунда - инициализация плагина масок SCP-096");
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
            
            foreach (var effectCoroutine in maskEffectCoroutines.Values)
            {
                if (effectCoroutine.IsRunning)
                    Timing.KillCoroutines(effectCoroutine);
            }
            maskEffectCoroutines.Clear();
            
            ClearAllHints();
        }

        private void OnPickingUpItem(PickingUpItemEventArgs ev)
        {
            if (ev.Pickup.Type != ItemType.Medkit)
                return;

            // Проверяем, является ли это маской SCP-096
            bool isMask = spawnedMasks.Contains(ev.Pickup);
            
            if (!isMask)
            {
                // Обычная аптечка
                return;
            }

            if (HasMask(ev.Player))
            {
                ev.IsAllowed = false;
                ShowHint(ev.Player, "<color=orange>У вас уже есть маска SCP-096!</color>", 3f);
                return;
            }

            // Останавливаем визуальные эффекты маски
            if (maskEffectCoroutines.TryGetValue(ev.Pickup, out var effectCoroutine))
            {
                if (effectCoroutine.IsRunning)
                    Timing.KillCoroutines(effectCoroutine);
                maskEffectCoroutines.Remove(ev.Pickup);
            }

            // Удаляем маску из списка заспавненных
            spawnedMasks.Remove(ev.Pickup);
            
            // Добавляем маску в инвентарь игрока
            Timing.CallDelayed(0.1f, () =>
            {
                var medkitItem = ev.Player.Items.FirstOrDefault(item => item.Type == ItemType.Medkit);
                if (medkitItem != null)
                {
                    playersWithMasks[ev.Player] = medkitItem;
                }
            });
            
            ShowHint(ev.Player, _config.Messages.MaskPickedUp, 6f);

            if (_config.Debug)
                Log.Debug($"Игрок {ev.Player.Nickname} подобрал маску SCP-096");
        }

        private void OnDroppingItem(DroppingItemEventArgs ev)
        {
            if (ev.Item.Type != ItemType.Medkit)
                return;

            // Проверяем, является ли это маской
            if (playersWithMasks.TryGetValue(ev.Player, out var maskItem) && maskItem == ev.Item)
            {
                // Прерываем процесс одевания, если он идет
                if (equipProcesses.TryGetValue(ev.Player, out var process))
                {
                    if (process.IsRunning)
                        Timing.KillCoroutines(process);
                    equipProcesses.Remove(ev.Player);
                    ShowHint(ev.Player, "<color=red>Процесс одевания маски прерван - вы выбросили маску!</color>", 3f);
                }

                // Удаляем из списка игроков с масками
                playersWithMasks.Remove(ev.Player);

                // Добавляем выброшенную маску обратно в список и запускаем эффекты
                Timing.CallDelayed(0.1f, () =>
                {
                    var droppedPickup = Pickup.List.FirstOrDefault(p => 
                        p.Type == ItemType.Medkit && 
                        Vector3.Distance(p.Position, ev.Player.Position) < 2f);
                    
                    if (droppedPickup != null)
                    {
                        spawnedMasks.Add(droppedPickup);
                        StartMaskVisualEffects(droppedPickup);
                    }
                });
            }
        }

        private void OnChangingRole(ChangingRoleEventArgs ev)
        {
            CleanupPlayer(ev.Player);
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
            if (playersWithMasks.ContainsKey(player))
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
            if (_config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                try
                {
                    ServerSpecificSettingsSync.SendToPlayer(ev.Player.ReferenceHub);
                }
                catch (Exception ex)
                {
                    if (_config.Debug)
                        Log.Debug($"Ошибка отправки настроек игроку {ev.Player.Nickname}: {ex}");
                }
            }
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
            if (!HasMask(ev.Player))
                return;

            TryInteractWithScp096(ev.Player);
            ev.IsAllowed = false;
        }

        private void TryInteractWithScp096(Player player)
        {
            if (!HasMask(player))
            {
                ShowHint(player, _config.Messages.NoMask, 3f);
                return;
            }

            // Проверяем, нужна ли маска в руке
            if (_config.RequireMaskInHand)
            {
                if (!playersWithMasks.TryGetValue(player, out var maskItem) || 
                    player.CurrentItem != maskItem)
                {
                    ShowHint(player, _config.Messages.MaskNotInHand, 3f);
                    return;
                }
            }

            if (equipProcesses.ContainsKey(player))
            {
                ShowHint(player, "<color=orange>Вы уже одеваете маску!</color>", 3f);
                return;
            }

            // Ищем ближайшего SCP-096
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

            // Начинаем процесс одевания маски
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
                    ShowHint(player, _config.Messages.ProcessInterrupted, 3f);
                    equipProcesses.Remove(player);
                    yield break;
                }

                // Проверяем, что маска все еще в руке (если требуется)
                if (_config.RequireMaskInHand)
                {
                    if (!playersWithMasks.TryGetValue(player, out var maskItem) || 
                        player.CurrentItem != maskItem)
                    {
                        ShowHint(player, "<color=red>Процесс прерван - маска не в руке!</color>", 3f);
                        equipProcesses.Remove(player);
                        yield break;
                    }
                }

                // Показываем прогресс
                if (_config.HintSettings.ShowProgress)
                {
                    float progress = elapsed / equipTime;
                    int progressBars = Mathf.RoundToInt(progress * 10);
                    string progressBar = $"<color=yellow>[{_config.HintSettings.ProgressBarStyle.PadRight(progressBars, _config.HintSettings.ProgressBarStyle[0])}{_config.HintSettings.EmptyProgressStyle.PadRight(10 - progressBars, _config.HintSettings.EmptyProgressStyle[0])}] {(progress * 100):F0}%</color>";
                    
                    ShowHint(player, $"{_config.Messages.MaskEquipping}\n{progressBar}", 0.5f);
                }

                elapsed += 0.2f;
                yield return Timing.WaitForSeconds(0.2f);
            }

            // Успешно надели маску
            if (playersWithMasks.TryGetValue(player, out var finalMaskItem))
            {
                player.RemoveItem(finalMaskItem);
                playersWithMasks.Remove(player);
            }
            
            maskedScp096s.Add(scp096);
            equipProcesses.Remove(player);

            ShowHint(player, _config.Messages.MaskEquipped, 5f);
            ShowHint(scp096, "<color=green>На вас надели маску!</color>", 5f);

            if (_config.Debug)
                Log.Debug($"Игрок {player.Nickname} успешно надел маску на SCP-096 {scp096.Nickname}");
        }

        public void SpawnMasks()
        {
            ClearAllMasks();

            for (int i = 0; i < _config.MasksToSpawn; i++)
            {
                Timing.CallDelayed(_config.SpawnDelay * i, () =>
                {
                    if (TryFindSpawnPosition(out Vector3 position))
                    {
                        var medkit = Item.Create(ItemType.Medkit);
                        var pickup = medkit.CreatePickup(position);
                        
                        // Модифицируем внешний вид маски
                        ModifyMaskAppearance(pickup);
                        
                        spawnedMasks.Add(pickup);
                        StartMaskVisualEffects(pickup);

                        if (_config.Debug)
                            Log.Debug($"Создана маска SCP-096 в {position}");
                    }
                });
            }
        }

        private void ModifyMaskAppearance(Pickup pickup)
        {
            try
            {
                // Изменяем размер маски
                pickup.Scale = Vector3.one * _config.MaskDisplay.Scale;
                
                // Применяем цвет (если возможно через API)
                if (ColorUtility.TryParseHtmlString(_config.MaskDisplay.Color, out Color maskColor))
                {
                    // Попытка изменить цвет через компоненты рендерера
                    var renderers = pickup.GameObject.GetComponentsInChildren<Renderer>();
                    foreach (var renderer in renderers)
                    {
                        if (renderer.material != null)
                        {
                            renderer.material.color = maskColor;
                            
                            if (_config.MaskDisplay.GlowEffect)
                            {
                                renderer.material.SetFloat("_EmissionIntensity", _config.MaskDisplay.GlowIntensity);
                                renderer.material.SetColor("_EmissionColor", maskColor * _config.MaskDisplay.GlowIntensity);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"Ошибка при модификации внешнего вида маски: {ex}");
            }
        }

        private void StartMaskVisualEffects(Pickup pickup)
        {
            if (_config.MaskDisplay.Rotate || _config.MaskDisplay.HoverHeight > 0)
            {
                var effectCoroutine = Timing.RunCoroutine(MaskVisualEffectCoroutine(pickup));
                maskEffectCoroutines[pickup] = effectCoroutine;
            }
        }

        private IEnumerator<float> MaskVisualEffectCoroutine(Pickup pickup)
        {
            Vector3 originalPosition = pickup.Position;
            float time = 0f;

            while (pickup != null && pickup.IsSpawned && spawnedMasks.Contains(pickup))
            {
                try
                {
                    // Вращение
                    if (_config.MaskDisplay.Rotate)
                    {
                        pickup.Rotation = Quaternion.Euler(0, time * _config.MaskDisplay.RotationSpeed, 0);
                    }

                    // Левитация
                    if (_config.MaskDisplay.HoverHeight > 0)
                    {
                        float hoverOffset = Mathf.Sin(time * _config.MaskDisplay.HoverSpeed) * _config.MaskDisplay.HoverHeight;
                        pickup.Position = originalPosition + Vector3.up * hoverOffset;
                    }

                    time += 0.1f;
                    yield return Timing.WaitForSeconds(0.1f);
                }
                catch (Exception ex)
                {
                    if (_config.Debug)
                        Log.Debug($"Ошибка в визуальных эффектах маски: {ex}");
                    break;
                }
            }

            // Убираем корутину из словаря
            if (maskEffectCoroutines.ContainsKey(pickup))
                maskEffectCoroutines.Remove(pickup);
        }

        private bool TryFindSpawnPosition(out Vector3 position)
        {
            position = Vector3.zero;

            // Используем конкретные комнаты, если указано
            if (_config.UseSpecificRooms && _config.SpecificSpawnRooms.Count > 0)
            {
                var availableRooms = Room.List.Where(r => _config.SpecificSpawnRooms.Contains(r.Type)).ToList();
                
                foreach (var room in availableRooms.OrderBy(r => random.Next()))
                {
                    if (TrySpawnInRoom(room, out position))
                        return true;
                }
            }
            else
            {
                // Используем зоны с весами
                var availableRooms = Room.List.Where(r => _config.SpawnWeights.ContainsKey(r.Zone)).ToList();
                
                foreach (var room in availableRooms.OrderBy(r => random.Next()))
                {
                    if (_config.SpawnWeights.TryGetValue(room.Zone, out float weight) && 
                        random.NextDouble() * 100 < weight)
                    {
                        if (TrySpawnInRoom(room, out position))
                            return true;
                    }
                }
            }

            return false;
        }

        private bool TrySpawnInRoom(Room room, out Vector3 position)
        {
            position = Vector3.zero;

            for (int i = 0; i < _config.MaxSpawnAttempts; i++)
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

            return false;
        }

        private bool IsValidSpawnPosition(Vector3 position)
        {
            return !Physics.CheckSphere(position, _config.SpawnCheckRadius, LayerMask.GetMask("Default", "Player", "Ragdoll")) &&
                   position.y > -10f;
        }

        private void ClearAllMasks()
        {
            foreach (var mask in spawnedMasks.ToList())
            {
                try
                {
                    if (mask != null && mask.IsSpawned)
                    {
                        // Останавливаем визуальные эффекты
                        if (maskEffectCoroutines.TryGetValue(mask, out var effectCoroutine))
                        {
                            if (effectCoroutine.IsRunning)
                                Timing.KillCoroutines(effectCoroutine);
                            maskEffectCoroutines.Remove(mask);
                        }
                        
                        mask.Destroy();
                    }
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
                
                // Fallback на обычные хинты
                player.ShowHint(message, (ushort)duration);
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

        // Публичные методы для использования в командах
        public bool HasMask(Player player)
        {
            return playersWithMasks.ContainsKey(player);
        }

        public void AddPlayerMask(Player player, Item maskItem)
        {
            playersWithMasks[player] = maskItem;
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
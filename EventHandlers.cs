using System;
using System.Collections.Generic;
using System.Linq;
using Exiled.API.Enums;
using Exiled.API.Features;
using Exiled.API.Features.Items;
using Exiled.API.Features.Pickups;
using Exiled.API.Features.Core.UserSettings;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using MEC;
using PlayerRoles;
using UnityEngine;
using UserSettings.ServerSpecific;
using Scp096Mask.Enums;

namespace Scp096Mask
{
    internal class EventHandlers
    {
        private readonly Config _config;
        private System.Random random = new System.Random();
        
        // Заспавненные маски
        public List<Pickup> spawnedMasks = new List<Pickup>();
        
        // Игроки с масками в инвентаре
        private Dictionary<Player, Item> playersWithMasks = new Dictionary<Player, Item>();
        
        // Замаскированные SCP-096
        private HashSet<Player> maskedScp096s = new HashSet<Player>();
        
        // Процессы одевания масок
        private Dictionary<Player, CoroutineHandle> equipProcesses = new Dictionary<Player, CoroutineHandle>();
        
        // Визуальные эффекты масок
        private Dictionary<Pickup, CoroutineHandle> maskVisualEffects = new Dictionary<Pickup, CoroutineHandle>();
        
        // Таймер респавна масок
        private CoroutineHandle respawnTimer;

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
            Exiled.Events.Handlers.Player.UsingItem += OnUsingItem;

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
            Exiled.Events.Handlers.Player.UsingItem -= OnUsingItem;

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
            ClearAllData();

            if (_config.AutoSpawnEnabled)
            {
                Timing.CallDelayed(3f, () => SpawnMasks());
            }

            // Запуск таймера респавна если включен
            if (_config.AdvancedSpawn.EnableRespawn)
            {
                respawnTimer = Timing.RunCoroutine(RespawnMasksRoutine());
            }

            if (_config.Debug)
                Log.Debug("Раунд начался - система масок SCP-096 инициализирована");
        }

        private void OnRoundEnded(RoundEndedEventArgs ev)
        {
            ClearAllData();
            
            if (respawnTimer.IsRunning)
                Timing.KillCoroutines(respawnTimer);

            if (_config.Debug)
                Log.Debug("Раунд окончен - система масок очищена");
        }

        private void OnPickingUpItem(PickingUpItemEventArgs ev)
        {
            if (ev.Pickup.Type != ItemType.Medkit)
                return;

            bool isMask = spawnedMasks.Contains(ev.Pickup);
            
            if (!isMask)
                return;

            if (HasMask(ev.Player))
            {
                ev.IsAllowed = false;
                ShowHint(ev.Player, "<color=orange>У вас уже есть маска SCP-096!</color>", 3f);
                return;
            }

            // Удаляем маску из списка заспавненных
            spawnedMasks.Remove(ev.Pickup);
            
            // Останавливаем визуальные эффекты
            if (maskVisualEffects.TryGetValue(ev.Pickup, out var effect))
            {
                if (effect.IsRunning)
                    Timing.KillCoroutines(effect);
                maskVisualEffects.Remove(ev.Pickup);
            }
            
            // Добавляем маску в инвентарь игрока
            Timing.CallDelayed(0.1f, () =>
            {
                var medkitItem = ev.Player.Items.FirstOrDefault(item => item.Type == ItemType.Medkit);
                if (medkitItem != null)
                {
                    playersWithMasks[ev.Player] = medkitItem;
                    
                    // Играем звук подбора если включен
                    if (_config.Effects.PlayPickupSound)
                    {
                        // В будущих версиях можно добавить кастомный звук
                    }
                }
            });
            
            ShowHint(ev.Player, _config.Messages.MaskPickedUp, 6f);

            if (_config.Debug)
                Log.Debug($"Игрок {ev.Player.Nickname} подобрал маску SCP-096");
        }

        private void OnUsingItem(UsingItemEventArgs ev)
        {
            if (ev.Item.Type != ItemType.Medkit)
                return;

            // Проверяем, является ли это маской
            if (playersWithMasks.TryGetValue(ev.Player, out var maskItem) && maskItem == ev.Item)
            {
                ev.IsAllowed = false;
                ShowHint(ev.Player, "<color=orange>Это маска SCP-096! Используйте её рядом с SCP-096!</color>", 3f);
            }
        }

        private void OnDroppingItem(DroppingItemEventArgs ev)
        {
            if (ev.Item.Type != ItemType.Medkit)
                return;

            // Проверяем, является ли это маской
            if (playersWithMasks.TryGetValue(ev.Player, out var maskItem) && maskItem == ev.Item)
            {
                // Прерываем процесс одевания если он идет
                if (equipProcesses.TryGetValue(ev.Player, out var process))
                {
                    if (process.IsRunning)
                        Timing.KillCoroutines(process);
                    equipProcesses.Remove(ev.Player);
                    ShowHint(ev.Player, "<color=red>Процесс одевания маски прерван - вы выбросили маску!</color>", 3f);
                }

                // Удаляем из списка игроков с масками
                playersWithMasks.Remove(ev.Player);

                // Добавляем обратно в список заспавненных масок с визуальными эффектами
                Timing.CallDelayed(0.1f, () =>
                {
                    var droppedPickup = Pickup.List.FirstOrDefault(p => p.Type == ItemType.Medkit && 
                        Vector3.Distance(p.Position, ev.Player.Position) < 2f);
                    
                    if (droppedPickup != null)
                    {
                        spawnedMasks.Add(droppedPickup);
                        ApplyMaskVisualEffects(droppedPickup);
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
        }

        private void OnVerified(VerifiedEventArgs ev)
        {
            if (_config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                try
                {
                    // Отправляем серверные настройки игроку с задержкой
                    Timing.CallDelayed(2f, () =>
                    {
                        try
                        {
                            if (ev.Player != null && ev.Player.IsConnected)
                            {
                                SettingBase.SendToPlayer(ev.Player);
                                
                                if (_config.Debug)
                                    Log.Debug($"Серверные настройки отправлены игроку {ev.Player.Nickname}");
                            }
                        }
                        catch (Exception ex2)
                        {
                            if (_config.Debug)
                                Log.Debug($"Ошибка отправки настроек игроку {ev.Player.Nickname}: {ex2}");
                        }
                    });
                }
                catch (Exception ex)
                {
                    if (_config.Debug)
                        Log.Debug($"Ошибка при попытке отправить настройки игроку {ev.Player.Nickname}: {ex}");
                }
            }
        }

        private void OnSettingValueReceived(ReferenceHub hub, ServerSpecificSettingBase settingBase)
        {
            if (!Player.TryGet(hub, out Player player))
                return;

            if (settingBase is SSKeybindSetting keybindSetting && 
                keybindSetting.SettingId == 1 && 
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

            // Проверяем, требуется ли маска в руке
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

            // Ищем ближайший SCP-096
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

            // Запускаем процесс одевания маски
            var equipProcess = Timing.RunCoroutine(EquipMaskProcess(player, nearestScp096));
            equipProcesses[player] = equipProcess;
        }

        private IEnumerator<float> EquipMaskProcess(Player player, Player scp096)
        {
            float equipTime = _config.MaskEquipTime;
            float elapsed = 0f;

            ShowHint(player, _config.Messages.MaskEquipping, equipTime + 1f);
            ShowHint(scp096, "<color=yellow>На вас одевают маску...</color>", equipTime + 1f);

            while (elapsed < equipTime)
            {
                // Проверяем условия прерывания
                if (player == null || !player.IsConnected || !player.IsAlive ||
                    scp096 == null || !scp096.IsConnected || !scp096.IsAlive ||
                    Vector3.Distance(player.Position, scp096.Position) > _config.InteractionDistance)
                {
                    ShowHint(player, "<color=red>Процесс прерван!</color>", 3f);
                    ShowHint(scp096, "<color=red>Процесс одевания маски прерван!</color>", 3f);
                    equipProcesses.Remove(player);
                    yield break;
                }

                // Проверяем маску в руке если требуется
                if (_config.RequireMaskInHand)
                {
                    if (!playersWithMasks.TryGetValue(player, out var maskItem) || 
                        player.CurrentItem != maskItem)
                    {
                        ShowHint(player, "<color=red>Процесс прерван - маска не в руке!</color>", 3f);
                        ShowHint(scp096, "<color=red>Процесс одевания маски прерван!</color>", 3f);
                        equipProcesses.Remove(player);
                        yield break;
                    }
                }

                // Обновляем прогресс
                float progress = elapsed / equipTime;
                int progressBars = Mathf.RoundToInt(progress * 10);
                string progressBar = $"<color=yellow>[{"█".PadRight(progressBars, '█')}{"░".PadRight(10 - progressBars, '░')}] {(progress * 100):F0}%</color>";
                
                ShowHint(player, $"{_config.Messages.MaskEquipping}\n{progressBar}", 0.5f);

                elapsed += 0.2f;
                yield return Timing.WaitForSeconds(0.2f);
            }

            // Успешное завершение
            CompleteMaskEquipping(player, scp096);
        }

        private void CompleteMaskEquipping(Player player, Player scp096)
        {
            // Удаляем маску из инвентаря
            if (playersWithMasks.TryGetValue(player, out var finalMaskItem))
            {
                player.RemoveItem(finalMaskItem);
                playersWithMasks.Remove(player);
            }
            
            // Добавляем SCP-096 в список замаскированных
            maskedScp096s.Add(scp096);
            equipProcesses.Remove(player);

            // Показываем сообщения
            ShowHint(player, _config.Messages.MaskEquipped, 5f);
            ShowHint(scp096, "<color=green>На вас надели маску! Теперь вы не будете агриться!</color>", 5f);

            // Эффекты при одевании
            if (_config.Effects.EnableEquipEffects)
            {
                if (_config.Effects.PlayEquipSound)
                {
                    // Звуковые эффекты
                }

                if (_config.Effects.ShowParticleEffect)
                {
                    // Эффекты частиц
                }

                if (_config.Effects.ScreenShake)
                {
                    // Встряска экрана
                }
            }

            if (_config.Debug)
                Log.Debug($"Игрок {player.Nickname} успешно надел маску на SCP-096 {scp096.Nickname}");
        }

        public void SpawnMasks()
        {
            // Проверяем условия спавна
            if (_config.AdvancedSpawn.OnlyWhenScp096Present)
            {
                if (!Player.List.Any(p => p.Role.Type == RoleTypeId.Scp096))
                {
                    if (_config.Debug)
                        Log.Debug("Маски не заспавнены - нет SCP-096");
                    return;
                }
            }

            if (Player.List.Count() < _config.AdvancedSpawn.MinPlayersForSpawn)
            {
                if (_config.Debug)
                    Log.Debug($"Маски не заспавнены - недостаточно игроков ({Player.List.Count()}/{_config.AdvancedSpawn.MinPlayersForSpawn})");
                return;
            }

            if (spawnedMasks.Count >= _config.AdvancedSpawn.MaxMasksOnMap)
            {
                if (_config.Debug)
                    Log.Debug("Маски не заспавнены - достигнут лимит масок на карте");
                return;
            }

            ClearAllMasks();

            int masksToSpawn = Math.Min(_config.MasksToSpawn, _config.AdvancedSpawn.MaxMasksOnMap);
            int spawnedCount = 0;

            for (int i = 0; i < masksToSpawn && spawnedCount < masksToSpawn; i++)
            {
                Timing.CallDelayed(0.5f * i, () =>
                {
                    if (spawnedMasks.Count < _config.AdvancedSpawn.MaxMasksOnMap && 
                        TryFindSpawnPosition(out Vector3 position))
                    {
                        var medkit = Item.Create(ItemType.Medkit);
                        var pickup = medkit.CreatePickup(position);
                        
                        spawnedMasks.Add(pickup);
                        ApplyMaskVisualEffects(pickup);
                        spawnedCount++;

                        if (_config.AdvancedSpawn.LogMaskSpawns)
                        {
                            var parentRoom = Room.FindParentRoom(pickup.GameObject);
                            if (parentRoom != null)
                                Log.Info($"Маска SCP-096 создана в {parentRoom.Type} ({position})");
                            else
                                Log.Info($"Маска SCP-096 создана в неизвестной комнате ({position})");
                        }
                    }
                });
            }

            if (_config.Debug)
                Log.Debug($"Запущен спавн {masksToSpawn} масок SCP-096");
        }

        private bool TryFindSpawnPosition(out Vector3 position)
        {
            position = Vector3.zero;

            // Попытки найти позицию
            for (int attempt = 0; attempt < _config.MaxSpawnAttempts; attempt++)
            {
                // Сначала проверяем конкретные комнаты
                if (TrySpawnInSpecificRoom(out position))
                    return true;

                // Затем пробуем зоны
                if (TrySpawnInZone(out position))
                    return true;
            }

            return false;
        }

        private bool TrySpawnInSpecificRoom(out Vector3 position)
        {
            position = Vector3.zero;

            var availableRooms = Room.List.Where(r => 
                _config.SpecificRoomSpawn.ContainsKey(r.Type) &&
                !_config.AdvancedSpawn.ForbiddenRooms.Contains(r.Type)).ToList();

            foreach (var room in availableRooms.OrderBy(r => random.Next()))
            {
                if (_config.SpecificRoomSpawn.TryGetValue(room.Type, out float chance) && 
                    random.NextDouble() * 100 < chance)
                {
                    if (TryFindValidPositionInRoom(room, out position))
                        return true;
                }
            }

            return false;
        }

        private bool TrySpawnInZone(out Vector3 position)
        {
            position = Vector3.zero;

            var availableZones = _config.SpawnWeights.Keys.Where(z => 
                !_config.AdvancedSpawn.ForbiddenZones.Contains(z)).ToList();

            // Приоритет для приоритетных зон
            var priorityZones = availableZones.Where(z => _config.AdvancedSpawn.PriorityZones.Contains(z)).ToList();
            var normalZones = availableZones.Except(priorityZones).ToList();

            var zonesToCheck = priorityZones.Concat(normalZones);

            foreach (var zone in zonesToCheck.OrderBy(z => random.Next()))
            {
                if (_config.SpawnWeights.TryGetValue(zone, out float weight) && 
                    random.NextDouble() * 100 < weight)
                {
                    var roomsInZone = Room.List.Where(r => r.Zone == zone && 
                        !_config.AdvancedSpawn.ForbiddenRooms.Contains(r.Type)).ToList();

                    foreach (var room in roomsInZone.OrderBy(r => random.Next()))
                    {
                        if (TryFindValidPositionInRoom(room, out position))
                            return true;
                    }
                }
            }

            return false;
        }

        private bool TryFindValidPositionInRoom(Room room, out Vector3 position)
        {
            position = Vector3.zero;

            for (int i = 0; i < 15; i++)
            {
                Vector3 testPos = room.Position + new Vector3(
                    (float)(random.NextDouble() * 8 - 4),
                    1.2f,
                    (float)(random.NextDouble() * 8 - 4));

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
            // Проверка коллизий
            bool hasCollision = Physics.CheckSphere(position, 0.5f, LayerMask.GetMask("Default", "Player", "Ragdoll"));
            
            // Проверка высоты
            bool validHeight = position.y > -10f && position.y < 50f;
            
            // Проверка минимального расстояния от других масок
            bool farFromOtherMasks = !spawnedMasks.Any(mask => 
                Vector3.Distance(mask.Position, position) < _config.MinMaskDistance);

            return !hasCollision && validHeight && farFromOtherMasks;
        }

        private void ApplyMaskVisualEffects(Pickup pickup)
        {
            if (!_config.VisualSettings.EnableGlow && !_config.VisualSettings.EnableRotation && 
                !_config.VisualSettings.EnableBobbing)
                return;

            var effectCoroutine = Timing.RunCoroutine(MaskVisualEffectsRoutine(pickup));
            maskVisualEffects[pickup] = effectCoroutine;
        }

        private IEnumerator<float> MaskVisualEffectsRoutine(Pickup pickup)
        {
            Vector3 originalPosition = pickup.Position;
            float timeOffset = UnityEngine.Random.Range(0f, 10f);

            while (pickup != null && pickup.IsSpawned && spawnedMasks.Contains(pickup))
            {
                try
                {
                    float time = Time.time + timeOffset;
                    Vector3 newPosition = originalPosition;

                    // Эффект подпрыгивания
                    if (_config.VisualSettings.EnableBobbing)
                    {
                        float bobOffset = Mathf.Sin(time * _config.VisualSettings.BobbingSpeed) * _config.VisualSettings.BobbingHeight;
                        newPosition.y = originalPosition.y + bobOffset;
                    }

                    // Применяем новую позицию
                    pickup.Position = newPosition;

                    // Эффект вращения
                    if (_config.VisualSettings.EnableRotation)
                    {
                        float rotationY = time * _config.VisualSettings.RotationSpeed;
                        pickup.Rotation = Quaternion.Euler(0, rotationY, 0);
                    }

                    // Изменение размера
                    if (_config.VisualSettings.Scale != 1f)
                    {
                        pickup.Scale = Vector3.one * _config.VisualSettings.Scale;
                    }
                }
                catch (Exception ex)
                {
                    if (_config.Debug)
                        Log.Debug($"Ошибка в визуальных эффектах маски: {ex}");
                    break;
                }

                yield return Timing.WaitForSeconds(0.1f);
            }

            // Очистка при завершении
            if (maskVisualEffects.ContainsKey(pickup))
                maskVisualEffects.Remove(pickup);
        }

        private IEnumerator<float> RespawnMasksRoutine()
        {
            while (Round.IsStarted)
            {
                yield return Timing.WaitForSeconds(_config.AdvancedSpawn.RespawnInterval);

                if (spawnedMasks.Count < _config.AdvancedSpawn.MaxMasksOnMap && 
                    random.NextDouble() * 100 < _config.AdvancedSpawn.RespawnChance)
                {
                    if (TryFindSpawnPosition(out Vector3 position))
                    {
                        var medkit = Item.Create(ItemType.Medkit);
                        var pickup = medkit.CreatePickup(position);
                        
                        spawnedMasks.Add(pickup);
                        ApplyMaskVisualEffects(pickup);

                        if (_config.AdvancedSpawn.LogMaskSpawns)
                        {
                            var parentRoom = Room.FindParentRoom(pickup.GameObject);
                            if (parentRoom != null)
                                Log.Info($"Респавн маски SCP-096 в {parentRoom.Type}");
                            else
                                Log.Info($"Респавн маски SCP-096 в неизвестной комнате");
                        }
                    }
                }
            }
        }

        private void ClearAllMasks()
        {
            foreach (var mask in spawnedMasks.ToList())
            {
                try
                {
                    if (maskVisualEffects.TryGetValue(mask, out var effect))
                    {
                        if (effect.IsRunning)
                            Timing.KillCoroutines(effect);
                        maskVisualEffects.Remove(mask);
                    }

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

        private void ClearAllData()
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
        }

        private void ShowHint(Player player, string message, float duration)
        {
            try
            {
                // Fallback на обычный хинт Exiled
                player.ShowHint(message, (ushort)duration);
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Error($"Не удалось показать хинт: {ex}");
            }
        }

        // Публичные методы для использования в других классах
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

        public int GetMaskCount()
        {
            return spawnedMasks.Count;
        }

        public int GetMaskedScp096Count()
        {
            return maskedScp096s.Count;
        }

        public List<Player> GetMaskedScp096s()
        {
            return maskedScp096s.ToList();
        }
    }
}
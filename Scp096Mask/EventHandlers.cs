using System;
using System.Collections.Generic;
using System.Linq;
using Exiled.API.Enums;
using Exiled.API.Features;
using Exiled.API.Features.Items;
using Exiled.API.Features.Pickups;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using Exiled.Events.EventArgs.Scp096;
using MEC;
using PlayerRoles;
using UnityEngine;
using Hint = HintServiceMeow.Core.Models.Hints.Hint;
using HintServiceMeow.Core.Enum;
using HintServiceMeow.Core.Utilities;
using UserSettings.ServerSpecific;

namespace Scp096Mask
{
    internal class EventHandlers
    {
        private readonly Config _config;

        private readonly System.Random _random = new();

        private readonly List<Pickup> _spawnedMaskPickups = new();
        private readonly HashSet<ushort> _maskSerials = new();
        private readonly HashSet<Player> _masked096 = new();

        private readonly Dictionary<Player, Hint> _hints = new();
        private readonly Dictionary<Player, CoroutineHandle> _activeEquipCoroutines = new();

        internal EventHandlers(Config config)
        {
            _config = config;
        }

        internal void RegisterEvents()
        {
            Exiled.Events.Handlers.Server.RoundStarted += OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded += OnRoundEnded;
            Exiled.Events.Handlers.Server.RestartingRound += OnRestartingRound;

            Exiled.Events.Handlers.Player.PickingUpItem += OnPickingUpItem;
            Exiled.Events.Handlers.Player.UsingItem += OnUsingItem;
            Exiled.Events.Handlers.Player.DroppedItem += OnDroppedItem;
            Exiled.Events.Handlers.Player.Destroying += OnPlayerDestroying;
            Exiled.Events.Handlers.Player.ChangingRole += OnChangingRole;
            Exiled.Events.Handlers.Player.Verified += OnVerified;

            ServerSpecificSettingsSync.ServerOnSettingValueReceived += OnSettingValueReceived;

            Exiled.Events.Handlers.Scp096.AddingTarget += OnScp096AddingTarget;
        }

        internal void UnregisterEvents()
        {
            Exiled.Events.Handlers.Server.RoundStarted -= OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded -= OnRoundEnded;
            Exiled.Events.Handlers.Server.RestartingRound -= OnRestartingRound;

            Exiled.Events.Handlers.Player.PickingUpItem -= OnPickingUpItem;
            Exiled.Events.Handlers.Player.UsingItem -= OnUsingItem;
            Exiled.Events.Handlers.Player.DroppedItem -= OnDroppedItem;
            Exiled.Events.Handlers.Player.Destroying -= OnPlayerDestroying;
            Exiled.Events.Handlers.Player.ChangingRole -= OnChangingRole;
            Exiled.Events.Handlers.Player.Verified -= OnVerified;

            ServerSpecificSettingsSync.ServerOnSettingValueReceived -= OnSettingValueReceived;

            Exiled.Events.Handlers.Scp096.AddingTarget -= OnScp096AddingTarget;

            foreach (var hint in _hints.Values)
                hint.Hide = true;

            _hints.Clear();
            ClearAllMasks();
            _maskSerials.Clear();
            _masked096.Clear();

            foreach (var kvp in _activeEquipCoroutines.ToList())
                CancelEquipProgress(kvp.Key);

            _activeEquipCoroutines.Clear();
        }

        private void OnVerified(Exiled.Events.EventArgs.Player.VerifiedEventArgs ev)
        {
            ServerSpecificSettingsSync.SendToPlayer(ev.Player.ReferenceHub);
        }

        private void OnRoundStarted()
        {
            _spawnedMaskPickups.Clear();
            _maskSerials.Clear();
            _masked096.Clear();
            _activeEquipCoroutines.Clear();

            if (_config.AutoSpawnEnabled)
                SpawnMasks();
        }

        private void OnRoundEnded(RoundEndedEventArgs ev)
        {
            foreach (var kvp in _activeEquipCoroutines.ToList())
                CancelEquipProgress(kvp.Key);

            _activeEquipCoroutines.Clear();
            ClearAllMasks();
            _maskSerials.Clear();
            _masked096.Clear();
        }

        private void OnRestartingRound()
        {
            foreach (var kvp in _activeEquipCoroutines.ToList())
                CancelEquipProgress(kvp.Key);

            _activeEquipCoroutines.Clear();
            ClearAllMasks();
            _maskSerials.Clear();
            _masked096.Clear();
        }

        private void OnPickingUpItem(PickingUpItemEventArgs ev)
        {
            try
            {
                if (ev.Pickup == null)
                    return;

                if (_spawnedMaskPickups.Contains(ev.Pickup))
                {
                    _spawnedMaskPickups.Remove(ev.Pickup);
                }

                if (_maskSerials.Contains(ev.Pickup.Serial))
                {
                    _maskSerials.Remove(ev.Pickup.Serial);

                    if (ev.Player != null && ev.Item != null)
                    {
                        _maskSerials.Add(ev.Item.Serial);
                        ShowHint(ev.Player, _config.PickupMaskMessage, 5f);
                    }
                }
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"OnPickingUpItem error: {ex}");
            }
        }

        private void OnUsingItem(UsingItemEventArgs ev)
        {
            try
            {
                if (ev.Item == null)
                    return;

                if (ev.Item.Type == ItemType.Medkit && _maskSerials.Contains(ev.Item.Serial) && !_config.AllowMaskAsMedkit)
                {
                    ev.IsAllowed = false;
                    ShowHint(ev.Player, _config.NeedLookAt096Message, 3f);
                }
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"OnUsingItem error: {ex}");
            }
        }

        private void OnDroppedItem(Exiled.Events.EventArgs.Player.DroppedItemEventArgs ev)
        {
            try
            {
                if (ev.Item == null || ev.Pickup == null)
                    return;

                if (ev.Item.Type == ItemType.Medkit && _maskSerials.Contains(ev.Item.Serial))
                {
                    _maskSerials.Remove(ev.Item.Serial);
                    _maskSerials.Add(ev.Pickup.Serial);
                    if (!_spawnedMaskPickups.Contains(ev.Pickup))
                        _spawnedMaskPickups.Add(ev.Pickup);
                }
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"OnDroppedItem error: {ex}");
            }
        }

        private void OnPlayerDestroying(Exiled.Events.EventArgs.Player.DestroyingEventArgs ev)
        {
            if (_hints.TryGetValue(ev.Player, out Hint hint))
            {
                hint.Hide = true;
                _hints.Remove(ev.Player);
            }

            CancelEquipProgress(ev.Player);

            if (_masked096.Contains(ev.Player))
                _masked096.Remove(ev.Player);
        }

        private void OnChangingRole(Exiled.Events.EventArgs.Player.ChangingRoleEventArgs ev)
        {
            CancelEquipProgress(ev.Player);

            if (ev.Player == null)
                return;

            if (_masked096.Contains(ev.Player) && ev.NewRole != RoleTypeId.Scp096)
                _masked096.Remove(ev.Player);
        }

        private void OnSettingValueReceived(ReferenceHub hub, ServerSpecificSettingBase settingBase)
        {
            try
            {
                if (!Player.TryGet(hub, out Player player))
                    return;

                if (settingBase is SSKeybindSetting key && key.SettingId == _config.KeybindId && key.SyncIsPressed)
                {
                    TryStartEquip(player);
                }
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"OnSettingValueReceived error: {ex}");
            }
        }

        private void OnScp096AddingTarget(AddingTargetEventArgs ev)
        {
            try
            {
                var scp096Owner = ev.Scp096?.Owner;
                if (scp096Owner != null && _masked096.Contains(scp096Owner))
                {
                    ev.IsAllowed = false;
                }
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"OnScp096AddingTarget error: {ex}");
            }
        }

        private void TryStartEquip(Player player)
        {
            if (player == null || !player.IsAlive)
                return;

            if (_activeEquipCoroutines.ContainsKey(player))
                return;

            var currentItem = player.CurrentItem;
            if (currentItem == null || currentItem.Type != ItemType.Medkit || !_maskSerials.Contains(currentItem.Serial))
            {
                ShowHint(player, _config.NeedMaskInHandsMessage, 3f);
                return;
            }

            Player scp096 = FindLookedScp096(player, _config.EquipMaxDistance, _config.EquipMaxAngleDeg);
            if (scp096 == null)
            {
                ShowHint(player, _config.NeedLookAt096Message, 3f);
                return;
            }

            if (_masked096.Contains(scp096))
            {
                ShowHint(player, _config.MaskAlreadyOnMessage, 3f);
                return;
            }

            CoroutineHandle handle = Timing.RunCoroutine(EquipMaskRoutine(player, scp096, currentItem));
            _activeEquipCoroutines[player] = handle;
        }

        private IEnumerator<float> EquipMaskRoutine(Player installer, Player scp096, Item maskItem)
        {
            float time = 0f;
            float duration = Mathf.Max(0.1f, _config.EquipTimeSeconds);

            while (time < duration)
            {
                if (!installer.IsAlive || !scp096.IsAlive || installer.CurrentItem != maskItem)
                {
                    ShowHint(installer, _config.MaskEquipCancelledMessage, 2.5f);
                    CancelEquipProgress(installer);
                    yield break;
                }

                if (Vector3.Distance(installer.Position, scp096.Position) > _config.EquipMaxDistance)
                {
                    ShowHint(installer, _config.MaskEquipCancelledMessage, 2.0f);
                    CancelEquipProgress(installer);
                    yield break;
                }

                if (!IsLookingAt(installer, scp096, _config.EquipMaxAngleDeg))
                {
                    ShowHint(installer, _config.MaskEquipCancelledMessage, 2.0f);
                    CancelEquipProgress(installer);
                    yield break;
                }

                float progress = Mathf.Clamp01(time / duration);
                ShowProgress(installer, _config.EquipProgressTitle, progress);

                yield return Timing.WaitForSeconds(0.1f);
                time += 0.1f;
            }

            if (!_masked096.Contains(scp096))
                _masked096.Add(scp096);

            installer.RemoveItem(maskItem);

            ShowHint(installer, _config.MaskEquippedMessage, 4f);
            ShowHint(scp096, "<color=green>На вас надели маску. Взгляд игроков больше не вызывает агрессию.</color>", 5f);

            CancelEquipProgress(installer);
        }

        private void CancelEquipProgress(Player player)
        {
            if (_activeEquipCoroutines.TryGetValue(player, out var handle))
            {
                if (Timing.IsRunningCoroutine(handle))
                    Timing.KillCoroutine(handle);

                _activeEquipCoroutines.Remove(player);
            }

            if (_hints.TryGetValue(player, out var hint))
            {
                hint.Hide = true;
                _hints.Remove(player);
            }
        }

        private void SpawnMasks()
        {
            ClearAllMasks();

            for (int i = 0; i < _config.MasksToSpawn; i++)
            {
                Timing.CallDelayed(0.35f * i, () =>
                {
                    if (TryFindSpawnPosition(out Vector3 pos))
                    {
                        var item = Item.Create(ItemType.Medkit);
                        var pickup = item.CreatePickup(pos);

                        _spawnedMaskPickups.Add(pickup);
                        _maskSerials.Add(pickup.Serial);

                        if (_config.Debug)
                            Log.Debug($"Маска 096 создана в {pos}");
                    }
                });
            }
        }

        private bool TryFindSpawnPosition(out Vector3 position)
        {
            position = Vector3.zero;
            int tries = 0;

            foreach (var room in Room.List.OrderBy(_ => _random.Next()))
            {
                if (_config.SpawnWeights.TryGetValue(room.Zone, out float weight))
                {
                    if (_random.NextDouble() * 100d > weight)
                        continue;

                    for (int i = 0; i < _config.MaxSpawnTriesPerMask; i++)
                    {
                        tries++;
                        Vector3 test = room.Position + new Vector3(
                            (float)(_random.NextDouble() * 6 - 3),
                            1f,
                            (float)(_random.NextDouble() * 6 - 3));

                        if (IsValidSpawnPosition(test))
                        {
                            position = test;
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private bool IsValidSpawnPosition(Vector3 position)
        {
            return !Physics.CheckSphere(position, 0.5f, LayerMask.GetMask("Default", "Player", "Ragdoll")) && position.y > -10f;
        }

        private void ClearAllMasks()
        {
            foreach (var p in _spawnedMaskPickups.ToList())
            {
                try
                {
                    if (p != null && p.IsSpawned)
                        p.Destroy();
                }
                catch (Exception ex)
                {
                    if (_config.Debug)
                        Log.Debug($"Ошибка удаления маски: {ex}");
                }
            }
            _spawnedMaskPickups.Clear();
        }

        private Player FindLookedScp096(Player source, float maxDistance, float maxAngleDeg)
        {
            var scps = Player.List.Where(p => p.IsAlive && p.Role == RoleTypeId.Scp096).ToList();
            if (scps.Count == 0)
                return null;

            Player nearest = null;
            float nearestDist = float.MaxValue;

            foreach (var scp in scps)
            {
                float dist = Vector3.Distance(source.Position, scp.Position);
                if (dist > maxDistance)
                    continue;

                if (!IsLookingAt(source, scp, maxAngleDeg))
                    continue;

                if (dist < nearestDist)
                {
                    nearestDist = dist;
                    nearest = scp;
                }
            }

            return nearest;
        }

        private bool IsLookingAt(Player viewer, Player target, float maxAngleDeg)
        {
            try
            {
                Vector3 eyePos = viewer.CameraTransform.position;
                Vector3 toTarget = (target.Position + Vector3.up * 1.2f) - eyePos;
                Vector3 forward = viewer.CameraTransform.forward;

                float angle = Vector3.Angle(forward, toTarget);
                if (angle > maxAngleDeg)
                    return false;

                if (Physics.Linecast(eyePos, target.Position + Vector3.up * 1.2f, out RaycastHit hit, LayerMask.GetMask("Default")))
                {
                    var go = hit.collider.gameObject;
                    if (go != null && go != target.GameObject)
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private void ShowHint(Player player, string message, float duration)
        {
            try
            {
                if (!_hints.TryGetValue(player, out var hint))
                {
                    hint = new Hint
                    {
                        FontSize = _config.HintSettings.TextSize,
                        XCoordinate = _config.HintSettings.XPosition,
                        YCoordinate = _config.HintSettings.YPosition,
                        Alignment = HintAlignment.Center,
                        SyncSpeed = HintSyncSpeed.Fast,
                        Hide = false,
                        Text = string.Empty,
                    };
                    PlayerDisplay.Get(player).AddHint(hint);
                    _hints[player] = hint;
                }

                hint.Text = message;

                Timing.CallDelayed(duration, () =>
                {
                    if (_hints.TryGetValue(player, out var current) && ReferenceEquals(current, hint) && current.Text == message)
                    {
                        current.Hide = true;
                        _hints.Remove(player);
                    }
                });
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"ShowHint error: {ex}");
            }
        }

        private void ShowProgress(Player player, string title, float progress01)
        {
            try
            {
                progress01 = Mathf.Clamp01(progress01);
                int bars = 20;
                int filled = Mathf.RoundToInt(progress01 * bars);
                string bar = new string('█', filled) + new string('░', Math.Max(0, bars - filled));
                string text = $"<color=yellow><b>{title}</b></color>\n[{bar}] {(int)(progress01 * 100)}%";

                if (!_hints.TryGetValue(player, out var hint))
                {
                    hint = new Hint
                    {
                        FontSize = _config.HintSettings.TextSize,
                        XCoordinate = _config.HintSettings.XPosition,
                        YCoordinate = _config.HintSettings.YPosition,
                        Alignment = HintAlignment.Center,
                        SyncSpeed = HintSyncSpeed.Fast,
                        Hide = false,
                        Text = string.Empty,
                    };
                    PlayerDisplay.Get(player).AddHint(hint);
                    _hints[player] = hint;
                }

                hint.Text = text;
            }
            catch (Exception ex)
            {
                if (_config.Debug)
                    Log.Debug($"ShowProgress error: {ex}");
            }
        }
    }
}
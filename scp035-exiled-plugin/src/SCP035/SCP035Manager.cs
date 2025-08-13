using System;
using System.Collections.Generic;
using System.Linq;
using Exiled.API.Enums;
using Exiled.API.Features;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server; // RoundStartedEventArgs, RoundEndedEventArgs
using MEC;
using PlayerRoles;
using UnityEngine;
using InventorySystem.Items.Pickups;
using ItemType = InventorySystem.Items.ItemType;

namespace SCP035
{
    internal sealed class SCP035Manager
    {
        private readonly HashSet<int> _maskSerials = new();
        private readonly HashSet<int> _active035PlayerIds = new();
        private CoroutineHandle _hintCoroutine;
        private readonly System.Random _random = new();

        private Plugin _plugin => Plugin.Instance;
        private Config Cfg => _plugin.Config;

        public void OnWaitingForPlayers()
        {
            _maskSerials.Clear();
            _active035PlayerIds.Clear();
        }

        public void OnRoundStarted(RoundStartedEventArgs _)
        {
            if (Cfg.EnableMaskPickupTransformation)
                MarkRandomMasks();

            if (Cfg.EnableDirectAssignment && _random.NextDouble() < Cfg.DirectAssignmentChance)
            {
                TryDirectAssignment();
            }

            StartHintLoop();
        }

        public void OnRoundEnded(RoundEndedEventArgs _)
        {
            StopHintLoop();
            _maskSerials.Clear();
            _active035PlayerIds.Clear();
        }

        public void OnPickingUpItem(PickingUpItemEventArgs ev)
        {
            if (!_plugin.IsEnabled || ev.Player == null || ev.Pickup == null)
                return;

            try
            {
                int serial = ev.Pickup.Base?.Info.Serial ?? -1;
                if (serial != -1 && _maskSerials.Contains(serial))
                {
                    TransformTo035(ev.Player);
                    // Remove mask mark; single-use
                    _maskSerials.Remove(serial);
                }
            }
            catch (Exception ex)
            {
                Log.Error($"[SCP-035] Error in OnPickingUpItem: {ex}");
            }
        }

        public void OnDying(DyingEventArgs ev)
        {
            if (ev.Player == null)
                return;

            if (Is035(ev.Player))
            {
                _active035PlayerIds.Remove(ev.Player.Id);

                if (Cfg.DropMaskOnDeath)
                {
                    try
                    {
                        var pos = ev.Player.Position + Vector3.up * 0.2f;
                        Map.SpawnItem(Cfg.DroppedMaskItemType, pos);
                    }
                    catch (Exception ex)
                    {
                        Log.Error($"[SCP-035] Failed to drop mask on death: {ex}");
                    }
                }
            }
        }

        public void OnChangingRole(ChangingRoleEventArgs ev)
        {
            if (ev.Player == null)
                return;

            if (Is035(ev.Player))
            {
                _active035PlayerIds.Remove(ev.Player.Id);
                if (Cfg.ClearCustomInfoOnRoleChange)
                {
                    try
                    {
                        ev.Player.CustomInfo = string.Empty;
                    }
                    catch
                    {
                        // ignore
                    }
                }
            }
        }

        public void OnHurting(HurtingEventArgs ev)
        {
            if (ev.Attacker == null || ev.Target == null)
                return;

            if (!Cfg.TreatAsScpForDamageRules)
                return;

            bool attackerIs035 = Is035(ev.Attacker);
            bool targetIs035 = Is035(ev.Target);

            // Consider 035 as SCP side for FF rules
            if (attackerIs035)
            {
                // 035 attacking SCPs
                if (!Cfg.AllowDamageToScps && ev.Target.Role.Team == Team.SCPs)
                {
                    ev.IsAllowed = false;
                    return;
                }
                // 035 attacking Humans
                if (!Cfg.AllowDamageToHumans && (ev.Target.Role.Team == Team.FoundationForces || ev.Target.Role.Team == Team.ChaosInsurgency || ev.Target.Role.Team == Team.Scientists || ev.Target.Role.Team == Team.ClassD))
                {
                    ev.IsAllowed = false;
                    return;
                }
            }

            // SCPs attacking 035
            if (!Cfg.AllowDamageToScps && ev.Attacker.Role.Team == Team.SCPs && targetIs035)
            {
                ev.IsAllowed = false;
                return;
            }
        }

        private void MarkRandomMasks()
        {
            try
            {
                var allEligible = Map.Pickups.Where(p => Cfg.MaskEligibleItemTypes.Contains(p.Type)).ToList();
                if (allEligible.Count == 0)
                    return;

                int toMark = Mathf.Clamp(Cfg.MaskCount, 0, allEligible.Count);
                allEligible = allEligible.OrderBy(_ => _random.Next()).ToList();
                foreach (var pickup in allEligible.Take(toMark))
                {
                    int serial = pickup.Base?.Info.Serial ?? -1;
                    if (serial != -1)
                        _maskSerials.Add(serial);
                }

                if (Cfg.Debug)
                    Log.Info($"[SCP-035] Marked {_maskSerials.Count} item(s) as mask.");
            }
            catch (Exception ex)
            {
                Log.Error($"[SCP-035] Failed to mark masks: {ex}");
            }
        }

        private void TryDirectAssignment()
        {
            try
            {
                var candidates = Player.List.Where(p => p.IsAlive && Cfg.DirectAssignmentRoles.Contains(p.Role.Type)).ToList();
                if (candidates.Count == 0)
                    return;

                var chosen = candidates[_random.Next(candidates.Count)];
                TransformTo035(chosen);
            }
            catch (Exception ex)
            {
                Log.Error($"[SCP-035] Direct assignment failed: {ex}");
            }
        }

        private void TransformTo035(Player player)
        {
            if (player == null || !player.IsAlive)
                return;

            if (Is035(player))
                return;

            _active035PlayerIds.Add(player.Id);

            try
            {
                // Visual identity
                if (Cfg.OverrideBadgeWhile035)
                {
                    player.CustomInfo = Cfg.IdentityTag;
                }

                // Stats
                player.MaxHealth = Cfg.Scp035MaxHealth;
                player.Health = Mathf.Max(player.Health, Cfg.Scp035MaxHealth);
                player.ArtificialHealth = Cfg.Scp035ArtificialHp;

                // Small speed buff
                var intensity = Mathf.RoundToInt((Cfg.MovementSpeedMultiplier - 1f) * 100f);
                player.EnableEffect<CustomPlayerEffects.MovementBoost>(5f, intensity);

                // Notify
                HsmHintService.Show(player, Cfg.TransformHint, Cfg.TransformHintDuration, Cfg.UseHsmHints);
            }
            catch (Exception ex)
            {
                Log.Error($"[SCP-035] Failed to apply transform: {ex}");
            }
        }

        private bool Is035(Player player) => player != null && _active035PlayerIds.Contains(player.Id);

        private void StartHintLoop()
        {
            StopHintLoop();
            _hintCoroutine = Timing.RunCoroutine(HintTick(), Segment.Update);
        }

        private void StopHintLoop()
        {
            if (_hintCoroutine.IsRunning)
                Timing.KillCoroutine(_hintCoroutine);
        }

        private IEnumerator<float> HintTick()
        {
            while (Round.InProgress)
            {
                try
                {
                    if (!Cfg.UseHsmHints)
                    {
                        yield return Timing.WaitForSeconds(Cfg.ProximityHintIntervalSeconds);
                        continue;
                    }

                    var all035 = Player.List.Where(Is035).ToList();
                    if (all035.Count == 0)
                    {
                        yield return Timing.WaitForSeconds(Cfg.ProximityHintIntervalSeconds);
                        continue;
                    }

                    foreach (var scp in all035)
                    {
                        foreach (var other in Player.List)
                        {
                            if (other == scp || !other.IsAlive)
                                continue;

                            float dist = Vector3.Distance(other.Position, scp.Position);
                            if (dist <= Cfg.ProximityHintRadius)
                            {
                                HsmHintService.Show(other, Cfg.ProximityHint, Cfg.ProximityHintDuration, true);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Error($"[SCP-035] HintTick error: {ex}");
                }

                yield return Timing.WaitForSeconds(Cfg.ProximityHintIntervalSeconds);
            }
        }
    }
}
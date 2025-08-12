using System;
using System.Linq;
using Exiled.API.Features;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using PlayerRoles;
using UnityEngine;

namespace RpPlugin
{
    public class EventHandlers
    {
        private readonly RoleplayConfig _config;
        private DateTime _roundStartUtc = DateTime.MinValue;

        public EventHandlers(RoleplayConfig config)
        {
            _config = config;
        }

        public void OnRoundStarted(RoundStartedEventArgs ev)
        {
            _roundStartUtc = DateTime.UtcNow;
        }

        public void OnPlayerVerified(VerifiedEventArgs ev)
        {
            if (!_config.IsEnabled)
                return;

            if (_config.WhitelistEnabled)
            {
                string steamId = ev.Player.UserId.Split('@').FirstOrDefault() ?? ev.Player.UserId;
                if (!_config.Whitelist.Contains(steamId))
                {
                    ev.Player.Disconnect("Вы не в вайтлисте RP-сервера.");
                    return;
                }
            }

            if (RoleplayPlugin.Instance.IsRpModeEnabled && _config.UseCustomInfo)
            {
                TryApplyDisplayName(ev.Player, null);
            }
        }

        public void OnHurting(HurtingEventArgs ev)
        {
            if (!_config.IsEnabled || ev == null || ev.Player == null || ev.Attacker == null)
                return;

            if (_config.WarmupSeconds > 0)
            {
                var elapsed = DateTime.UtcNow - _roundStartUtc;
                if (elapsed.TotalSeconds < _config.WarmupSeconds)
                {
                    ev.IsAllowed = false;
                    ev.Player.ShowHint($"RP: мирный старт {Mathf.Ceil((float)(_config.WarmupSeconds - elapsed.TotalSeconds))}с", 2f);
                    return;
                }
            }

            if (!RoleplayPlugin.Instance.IsRpModeEnabled)
                return;

            if (_config.DisableCombatDuringRp)
            {
                string attackerRoleName = ev.Attacker.Role.Type.ToString();
                bool allowedByName = _config.DamageAllowedRoles.Contains(attackerRoleName);
                if (!allowedByName)
                {
                    ev.IsAllowed = false;
                    ev.Attacker.ShowHint("RP: бой отключён", 2f);
                }
            }
        }

        public void OnDying(DyingEventArgs ev)
        {
            if (!_config.IsEnabled)
                return;

            if (RoleplayPlugin.Instance.IsRpModeEnabled && _config.DisableCombatDuringRp)
            {
                Log.Info($"RP-KILL: {ev.Attacker?.Nickname} -> {ev.Player?.Nickname} ({ev.DamageHandler?.Type})");
            }
        }

        public void OnRoleChanged(ChangingRoleEventArgs ev)
        {
            if (!_config.IsEnabled)
                return;

            if (_config.ResetRpNameOnRoleChange && _config.UseCustomInfo)
            {
                TryApplyDisplayName(ev.Player, null);
            }
        }

        internal void TryApplyDisplayName(Player player, string? requestedName)
        {
            try
            {
                string display = string.IsNullOrWhiteSpace(requestedName) ? string.Empty : requestedName.Trim();
                if (!string.IsNullOrEmpty(_config.RpNamePrefix))
                    display = _config.RpNamePrefix + display;

                if (_config.UseCustomInfo)
                {
                    player.CustomInfo = display;
                    player.RefreshInfo();
                }
                else
                {
                    player.DisplayNickname = display;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Failed to set display name for {player.Nickname}: {ex}");
            }
        }

        internal static int SendProximityMessage(Player source, float radius, string message)
        {
            int count = 0;
            Vector3 pos = source.Position;
            foreach (var other in Player.List)
            {
                if (other == null || !other.IsAlive)
                    continue;
                if (Vector3.Distance(pos, other.Position) <= radius)
                {
                    other.ShowHint(message, 5f);
                    count++;
                }
            }
            return count;
        }
    }
}
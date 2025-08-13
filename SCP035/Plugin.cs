using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CommandSystem;
using Exiled.API.Enums;
using Exiled.API.Extensions;
using Exiled.API.Features;
using Exiled.API.Features.Items;
using Exiled.API.Features.Pickups;
using Exiled.API.Interfaces;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using Exiled.Permissions.Extensions;
using MEC;
using PlayerRoles;
using UnityEngine;
using Hint = HintServiceMeow.Core.Models.Hints.Hint;
using HintServiceMeow.Core.Enum;
using HintServiceMeow.Core.Utilities;

namespace SCP035
{
    public class Plugin : Plugin<Config>
    {
        public override string Name => "SCP-035";
        public override string Author => "SteamTime & GPT";
        public override Version Version => new Version(1, 0, 0);
        public string[] RequiredPermissions { get; } = new[] { "scp035.admin" };

        public static Plugin Instance;

        private readonly System.Random random = new System.Random();

        // Активные носители SCP-035
        private readonly Dictionary<Player, Scp035State> scp035Players = new Dictionary<Player, Scp035State>();

        // Активные HSM-хинты для игроков
        private readonly Dictionary<Player, Hint> activeHints = new Dictionary<Player, Hint>();

        // Заспавненные маски на карте
        public readonly List<Pickup> spawnedMasks = new List<Pickup>();

        public override void OnEnabled()
        {
            Instance = this;

            Exiled.Events.Handlers.Server.RoundStarted += OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded += OnRoundEnded;
            Exiled.Events.Handlers.Player.Destroying += OnPlayerDestroying;
            Exiled.Events.Handlers.Player.PickingUpItem += OnPickingUpItem;
            Exiled.Events.Handlers.Player.DroppingItem += OnDroppingItem;
            Exiled.Events.Handlers.Player.Died += OnPlayerDied;
            Exiled.Events.Handlers.Player.ChangingRole += OnChangingRole;

            if (Config.AutoSpawnEnabled)
                TrySpawnMasksAtRoundStart();

            Log.Info("SCP-035 загружен. Маска ждёт нового носителя...");
            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            Exiled.Events.Handlers.Server.RoundStarted -= OnRoundStarted;
            Exiled.Events.Handlers.Server.RoundEnded -= OnRoundEnded;
            Exiled.Events.Handlers.Player.Destroying -= OnPlayerDestroying;
            Exiled.Events.Handlers.Player.PickingUpItem -= OnPickingUpItem;
            Exiled.Events.Handlers.Player.DroppingItem -= OnDroppingItem;
            Exiled.Events.Handlers.Player.Died -= OnPlayerDied;
            Exiled.Events.Handlers.Player.ChangingRole -= OnChangingRole;

            foreach (var hint in activeHints.Values)
                hint.Hide = true;
            activeHints.Clear();

            CleanupMasks();
            scp035Players.Clear();
            Instance = null;
            Log.Info("SCP-035 выгружен.");
            base.OnDisabled();
        }

        private void OnRoundStarted()
        {
            scp035Players.Clear();
            CleanupMasks();
            if (Config.AutoSpawnEnabled)
                TrySpawnMasksAtRoundStart();

            if (Config.Debug)
                Log.Debug("Раунд начался. Проверка шанса и спавн маски(масок).");
        }

        private void OnRoundEnded(RoundEndedEventArgs ev)
        {
            CleanupMasks();
            foreach (var hint in activeHints.Values)
                hint.Hide = true;
            activeHints.Clear();
            scp035Players.Clear();
        }

        private void OnPlayerDestroying(DestroyingEventArgs ev)
        {
            HideHint(ev.Player);
            scp035Players.Remove(ev.Player);
        }

        private void OnChangingRole(ChangingRoleEventArgs ev)
        {
            // Если игрок меняет роль (ре-спавн и т.п.) — снимаем статус 035
            if (scp035Players.ContainsKey(ev.Player))
            {
                scp035Players.Remove(ev.Player);
                HideHint(ev.Player);
            }
        }

        private void OnPlayerDied(DiedEventArgs ev)
        {
            if (ev.Player == null)
                return;

            // Если умер носитель 035 — маска падает на землю
            if (scp035Players.ContainsKey(ev.Player))
            {
                scp035Players.Remove(ev.Player);
                HideHint(ev.Player);

                TryDropMask(ev.Player.Position);

                if (Config.Debug)
                    Log.Debug($"Носитель SCP-035 умер. Маска упала в {ev.Player.Position}.");
            }
        }

        private void OnPickingUpItem(PickingUpItemEventArgs ev)
        {
            if (ev.Pickup == null)
                return;

            // Проверяем, одна ли это из наших масок
            if (spawnedMasks.Contains(ev.Pickup) && ev.Pickup.Type == ItemType.SCP268)
            {
                // Проверка шанса стать SCP-035 при поднятии
                if (random.NextDouble() * 100f <= Config.BecomeChancePercent)
                {
                    spawnedMasks.Remove(ev.Pickup);
                    BecomeScp035(ev.Player);
                }
                else
                {
                    // Отказ — запрещаем подбирать, маска остаётся лежать
                    ev.IsAllowed = false;
                    ShowHint(ev.Player, Config.Messages.DenyPickupText, 4f);
                }
            }
        }

        private void OnDroppingItem(DroppingItemEventArgs ev)
        {
            if (!ev.IsAllowed || ev.Item == null)
                return;

            // Способность активируется попыткой выкинуть маску (SCP-268) у носителя SCP-035
            if (ev.Item.Type == ItemType.SCP268 && scp035Players.ContainsKey(ev.Player))
            {
                ev.IsAllowed = false; // Не даём выбросить, вместо этого — способность
                UseAbilityAoE(ev.Player);
            }
        }

        public void TrySpawnMasksAtRoundStart()
        {
            CleanupMasks();

            if (random.NextDouble() * 100 > Config.RoundSpawnChancePercent)
            {
                if (Config.Debug)
                    Log.Debug("Шанс спавна маски не прошёл. В этом раунде маски может не быть.");
                return;
            }

            for (int i = 0; i < Config.MasksToSpawn; i++)
            {
                Timing.CallDelayed(0.5f * i, () =>
                {
                    if (TryFindSpawnPosition(out Vector3 position))
                    {
                        var maskItem = Item.Create(ItemType.SCP268);
                        var pickup = maskItem.CreatePickup(position);
                        spawnedMasks.Add(pickup);

                        if (Config.Debug)
                            Log.Debug($"Заспавнена маска SCP-035 в {position}.");
                    }
                });
            }
        }

        private void TryDropMask(Vector3 position)
        {
            var item = Item.Create(ItemType.SCP268);
            var pickup = item.CreatePickup(position);
            spawnedMasks.Add(pickup);
        }

        private void CleanupMasks()
        {
            foreach (var m in spawnedMasks.ToList())
            {
                try
                {
                    if (m != null && m.IsSpawned)
                        m.Destroy();
                }
                catch (Exception ex)
                {
                    if (Config.Debug)
                        Log.Debug($"Ошибка удаления маски: {ex}");
                }
            }
            spawnedMasks.Clear();
        }

        private bool TryFindSpawnPosition(out Vector3 position)
        {
            position = Vector3.zero;

            foreach (var room in Room.List.OrderBy(r => random.Next()))
            {
                if (room == null)
                    continue;

                if (Config.SpawnWeights.TryGetValue(room.Zone, out float weight) && random.NextDouble() * 100 < weight)
                {
                    for (int i = 0; i < 10; i++)
                    {
                        Vector3 testPos = room.Position + new Vector3(
                            (float)(random.NextDouble() * 6 - 3),
                            1.2f,
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

        private void BecomeScp035(Player player)
        {
            if (player == null || !player.IsAlive)
                return;

            if (scp035Players.ContainsKey(player))
            {
                ShowHint(player, "<color=yellow>Вы уже являетесь носителем SCP-035.</color>", 4f);
                return;
            }

            // Выдаём носителю маску в инвентарь, если её нет
            if (!player.Items.Any(i => i.Type == ItemType.SCP268))
                player.AddItem(ItemType.SCP268);

            var state = new Scp035State
            {
                AbilityReadyTime = Time.time + Config.Ability.CooldownSeconds,
            };
            scp035Players[player] = state;

            if (Config.AnnounceOnPickup)
            {
                Map.Broadcast(6, Config.Messages.AnnouncePickupText);
            }

            ShowHint(player,
                $"<color=#ba55d3>Вы надели Маску SCP-035.</color>\n" +
                $"<color=#d8bfd8>Активируйте способность: попытайтесь выкинуть маску (G) — сработает АОЕ-атака.</color>\n" +
                $"<color=#87cefa>Радиус: {Config.Ability.Radius}м | Урон: {Config.Ability.MinDamage}-{Config.Ability.MaxDamage} | КД: {Config.Ability.CooldownSeconds}с</color>", 8f);
        }

        private void UseAbilityAoE(Player user)
        {
            if (!scp035Players.TryGetValue(user, out var state))
                return;

            float now = Time.time;
            if (now < state.AbilityReadyTime)
            {
                float left = state.AbilityReadyTime - now;
                ShowHint(user, $"<color=yellow>Способность на перезарядке: {left:0.0}с</color>", 2.5f);
                return;
            }

            int affected = 0;
            foreach (var target in Player.List.ToList())
            {
                if (target == null || !target.IsAlive || target == user)
                    continue;

                if (!Config.Ability.CanAffectScps && target.IsScp)
                    continue;

                // Проверяем дистанцию
                if (Vector3.Distance(user.Position, target.Position) > Config.Ability.Radius)
                    continue;

                // Простая проверка LOS — рейкаст вниз сверху над целью, чтобы реже бить сквозь стены
                // (упрощённо, чтобы избежать дорогого Raycast между игроками)
                var head = target.Position + Vector3.up * 1.2f;
                if (Physics.Raycast(head + Vector3.up * 0.2f, Vector3.down, out RaycastHit hit, 2f))
                {
                    // Шанс на успех по цели (можно настроить в конфиге)
                    if (random.NextDouble() * 100 <= Config.Ability.SuccessPercent)
                    {
                        int damage = random.Next(Config.Ability.MinDamage, Config.Ability.MaxDamage + 1);
                        target.Hurt(damage, "SCP-035: Токсичный психоз");
                        ShowHint(target, Config.Messages.VictimHitText.Replace("{damage}", damage.ToString()), 3.5f);
                        affected++;
                    }
                }
            }

            if (affected > 0)
            {
                ShowHint(user, Config.Messages.AbilityUsedText.Replace("{count}", affected.ToString()), 3.5f);
            }
            else
            {
                ShowHint(user, "<color=#aaa>Никого не задело...</color>", 2.5f);
            }

            state.AbilityReadyTime = Time.time + Config.Ability.CooldownSeconds;
            scp035Players[user] = state;
        }

        private void ShowHint(Player player, string message, float duration)
        {
            try
            {
                if (!activeHints.TryGetValue(player, out var hint))
                {
                    hint = new Hint
                    {
                        FontSize = Config.Hint.TextSize,
                        XCoordinate = Config.Hint.XPosition,
                        YCoordinate = Config.Hint.YPosition,
                        Alignment = HintAlignment.Center,
                        SyncSpeed = HintSyncSpeed.Fast,
                        Hide = false
                    };
                    PlayerDisplay.Get(player).AddHint(hint);
                    activeHints[player] = hint;
                }

                hint.Text = message;
                Timing.CallDelayed(duration, () =>
                {
                    if (activeHints.TryGetValue(player, out var h) && h.Text == message)
                    {
                        h.Hide = true;
                        activeHints.Remove(player);
                    }
                });
            }
            catch (Exception ex)
            {
                Log.Error($"Не удалось показать подсказку: {ex}");
            }
        }

        private void HideHint(Player player)
        {
            if (activeHints.TryGetValue(player, out var hint))
            {
                hint.Hide = true;
                activeHints.Remove(player);
            }
        }

        // Состояние SCP-035 на игроке
        private struct Scp035State
        {
            public float AbilityReadyTime;
        }
    }
}
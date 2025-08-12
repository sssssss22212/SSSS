using System;
using System.Collections.Generic;
using System.Linq;
using Exiled.API.Features;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using PlayerRoles;
using MEC;

namespace PlayerManagerPlugin
{
    /// <summary>
    /// Обработчики событий плагина
    /// </summary>
    public class EventHandlers
    {
        /// <summary>
        /// Словарь для хранения очков игроков
        /// </summary>
        private readonly Dictionary<string, int> _playerPoints = new Dictionary<string, int>();

        /// <summary>
        /// Словарь для отслеживания времени последней активности игроков (для AFK системы)
        /// </summary>
        private readonly Dictionary<string, DateTime> _lastActivity = new Dictionary<string, DateTime>();

        /// <summary>
        /// Корутина для проверки AFK игроков
        /// </summary>
        private CoroutineHandle _afkCheckCoroutine;

        /// <summary>
        /// Конструктор
        /// </summary>
        public EventHandlers()
        {
            // Запускаем корутину проверки AFK
            if (PlayerManagerPlugin.Instance.Config.EnableAfkKick)
            {
                _afkCheckCoroutine = Timing.RunCoroutine(CheckAfkPlayers());
            }
        }

        /// <summary>
        /// Обработчик подключения игрока
        /// </summary>
        public void OnPlayerVerified(VerifiedEventArgs ev)
        {
            try
            {
                Log.Debug($"Игрок {ev.Player.Nickname} подключился к серверу");

                // Показываем приветственное сообщение
                if (!string.IsNullOrEmpty(PlayerManagerPlugin.Instance.Config.WelcomeMessage))
                {
                    ev.Player.ShowHint(PlayerManagerPlugin.Instance.Config.WelcomeMessage, 
                        PlayerManagerPlugin.Instance.Config.WelcomeMessageDuration);
                }

                // Инициализируем очки игрока
                if (PlayerManagerPlugin.Instance.Config.EnablePointSystem)
                {
                    _playerPoints[ev.Player.UserId] = 0;
                }

                // Отмечаем время подключения для AFK системы
                if (PlayerManagerPlugin.Instance.Config.EnableAfkKick)
                {
                    _lastActivity[ev.Player.UserId] = DateTime.Now;
                }

                Log.Info($"Игрок {ev.Player.Nickname} ({ev.Player.UserId}) успешно подключился");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в OnPlayerVerified: {ex}");
            }
        }

        /// <summary>
        /// Обработчик отключения игрока
        /// </summary>
        public void OnPlayerLeft(LeftEventArgs ev)
        {
            try
            {
                Log.Debug($"Игрок {ev.Player.Nickname} покинул сервер");

                // Удаляем данные игрока
                _playerPoints.Remove(ev.Player.UserId);
                _lastActivity.Remove(ev.Player.UserId);

                Log.Info($"Игрок {ev.Player.Nickname} ({ev.Player.UserId}) покинул сервер");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в OnPlayerLeft: {ex}");
            }
        }

        /// <summary>
        /// Обработчик смерти игрока
        /// </summary>
        public void OnPlayerDying(DyingEventArgs ev)
        {
            try
            {
                if (ev.Attacker != null && ev.Attacker != ev.Player)
                {
                    Log.Debug($"Игрок {ev.Player.Nickname} был убит игроком {ev.Attacker.Nickname}");

                    // Показываем сообщение о смерти
                    if (PlayerManagerPlugin.Instance.Config.ShowDeathMessage)
                    {
                        string deathMessage = PlayerManagerPlugin.Instance.Config.DeathMessageFormat
                            .Replace("{player}", ev.Player.Nickname)
                            .Replace("{killer}", ev.Attacker.Nickname)
                            .Replace("{reason}", ev.DamageHandler.Type.ToString());

                        foreach (Player player in Player.List)
                        {
                            player.ShowHint(deathMessage, 3);
                        }
                    }

                    // Начисляем очки убийце
                    if (PlayerManagerPlugin.Instance.Config.EnablePointSystem)
                    {
                        int points = 0;
                        if (ev.Player.Role.Team == Team.SCPs)
                        {
                            points = PlayerManagerPlugin.Instance.Config.PointsForScpKill;
                        }
                        else
                        {
                            points = PlayerManagerPlugin.Instance.Config.PointsForPlayerKill;
                        }

                        AddPoints(ev.Attacker.UserId, points);
                        ev.Attacker.ShowHint($"<color=green>+{points} очков!</color>", 2);
                    }
                }

                // Обновляем активность
                if (PlayerManagerPlugin.Instance.Config.EnableAfkKick)
                {
                    _lastActivity[ev.Player.UserId] = DateTime.Now;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в OnPlayerDying: {ex}");
            }
        }

        /// <summary>
        /// Обработчик спавна игрока
        /// </summary>
        public void OnPlayerSpawning(SpawningEventArgs ev)
        {
            try
            {
                Log.Debug($"Игрок {ev.Player.Nickname} возрождается как {ev.Role}");

                // Автолечение при спавне
                if (PlayerManagerPlugin.Instance.Config.AutoHealOnSpawn)
                {
                    Timing.CallDelayed(1f, () =>
                    {
                        if (ev.Player != null && ev.Player.IsAlive)
                        {
                            ev.Player.Health = PlayerManagerPlugin.Instance.Config.AutoHealAmount;
                        }
                    });
                }

                // Выдача стартовых предметов
                string roleName = ev.Role.ToString();
                if (PlayerManagerPlugin.Instance.Config.RoleStartingItems.ContainsKey(roleName))
                {
                    Timing.CallDelayed(2f, () =>
                    {
                        if (ev.Player != null && ev.Player.IsAlive)
                        {
                            foreach (string itemName in PlayerManagerPlugin.Instance.Config.RoleStartingItems[roleName])
                            {
                                if (Enum.TryParse<ItemType>(itemName, out ItemType itemType))
                                {
                                    ev.Player.AddItem(itemType);
                                }
                            }
                        }
                    });
                }

                // Обновляем активность
                if (PlayerManagerPlugin.Instance.Config.EnableAfkKick)
                {
                    _lastActivity[ev.Player.UserId] = DateTime.Now;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в OnPlayerSpawning: {ex}");
            }
        }

        /// <summary>
        /// Обработчик начала раунда
        /// </summary>
        public void OnRoundStarted()
        {
            try
            {
                Log.Info("Раунд начался!");
                
                // Очищаем очки всех игроков
                if (PlayerManagerPlugin.Instance.Config.EnablePointSystem)
                {
                    _playerPoints.Clear();
                }

                // Сбрасываем активность всех игроков
                if (PlayerManagerPlugin.Instance.Config.EnableAfkKick)
                {
                    _lastActivity.Clear();
                    foreach (Player player in Player.List)
                    {
                        _lastActivity[player.UserId] = DateTime.Now;
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в OnRoundStarted: {ex}");
            }
        }

        /// <summary>
        /// Обработчик окончания раунда
        /// </summary>
        public void OnRoundEnded(RoundEndedEventArgs ev)
        {
            try
            {
                Log.Info($"Раунд закончился! Победившая команда: {ev.LeadingTeam}");

                // Показываем топ игроков по очкам
                if (PlayerManagerPlugin.Instance.Config.EnablePointSystem && _playerPoints.Count > 0)
                {
                    var topPlayers = _playerPoints.OrderByDescending(x => x.Value).Take(3).ToList();
                    string topMessage = "<color=yellow>Топ игроков по очкам:</color>\n";
                    
                    for (int i = 0; i < topPlayers.Count; i++)
                    {
                        Player player = Player.List.FirstOrDefault(p => p.UserId == topPlayers[i].Key);
                        if (player != null)
                        {
                            topMessage += $"{i + 1}. {player.Nickname}: {topPlayers[i].Value} очков\n";
                        }
                    }

                    foreach (Player player in Player.List)
                    {
                        player.ShowHint(topMessage, 10);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в OnRoundEnded: {ex}");
            }
        }

        /// <summary>
        /// Добавляет очки игроку
        /// </summary>
        private void AddPoints(string userId, int points)
        {
            if (_playerPoints.ContainsKey(userId))
            {
                _playerPoints[userId] += points;
            }
            else
            {
                _playerPoints[userId] = points;
            }
        }

        /// <summary>
        /// Корутина для проверки AFK игроков
        /// </summary>
        private IEnumerator<float> CheckAfkPlayers()
        {
            while (true)
            {
                yield return Timing.WaitForSeconds(30f); // Проверяем каждые 30 секунд

                try
                {
                    if (!PlayerManagerPlugin.Instance.Config.EnableAfkKick)
                        continue;

                    foreach (Player player in Player.List.ToList())
                    {
                        if (player == null || !player.IsConnected)
                            continue;

                        if (_lastActivity.ContainsKey(player.UserId))
                        {
                            TimeSpan timeSinceLastActivity = DateTime.Now - _lastActivity[player.UserId];
                            
                            if (timeSinceLastActivity.TotalSeconds > PlayerManagerPlugin.Instance.Config.AfkKickTime)
                            {
                                Log.Info($"Кикаем игрока {player.Nickname} за AFK ({timeSinceLastActivity.TotalSeconds} секунд)");
                                player.Kick(PlayerManagerPlugin.Instance.Config.AfkKickMessage);
                            }
                            else if (timeSinceLastActivity.TotalSeconds > PlayerManagerPlugin.Instance.Config.AfkKickTime - 60)
                            {
                                // Предупреждение за минуту до кика
                                int remainingSeconds = PlayerManagerPlugin.Instance.Config.AfkKickTime - (int)timeSinceLastActivity.TotalSeconds;
                                player.ShowHint($"<color=red>Внимание! Вы будете кикнуты за AFK через {remainingSeconds} секунд!</color>", 5);
                            }
                        }
                        else
                        {
                            _lastActivity[player.UserId] = DateTime.Now;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Error($"Ошибка в CheckAfkPlayers: {ex}");
                }
            }
        }

        /// <summary>
        /// Очистка ресурсов
        /// </summary>
        public void Dispose()
        {
            if (_afkCheckCoroutine.IsRunning)
            {
                Timing.KillCoroutines(_afkCheckCoroutine);
            }
        }
    }
}
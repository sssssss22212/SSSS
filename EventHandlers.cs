using Exiled.API.Features;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using System;
using System.Linq;

namespace SCPRoleplayPlugin
{
    /// <summary>
    /// Обработчики событий для RP плагина
    /// </summary>
    public class EventHandlers
    {
        public EventHandlers()
        {
            Log.Debug("Обработчики событий инициализированы");
        }

        /// <summary>
        /// Обработчик входа игрока на сервер
        /// </summary>
        public void OnPlayerJoined(JoinedEventArgs ev)
        {
            try
            {
                var player = ev.Player;
                
                Log.Info($"Игрок {player.Nickname} ({player.UserId}) подключился к серверу");

                // Отправляем приветственное сообщение
                player.SendConsoleMessage("\n=== ДОБРО ПОЖАЛОВАТЬ НА РОЛЕВОЙ СЕРВЕР SCP:SL ===", "green");
                player.SendConsoleMessage("Этот сервер использует расширенную ролевую систему.", "white");
                player.SendConsoleMessage("Доступные команды:", "yellow");
                player.SendConsoleMessage("!help - помощь по командам", "white");
                player.SendConsoleMessage("!role - управление ролями", "white");
                player.SendConsoleMessage("!money - система денег", "white");
                player.SendConsoleMessage("/me [действие] - описание действий", "white");
                player.SendConsoleMessage("/do [описание] - описание окружения", "white");
                player.SendConsoleMessage("((текст)) или [OOC] - чат вне роли", "white");
                player.SendConsoleMessage("========================================\n", "green");

                // Автоматическое назначение ролей, если включено
                if (Plugin.PluginConfig.AutoAssignRoles)
                {
                    AssignDefaultRole(player);
                }

                // Создаем банковский аккаунт, если включена система денег
                if (Plugin.PluginConfig.EnableMoneySystem && Plugin.Instance.MoneySystem != null)
                {
                    Plugin.Instance.MoneySystem.GetBalance(player); // Это создаст аккаунт автоматически
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке входа игрока: {ex}");
            }
        }

        /// <summary>
        /// Обработчик выхода игрока с сервера
        /// </summary>
        public void OnPlayerLeft(LeftEventArgs ev)
        {
            try
            {
                var player = ev.Player;
                Log.Info($"Игрок {player.Nickname} покинул сервер");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке выхода игрока: {ex}");
            }
        }

        /// <summary>
        /// Обработчик спавна игрока
        /// </summary>
        public void OnPlayerSpawning(SpawningEventArgs ev)
        {
            try
            {
                var player = ev.Player;
                
                // Показываем информацию о роли
                var roles = Plugin.Instance.RoleSystem?.GetPlayerRoles(player);
                if (roles?.Any() == true)
                {
                    var role = roles.First();
                    player.ShowHint($"Ваша роль: {role.Template.Name}\n{role.Template.Description}", 8);
                }
                else
                {
                    player.ShowHint("У вас нет назначенной RP роли\nИспользуйте !role для получения роли", 6);
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке спавна игрока: {ex}");
            }
        }

        /// <summary>
        /// Обработчик смерти игрока
        /// </summary>
        public void OnPlayerDying(DyingEventArgs ev)
        {
            try
            {
                var player = ev.Player;
                var attacker = ev.Attacker;

                Log.Info($"Игрок {player.Nickname} погиб");

                // Добавляем случайные травмы при смерти для медицинской системы
                if (Plugin.PluginConfig.EnableMedicalSystem && Plugin.Instance.MedicalSystem != null)
                {
                    var injuryTypes = Enum.GetValues<InjuryType>();
                    var randomType = injuryTypes[UnityEngine.Random.Range(0, injuryTypes.Length)];
                    var severity = UnityEngine.Random.Range(0, 100) < 30 ? InjurySeverity.Critical : InjurySeverity.Serious;
                    
                    Plugin.Instance.MedicalSystem.AddInjury(player, randomType, severity, "Полученная при смерти");
                }

                // Снимаем деньги за смерть (штраф)
                if (Plugin.PluginConfig.EnableMoneySystem && Plugin.Instance.MoneySystem != null)
                {
                    var penalty = 100;
                    Plugin.Instance.MoneySystem.RemoveMoney(player, penalty, "Штраф за смерть");
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке смерти игрока: {ex}");
            }
        }

        /// <summary>
        /// Обработчик сообщений в чате
        /// </summary>
        public void OnSendingMessage(SendingMessageEventArgs ev)
        {
            try
            {
                if (Plugin.PluginConfig.EnableRpChannels && Plugin.Instance.ChatSystem != null)
                {
                    Plugin.Instance.ChatSystem.ProcessMessage(ev);
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке сообщения: {ex}");
            }
        }

        /// <summary>
        /// Обработчик использования интеркома
        /// </summary>
        public void OnIntercomSpeaking(IntercomSpeakingEventArgs ev)
        {
            try
            {
                var player = ev.Player;
                
                // Проверяем права на использование интеркома
                if (Plugin.Instance.RoleSystem != null)
                {
                    var hasPermission = Plugin.Instance.RoleSystem.HasPermission(player, "use_intercom") ||
                                      player.GroupName == "admin" ||
                                      player.GroupName == "moderator";

                    if (!hasPermission)
                    {
                        ev.IsAllowed = false;
                        player.ShowHint("У вас нет прав для использования интеркома!", 5);
                        return;
                    }
                }

                var roles = Plugin.Instance.RoleSystem?.GetPlayerRoles(player);
                var roleName = roles?.FirstOrDefault()?.Template?.Name ?? "Неизвестный";

                // Логируем использование интеркома
                Log.Info($"[ИНТЕРКОМ] [{roleName}] {player.Nickname} использует интерком");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке интеркома: {ex}");
            }
        }

        /// <summary>
        /// Обработчик начала раунда
        /// </summary>
        public void OnRoundStarted()
        {
            try
            {
                Log.Info("Раунд начался - инициализация RP систем");

                // Уведомляем всех игроков о начале раунда
                foreach (var player in Player.List)
                {
                    if (player?.IsAlive == true)
                    {
                        player.ShowHint("<color=green>Раунд начался!</color>\nУдачной игры в роли!", 5);

                        // Награждаем за участие в раунде
                        if (Plugin.PluginConfig.EnableMoneySystem && Plugin.Instance.MoneySystem != null)
                        {
                            Plugin.Instance.MoneySystem.AddMoney(player, 50, "Участие в раунде");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке начала раунда: {ex}");
            }
        }

        /// <summary>
        /// Обработчик окончания раунда
        /// </summary>
        public void OnRoundEnded(RoundEndedEventArgs ev)
        {
            try
            {
                Log.Info($"Раунд окончен - команда победитель: {ev.LeadingTeam}");

                // Награждаем выживших игроков
                if (Plugin.PluginConfig.EnableMoneySystem && Plugin.Instance.MoneySystem != null)
                {
                    foreach (var player in Player.List)
                    {
                        if (player?.IsAlive == true)
                        {
                            var reward = 200;
                            Plugin.Instance.MoneySystem.AddMoney(player, reward, "Награда за выживание");
                            player.ShowHint($"<color=green>Награда за выживание: +{reward}₽</color>", 5);
                        }
                    }
                }

                // Очищаем временные данные раунда
                ClearRoundData();
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке окончания раунда: {ex}");
            }
        }

        /// <summary>
        /// Назначить стандартную роль новому игроку
        /// </summary>
        private void AssignDefaultRole(Player player)
        {
            try
            {
                var availableRoles = Plugin.Instance.RoleSystem?.GetAvailableRoles();
                if (availableRoles?.Any() != true)
                    return;

                // Назначаем базовую роль в зависимости от игровой роли
                string defaultRoleId = player.Role.Type switch
                {
                    RoleTypeId.Scientist => "scientist_researcher",
                    RoleTypeId.FacilityGuard => "guard_cadet",
                    RoleTypeId.ClassD => "dclass_prisoner",
                    RoleTypeId.NtfCaptain or RoleTypeId.NtfSergeant or RoleTypeId.NtfSpecialist or RoleTypeId.NtfPrivate => "mtf_operative",
                    RoleTypeId.ChaosConscript or RoleTypeId.ChaosMarauder or RoleTypeId.ChaosRepressor or RoleTypeId.ChaosRifleman => "ci_operative",
                    _ => "dclass_prisoner"
                };

                Plugin.Instance.RoleSystem?.AssignRole(player, defaultRoleId);
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при назначении стандартной роли: {ex}");
            }
        }

        /// <summary>
        /// Очистить данные раунда
        /// </summary>
        private void ClearRoundData()
        {
            try
            {
                // Здесь можно очистить временные данные, которые не должны сохраняться между раундами
                Log.Debug("Данные раунда очищены");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при очистке данных раунда: {ex}");
            }
        }

        /// <summary>
        /// Очистка обработчиков событий
        /// </summary>
        public void Cleanup()
        {
            Log.Debug("Обработчики событий очищены");
        }
    }
}
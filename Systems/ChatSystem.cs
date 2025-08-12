using Exiled.API.Features;
using Exiled.Events.EventArgs.Player;
using System;
using System.Linq;
using UnityEngine;

namespace SCPRoleplayPlugin
{
    /// <summary>
    /// Система управления чатом на RP сервере
    /// </summary>
    public class ChatSystem
    {
        public ChatSystem()
        {
            Log.Debug("Система чата инициализирована");
        }

        /// <summary>
        /// Обработать сообщение игрока
        /// </summary>
        public bool ProcessMessage(SendingMessageEventArgs ev)
        {
            try
            {
                var player = ev.Player;
                var message = ev.Message;

                // Проверяем префиксы для разных типов чата
                if (message.StartsWith(Plugin.PluginConfig.OocPrefix) || message.StartsWith("((") || message.StartsWith("//"))
                {
                    HandleOocMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
                else if (message.StartsWith("/me "))
                {
                    HandleMeMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
                else if (message.StartsWith("/do "))
                {
                    HandleDoMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
                else if (message.StartsWith("/local ") || message.StartsWith("/l "))
                {
                    HandleLocalMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
                else if (message.StartsWith("/radio ") || message.StartsWith("/r "))
                {
                    HandleRadioMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
                else if (message.StartsWith("/whisper ") || message.StartsWith("/w "))
                {
                    HandleWhisperMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
                else if (message.StartsWith("/shout ") || message.StartsWith("/s "))
                {
                    HandleShoutMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
                else
                {
                    // Обычное IC сообщение
                    HandleIcMessage(player, message);
                    ev.IsAllowed = false;
                    return true;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при обработке сообщения: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Обработать OOC сообщение (вне роли)
        /// </summary>
        private void HandleOocMessage(Player player, string message)
        {
            // Удаляем префикс
            message = message.Replace(Plugin.PluginConfig.OocPrefix, "")
                            .Replace("((", "").Replace("))", "")
                            .Replace("//", "").Trim();

            if (string.IsNullOrEmpty(message))
                return;

            var formattedMessage = $"<color=yellow>{Plugin.PluginConfig.OocPrefix}</color> <color=cyan>{player.Nickname}</color>: {message}";
            
            // Отправляем всем игрокам
            foreach (var p in Player.List)
            {
                p.SendConsoleMessage(formattedMessage, "white");
            }

            Log.Info($"[OOC] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Обработать IC сообщение (в роли)
        /// </summary>
        private void HandleIcMessage(Player player, string message)
        {
            if (string.IsNullOrEmpty(message))
                return;

            var roles = Plugin.Instance.RoleSystem?.GetPlayerRoles(player);
            var roleName = roles?.FirstOrDefault()?.Template?.Name ?? "Гражданский";

            var formattedMessage = $"<color=white>{Plugin.PluginConfig.IcPrefix}</color> <color=green>[{roleName}] {player.Nickname}</color>: {message}";
            
            // Отправляем игрокам в радиусе
            SendToNearbyPlayers(player, formattedMessage, Plugin.PluginConfig.LocalChatRadius);

            Log.Info($"[IC] [{roleName}] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Обработать /me сообщение (действие)
        /// </summary>
        private void HandleMeMessage(Player player, string message)
        {
            message = message.Substring(4).Trim(); // Убираем "/me "
            
            if (string.IsNullOrEmpty(message))
                return;

            var formattedMessage = $"<color=magenta>* {player.Nickname} {message}</color>";
            
            SendToNearbyPlayers(player, formattedMessage, Plugin.PluginConfig.LocalChatRadius);
            
            Log.Info($"[ME] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Обработать /do сообщение (описание окружения)
        /// </summary>
        private void HandleDoMessage(Player player, string message)
        {
            message = message.Substring(4).Trim(); // Убираем "/do "
            
            if (string.IsNullOrEmpty(message))
                return;

            var formattedMessage = $"<color=orange>* {message} (( {player.Nickname} ))</color>";
            
            SendToNearbyPlayers(player, formattedMessage, Plugin.PluginConfig.LocalChatRadius);
            
            Log.Info($"[DO] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Обработать локальное сообщение
        /// </summary>
        private void HandleLocalMessage(Player player, string message)
        {
            message = message.StartsWith("/local ") ? message.Substring(7).Trim() : message.Substring(3).Trim();
            
            if (string.IsNullOrEmpty(message))
                return;

            var formattedMessage = $"<color=lightblue>[ЛОКАЛЬНО] {player.Nickname}</color>: {message}";
            
            SendToNearbyPlayers(player, formattedMessage, Plugin.PluginConfig.LocalChatRadius * 0.5f);
            
            Log.Info($"[LOCAL] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Обработать радио сообщение
        /// </summary>
        private void HandleRadioMessage(Player player, string message)
        {
            message = message.StartsWith("/radio ") ? message.Substring(7).Trim() : message.Substring(3).Trim();
            
            if (string.IsNullOrEmpty(message))
                return;

            // Проверяем, есть ли у игрока радио
            if (!HasRadio(player))
            {
                player.ShowHint("У вас нет рации!", 3);
                return;
            }

            var formattedMessage = $"<color=lime>[РАДИО] {player.Nickname}</color>: {message}";
            
            // Отправляем игрокам с радио в той же команде/фракции
            SendToRadioUsers(player, formattedMessage);
            
            Log.Info($"[RADIO] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Обработать шепот
        /// </summary>
        private void HandleWhisperMessage(Player player, string message)
        {
            message = message.StartsWith("/whisper ") ? message.Substring(9).Trim() : message.Substring(3).Trim();
            
            if (string.IsNullOrEmpty(message))
                return;

            var formattedMessage = $"<color=gray>[ШЕПОТ] {player.Nickname}</color>: {message}";
            
            SendToNearbyPlayers(player, formattedMessage, Plugin.PluginConfig.LocalChatRadius * 0.3f);
            
            Log.Info($"[WHISPER] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Обработать крик
        /// </summary>
        private void HandleShoutMessage(Player player, string message)
        {
            message = message.StartsWith("/shout ") ? message.Substring(7).Trim() : message.Substring(3).Trim();
            
            if (string.IsNullOrEmpty(message))
                return;

            var formattedMessage = $"<color=red>[КРИК] {player.Nickname.ToUpper()}</color>: <b>{message.ToUpper()}</b>";
            
            SendToNearbyPlayers(player, formattedMessage, Plugin.PluginConfig.LocalChatRadius * 2f);
            
            Log.Info($"[SHOUT] {player.Nickname}: {message}");
        }

        /// <summary>
        /// Отправить сообщение игрокам в радиусе
        /// </summary>
        private void SendToNearbyPlayers(Player sender, string message, float radius)
        {
            var senderPosition = sender.Position;
            
            foreach (var player in Player.List)
            {
                if (player == sender || Vector3.Distance(player.Position, senderPosition) <= radius)
                {
                    player.SendConsoleMessage(message, "white");
                }
            }
        }

        /// <summary>
        /// Отправить радио сообщение
        /// </summary>
        private void SendToRadioUsers(Player sender, string message)
        {
            foreach (var player in Player.List)
            {
                // Проверяем, может ли игрок получать радио сообщения
                if (CanReceiveRadio(player, sender))
                {
                    player.SendConsoleMessage(message, "white");
                }
            }
        }

        /// <summary>
        /// Проверить, есть ли у игрока радио
        /// </summary>
        private bool HasRadio(Player player)
        {
            // Проверяем инвентарь на наличие радио
            return player.Items.Any(item => item.Type == ItemType.Radio);
        }

        /// <summary>
        /// Проверить, может ли игрок получать радио сообщения
        /// </summary>
        private bool CanReceiveRadio(Player receiver, Player sender)
        {
            // Если у получателя нет радио, он не может слышать
            if (!HasRadio(receiver))
                return false;

            // Если это тот же игрок
            if (receiver == sender)
                return true;

            // Проверяем принадлежность к одной команде/фракции
            if (receiver.Role.Team == sender.Role.Team)
                return true;

            // Дополнительные проверки для RP ролей
            var receiverRoles = Plugin.Instance.RoleSystem?.GetPlayerRoles(receiver);
            var senderRoles = Plugin.Instance.RoleSystem?.GetPlayerRoles(sender);

            if (receiverRoles?.Any() == true && senderRoles?.Any() == true)
            {
                var receiverRole = receiverRoles.First().Template;
                var senderRole = senderRoles.First().Template;

                // Проверяем совместимые роли для радиосвязи
                return AreRadioCompatible(receiverRole, senderRole);
            }

            return false;
        }

        /// <summary>
        /// Проверить совместимость ролей для радиосвязи
        /// </summary>
        private bool AreRadioCompatible(RoleTemplate role1, RoleTemplate role2)
        {
            // Охрана может связываться с охраной и администрацией
            if ((role1.Id.Contains("guard") || role1.Id.Contains("mtf")) && 
                (role2.Id.Contains("guard") || role2.Id.Contains("mtf") || role2.Id.Contains("admin")))
                return true;

            // Научный персонал может связываться с научным персоналом и администрацией
            if (role1.Id.Contains("scientist") && 
                (role2.Id.Contains("scientist") || role2.Id.Contains("admin")))
                return true;

            // ХИ может связываться только с ХИ
            if (role1.Id.Contains("ci") && role2.Id.Contains("ci"))
                return true;

            // Администраторы могут связываться со всеми
            if (role1.Id.Contains("admin") || role2.Id.Contains("admin"))
                return true;

            return false;
        }

        /// <summary>
        /// Очистка системы
        /// </summary>
        public void Cleanup()
        {
            Log.Debug("Система чата очищена");
        }
    }
}
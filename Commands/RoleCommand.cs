using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using System;
using System.Linq;

namespace SCPRoleplayPlugin.Commands
{
    /// <summary>
    /// Команда для управления ролями
    /// </summary>
    [CommandHandler(typeof(ClientCommandHandler))]
    public class RoleCommand : ICommand
    {
        public string Command => "role";
        public string[] Aliases => new[] { "r", "роль" };
        public string Description => "Управление ролями игроков";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            try
            {
                var player = Player.Get(sender);
                if (player == null)
                {
                    response = "Эта команда доступна только игрокам!";
                    return false;
                }

                if (arguments.Count == 0)
                {
                    response = GetRoleHelp();
                    return true;
                }

                var action = arguments.At(0).ToLower();

                switch (action)
                {
                    case "list":
                    case "список":
                        return HandleListRoles(player, out response);

                    case "info":
                    case "инфо":
                        return HandleRoleInfo(player, arguments, out response);

                    case "assign":
                    case "назначить":
                        return HandleAssignRole(player, arguments, out response);

                    case "remove":
                    case "снять":
                        return HandleRemoveRole(player, arguments, out response);

                    case "my":
                    case "мои":
                        return HandleMyRoles(player, out response);

                    default:
                        response = "Неизвестное действие! Используйте: !role для помощи";
                        return false;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в команде role: {ex}");
                response = "Произошла ошибка при выполнении команды!";
                return false;
            }
        }

        /// <summary>
        /// Получить справку по команде
        /// </summary>
        private string GetRoleHelp()
        {
            return "=== КОМАНДЫ УПРАВЛЕНИЯ РОЛЯМИ ===\n" +
                   "!role list - список всех ролей\n" +
                   "!role my - мои роли\n" +
                   "!role info <id> - информация о роли\n" +
                   "!role assign <игрок> <роль> - назначить роль (админ)\n" +
                   "!role remove <игрок> <роль> - снять роль (админ)\n" +
                   "================================";
        }

        /// <summary>
        /// Обработать список ролей
        /// </summary>
        private bool HandleListRoles(Player player, out string response)
        {
            var roles = Plugin.Instance.RoleSystem?.GetAvailableRoles();
            if (roles?.Any() != true)
            {
                response = "Доступных ролей не найдено!";
                return false;
            }

            response = "=== ДОСТУПНЫЕ РОЛИ ===\n";
            foreach (var role in roles)
            {
                response += $"{role.Id}: {role.Name}\n";
                response += $"  Описание: {role.Description}\n";
                response += $"  Группа: {role.RequiredGroup}\n\n";
            }

            return true;
        }

        /// <summary>
        /// Обработать информацию о роли
        /// </summary>
        private bool HandleRoleInfo(Player player, ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = "Использование: !role info <id_роли>";
                return false;
            }

            var roleId = arguments.At(1);
            var roles = Plugin.Instance.RoleSystem?.GetAvailableRoles();
            var role = roles?.FirstOrDefault(r => r.Id.Equals(roleId, StringComparison.OrdinalIgnoreCase));

            if (role == null)
            {
                response = $"Роль с ID '{roleId}' не найдена!";
                return false;
            }

            response = $"=== ИНФОРМАЦИЯ О РОЛИ ===\n";
            response += $"ID: {role.Id}\n";
            response += $"Название: {role.Name}\n";
            response += $"Описание: {role.Description}\n";
            response += $"Требуемая группа: {role.RequiredGroup}\n";
            response += $"Разрешения: {string.Join(", ", role.Permissions)}\n";

            return true;
        }

        /// <summary>
        /// Обработать назначение роли
        /// </summary>
        private bool HandleAssignRole(Player player, ArraySegment<string> arguments, out string response)
        {
            if (!player.CheckPermission("scp_rp.role.assign"))
            {
                response = "У вас нет прав для назначения ролей!";
                return false;
            }

            if (arguments.Count < 3)
            {
                response = "Использование: !role assign <игрок> <id_роли>";
                return false;
            }

            var targetName = arguments.At(1);
            var roleId = arguments.At(2);

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            var success = Plugin.Instance.RoleSystem?.AssignRole(target, roleId, player);
            if (success == true)
            {
                response = $"Роль '{roleId}' успешно назначена игроку {target.Nickname}!";
                return true;
            }
            else
            {
                response = $"Не удалось назначить роль '{roleId}' игроку {target.Nickname}!";
                return false;
            }
        }

        /// <summary>
        /// Обработать снятие роли
        /// </summary>
        private bool HandleRemoveRole(Player player, ArraySegment<string> arguments, out string response)
        {
            if (!player.CheckPermission("scp_rp.role.remove"))
            {
                response = "У вас нет прав для снятия ролей!";
                return false;
            }

            if (arguments.Count < 3)
            {
                response = "Использование: !role remove <игрок> <id_роли>";
                return false;
            }

            var targetName = arguments.At(1);
            var roleId = arguments.At(2);

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            var success = Plugin.Instance.RoleSystem?.RemoveRole(target, roleId, player);
            if (success == true)
            {
                response = $"Роль '{roleId}' успешно снята с игрока {target.Nickname}!";
                return true;
            }
            else
            {
                response = $"Не удалось снять роль '{roleId}' с игрока {target.Nickname}!";
                return false;
            }
        }

        /// <summary>
        /// Обработать мои роли
        /// </summary>
        private bool HandleMyRoles(Player player, out string response)
        {
            var roles = Plugin.Instance.RoleSystem?.GetPlayerRoles(player);
            if (roles?.Any() != true)
            {
                response = "У вас нет назначенных ролей!";
                return true;
            }

            response = "=== ВАШИ РОЛИ ===\n";
            foreach (var role in roles)
            {
                response += $"• {role.Template.Name}\n";
                response += $"  Описание: {role.Template.Description}\n";
                response += $"  Назначена: {role.AssignedAt:dd.MM.yyyy HH:mm}\n";
                response += $"  Кем: {role.AssignedBy}\n\n";
            }

            return true;
        }
    }
}
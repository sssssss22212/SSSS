using Exiled.API.Features;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SCPRoleplayPlugin
{
    /// <summary>
    /// Система управления ролями игроков на RP сервере
    /// </summary>
    public class RoleSystem
    {
        private Dictionary<string, PlayerRole> playerRoles = new Dictionary<string, PlayerRole>();
        private List<RoleTemplate> availableRoles = new List<RoleTemplate>();

        public RoleSystem()
        {
            InitializeDefaultRoles();
        }

        /// <summary>
        /// Инициализация стандартных ролей
        /// </summary>
        private void InitializeDefaultRoles()
        {
            // Научный персонал
            availableRoles.Add(new RoleTemplate
            {
                Id = "scientist_researcher",
                Name = "Научный сотрудник",
                Description = "Исследователь Фонда SCP",
                Permissions = new List<string> { "access_research", "use_keycard_scientist" },
                RequiredGroup = "scientist"
            });

            availableRoles.Add(new RoleTemplate
            {
                Id = "scientist_senior",
                Name = "Старший научный сотрудник",
                Description = "Опытный исследователь с расширенными правами",
                Permissions = new List<string> { "access_research", "access_containment", "use_keycard_senior" },
                RequiredGroup = "scientist"
            });

            // Охрана
            availableRoles.Add(new RoleTemplate
            {
                Id = "guard_cadet",
                Name = "Кадет охраны",
                Description = "Новичок в службе безопасности",
                Permissions = new List<string> { "access_security", "use_weapons_basic" },
                RequiredGroup = "guard"
            });

            availableRoles.Add(new RoleTemplate
            {
                Id = "guard_officer",
                Name = "Офицер охраны",
                Description = "Опытный сотрудник безопасности",
                Permissions = new List<string> { "access_security", "access_armory", "use_weapons_advanced" },
                RequiredGroup = "guard"
            });

            // D-класс персонал
            availableRoles.Add(new RoleTemplate
            {
                Id = "dclass_prisoner",
                Name = "D-класс заключенный",
                Description = "Подопытный класса D",
                Permissions = new List<string> { "access_dclass_cells" },
                RequiredGroup = "dclass"
            });

            // Административные роли
            availableRoles.Add(new RoleTemplate
            {
                Id = "administrator",
                Name = "Администратор объекта",
                Description = "Руководитель объекта с полными правами",
                Permissions = new List<string> { "access_all", "command_all", "override_security" },
                RequiredGroup = "admin"
            });

            // Особые роли
            availableRoles.Add(new RoleTemplate
            {
                Id = "ci_operative",
                Name = "Оперативник ХИ",
                Description = "Агент Хаоса Инсурженси",
                Permissions = new List<string> { "access_ci_base", "use_ci_equipment" },
                RequiredGroup = "chaos"
            });

            availableRoles.Add(new RoleTemplate
            {
                Id = "mtf_operative",
                Name = "Оперативник МОГ",
                Description = "Боец мобильной оперативной группы",
                Permissions = new List<string> { "access_mtf_base", "use_mtf_equipment", "command_squads" },
                RequiredGroup = "mtf"
            });

            Log.Debug($"Инициализировано {availableRoles.Count} ролей");
        }

        /// <summary>
        /// Назначить роль игроку
        /// </summary>
        public bool AssignRole(Player player, string roleId, Player assignedBy = null)
        {
            try
            {
                var roleTemplate = availableRoles.FirstOrDefault(r => r.Id == roleId);
                if (roleTemplate == null)
                {
                    Log.Warn($"Роль {roleId} не найдена");
                    return false;
                }

                // Проверка прав на назначение роли
                if (assignedBy != null && !CanAssignRole(assignedBy, roleTemplate))
                {
                    player.ShowHint("У вас нет прав для назначения этой роли!", 5);
                    return false;
                }

                // Проверка максимального количества ролей
                if (GetPlayerRoles(player).Count >= Plugin.PluginConfig.MaxRolesPerPlayer)
                {
                    player.ShowHint($"Максимальное количество ролей: {Plugin.PluginConfig.MaxRolesPerPlayer}", 5);
                    return false;
                }

                var playerRole = new PlayerRole
                {
                    Template = roleTemplate,
                    AssignedAt = DateTime.Now,
                    AssignedBy = assignedBy?.Nickname ?? "Система"
                };

                var key = player.UserId;
                if (!playerRoles.ContainsKey(key))
                {
                    playerRoles[key] = playerRole;
                }

                player.ShowHint($"Вам назначена роль: {roleTemplate.Name}", 7);
                Log.Info($"Игроку {player.Nickname} назначена роль {roleTemplate.Name}");

                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при назначении роли: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Снять роль с игрока
        /// </summary>
        public bool RemoveRole(Player player, string roleId, Player removedBy = null)
        {
            try
            {
                var key = player.UserId;
                if (!playerRoles.ContainsKey(key))
                    return false;

                var role = playerRoles[key];
                if (role.Template.Id != roleId)
                    return false;

                // Проверка прав на снятие роли
                if (removedBy != null && !CanRemoveRole(removedBy, role.Template))
                {
                    removedBy.ShowHint("У вас нет прав для снятия этой роли!", 5);
                    return false;
                }

                playerRoles.Remove(key);
                player.ShowHint($"С вас снята роль: {role.Template.Name}", 5);
                Log.Info($"С игрока {player.Nickname} снята роль {role.Template.Name}");

                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при снятии роли: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Получить роли игрока
        /// </summary>
        public List<PlayerRole> GetPlayerRoles(Player player)
        {
            var roles = new List<PlayerRole>();
            var key = player.UserId;

            if (playerRoles.ContainsKey(key))
            {
                roles.Add(playerRoles[key]);
            }

            return roles;
        }

        /// <summary>
        /// Получить список доступных ролей
        /// </summary>
        public List<RoleTemplate> GetAvailableRoles()
        {
            return availableRoles.ToList();
        }

        /// <summary>
        /// Проверить, может ли игрок назначать роль
        /// </summary>
        private bool CanAssignRole(Player player, RoleTemplate role)
        {
            if (player.GroupName == "admin" || player.GroupName == "owner")
                return true;

            if (Plugin.PluginConfig.AllowedRoleGroups.Contains(player.GroupName))
                return true;

            return false;
        }

        /// <summary>
        /// Проверить, может ли игрок снимать роль
        /// </summary>
        private bool CanRemoveRole(Player player, RoleTemplate role)
        {
            return CanAssignRole(player, role);
        }

        /// <summary>
        /// Проверить, имеет ли игрок определенное разрешение
        /// </summary>
        public bool HasPermission(Player player, string permission)
        {
            var roles = GetPlayerRoles(player);
            return roles.Any(role => role.Template.Permissions.Contains(permission));
        }

        /// <summary>
        /// Очистка системы
        /// </summary>
        public void Cleanup()
        {
            playerRoles.Clear();
            availableRoles.Clear();
        }
    }

    /// <summary>
    /// Шаблон роли
    /// </summary>
    public class RoleTemplate
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public List<string> Permissions { get; set; } = new List<string>();
        public string RequiredGroup { get; set; }
    }

    /// <summary>
    /// Роль игрока
    /// </summary>
    public class PlayerRole
    {
        public RoleTemplate Template { get; set; }
        public DateTime AssignedAt { get; set; }
        public string AssignedBy { get; set; }
    }
}
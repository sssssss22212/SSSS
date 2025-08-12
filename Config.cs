using Exiled.API.Interfaces;
using System.ComponentModel;

namespace SCPRoleplayPlugin
{
    /// <summary>
    /// Конфигурация плагина для ролевого сервера SCP:SL
    /// </summary>
    public class Config : IConfig
    {
        [Description("Включен ли плагин?")]
        public bool IsEnabled { get; set; } = true;

        [Description("Включить отладочные сообщения?")]
        public bool Debug { get; set; } = false;

        [Description("Префикс для ролевых команд")]
        public string RoleCommandPrefix { get; set; } = "!";

        [Description("Разрешить использование ролей только для определенных групп?")]
        public bool RestrictRolesToGroups { get; set; } = true;

        [Description("Список групп, которым разрешено использовать роли")]
        public string[] AllowedRoleGroups { get; set; } = { "admin", "moderator", "gamemaster" };

        [Description("Автоматически назначать роли при входе?")]
        public bool AutoAssignRoles { get; set; } = false;

        [Description("Максимальное количество ролей на одного игрока")]
        public int MaxRolesPerPlayer { get; set; } = 3;

        [Description("Включить систему денег для RP?")]
        public bool EnableMoneySystem { get; set; } = true;

        [Description("Начальная сумма денег для новых игроков")]
        public int StartingMoney { get; set; } = 1000;

        [Description("Включить RP чат каналы?")]
        public bool EnableRpChannels { get; set; } = true;

        [Description("Префикс для OOC (Out of Character) сообщений")]
        public string OocPrefix { get; set; } = "[OOC]";

        [Description("Префикс для IC (In Character) сообщений")]
        public string IcPrefix { get; set; } = "[IC]";

        [Description("Радиус для локального RP чата")]
        public float LocalChatRadius { get; set; } = 5.0f;

        [Description("Включить систему ранений и лечения?")]
        public bool EnableMedicalSystem { get; set; } = true;

        [Description("Время восстановления здоровья в секундах")]
        public float HealthRegenTime { get; set; } = 30.0f;
    }
}
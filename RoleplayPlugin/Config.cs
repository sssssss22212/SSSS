using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Interfaces;

namespace RpPlugin
{
    public class RoleplayConfig : IConfig
    {
        [Description("Включить плагин")] public bool IsEnabled { get; set; } = true;

        [Description("Отладочные логи")] public bool Debug { get; set; } = false;

        [Description("RP режим включен по умолчанию")] public bool IsRpModeEnabled { get; set; } = true;

        [Description("Запрет урона между всеми в RP (кроме спец. ролей)")]
        public bool DisableCombatDuringRp { get; set; } = true;

        [Description("Список ролей, которым можно наносить урон даже при RP")] 
        public List<string> DamageAllowedRoles { get; set; } = new() { "SCP-049-2" };

        [Description("Время мирного начала (сек) после старта раунда")] public float WarmupSeconds { get; set; } = 60f;

        [Description("Радиус /me (метры)")] public float MeRadius { get; set; } = 15f;

        [Description("Макс. длина RP-имени")] public int MaxRpNameLength { get; set; } = 24;

        [Description("Разрешённые символы RP-имени (regex)")] public string AllowedNameRegex { get; set; } = @"^[A-Za-zА-Яа-я0-9 _\-]{3,24}$";

        [Description("Использовать вайтлист для входа")] public bool WhitelistEnabled { get; set; } = false;

        [Description("SteamID64, имеющие доступ при включённом вайтлисте")] public HashSet<string> Whitelist { get; set; } = new();

        [Description("Префикс к никнейму при RP")] public string RpNamePrefix { get; set; } = ""; // например, "[RP] "

        [Description("Показывать имя как CustomInfo (над головой)")] public bool UseCustomInfo { get; set; } = true;

        [Description("Сбрасывать кастомное имя на смене роли")] public bool ResetRpNameOnRoleChange { get; set; } = false;
    }
}
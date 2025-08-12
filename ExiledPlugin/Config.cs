using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Interfaces;

namespace PlayerManagerPlugin
{
    /// <summary>
    /// Конфигурация плагина PlayerManager
    /// </summary>
    public class Config : IConfig
    {
        /// <summary>
        /// Включен ли плагин
        /// </summary>
        [Description("Включен ли плагин")]
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// Включена ли отладка
        /// </summary>
        [Description("Включена ли отладка")]
        public bool Debug { get; set; } = false;

        /// <summary>
        /// Приветственное сообщение при подключении игрока
        /// </summary>
        [Description("Приветственное сообщение при подключении игрока")]
        public string WelcomeMessage { get; set; } = "<color=green>Добро пожаловать на сервер!</color>";

        /// <summary>
        /// Длительность показа приветственного сообщения (в секундах)
        /// </summary>
        [Description("Длительность показа приветственного сообщения (в секундах)")]
        public ushort WelcomeMessageDuration { get; set; } = 5;

        /// <summary>
        /// Автоматическое лечение игроков при возрождении
        /// </summary>
        [Description("Автоматическое лечение игроков при возрождении")]
        public bool AutoHealOnSpawn { get; set; } = true;

        /// <summary>
        /// Количество здоровья для автолечения
        /// </summary>
        [Description("Количество здоровья для автолечения")]
        public float AutoHealAmount { get; set; } = 100f;

        /// <summary>
        /// Показывать ли сообщение о смерти игрока
        /// </summary>
        [Description("Показывать ли сообщение о смерти игрока")]
        public bool ShowDeathMessage { get; set; } = true;

        /// <summary>
        /// Формат сообщения о смерти
        /// </summary>
        [Description("Формат сообщения о смерти. {player} - имя игрока, {killer} - убийца, {reason} - причина")]
        public string DeathMessageFormat { get; set; } = "<color=red>{player} был убит игроком {killer} ({reason})</color>";

        /// <summary>
        /// Включить ли систему очков
        /// </summary>
        [Description("Включить ли систему очков")]
        public bool EnablePointSystem { get; set; } = true;

        /// <summary>
        /// Очки за убийство SCP
        /// </summary>
        [Description("Очки за убийство SCP")]
        public int PointsForScpKill { get; set; } = 100;

        /// <summary>
        /// Очки за убийство игрока
        /// </summary>
        [Description("Очки за убийство игрока")]
        public int PointsForPlayerKill { get; set; } = 50;

        /// <summary>
        /// Очки за побег
        /// </summary>
        [Description("Очки за побег")]
        public int PointsForEscape { get; set; } = 200;

        /// <summary>
        /// Список ролей, которые получают дополнительные предметы при спавне
        /// </summary>
        [Description("Список ролей, которые получают дополнительные предметы при спавне")]
        public Dictionary<string, List<string>> RoleStartingItems { get; set; } = new Dictionary<string, List<string>>
        {
            ["Scientist"] = new List<string> { "KeycardScientist", "Flashlight" },
            ["ClassD"] = new List<string> { "Coin" },
            ["Guard"] = new List<string> { "KeycardGuard", "Radio" }
        };

        /// <summary>
        /// Максимальное количество игроков одной роли
        /// </summary>
        [Description("Максимальное количество игроков одной роли")]
        public Dictionary<string, int> MaxPlayersPerRole { get; set; } = new Dictionary<string, int>
        {
            ["Scp173"] = 1,
            ["Scp106"] = 1,
            ["Scp096"] = 1,
            ["Scp049"] = 1
        };

        /// <summary>
        /// Включить ли автоматическую остановку варлока (decontamination)
        /// </summary>
        [Description("Включить ли автоматическую остановку варлока при определенном количестве игроков")]
        public bool EnableAutoDecontaminationStop { get; set; } = true;

        /// <summary>
        /// Минимальное количество живых игроков для остановки варлока
        /// </summary>
        [Description("Минимальное количество живых игроков для остановки варлока")]
        public int MinPlayersForDecontamination { get; set; } = 5;

        /// <summary>
        /// Включить ли систему AFK кика
        /// </summary>
        [Description("Включить ли систему AFK кика")]
        public bool EnableAfkKick { get; set; } = true;

        /// <summary>
        /// Время в секундах до кика за AFK
        /// </summary>
        [Description("Время в секундах до кика за AFK")]
        public int AfkKickTime { get; set; } = 300;

        /// <summary>
        /// Сообщение при кике за AFK
        /// </summary>
        [Description("Сообщение при кике за AFK")]
        public string AfkKickMessage { get; set; } = "Вы были кикнуты за неактивность";
    }
}
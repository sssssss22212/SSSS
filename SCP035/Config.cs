using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Enums;
using Exiled.API.Interfaces;

namespace SCP035
{
    public class Config : IConfig
    {
        [Description("Включен ли плагин")] 
        public bool IsEnabled { get; set; } = true;

        [Description("Режим отладки")] 
        public bool Debug { get; set; } = false;

        [Description("Автоматический спавн маски в начале раунда")] 
        public bool AutoSpawnEnabled { get; set; } = true;

        [Description("Сколько масок спавнить при успешной проверке шанса")]
        public int MasksToSpawn { get; set; } = 1;

        [Description("Общий шанс, что в этом раунде маска(и) вообще появятся, %")]
        public float RoundSpawnChancePercent { get; set; } = 60f;

        [Description("Шансы спавна по зонам (в %). Суммирование не требуется, это индивидуальный шанс попытки на комнату в зоне")]
        public Dictionary<ZoneType, float> SpawnWeights { get; set; } = new Dictionary<ZoneType, float>
        {
            [ZoneType.LightContainment] = 45f,
            [ZoneType.HeavyContainment] = 30f,
            [ZoneType.Entrance] = 20f,
            [ZoneType.Surface] = 10f,
        };

        [Description("Показывать общую анонс-надпись при поднятии маски")] 
        public bool AnnounceOnPickup { get; set; } = true;

        [Description("Сообщения плагина")] 
        public MessageConfig Messages { get; set; } = new MessageConfig();

        [Description("Настройки HSM-хинтов")] 
        public HintConfig Hint { get; set; } = new HintConfig();

        [Description("Настройки способности SCP-035")] 
        public AbilityConfig Ability { get; set; } = new AbilityConfig();

        [Description("Шанс стать SCP-035 при поднятии маски, %")] 
        public float BecomeChancePercent { get; set; } = 100f;
    }

    public class MessageConfig
    {
        [Description("Анонс при поднятии маски")] 
        public string AnnouncePickupText { get; set; } =
            "<color=#ba55d3>ВНИМАНИЕ:</color> <color=#d8bfd8>обнаружен носитель SCP-035.</color>";

        [Description("Хинт жертве, которую задело АОЕ. {damage} будет заменён на число урона")] 
        public string VictimHitText { get; set; } =
            "<color=#ff6a6a>Вы поражены ядовитой речью SCP-035 (-{damage} HP)</color>";

        [Description("Хинт носителю, если успешно задело кого-то. {count} заменится на число целей")] 
        public string AbilityUsedText { get; set; } =
            "<color=#7fffd4>Вы задели целей: {count}</color>";

        [Description("Сообщение игроку, если маска отказалась присоединиться")] 
        public string DenyPickupText { get; set; } =
            "<color=#aaa>Маска холодно шепчет: 'Не тебя я ищу...'</color>";
    }

    public class HintConfig
    {
        [Description("Размер текста (10-30)")] 
        public int TextSize { get; set; } = 20;

        [Description("Позиция по X (-100 - 100)")] 
        public int XPosition { get; set; } = 0;

        [Description("Позиция по Y (-100 - 100)")] 
        public int YPosition { get; set; } = 50;
    }

    public class AbilityConfig
    {
        [Description("Радиус действия способности (метры)")] 
        public float Radius { get; set; } = 8f;

        [Description("Минимальный урон способности")] 
        public int MinDamage { get; set; } = 10;

        [Description("Максимальный урон способности")] 
        public int MaxDamage { get; set; } = 25;

        [Description("Кулдаун способности (сек)")] 
        public float CooldownSeconds { get; set; } = 25f;

        [Description("Может ли способность задевать SCP")] 
        public bool CanAffectScps { get; set; } = false;

        [Description("Шанс успешного применения по каждой цели, %")] 
        public float SuccessPercent { get; set; } = 100f;
    }
}
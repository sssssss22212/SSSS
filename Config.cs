using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Enums;
using Exiled.API.Interfaces;
using Scp096Mask.Enums;

namespace Scp096Mask
{
    public class Config : IConfig
    {
        [Description("Включен ли плагин")]
        public bool IsEnabled { get; set; } = true;

        [Description("Режим отладки")]
        public bool Debug { get; set; } = false;

        [Description("Тип активации: ServerSpecificSettings (кастомные настройки) или NoClip (клавиша NoClip)")]
        public ActivationType ActivationType { get; set; } = ActivationType.ServerSpecificSettings;

        [Description("Автоматический спавн масок")]
        public bool AutoSpawnEnabled { get; set; } = true;

        [Description("Количество масок для спавна")]
        public int MasksToSpawn { get; set; } = 8;

        [Description("Шансы спавна по зонам (в %)")]
        public Dictionary<ZoneType, float> SpawnWeights { get; set; } = new Dictionary<ZoneType, float>
        {
            [ZoneType.LightContainment] = 35f,
            [ZoneType.HeavyContainment] = 45f,
            [ZoneType.Entrance] = 15f,
            [ZoneType.Surface] = 5f
        };

        [Description("Время одевания маски (в секундах)")]
        public float MaskEquipTime { get; set; } = 5f;

        [Description("Дистанция взаимодействия с SCP-096")]
        public float InteractionDistance { get; set; } = 3f;

        [Description("Настройки хинтов")]
        public HintSettings HintSettings { get; set; } = new HintSettings();

        [Description("Сообщения")]
        public Messages Messages { get; set; } = new Messages();

        [Description("Заголовок категории настроек")]
        public string SettingHeaderLabel { get; set; } = "Scp096Mask";

        [Description("Уникальный ID настройки")]
        public int KeybindId { get; set; } = 300;

        [Description("Название клавиши")]
        public string KeybindLabel { get; set; } = "Взаимодействие с SCP-096";

        [Description("Подсказка для клавиши")]
        public string KeybindHint { get; set; } = "Позволяет надеть маску на SCP-096";
    }

    public class HintSettings
    {
        [Description("Размер текста (10-30)")]
        public int TextSize { get; set; } = 20;

        [Description("Позиция по X (-100 - 100)")]
        public int XPosition { get; set; } = 0;

        [Description("Позиция по Y (-100 - 100)")]
        public int YPosition { get; set; } = 50;
    }

    public class Messages
    {
        [Description("Сообщение при подборе маски")]
        public string MaskPickedUp { get; set; } = "<color=green>🎭 Вы подобрали маску SCP-096!\nПодойдите к SCP-096 и нажмите клавишу взаимодействия</color>";

        [Description("Сообщение о начале одевания маски")]
        public string MaskEquipping { get; set; } = "<color=yellow>🎭 Одеваем маску на SCP-096...\nНе отходите!</color>";

        [Description("Сообщение об успешном одевании маски")]
        public string MaskEquipped { get; set; } = "<color=green>✅ Маска успешно надета на SCP-096!\nТеперь он не агрится при взгляде</color>";

        [Description("Сообщение о том, что игрок слишком далеко")]
        public string TooFarAway { get; set; } = "<color=red>❌ Вы слишком далеко от SCP-096!</color>";

        [Description("Сообщение о том, что у игрока нет маски")]
        public string NoMask { get; set; } = "<color=red>❌ У вас нет маски SCP-096!</color>";

        [Description("Сообщение о том, что на SCP-096 уже есть маска")]
        public string AlreadyMasked { get; set; } = "<color=orange>⚠ На SCP-096 уже надета маска!</color>";

        [Description("Сообщение при снятии маски")]
        public string MaskRemoved { get; set; } = "<color=yellow>🎭 Маска снята с SCP-096</color>";

        [Description("Инструкция для игроков")]
        public string Instructions { get; set; } = "<color=cyan>🎭 Найдите маску SCP-096 (аптечка) в комнатах\nИспользуйте настроенную клавишу для взаимодействия</color>";
    }
}
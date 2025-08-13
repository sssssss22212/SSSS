using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Enums;
using Exiled.API.Interfaces;

namespace Scp096Mask
{
    public class Config : IConfig
    {
        [Description("Включен ли плагин")] 
        public bool IsEnabled { get; set; } = true;

        [Description("Режим отладки")] 
        public bool Debug { get; set; } = false;

        [Description("Автоматический спавн масок на карте")] 
        public bool AutoSpawnEnabled { get; set; } = true;

        [Description("Количество масок для спавна")] 
        public int MasksToSpawn { get; set; } = 6;

        [Description("Шансы спавна по зонам (в %)")] 
        public Dictionary<ZoneType, float> SpawnWeights { get; set; } = new()
        {
            [ZoneType.LightContainment] = 40f,
            [ZoneType.HeavyContainment] = 30f,
            [ZoneType.Entrance] = 20f,
            [ZoneType.Surface] = 10f,
        };

        [Description("Максимум попыток поиска валидной точки спавна на одну маску")] 
        public int MaxSpawnTriesPerMask { get; set; } = 12;

        [Description("Настройки отображения подсказок через HSM")] 
        public HintSettings HintSettings { get; set; } = new();

        [Description("Сообщение при поднятии маски")] 
        public string PickupMaskMessage { get; set; } = "<color=yellow>Вы нашли <b>Маску SCP-096</b>! Держите её в руках и используйте привязку, чтобы надеть её на 096.</color>";

        [Description("Сообщение, когда игрок не держит маску в руках")] 
        public string NeedMaskInHandsMessage { get; set; } = "<color=orange>Возьмите маску в руки (это аптечка, выданная этим плагином).</color>";

        [Description("Сообщение, когда рядом нет 096 или вы на него не смотрите")] 
        public string NeedLookAt096Message { get; set; } = "<color=orange>Подойдите к SCP-096, посмотрите на него и затем активируйте привязку.</color>";

        [Description("Сообщение при успешной установке маски")] 
        public string MaskEquippedMessage { get; set; } = "<color=green>Маска установлена на SCP-096. Он больше не агрится от взгляда.</color>";

        [Description("Сообщение при отмене установки маски")] 
        public string MaskEquipCancelledMessage { get; set; } = "<color=red>Установка маски прервана.</color>";

        [Description("Сообщение, если на 096 уже надета маска")] 
        public string MaskAlreadyOnMessage { get; set; } = "<color=#aaaaaa>На SCP-096 уже надета маска.</color>";

        [Description("Максимальная дистанция до 096 для начала установки маски (в метрах)")] 
        public float EquipMaxDistance { get; set; } = 2.2f;

        [Description("Максимальный угол отклонения взгляда от направления к 096 (в градусах)")] 
        public float EquipMaxAngleDeg { get; set; } = 20f;

        [Description("Время установки маски (сек)")] 
        public float EquipTimeSeconds { get; set; } = 3.0f;

        [Description("Текст заголовка прогресса установки")] 
        public string EquipProgressTitle { get; set; } = "Установка маски на SCP-096";

        [Description("Разрешить использовать маску как обычную аптечку (должно быть false)")] 
        public bool AllowMaskAsMedkit { get; set; } = false;

        [Description("Текст категории настроек ServerSpecificSettings")] 
        public string SettingHeaderLabel { get; set; } = "Scp096Mask";

        [Description("ID бинда для ServerSpecificSettings")] 
        public int KeybindId { get; set; } = 301;

        [Description("Название бинда")] 
        public string KeybindLabel { get; set; } = "Надеть маску на SCP-096";

        [Description("Подсказка для бинда")] 
        public string KeybindHint { get; set; } = "Будучи рядом и глядя на SCP-096, активируйте для начала установки маски.";
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
}
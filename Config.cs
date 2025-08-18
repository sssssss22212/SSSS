using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Interfaces;
using Exiled.API.Enums;
using Scp096Mask.Enums;

namespace Scp096Mask
{
    public class Config : IConfig
    {
        [Description("Включен ли плагин?")]
        public bool IsEnabled { get; set; } = true;

        [Description("Режим отладки")]
        public bool Debug { get; set; } = false;

        [Description("Автоматический спавн масок в начале раунда")]
        public bool AutoSpawnEnabled { get; set; } = true;

        [Description("Количество масок для спавна")]
        public int MasksToSpawn { get; set; } = 3;

        [Description("Время одевания маски (в секундах)")]
        public float MaskEquipTime { get; set; } = 5f;

        [Description("Дистанция взаимодействия с SCP-096 (в метрах)")]
        public float InteractionDistance { get; set; } = 3f;

        [Description("Требовать ли маску в руке для одевания")]
        public bool RequireMaskInHand { get; set; } = true;

        [Description("Тип активации маски")]
        public ActivationType ActivationType { get; set; } = ActivationType.ServerSpecificSettings;

        [Description("Шансы спавна масок по зонам (0-100%)")]
        public Dictionary<ZoneType, float> SpawnWeights { get; set; } = new Dictionary<ZoneType, float>
        {
            { ZoneType.LightContainment, 35f },
            { ZoneType.HeavyContainment, 25f },
            { ZoneType.Entrance, 20f },
            { ZoneType.Office, 15f },
            { ZoneType.Surface, 5f }
        };

        [Description("Конкретные комнаты для спавна масок (если не указаны, используются все комнаты зон)")]
        public List<RoomType> SpecificSpawnRooms { get; set; } = new List<RoomType>
        {
            RoomType.LczClassDSpawn,
            RoomType.LczCheckpointA,
            RoomType.LczCheckpointB,
            RoomType.Hcz049,
            RoomType.HczCheckpointA,
            RoomType.HczCheckpointB,
            RoomType.EzCheckpointHallway,
            RoomType.EzGateA,
            RoomType.EzGateB
        };

        [Description("Использовать конкретные комнаты вместо зон")]
        public bool UseSpecificRooms { get; set; } = false;

        [Description("Минимальная задержка между спавнами масок (секунды)")]
        public float SpawnDelay { get; set; } = 0.3f;

        [Description("Максимальные попытки найти позицию для спавна")]
        public int MaxSpawnAttempts { get; set; } = 10;

        [Description("Радиус проверки свободного места для спавна")]
        public float SpawnCheckRadius { get; set; } = 0.5f;

        [Description("Настройки отображения масок")]
        public MaskDisplaySettings MaskDisplay { get; set; } = new MaskDisplaySettings();

        [Description("Настройки подсказок")]
        public HintSettings HintSettings { get; set; } = new HintSettings();

        [Description("Сообщения плагина")]
        public MessageConfig Messages { get; set; } = new MessageConfig();

        [Description("ID клавиши для Server Specific Settings")]
        public uint KeybindId { get; set; } = 1;

        [Description("Название клавиши для Server Specific Settings")]
        public string KeybindLabel { get; set; } = "Надеть маску SCP-096";

        [Description("Подсказка для клавиши")]
        public string KeybindHint { get; set; } = "Нажмите чтобы надеть маску на ближайшего SCP-096";

        [Description("Заголовок настроек")]
        public string SettingHeaderLabel { get; set; } = "SCP-096 Маска";
    }

    public class MaskDisplaySettings
    {
        [Description("Размер маски (множитель)")]
        public float Scale { get; set; } = 1.2f;

        [Description("Цвет маски (RGB)")]
        public string Color { get; set; } = "#FF6B6B";

        [Description("Эффект свечения")]
        public bool GlowEffect { get; set; } = true;

        [Description("Интенсивность свечения")]
        public float GlowIntensity { get; set; } = 2f;

        [Description("Вращение маски")]
        public bool Rotate { get; set; } = true;

        [Description("Скорость вращения")]
        public float RotationSpeed { get; set; } = 30f;

        [Description("Высота левитации")]
        public float HoverHeight { get; set; } = 0.5f;

        [Description("Скорость левитации")]
        public float HoverSpeed { get; set; } = 1f;
    }

    public class HintSettings
    {
        [Description("Размер текста подсказок")]
        public int TextSize { get; set; } = 20;

        [Description("Позиция X подсказок")]
        public float XPosition { get; set; } = 50f;

        [Description("Позиция Y подсказок")]
        public float YPosition { get; set; } = 80f;

        [Description("Показывать прогресс одевания")]
        public bool ShowProgress { get; set; } = true;

        [Description("Стиль прогресс-бара")]
        public string ProgressBarStyle { get; set; } = "█";

        [Description("Стиль пустого прогресса")]
        public string EmptyProgressStyle { get; set; } = "░";
    }

    public class MessageConfig
    {
        [Description("Сообщение при подборе маски")]
        public string MaskPickedUp { get; set; } = "<color=green>Вы подобрали маску SCP-096!</color>\n<color=yellow>Подойдите к SCP-096 и нажмите клавишу взаимодействия</color>";

        [Description("Сообщение об отсутствии маски")]
        public string NoMask { get; set; } = "<color=red>У вас нет маски SCP-096!</color>";

        [Description("Сообщение о том, что маска не в руке")]
        public string MaskNotInHand { get; set; } = "<color=orange>Возьмите маску в руку!</color>";

        [Description("Сообщение о слишком большом расстоянии")]
        public string TooFarAway { get; set; } = "<color=red>Нет SCP-096 поблизости!</color>\n<color=yellow>Подойдите ближе к SCP-096</color>";

        [Description("Сообщение о том, что SCP-096 уже в маске")]
        public string AlreadyMasked { get; set; } = "<color=orange>На этом SCP-096 уже есть маска!</color>";

        [Description("Сообщение в процессе одевания")]
        public string MaskEquipping { get; set; } = "<color=yellow>Одеваю маску на SCP-096...</color>\n<color=gray>Не отходите далеко!</color>";

        [Description("Сообщение об успешном одевании")]
        public string MaskEquipped { get; set; } = "<color=green>Маска успешно надета!</color>\n<color=cyan>SCP-096 больше не будет агриться!</color>";

        [Description("Сообщение о снятии маски")]
        public string MaskRemoved { get; set; } = "<color=orange>С вас сняли маску!</color>";

        [Description("Сообщение о прерванном процессе")]
        public string ProcessInterrupted { get; set; } = "<color=red>Процесс одевания маски прерван!</color>";
    }
}
using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Interfaces;
using Exiled.API.Enums;
using Scp096Mask.Enums;
using UnityEngine;

namespace Scp096Mask
{
    public class Config : IConfig
    {
        [Description("Включен ли плагин?")]
        public bool IsEnabled { get; set; } = true;

        [Description("Включить дебаг?")]
        public bool Debug { get; set; } = false;

        [Description("Автоматический спавн масок в начале раунда")]
        public bool AutoSpawnEnabled { get; set; } = true;

        [Description("Количество масок для спавна")]
        public int MasksToSpawn { get; set; } = 5;

        [Description("Время одевания маски в секундах")]
        public float MaskEquipTime { get; set; } = 8f;

        [Description("Дистанция взаимодействия с SCP-096")]
        public float InteractionDistance { get; set; } = 3f;

        [Description("Требовать ли маску в руке для одевания")]
        public bool RequireMaskInHand { get; set; } = true;

        [Description("Шансы спавна масок по зонам (в процентах)")]
        public Dictionary<ZoneType, float> SpawnWeights { get; set; } = new Dictionary<ZoneType, float>
        {
            { ZoneType.LightContainment, 40f },
            { ZoneType.HeavyContainment, 30f },
            { ZoneType.Entrance, 20f },
            { ZoneType.Surface, 5f },
            { ZoneType.Other, 5f }
        };

        [Description("Конкретные комнаты для спавна масок (приоритет над зонами)")]
        public Dictionary<RoomType, float> SpecificRoomSpawn { get; set; } = new Dictionary<RoomType, float>
        {
            { RoomType.Lcz914, 60f },
            { RoomType.LczClassDSpawn, 40f },
            { RoomType.LczGreenhouse, 35f },
            { RoomType.LczToilets, 30f },
            { RoomType.LczCafe, 45f },
            { RoomType.Hcz096, 80f },
            { RoomType.HczTesla, 25f },
            { RoomType.EzGateA, 20f },
            { RoomType.EzGateB, 20f },
            { RoomType.Surface, 10f }
        };

        [Description("Настройки спавна в конкретных комнатах с расширенными возможностями")]
        public List<RoomSpawnConfig> RoomSpawnConfigs { get; set; } = new List<RoomSpawnConfig>
        {
            new RoomSpawnConfig
            {
                RoomType = RoomType.Hcz096,
                SpawnChance = 80f,
                MaxMasksInRoom = 2,
                MinPlayersRequired = 3,
                SpawnOnlyWithScp096 = true,
                SpawnPositions = new List<Vector3>
                {
                    new Vector3(0f, 1.2f, 0f),
                    new Vector3(3f, 1.2f, 3f)
                }
            },
            new RoomSpawnConfig
            {
                RoomType = RoomType.Lcz914,
                SpawnChance = 60f,
                MaxMasksInRoom = 1,
                MinPlayersRequired = 5,
                SpawnOnlyWithScp096 = false,
                SpawnPositions = new List<Vector3>
                {
                    new Vector3(-5f, 1.2f, 0f)
                }
            },
            new RoomSpawnConfig
            {
                RoomType = RoomType.LczClassDSpawn,
                SpawnChance = 40f,
                MaxMasksInRoom = 1,
                MinPlayersRequired = 4,
                SpawnOnlyWithScp096 = false,
                SpawnPositions = new List<Vector3>()
            }
        };

        [Description("Минимальное расстояние между масками")]
        public float MinMaskDistance { get; set; } = 15f;

        [Description("Максимальные попытки найти позицию для спавна")]
        public int MaxSpawnAttempts { get; set; } = 20;

        [Description("Тип активации маски")]
        public ActivationType ActivationType { get; set; } = ActivationType.ServerSpecificSettings;

        [Description("ID клавиши для серверных настроек")]
        public string KeybindId { get; set; } = "scp096_mask_interact";

        [Description("Название клавиши в настройках")]
        public string KeybindLabel { get; set; } = "Взаимодействие с маской SCP-096";

        [Description("Подсказка для клавиши")]
        public string KeybindHint { get; set; } = "Нажмите, чтобы надеть маску на SCP-096";

        [Description("Заголовок раздела настроек")]
        public string SettingHeaderLabel { get; set; } = "Маска SCP-096";

        [Description("Визуальные настройки маски")]
        public MaskVisualSettings VisualSettings { get; set; } = new MaskVisualSettings();

        [Description("Настройки хинтов")]
        public HintSettings HintSettings { get; set; } = new HintSettings();

        [Description("Сообщения плагина")]
        public Messages Messages { get; set; } = new Messages();

        [Description("Эффекты при одевании маски")]
        public EffectSettings Effects { get; set; } = new EffectSettings();

        [Description("Дополнительные настройки спавна")]
        public AdvancedSpawnSettings AdvancedSpawn { get; set; } = new AdvancedSpawnSettings();
    }

    [System.Serializable]
    public class RoomSpawnConfig
    {
        [Description("Тип комнаты")]
        public RoomType RoomType { get; set; } = RoomType.Unknown;

        [Description("Шанс спавна в процентах (0-100)")]
        public float SpawnChance { get; set; } = 50f;

        [Description("Максимальное количество масок в комнате")]
        public int MaxMasksInRoom { get; set; } = 1;

        [Description("Минимальное количество игроков для спавна")]
        public int MinPlayersRequired { get; set; } = 1;

        [Description("Спавнить только при наличии SCP-096")]
        public bool SpawnOnlyWithScp096 { get; set; } = false;

        [Description("Конкретные позиции для спавна (если пусто - случайные)")]
        public List<Vector3> SpawnPositions { get; set; } = new List<Vector3>();

        [Description("Включен ли спавн в этой комнате")]
        public bool IsEnabled { get; set; } = true;

        [Description("Приоритет спавна (чем выше, тем раньше проверяется)")]
        public int Priority { get; set; } = 1;
    }

    public class MaskVisualSettings
    {
        [Description("Размер маски по X (множитель от оригинала)")]
        public float ScaleX { get; set; } = 1.5f;

        [Description("Размер маски по Y (множитель от оригинала)")]
        public float ScaleY { get; set; } = 0.8f;

        [Description("Размер маски по Z (множитель от оригинала)")]
        public float ScaleZ { get; set; } = 1.2f;

        [Description("Цвет маски (RGB)")]
        public string Color { get; set; } = "255,200,200";

        [Description("Включить свечение маски")]
        public bool EnableGlow { get; set; } = true;

        [Description("Цвет свечения (RGB)")]
        public string GlowColor { get; set; } = "255,150,150";

        [Description("Интенсивность свечения")]
        public float GlowIntensity { get; set; } = 2f;

        [Description("Вращение маски")]
        public bool EnableRotation { get; set; } = true;

        [Description("Скорость вращения")]
        public float RotationSpeed { get; set; } = 30f;

        [Description("Подпрыгивание маски")]
        public bool EnableBobbing { get; set; } = true;

        [Description("Высота подпрыгивания")]
        public float BobbingHeight { get; set; } = 0.3f;

        [Description("Скорость подпрыгивания")]
        public float BobbingSpeed { get; set; } = 2f;

        [Description("Деформация маски (растягивание)")]
        public bool EnableDeformation { get; set; } = true;

        [Description("Интенсивность деформации")]
        public float DeformationIntensity { get; set; } = 0.2f;

        [Description("Скорость деформации")]
        public float DeformationSpeed { get; set; } = 1.5f;
    }

    public class HintSettings
    {
        [Description("Размер текста хинта")]
        public int TextSize { get; set; } = 25;

        [Description("X позиция хинта")]
        public int XPosition { get; set; } = 50;

        [Description("Y позиция хинта")]
        public int YPosition { get; set; } = 85;

        [Description("Длительность хинтов в секундах")]
        public float DefaultDuration { get; set; } = 4f;
    }

    public class Messages
    {
        [Description("Маска подобрана")]
        public string MaskPickedUp { get; set; } = "<color=green>Вы подобрали маску SCP-096!</color>\n<color=yellow>Подойдите к SCP-096 и используйте клавишу взаимодействия</color>";

        [Description("У игрока нет маски")]
        public string NoMask { get; set; } = "<color=red>У вас нет маски SCP-096!</color>";

        [Description("Маска не в руке")]
        public string MaskNotInHand { get; set; } = "<color=orange>Возьмите маску в руку для использования!</color>";

        [Description("Слишком далеко от SCP-096")]
        public string TooFarAway { get; set; } = "<color=red>Нет SCP-096 поблизости!</color>";

        [Description("SCP-096 уже в маске")]
        public string AlreadyMasked { get; set; } = "<color=orange>На этом SCP-096 уже есть маска!</color>";

        [Description("Процесс одевания маски")]
        public string MaskEquipping { get; set; } = "<color=yellow>Одеваем маску на SCP-096...</color>";

        [Description("Маска успешно надета")]
        public string MaskEquipped { get; set; } = "<color=green>Маска успешно надета на SCP-096!</color>\n<color=cyan>Теперь он не будет агриться на игроков!</color>";

        [Description("Маска снята")]
        public string MaskRemoved { get; set; } = "<color=red>С вас сняли маску!</color>";

        [Description("Маска найдена")]
        public string MaskFound { get; set; } = "<color=yellow>Вы нашли маску SCP-096!</color>";
    }

    public class EffectSettings
    {
        [Description("Показывать эффекты при одевании")]
        public bool EnableEquipEffects { get; set; } = true;

        [Description("Звук при подборе маски")]
        public bool PlayPickupSound { get; set; } = true;

        [Description("Звук при одевании маски")]
        public bool PlayEquipSound { get; set; } = true;

        [Description("Эффект частиц при одевании")]
        public bool ShowParticleEffect { get; set; } = true;

        [Description("Встряска экрана при одевании")]
        public bool ScreenShake { get; set; } = true;
    }

    public class AdvancedSpawnSettings
    {
        [Description("Спавнить маски только когда есть SCP-096")]
        public bool OnlyWhenScp096Present { get; set; } = true;

        [Description("Минимальное количество игроков для спавна")]
        public int MinPlayersForSpawn { get; set; } = 5;

        [Description("Максимальное количество масок на карте")]
        public int MaxMasksOnMap { get; set; } = 8;

        [Description("Респавн масок в течение раунда")]
        public bool EnableRespawn { get; set; } = false;

        [Description("Интервал респавна в секундах")]
        public float RespawnInterval { get; set; } = 300f;

        [Description("Шанс респавна (%%)")]
        public float RespawnChance { get; set; } = 30f;

        [Description("Удалять маски при окончании раунда")]
        public bool CleanupOnRoundEnd { get; set; } = true;

        [Description("Лог спавна масок")]
        public bool LogMaskSpawns { get; set; } = true;

        [Description("Запрещенные зоны для спавна")]
        public List<ZoneType> ForbiddenZones { get; set; } = new List<ZoneType>();

        [Description("Запрещенные комнаты для спавна")]
        public List<RoomType> ForbiddenRooms { get; set; } = new List<RoomType>
        {
            RoomType.Pocket,
            RoomType.HczWarhead,
            RoomType.LczAirlock
        };

        [Description("Приоритетные зоны для спавна")]
        public List<ZoneType> PriorityZones { get; set; } = new List<ZoneType>
        {
            ZoneType.LightContainment,
            ZoneType.HeavyContainment
        };

        [Description("Использовать новую систему спавна по комнатам")]
        public bool UseAdvancedRoomSpawn { get; set; } = true;

        [Description("Множитель шанса для каждой дополнительной маски в комнате")]
        public float AdditionalMaskChanceMultiplier { get; set; } = 0.5f;
    }
}
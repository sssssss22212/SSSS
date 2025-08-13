using System;
using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Enums;
using Exiled.API.Interfaces;
using PlayerRoles;

namespace SCP035Plugin
{
    /// <summary>
    /// Конфигурация плагина SCP-035
    /// Все параметры можно настроить в конфигурационном файле сервера
    /// </summary>
    public class Config : IConfig
    {
        [Description("Включен ли плагин SCP-035")]
        public bool IsEnabled { get; set; } = true;

        [Description("Режим отладки (показывает дополнительную информацию в консоли)")]
        public bool Debug { get; set; } = false;

        #region Настройки спавна SCP-035

        [Description("Включить автоматический спавн SCP-035 в начале раунда")]
        public bool EnableSCP035Spawn { get; set; } = true;

        [Description("Минимальное количество игроков для спавна SCP-035")]
        public int MinPlayersForSpawn { get; set; } = 5;

        [Description("Задержка перед спавном SCP-035 (в секундах)")]
        public float SpawnDelay { get; set; } = 10f;

        [Description("Шанс спавна SCP-035 (в процентах от общего количества игроков)")]
        public float SCP035SpawnChance { get; set; } = 15f;

        [Description("Максимальное количество SCP-035 за раунд")]
        public int MaxSCP035Count { get; set; } = 2;

        #endregion

        #region Характеристики SCP-035

        [Description("Здоровье SCP-035")]
        public float SCP035Health { get; set; } = 150f;

        [Description("Размер модели SCP-035 (1.0 = нормальный размер)")]
        public Vector3 SCP035Scale { get; set; } = new Vector3(1.0f, 1.0f, 1.0f);

        [Description("Предметы, которые получает SCP-035 при спавне")]
        public List<ItemType> SCP035StartItems { get; set; } = new List<ItemType>
        {
            ItemType.Flashlight,
            ItemType.Medkit,
            ItemType.KeycardJanitor,
            ItemType.Coin
        };

        [Description("Может ли SCP-035 открывать двери без карт доступа")]
        public bool SCP035CanOpenDoors { get; set; } = true;

        [Description("Эффективность лечения для SCP-035 (1.0 = 100%, 0.5 = 50%)")]
        public float SCP035HealingEfficiency { get; set; } = 0.6f;

        [Description("Множители урона для SCP-035 по типам урона")]
        public Dictionary<DamageType, float> SCP035DamageMultipliers { get; set; } = new Dictionary<DamageType, float>
        {
            [DamageType.Firearm] = 0.8f,        // Пулевые ранения - 80% урона
            [DamageType.Explosion] = 1.2f,      // Взрывы - 120% урона  
            [DamageType.Scp] = 0.9f,            // Урон от SCP - 90% урона
            [DamageType.Tesla] = 1.5f,          // Тесла - 150% урона
            [DamageType.Warhead] = 2.0f,        // Боеголовка - 200% урона
            [DamageType.Decontamination] = 1.0f // Деконтаминация - 100% урона
        };

        #endregion

        #region Настройки контроля (Possession)

        [Description("Дальность контроля игроков (в метрах)")]
        public float PossessionRange { get; set; } = 5f;

        [Description("Базовый шанс успешного контроля (в процентах)")]
        public float BasePossessionChance { get; set; } = 70f;

        [Description("Длительность контроля (в секундах)")]
        public float PossessionDuration { get; set; } = 15f;

        [Description("Кулдаун между попытками контроля (в секундах)")]
        public float PossessionCooldown { get; set; } = 20f;

        [Description("Вызывает ли контроль коррозию у жертвы")]
        public bool PossessionCausesCorrosion { get; set; } = true;

        [Description("Модификаторы шанса контроля в зависимости от роли цели")]
        public Dictionary<RoleTypeId, float> PossessionChanceByRole { get; set; } = new Dictionary<RoleTypeId, float>
        {
            // Класс D - легко контролировать
            [RoleTypeId.ClassD] = 1.2f,
            
            // Учёные - средняя сложность
            [RoleTypeId.Scientist] = 1.0f,
            
            // Охрана - сложнее контролировать
            [RoleTypeId.FacilityGuard] = 0.8f,
            
            // МОГ - очень сложно
            [RoleTypeId.NtfCaptain] = 0.5f,
            [RoleTypeId.NtfSergeant] = 0.6f,
            [RoleTypeId.NtfSpecialist] = 0.7f,
            [RoleTypeId.NtfPrivate] = 0.7f,
            
            // Хаос - средняя сложность
            [RoleTypeId.ChaosConscript] = 0.9f,
            [RoleTypeId.ChaosMarauder] = 0.8f,
            [RoleTypeId.ChaosRepressor] = 0.7f,
            [RoleTypeId.ChaosRifleman] = 0.8f,
            
            // SCP - невозможно контролировать
            [RoleTypeId.Scp049] = 0.0f,
            [RoleTypeId.Scp0492] = 0.0f,
            [RoleTypeId.Scp079] = 0.0f,
            [RoleTypeId.Scp096] = 0.0f,
            [RoleTypeId.Scp106] = 0.0f,
            [RoleTypeId.Scp173] = 0.0f,
            [RoleTypeId.Scp939] = 0.0f,
            [RoleTypeId.Scp3114] = 0.0f,
            
            // Специальные роли
            [RoleTypeId.Tutorial] = 0.0f,
            [RoleTypeId.Spectator] = 0.0f
        };

        #endregion

        #region Настройки коррозии

        [Description("Включить эффект коррозии для SCP-035")]
        public bool EnableCorrosion { get; set; } = true;

        [Description("Урон от коррозии за тик")]
        public float CorrosionDamagePerTick { get; set; } = 3f;

        [Description("Интервал между тиками коррозии (в секундах)")]
        public float CorrosionInterval { get; set; } = 8f;

        #endregion

        #region Настройки вселения после смерти

        [Description("Разрешить вселение в другого игрока при смерти SCP-035")]
        public bool AllowPossessionOnDeath { get; set; } = true;

        [Description("Дальность поиска нового хозяина при смерти (в метрах)")]
        public float DeathPossessionRange { get; set; } = 10f;

        [Description("Шанс успешного вселения при смерти (в процентах)")]
        public float DeathPossessionChance { get; set; } = 40f;

        #endregion

        #region Настройки HSM подсказок

        [Description("Настройки системы подсказок")]
        public HintSettings HintSettings { get; set; } = new HintSettings();

        #endregion

        #region Расширенные настройки

        [Description("Особые эффекты при контроле")]
        public PossessionEffects PossessionEffects { get; set; } = new PossessionEffects();

        [Description("Настройки взаимодействия с окружением")]
        public EnvironmentSettings EnvironmentSettings { get; set; } = new EnvironmentSettings();

        #endregion
    }

    /// <summary>
    /// Настройки системы подсказок HSM
    /// </summary>
    public class HintSettings
    {
        [Description("Размер текста подсказок (10-30)")]
        public int TextSize { get; set; } = 18;

        [Description("Позиция по оси X (-100 до 100)")]
        public int XPosition { get; set; } = 0;

        [Description("Позиция по оси Y (-100 до 100)")]
        public int YPosition { get; set; } = 40;

        [Description("Показывать подсказки о статусе коррозии")]
        public bool ShowCorrosionStatus { get; set; } = true;

        [Description("Показывать подсказки о контроле")]
        public bool ShowPossessionHints { get; set; } = true;

        [Description("Показывать информацию о способностях при спавне")]
        public bool ShowAbilitiesInfo { get; set; } = true;

        [Description("Длительность показа информационных подсказок (в секундах)")]
        public float InfoHintDuration { get; set; } = 8f;

        [Description("Длительность показа статусных подсказок (в секундах)")]
        public float StatusHintDuration { get; set; } = 3f;
    }

    /// <summary>
    /// Особые эффекты при контроле игроков
    /// </summary>
    public class PossessionEffects
    {
        [Description("Замедлять контролируемого игрока")]
        public bool SlowDownPossessed { get; set; } = true;

        [Description("Множитель скорости для контролируемого (1.0 = нормальная скорость)")]
        public float PossessedSpeedMultiplier { get; set; } = 0.7f;

        [Description("Затемнять экран контролируемого")]
        public bool DimPossessedVision { get; set; } = true;

        [Description("Блокировать использование предметов контролируемым")]
        public bool BlockPossessedItems { get; set; } = true;

        [Description("Блокировать взаимодействие с дверями контролируемым")]
        public bool BlockPossessedDoors { get; set; } = true;

        [Description("Наносить периодический урон контролируемому")]
        public bool DamagePossessedOverTime { get; set; } = true;

        [Description("Урон контролируемому за тик (если включён)")]
        public float PossessedDamagePerTick { get; set; } = 2f;

        [Description("Интервал урона контролируемому (в секундах)")]
        public float PossessedDamageInterval { get; set; } = 5f;
    }

    /// <summary>
    /// Настройки взаимодействия с окружением
    /// </summary>
    public class EnvironmentSettings
    {
        [Description("SCP-035 может взаимодействовать с SCP-914")]
        public bool CanUseScp914 { get; set; } = true;

        [Description("SCP-035 может использовать лифты")]
        public bool CanUseElevators { get; set; } = true;

        [Description("SCP-035 может активировать боеголовку")]
        public bool CanActivateWarhead { get; set; } = false;

        [Description("SCP-035 может отключать генераторы")]
        public bool CanDisableGenerators { get; set; } = true;

        [Description("SCP-035 получает уведомления о событиях")]
        public bool ReceiveEventNotifications { get; set; } = true;

        [Description("Радиус в котором SCP-035 чувствует других SCP")]
        public float ScpDetectionRadius { get; set; } = 20f;

        [Description("Показывать местоположение других SCP на карте")]
        public bool ShowScpLocations { get; set; } = false;
    }

    /// <summary>
    /// Настройки звуковых и визуальных эффектов
    /// </summary>
    public class EffectSettings
    {
        [Description("Воспроизводить звук при успешном контроле")]
        public bool PlayPossessionSound { get; set; } = true;

        [Description("Воспроизводить звук коррозии")]
        public bool PlayCorrosionSound { get; set; } = true;

        [Description("Показывать частицы коррозии")]
        public bool ShowCorrosionParticles { get; set; } = true;

        [Description("Мигание экрана при контроле")]
        public bool FlashScreenOnPossession { get; set; } = true;

        [Description("Цвет мигания экрана (R,G,B,A)")]
        public Color FlashColor { get; set; } = new Color(1f, 0f, 0f, 0.3f);

        [Description("Длительность мигания (в секундах)")]
        public float FlashDuration { get; set; } = 0.5f;
    }

    /// <summary>
    /// Настройки баланса игры
    /// </summary>
    public class BalanceSettings
    {
        [Description("SCP-035 засчитывается как SCP для условий победы")]
        public bool CountAsScpForVictory { get; set; } = true;

        [Description("SCP-035 может быть целью для SCP-049")]
        public bool CanBeTargetedByScp049 { get; set; } = false;

        [Description("SCP-035 может видеть других SCP через стены")]
        public bool CanSeeScpThroughWalls { get; set; } = false;

        [Description("SCP-035 получает очки опыта за контроль")]
        public int ExperiencePerPossession { get; set; } = 10;

        [Description("SCP-035 получает очки опыта за выживание")]
        public int ExperiencePerMinuteAlive { get; set; } = 5;

        [Description("Максимальное время жизни SCP-035 (0 = без ограничений)")]
        public float MaxLifetime { get; set; } = 0f;
    }

    /// <summary>
    /// Настройки совместимости с другими плагинами
    /// </summary>
    public class CompatibilitySettings
    {
        [Description("Совместимость с плагинами кастомных ролей")]
        public bool CustomRolesCompatibility { get; set; } = true;

        [Description("Совместимость с плагинами экономики")]
        public bool EconomyPluginsCompatibility { get; set; } = true;

        [Description("Совместимость с плагинами статистики")]
        public bool StatsPluginsCompatibility { get; set; } = true;

        [Description("Список плагинов для игнорирования конфликтов")]
        public List<string> IgnoredPlugins { get; set; } = new List<string>();

        [Description("Приоритет обработки событий (чем выше, тем раньше)")]
        public int EventPriority { get; set; } = 100;
    }

    /// <summary>
    /// Локализация сообщений
    /// </summary>
    public class LocalizationSettings
    {
        [Description("Язык плагина (ru, en)")]
        public string Language { get; set; } = "ru";

        [Description("Кастомные сообщения плагина")]
        public Dictionary<string, string> CustomMessages { get; set; } = new Dictionary<string, string>
        {
            ["BecameScp035"] = "<color=red>🎭 ВЫ СТАЛИ SCP-035 \"ОДЕРЖИМАЯ МАСКА\"!</color>",
            ["PossessionSuccess"] = "<color=green>✅ Вы контролируете {0}!</color>",
            ["PossessionFailed"] = "<color=red>❌ Цель сопротивляется вашему контролю!</color>",
            ["PossessionEnded"] = "<color=yellow>⏰ Контроль завершён</color>",
            ["BeingPossessed"] = "<color=red>🎭 ВАС КОНТРОЛИРУЕТ SCP-035!</color>",
            ["CorrosionDamage"] = "<color=#ff6666>🧪 Коррозия: -{0} HP</color>",
            ["HealingUsed"] = "<color=green>💉 Восстановлено {0} HP</color>",
            ["NoCooldown"] = "<color=red>⏰ Подождите {0} сек. перед следующей попыткой</color>",
            ["NoTargetsNearby"] = "<color=red>❌ Поблизости нет подходящих целей</color>",
            ["DoorOpened"] = "<color=yellow>🚪 Психические способности открыли дверь</color>",
            ["DeathPossession"] = "<color=red>💀 SCP-035 вселился в ваше тело!</color>"
        };
    }

    /// <summary>
    /// Структура для хранения цвета
    /// </summary>
    public struct Color
    {
        public float R { get; set; }
        public float G { get; set; }
        public float B { get; set; }
        public float A { get; set; }

        public Color(float r, float g, float b, float a)
        {
            R = r;
            G = g;
            B = b;
            A = a;
        }
    }

    /// <summary>
    /// Структура для хранения 3D вектора
    /// </summary>
    public struct Vector3
    {
        public float X { get; set; }
        public float Y { get; set; }
        public float Z { get; set; }

        public Vector3(float x, float y, float z)
        {
            X = x;
            Y = y;
            Z = z;
        }
    }
}
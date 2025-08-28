namespace Scp096Mask.Constants
{
    /// <summary>
    /// Константы для плагина масок SCP-096
    /// </summary>
    public static class MaskConstants
    {
        /// <summary>
        /// Название плагина
        /// </summary>
        public const string PLUGIN_NAME = "SCP-096 Mask";

        /// <summary>
        /// Версия плагина
        /// </summary>
        public const string PLUGIN_VERSION = "1.2.0";

        /// <summary>
        /// Автор плагина
        /// </summary>
        public const string PLUGIN_AUTHOR = "SteamTime";

        /// <summary>
        /// Описание плагина
        /// </summary>
        public const string PLUGIN_DESCRIPTION = "Плагин масок для SCP-096 в SCP: Secret Laboratory";

        /// <summary>
        /// Права доступа
        /// </summary>
        public static class Permissions
        {
            public const string ADMIN = "mask096.admin";
            public const string INFO = "mask096.info";
            public const string USE = "mask096.use";
            public const string SPAWN = "mask096.spawn";
            public const string GIVE = "mask096.give";
            public const string REMOVE = "mask096.remove";
            public const string DEBUG = "mask096.debug";
        }

        /// <summary>
        /// Команды
        /// </summary>
        public static class Commands
        {
            public const string MAIN = "mask096";
            public const string USE = "usemask";
            public const string INFO = "maskinfo";
            
            public static class SubCommands
            {
                public const string HELP = "help";
                public const string SPAWN = "spawn";
                public const string GIVE = "give";
                public const string GIVE_INVENTORY = "giveinv";
                public const string REMOVE = "remove";
                public const string LIST = "list";
                public const string CLEAR = "clear";
                public const string RELOAD = "reload";
                public const string STATS = "stats";
                public const string DEBUG = "debug";
                public const string INFO = "info";
                public const string USE = "use";
                public const string ACTIVATE = "activate";
            }
        }

        /// <summary>
        /// Настройки по умолчанию
        /// </summary>
        public static class Defaults
        {
            public const int MASKS_TO_SPAWN = 5;
            public const float MASK_EQUIP_TIME = 8f;
            public const float INTERACTION_DISTANCE = 3f;
            public const float MIN_MASK_DISTANCE = 15f;
            public const int MAX_SPAWN_ATTEMPTS = 20;
            public const int MAX_MASKS_ON_MAP = 8;
            public const int MIN_PLAYERS_FOR_SPAWN = 5;
            
            // Визуальные настройки
            public const float SCALE_X = 1.5f;
            public const float SCALE_Y = 0.8f;
            public const float SCALE_Z = 1.2f;
            public const float BOBBING_HEIGHT = 0.3f;
            public const float BOBBING_SPEED = 2f;
            public const float ROTATION_SPEED = 30f;
            public const float DEFORMATION_INTENSITY = 0.2f;
            public const float DEFORMATION_SPEED = 1.5f;
            public const float GLOW_INTENSITY = 2f;
        }

        /// <summary>
        /// Сообщения по умолчанию
        /// </summary>
        public static class Messages
        {
            public const string MASK_PICKED_UP = "<color=green>Вы подобрали маску SCP-096!</color>\n<color=yellow>Подойдите к SCP-096 и используйте клавишу взаимодействия</color>";
            public const string NO_MASK = "<color=red>У вас нет маски SCP-096!</color>";
            public const string MASK_NOT_IN_HAND = "<color=orange>Возьмите маску в руку для использования!</color>";
            public const string TOO_FAR_AWAY = "<color=red>Нет SCP-096 поблизости!</color>";
            public const string ALREADY_MASKED = "<color=orange>На этом SCP-096 уже есть маска!</color>";
            public const string MASK_EQUIPPING = "<color=yellow>Одеваем маску на SCP-096...</color>";
            public const string MASK_EQUIPPED = "<color=green>Маска успешно надета на SCP-096!</color>\n<color=cyan>Теперь он не будет агриться на игроков!</color>";
            public const string MASK_REMOVED = "<color=red>С вас сняли маску!</color>";
            public const string MASK_FOUND = "<color=yellow>Вы нашли маску SCP-096!</color>";
        }

        /// <summary>
        /// Цвета
        /// </summary>
        public static class Colors
        {
            public const string DEFAULT_MASK_COLOR = "255,200,200";
            public const string DEFAULT_GLOW_COLOR = "255,150,150";
            public const string SUCCESS_COLOR = "green";
            public const string ERROR_COLOR = "red";
            public const string WARNING_COLOR = "orange";
            public const string INFO_COLOR = "cyan";
            public const string HIGHLIGHT_COLOR = "yellow";
        }

        /// <summary>
        /// Настройки серверных опций
        /// </summary>
        public static class ServerSettings
        {
            public const string KEYBIND_ID = "scp096_mask_interact";
            public const string KEYBIND_LABEL = "Взаимодействие с маской SCP-096";
            public const string KEYBIND_HINT = "Нажмите, чтобы надеть маску на SCP-096";
            public const string HEADER_LABEL = "Маска SCP-096";
        }

        /// <summary>
        /// Лимиты
        /// </summary>
        public static class Limits
        {
            public const int MAX_MASKS_PER_ROOM = 5;
            public const int MAX_TOTAL_MASKS = 20;
            public const int MAX_SPAWN_ATTEMPTS = 50;
            public const int MAX_VISUAL_EFFECTS = 10;
            public const float MAX_INTERACTION_DISTANCE = 10f;
            public const float MIN_INTERACTION_DISTANCE = 1f;
            public const float MAX_EQUIP_TIME = 30f;
            public const float MIN_EQUIP_TIME = 1f;
        }

        /// <summary>
        /// Интервалы времени
        /// </summary>
        public static class Intervals
        {
            public const float VISUAL_EFFECT_UPDATE = 0.1f;
            public const float PROGRESS_UPDATE = 0.2f;
            public const float RESPAWN_CHECK = 300f;
            public const float HINT_DEFAULT_DURATION = 4f;
            public const float HINT_SHORT_DURATION = 2f;
            public const float HINT_LONG_DURATION = 8f;
        }
    }
}
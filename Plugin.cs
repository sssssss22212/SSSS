using Exiled.API.Features;
using Exiled.Events.EventArgs.Player;
using Exiled.Events.EventArgs.Server;
using System;
using System.Collections.Generic;
using PlayerEvents = Exiled.Events.Handlers.Player;
using ServerEvents = Exiled.Events.Handlers.Server;

namespace SCPRoleplayPlugin
{
    /// <summary>
    /// Основной класс плагина для ролевого сервера SCP: Secret Laboratory
    /// </summary>
    public class Plugin : Plugin<Config>
    {
        public override string Name => "SCP Roleplay Plugin";
        public override string Author => "RP Server Team";
        public override Version Version => new Version(1, 0, 0);
        public override string Prefix => "SCPRoleplay";

        // Системы плагина
        public RoleSystem RoleSystem { get; private set; }
        public MoneySystem MoneySystem { get; private set; }
        public ChatSystem ChatSystem { get; private set; }
        public MedicalSystem MedicalSystem { get; private set; }
        public EventHandlers EventHandlers { get; private set; }

        // Статические экземпляры для доступа из других классов
        public static Plugin Instance { get; private set; }
        public static Config PluginConfig => Instance?.Config;

        public override void OnEnabled()
        {
            Instance = this;

            Log.Info($"Загружается {Name} версии {Version}...");

            // Инициализация систем
            InitializeSystems();

            // Регистрация обработчиков событий
            RegisterEvents();

            Log.Info($"{Name} успешно загружен!");
            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            Log.Info($"Выгружается {Name}...");

            // Отмена регистрации событий
            UnregisterEvents();

            // Очистка систем
            CleanupSystems();

            Instance = null;

            Log.Info($"{Name} выгружен!");
            base.OnDisabled();
        }

        /// <summary>
        /// Инициализация всех систем плагина
        /// </summary>
        private void InitializeSystems()
        {
            try
            {
                RoleSystem = new RoleSystem();
                Log.Debug("Система ролей инициализирована");

                if (Config.EnableMoneySystem)
                {
                    MoneySystem = new MoneySystem();
                    Log.Debug("Система денег инициализирована");
                }

                if (Config.EnableRpChannels)
                {
                    ChatSystem = new ChatSystem();
                    Log.Debug("Система чата инициализирована");
                }

                if (Config.EnableMedicalSystem)
                {
                    MedicalSystem = new MedicalSystem();
                    Log.Debug("Медицинская система инициализирована");
                }

                EventHandlers = new EventHandlers();
                Log.Debug("Обработчики событий инициализированы");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при инициализации систем: {ex}");
            }
        }

        /// <summary>
        /// Регистрация обработчиков событий
        /// </summary>
        private void RegisterEvents()
        {
            PlayerEvents.Joined += EventHandlers.OnPlayerJoined;
            PlayerEvents.Left += EventHandlers.OnPlayerLeft;
            PlayerEvents.Spawning += EventHandlers.OnPlayerSpawning;
            PlayerEvents.Dying += EventHandlers.OnPlayerDying;
            PlayerEvents.IntercomSpeaking += EventHandlers.OnIntercomSpeaking;
            ServerEvents.RoundStarted += EventHandlers.OnRoundStarted;
            ServerEvents.RoundEnded += EventHandlers.OnRoundEnded;

            if (Config.EnableRpChannels)
            {
                PlayerEvents.SendingMessage += EventHandlers.OnSendingMessage;
            }

            Log.Debug("События зарегистрированы");
        }

        /// <summary>
        /// Отмена регистрации обработчиков событий
        /// </summary>
        private void UnregisterEvents()
        {
            PlayerEvents.Joined -= EventHandlers.OnPlayerJoined;
            PlayerEvents.Left -= EventHandlers.OnPlayerLeft;
            PlayerEvents.Spawning -= EventHandlers.OnPlayerSpawning;
            PlayerEvents.Dying -= EventHandlers.OnPlayerDying;
            PlayerEvents.IntercomSpeaking -= EventHandlers.OnIntercomSpeaking;
            ServerEvents.RoundStarted -= EventHandlers.OnRoundStarted;
            ServerEvents.RoundEnded -= EventHandlers.OnRoundEnded;

            if (Config.EnableRpChannels)
            {
                PlayerEvents.SendingMessage -= EventHandlers.OnSendingMessage;
            }

            Log.Debug("События отменены");
        }

        /// <summary>
        /// Очистка систем при выгрузке плагина
        /// </summary>
        private void CleanupSystems()
        {
            RoleSystem?.Cleanup();
            MoneySystem?.Cleanup();
            ChatSystem?.Cleanup();
            MedicalSystem?.Cleanup();
            EventHandlers?.Cleanup();
        }
    }
}
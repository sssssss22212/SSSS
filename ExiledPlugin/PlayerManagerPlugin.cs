using System;
using Exiled.API.Features;
using Exiled.API.Interfaces;

namespace PlayerManagerPlugin
{
    /// <summary>
    /// Основной класс плагина для управления игроками
    /// </summary>
    public class PlayerManagerPlugin : Plugin<Config>
    {
        /// <summary>
        /// Экземпляр плагина
        /// </summary>
        public static PlayerManagerPlugin Instance { get; private set; }

        /// <summary>
        /// Обработчик событий
        /// </summary>
        public EventHandlers EventHandlers { get; private set; }

        /// <summary>
        /// Название плагина
        /// </summary>
        public override string Name => "PlayerManager";

        /// <summary>
        /// Автор плагина
        /// </summary>
        public override string Author => "YourName";

        /// <summary>
        /// Версия плагина
        /// </summary>
        public override Version Version => new Version(1, 0, 0);

        /// <summary>
        /// Минимальная версия Exiled
        /// </summary>
        public override Version RequiredExiledVersion => new Version(8, 0, 0);

        /// <summary>
        /// Описание плагина
        /// </summary>
        public override string Description => "Плагин для управления игроками с расширенными функциями";

        /// <summary>
        /// Включение плагина
        /// </summary>
        public override void OnEnabled()
        {
            Instance = this;
            EventHandlers = new EventHandlers();

            // Регистрируем обработчики событий
            Exiled.Events.Player.Verified += EventHandlers.OnPlayerVerified;
            Exiled.Events.Player.Left += EventHandlers.OnPlayerLeft;
            Exiled.Events.Player.Dying += EventHandlers.OnPlayerDying;
            Exiled.Events.Player.Spawning += EventHandlers.OnPlayerSpawning;
            Exiled.Events.Server.RoundStarted += EventHandlers.OnRoundStarted;
            Exiled.Events.Server.RoundEnded += EventHandlers.OnRoundEnded;

            Log.Info($"Плагин {Name} версии {Version} успешно загружен!");
            base.OnEnabled();
        }

        /// <summary>
        /// Отключение плагина
        /// </summary>
        public override void OnDisabled()
        {
            // Отменяем регистрацию обработчиков событий
            Exiled.Events.Player.Verified -= EventHandlers.OnPlayerVerified;
            Exiled.Events.Player.Left -= EventHandlers.OnPlayerLeft;
            Exiled.Events.Player.Dying -= EventHandlers.OnPlayerDying;
            Exiled.Events.Player.Spawning -= EventHandlers.OnPlayerSpawning;
            Exiled.Events.Server.RoundStarted -= EventHandlers.OnRoundStarted;
            Exiled.Events.Server.RoundEnded -= EventHandlers.OnRoundEnded;

            EventHandlers = null;
            Instance = null;

            Log.Info($"Плагин {Name} выгружен!");
            base.OnDisabled();
        }
    }
}
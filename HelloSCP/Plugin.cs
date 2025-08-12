using Exiled.API.Features;
using System;

namespace HelloSCP
{
    public sealed class Plugin : Plugin<PluginConfig>
    {
        public override string Author => "YourName";
        public override string Name => "HelloSCP";
        public override string Prefix => "HelloSCP";
        public override Version Version => new Version(1, 0, 0);
        public override Version RequiredExiledVersion => new Version(8, 0, 0);

        public static Plugin Instance { get; private set; }

        private EventHandlers _eventHandlers;

        public override void OnEnabled()
        {
            Instance = this;
            _eventHandlers = new EventHandlers();

            // Player events
            Exiled.Events.Handlers.Player.Verified += _eventHandlers.OnPlayerVerified;

            // Server/Round events
            Exiled.Events.Handlers.Server.RoundStarted += _eventHandlers.OnRoundStarted;

            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            // Unsubscribe
            Exiled.Events.Handlers.Player.Verified -= _eventHandlers.OnPlayerVerified;
            Exiled.Events.Handlers.Server.RoundStarted -= _eventHandlers.OnRoundStarted;

            _eventHandlers = null;
            Instance = null;

            base.OnDisabled();
        }
    }
}
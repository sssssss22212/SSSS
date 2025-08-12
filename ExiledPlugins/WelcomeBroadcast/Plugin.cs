using System;
using Exiled.API.Features;
using Exiled.Events.EventArgs.Player;
using Player = Exiled.API.Features.Player;

namespace WelcomeBroadcast
{
    public class Plugin : Plugin<Config>
    {
        public override string Name => "WelcomeBroadcast";
        public override string Author => "YourName";
        public override Version Version => new Version(1, 0, 0);
        public override Version RequiredExiledVersion => new Version(8, 8, 1);

        private EventHandlers? _handlers;

        public override void OnEnabled()
        {
            _handlers = new EventHandlers(Config);
            Exiled.Events.Handlers.Player.Verified += _handlers.OnVerified;
            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            Exiled.Events.Handlers.Player.Verified -= _handlers!.OnVerified;
            _handlers = null;
            base.OnDisabled();
        }
    }

    internal sealed class EventHandlers
    {
        private readonly Config _config;

        public EventHandlers(Config config)
        {
            _config = config;
        }

        public void OnVerified(VerifiedEventArgs ev)
        {
            if (!_config.IsEnabled)
                return;

            string message = _config.WelcomeMessage
                .Replace("{player}", ev.Player.Nickname)
                .Replace("{server}", Server.Name);

            ev.Player.Broadcast(_config.BroadcastDurationSeconds, message, Broadcast.BroadcastFlags.Normal, true);

            if (_config.LogToConsole)
            {
                Log.Info($"Отправлено приветствие игроку {ev.Player.Nickname}");
            }
        }
    }
}
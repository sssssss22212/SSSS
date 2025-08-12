using System;
using Exiled.API.Features;
using Exiled.API.Interfaces;

namespace RpPlugin
{
    public sealed class RoleplayPlugin : Plugin<RoleplayConfig>
    {
        public override string Name => "RoleplayPlugin";
        public override string Prefix => "rp";
        public override string Author => "Cursor-GPT";
        public override Version Version => new Version(1, 0, 0);
        public override Version RequiredExiledVersion => new Version(8, 8, 0);

        public static RoleplayPlugin Instance { get; private set; } = null!;
        private EventHandlers _handlers = null!;

        internal EventHandlers Handlers => _handlers;

        public bool IsRpModeEnabled
        {
            get => Config.IsRpModeEnabled;
            set => Config.IsRpModeEnabled = value;
        }

        public override void OnEnabled()
        {
            Instance = this;
            _handlers = new EventHandlers(Config);

            RegisterEvents();
            base.OnEnabled();
            Log.Info($"{Name} enabled. RP mode: {(IsRpModeEnabled ? "ON" : "OFF")}");
        }

        public override void OnDisabled()
        {
            UnregisterEvents();
            _handlers = null!;
            base.OnDisabled();
            Log.Info($"{Name} disabled");
        }

        private void RegisterEvents()
        {
            Exiled.Events.Handlers.Player.Verified += _handlers.OnPlayerVerified;
            Exiled.Events.Handlers.Player.Hurting += _handlers.OnHurting;
            Exiled.Events.Handlers.Player.Dying += _handlers.OnDying;
            Exiled.Events.Handlers.Player.ChangingRole += _handlers.OnRoleChanged;
            Exiled.Events.Handlers.Server.RoundStarted += _handlers.OnRoundStarted;
        }

        private void UnregisterEvents()
        {
            Exiled.Events.Handlers.Player.Verified -= _handlers.OnPlayerVerified;
            Exiled.Events.Handlers.Player.Hurting -= _handlers.OnHurting;
            Exiled.Events.Handlers.Player.Dying -= _handlers.OnDying;
            Exiled.Events.Handlers.Player.ChangingRole -= _handlers.OnRoleChanged;
            Exiled.Events.Handlers.Server.RoundStarted -= _handlers.OnRoundStarted;
        }
    }
}
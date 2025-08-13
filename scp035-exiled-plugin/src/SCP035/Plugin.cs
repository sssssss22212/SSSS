using System;
using Exiled.API.Features;
using PlayerHandlers = Exiled.Events.Handlers.Player;
using ServerHandlers = Exiled.Events.Handlers.Server;

namespace SCP035
{
    public class Plugin : Plugin<Config>
    {
        public override string Name => "SCP035";
        public override string Author => "Cursor-GPT";
        public override string Prefix => "SCP035";
        public override Version Version => new Version(1, 0, 0);
        public override Version RequiredExiledVersion => new Version(8, 0, 0);

        public static Plugin Instance { get; private set; } = null!;

        private SCP035Manager _manager = null!;

        public override void OnEnabled()
        {
            Instance = this;
            _manager = new SCP035Manager();

            ServerHandlers.WaitingForPlayers += _manager.OnWaitingForPlayers;
            ServerHandlers.RoundStarted += _manager.OnRoundStarted;
            ServerHandlers.RoundEnded += _manager.OnRoundEnded;

            PlayerHandlers.PickingUpItem += _manager.OnPickingUpItem;
            PlayerHandlers.Dying += _manager.OnDying;
            PlayerHandlers.ChangingRole += _manager.OnChangingRole;
            PlayerHandlers.Hurting += _manager.OnHurting;

            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            ServerHandlers.WaitingForPlayers -= _manager.OnWaitingForPlayers;
            ServerHandlers.RoundStarted -= _manager.OnRoundStarted;
            ServerHandlers.RoundEnded -= _manager.OnRoundEnded;

            PlayerHandlers.PickingUpItem -= _manager.OnPickingUpItem;
            PlayerHandlers.Dying -= _manager.OnDying;
            PlayerHandlers.ChangingRole -= _manager.OnChangingRole;
            PlayerHandlers.Hurting -= _manager.OnHurting;

            Instance = null!;
            _manager = null!;

            base.OnDisabled();
        }
    }
}
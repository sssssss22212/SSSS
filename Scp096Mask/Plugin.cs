using System;
using System.Collections.Generic;
using Exiled.API.Features;
using Exiled.API.Features.Core.UserSettings;
using Exiled.API.Interfaces;

namespace Scp096Mask
{
    public class Plugin : Plugin<Config>
    {
        public override string Name => "Scp096Mask";
        public override string Author => "SteamTime";
        public override Version Version => new(1, 0, 0);
        public override Version RequiredExiledVersion => new(9, 6, 1);

        internal static Plugin Instance;
        private EventHandlers _eventHandlers;

        public override void OnEnabled()
        {
            Instance = this;

            _eventHandlers = new EventHandlers(Config);
            _eventHandlers.RegisterEvents();

            HeaderSetting header = new(Config.SettingHeaderLabel);
            IEnumerable<SettingBase> settings = new SettingBase[]
            {
                new KeybindSetting(Config.KeybindId, Config.KeybindLabel, default, hintDescription: Config.KeybindHint),
            };

            SettingBase.Register(settings);
            SettingBase.SendToAll();

            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            _eventHandlers?.UnregisterEvents();
            _eventHandlers = null;

            Instance = null;
            base.OnDisabled();
        }
    }
}
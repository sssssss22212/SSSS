using System;
using System.Collections.Generic;
using Exiled.API.Features;
using Exiled.API.Features.Core.UserSettings;
using Scp096Mask.Enums;

namespace Scp096Mask
{
    public class Plugin : Plugin<Config>
    {
        public override string Name => "Scp096Mask";
        public override string Author => "SteamTime";
        public override Version Version => new Version(1, 0, 0);
        public override Version RequiredExiledVersion => new Version(9, 6, 1);

        public static Plugin Instance;
        internal EventHandlers _eventHandlers;

        public override void OnEnabled()
        {
            Instance = this;
            
            _eventHandlers = new EventHandlers(Config);
            _eventHandlers.RegisterEvents();

            if (Config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                HeaderSetting header = new HeaderSetting(Config.SettingHeaderLabel);
                IEnumerable<SettingBase> settingBases = new SettingBase[]
                {
                    new KeybindSetting(Config.KeybindId, Config.KeybindLabel, default, hintDescription: Config.KeybindHint),
                };

                SettingBase.Register(settingBases);
                SettingBase.SendToAll();
            }

            Log.Info("Плагин маски SCP-096 загружен!");
            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            _eventHandlers?.UnregisterEvents();
            Instance = null;
            Log.Info("Плагин маски SCP-096 выключен.");
            base.OnDisabled();
        }
    }
}
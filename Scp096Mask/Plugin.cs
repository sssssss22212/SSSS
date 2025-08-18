using System;
using System.Collections.Generic;
using Exiled.API.Features;
using Exiled.API.Features.Core.UserSettings;
using HarmonyLib;
using Scp096Mask.Enums;

namespace Scp096Mask
{
	public sealed class Plugin : Plugin<Config>
	{
		public override string Name => "Scp096Mask";
		public override string Author => "SteamTime";
		public override Version Version => new Version(1, 0, 0);
		public override Version RequiredExiledVersion => new Version(9, 6, 1);

		public static Plugin Instance;
		internal EventHandlers _eventHandlers;
		private Harmony _harmony;

		public override void OnEnabled()
		{
			Instance = this;

			_eventHandlers = new EventHandlers(Config);
			_eventHandlers.RegisterEvents();

			_harmony = new Harmony("Scp096Mask.Harmony");
			_harmony.PatchAll();

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
			_eventHandlers = null;

			try
			{
				_harmony?.UnpatchAll(_harmony?.Id);
			}
			catch (Exception)
			{
				// ignore
			}
			_harmony = null;

			Instance = null;
			Log.Info("Плагин маски SCP-096 выключен.");
			base.OnDisabled();
		}
	}
}
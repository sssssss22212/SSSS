using System;
using System.Collections.Generic;
using Exiled.API.Features;
using Exiled.API.Features.Core.UserSettings;
using HarmonyLib;
using Scp096Mask.Enums;

namespace Scp096Mask
{
    public class Plugin : Plugin<Config>
    {
        public override string Name => "Scp096Mask";
        public override string Author => "SteamTime";
        public override Version Version => new Version(1, 2, 0);
        public override Version RequiredExiledVersion => new Version(9, 6, 1);

        public static Plugin Instance;
        internal EventHandlers _eventHandlers;
        private Harmony _harmony;

        public override void OnEnabled()
        {
            Instance = this;

            // Инициализация Harmony для патчей
            _harmony = new Harmony($"Scp096Mask-{DateTime.Now.Ticks}");
            _harmony.PatchAll();

            _eventHandlers = new EventHandlers(Config);
            _eventHandlers.RegisterEvents();

            if (Config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                HeaderSetting header = new HeaderSetting(Config.SettingHeaderLabel);
                IEnumerable<SettingBase> settingBases = new SettingBase[]
                {
                    header,
                    new KeybindSetting(Config.KeybindId, Config.KeybindLabel, UnityEngine.KeyCode.None, hintDescription: Config.KeybindHint),
                };
                SettingBase.Register(settingBases);
                SettingBase.SendToAll();
            }

            Log.Info($"Плагин маски SCP-096 версии {Version} загружен!");
            Log.Info($"Автор: {Author}");
            
            if (Config.Debug)
            {
                Log.Debug("Режим отладки включен");
                Log.Debug($"Тип активации: {Config.ActivationType}");
                Log.Debug($"Автоспавн: {Config.AutoSpawnEnabled}");
                Log.Debug($"Количество масок для спавна: {Config.MasksToSpawn}");
            }

            base.OnEnabled();
        }

        public override void OnDisabled()
        {
            _eventHandlers?.UnregisterEvents();
            _eventHandlers = null;

            // Удаление патчей Harmony
            _harmony?.UnpatchAll();
            _harmony = null;

            // Очистка серверных настроек
            if (Config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                try
                {
                    // Убираем UnregisterAll так как этого метода может не быть
                    // SettingBase.UnregisterAll();
                }
                catch (Exception ex)
                {
                    Log.Debug($"Ошибка при удалении настроек: {ex}");
                }
            }

            Instance = null;
            Log.Info("Плагин маски SCP-096 выключен.");
            base.OnDisabled();
        }

        public override void OnReloaded()
        {
            Log.Info("Плагин маски SCP-096 перезагружен!");
            base.OnReloaded();
        }
    }
}
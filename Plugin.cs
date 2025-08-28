using System;
using System.Collections.Generic;
using Exiled.API.Features;
using Exiled.API.Features.Core.UserSettings;
using HarmonyLib;
using Scp096Mask.Enums;
using UnityEngine;
using MEC;

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
            _harmony = new Harmony(string.Format("Scp096Mask-{0}", DateTime.Now.Ticks));
            _harmony.PatchAll();

            _eventHandlers = new EventHandlers(Config);
            _eventHandlers.RegisterEvents();

            // Регистрация серверных настроек
            if (Config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                try
                {
                    RegisterServerSpecificSettings();
                }
                catch (Exception ex)
                {
                    Log.Error(string.Format("Ошибка регистрации серверных настроек: {0}", ex));
                }
            }

            Log.Info(string.Format("Плагин маски SCP-096 версии {0} загружен!", Version));
            Log.Info(string.Format("Автор: {0}", Author));
            
            if (Config.Debug)
            {
                Log.Debug("Режим отладки включен");
                Log.Debug(string.Format("Тип активации: {0}", Config.ActivationType));
                Log.Debug(string.Format("Автоспавн: {0}", Config.AutoSpawnEnabled));
                Log.Debug(string.Format("Количество масок для спавна: {0}", Config.MasksToSpawn));
                Log.Debug(string.Format("Визуальные настройки - ScaleX: {0}, ScaleY: {1}, ScaleZ: {2}", 
                    Config.VisualSettings.ScaleX, Config.VisualSettings.ScaleY, Config.VisualSettings.ScaleZ));
            }

            base.OnEnabled();
        }

        private void RegisterServerSpecificSettings()
        {
            try
            {
                // Создаем заголовок секции
                HeaderSetting headerSetting = new HeaderSetting(Config.SettingHeaderLabel);
                
                // Создаем настройку клавиши
                KeybindSetting keybindSetting = new KeybindSetting(
                    Config.KeybindId, 
                    Config.KeybindLabel, 
                    KeyCode.X, // Клавиша по умолчанию
                    hintDescription: Config.KeybindHint
                );

                // Регистрируем настройки
                List<SettingBase> settings = new List<SettingBase>
                {
                    headerSetting,
                    keybindSetting
                };

                SettingBase.Register(settings);

                // Отправляем настройки всем подключенным игрокам
                Timing.CallDelayed(1f, () =>
                {
                    foreach (var player in Player.List)
                    {
                        try
                        {
                            SettingBase.SendToPlayer(player.ReferenceHub);
                        }
                        catch (Exception ex)
                        {
                            if (Config.Debug)
                                Log.Debug(string.Format("Ошибка отправки настроек игроку {0}: {1}", player.Nickname, ex));
                        }
                    }
                });

                Log.Info("Серверные настройки успешно зарегистрированы!");
            }
            catch (Exception ex)
            {
                Log.Error(string.Format("Критическая ошибка при регистрации серверных настроек: {0}", ex));
            }
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
                    // Попытка очистки настроек (если доступно)
                    Log.Debug("Очистка серверных настроек");
                }
                catch (Exception ex)
                {
                    Log.Debug(string.Format("Ошибка при удалении настроек: {0}", ex));
                }
            }

            Instance = null;
            Log.Info("Плагин маски SCP-096 выключен.");
            base.OnDisabled();
        }

        public override void OnReloaded()
        {
            Log.Info("Плагин маски SCP-096 перезагружен!");
            
            // Перерегистрируем серверные настройки
            if (Config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                RegisterServerSpecificSettings();
            }
            
            base.OnReloaded();
        }
    }
}
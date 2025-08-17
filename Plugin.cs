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
            _harmony = new Harmony($"Scp096Mask-{DateTime.Now.Ticks}");
            _harmony.PatchAll();

            _eventHandlers = new EventHandlers(Config);
            _eventHandlers.RegisterEvents();

            // Регистрация команд
            try
            {
                CommandHandler.RegisterCommands();
                CommandHandler.TestCommands();
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка регистрации команд: {ex}");
            }

            // Регистрация серверных настроек
            if (Config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                try
                {
                    RegisterServerSpecificSettings();
                }
                catch (Exception ex)
                {
                    Log.Error($"Ошибка регистрации серверных настроек: {ex}");
                }
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
                                Log.Debug($"Ошибка отправки настроек игроку {player.Nickname}: {ex}");
                        }
                    }
                });

                Log.Info("Серверные настройки успешно зарегистрированы!");
            }
            catch (Exception ex)
            {
                Log.Error($"Критическая ошибка при регистрации серверных настроек: {ex}");
            }
        }

        public override void OnDisabled()
        {
            _eventHandlers?.UnregisterEvents();
            _eventHandlers = null;

            // Отмена регистрации команд
            try
            {
                CommandHandler.UnregisterCommands();
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка отмены регистрации команд: {ex}");
            }

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
            
            // Перерегистрируем команды
            try
            {
                CommandHandler.RegisterCommands();
                Log.Info("Команды перерегистрированы");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка перерегистрации команд: {ex}");
            }
            
            // Перерегистрируем серверные настройки
            if (Config.ActivationType == ActivationType.ServerSpecificSettings)
            {
                RegisterServerSpecificSettings();
            }
            
            base.OnReloaded();
        }
    }
}
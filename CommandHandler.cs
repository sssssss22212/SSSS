using System;
using CommandSystem;
using Exiled.API.Features;

namespace Scp096Mask
{
    /// <summary>
    /// Обработчик команд для плагина масок SCP-096
    /// Обеспечивает правильную регистрацию команд в системе
    /// </summary>
    public static class CommandHandler
    {
        /// <summary>
        /// Регистрирует все команды плагина
        /// </summary>
        public static void RegisterCommands()
        {
            try
            {
                // Регистрируем основную команду
                var mainCommand = new Commands.MaskCommands();
                Log.Info($"Регистрация основной команды: {mainCommand.Command}");
                
                // Регистрируем команду быстрого использования
                var useCommand = new Commands.UseMaskCommand();
                Log.Info($"Регистрация команды использования: {useCommand.Command}");
                
                // Регистрируем команду информации
                var infoCommand = new Commands.MaskInfoCommand();
                Log.Info($"Регистрация команды информации: {infoCommand.Command}");
                
                Log.Info("Все команды плагина масок SCP-096 зарегистрированы!");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при регистрации команд: {ex}");
            }
        }

        /// <summary>
        /// Отменяет регистрацию команд
        /// </summary>
        public static void UnregisterCommands()
        {
            try
            {
                Log.Info("Команды плагина масок SCP-096 отменены");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при отмене регистрации команд: {ex}");
            }
        }

        /// <summary>
        /// Проверяет доступность команд
        /// </summary>
        public static void TestCommands()
        {
            try
            {
                Log.Info("=== Тест команд плагина масок SCP-096 ===");
                Log.Info("Доступные команды:");
                Log.Info("- mask096 (основная команда)");
                Log.Info("- usemask (быстрое использование)");
                Log.Info("- maskinfo (информация)");
                Log.Info("=== Конец теста команд ===");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при тестировании команд: {ex}");
            }
        }
    }
}
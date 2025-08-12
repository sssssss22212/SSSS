using CommandSystem;
using Exiled.API.Features;
using System;

namespace SCPRoleplayPlugin.Commands
{
    /// <summary>
    /// Основная команда помощи для RP плагина
    /// </summary>
    [CommandHandler(typeof(ClientCommandHandler))]
    public class HelpCommand : ICommand
    {
        public string Command => "rphelp";
        public string[] Aliases => new[] { "rph", "помощь" };
        public string Description => "Помощь по ролевому серверу";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            try
            {
                var player = Player.Get(sender);
                if (player == null)
                {
                    response = "Эта команда доступна только игрокам!";
                    return false;
                }

                response = GetHelpText();
                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в команде rphelp: {ex}");
                response = "Произошла ошибка при выполнении команды!";
                return false;
            }
        }

        /// <summary>
        /// Получить текст справки
        /// </summary>
        private string GetHelpText()
        {
            var help = "=== СПРАВКА ПО РОЛЕВОМУ СЕРВЕРУ SCP:SL ===\n\n";

            help += "🎭 СИСТЕМА РОЛЕЙ:\n";
            help += "!role - управление ролями\n";
            help += "!role list - список доступных ролей\n";
            help += "!role my - ваши роли\n";
            help += "!role info <id> - информация о роли\n\n";

            if (Plugin.PluginConfig.EnableMoneySystem)
            {
                help += "💰 ДЕНЕЖНАЯ СИСТЕМА:\n";
                help += "!money - управление деньгами\n";
                help += "!money balance - ваш баланс\n";
                help += "!money transfer <игрок> <сумма> - перевести деньги\n";
                help += "!money top - топ богатых игроков\n";
                help += "!money history - история транзакций\n\n";
            }

            if (Plugin.PluginConfig.EnableMedicalSystem)
            {
                help += "🏥 МЕДИЦИНСКАЯ СИСТЕМА:\n";
                help += "!medical - медицинские команды\n";
                help += "!medical status - ваше состояние здоровья\n";
                help += "!medical checkup <игрок> - провести осмотр\n";
                help += "!medical heal <игрок> <номер> - лечить травму\n\n";
            }

            if (Plugin.PluginConfig.EnableRpChannels)
            {
                help += "💬 СИСТЕМА ЧАТА:\n";
                help += "/me [действие] - описание ваших действий\n";
                help += "/do [описание] - описание окружения\n";
                help += "/local [сообщение] или /l - локальный чат\n";
                help += "/whisper [сообщение] или /w - шепот\n";
                help += "/shout [сообщение] или /s - крик\n";
                help += "/radio [сообщение] или /r - радиосвязь\n";
                help += "((сообщение)) или [OOC] - чат вне роли\n\n";
            }

            help += "📋 ОСНОВНЫЕ ПРАВИЛА:\n";
            help += "• Играйте в соответствии с вашей ролью\n";
            help += "• Используйте подходящие каналы чата\n";
            help += "• Уважайте других игроков\n";
            help += "• Следуйте указаниям администрации\n\n";

            help += "ℹ️ ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ:\n";
            help += "• Роли влияют на ваши возможности в игре\n";
            help += "• За выполнение заданий вы получаете деньги\n";
            help += "• Медицинская система влияет на геймплей\n";
            help += "• Используйте правильные каналы связи\n\n";

            help += "🔧 ВЕРСИЯ ПЛАГИНА: " + Plugin.Instance.Version + "\n";
            help += "==========================================";

            return help;
        }
    }
}
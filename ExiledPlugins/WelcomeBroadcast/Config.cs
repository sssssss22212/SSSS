using Exiled.API.Interfaces;
using System.ComponentModel;

namespace WelcomeBroadcast
{
    public sealed class Config : IConfig
    {
        [Description("Включен ли плагин")] 
        public bool IsEnabled { get; set; } = true;

        [Description("Писать ли лог в консоль при отправке сообщения")] 
        public bool LogToConsole { get; set; } = true;

        [Description("Текст приветствия. Подстановки: {player}, {server}")]
        public string WelcomeMessage { get; set; } = "Добро пожаловать, {player}, на сервер {server}!";

        [Description("Длительность показа приветствия в секундах")] 
        public ushort BroadcastDurationSeconds { get; set; } = 7;
    }
}
using Exiled.API.Interfaces;

namespace HelloSCP
{
    public sealed class PluginConfig : IConfig
    {
        public bool IsEnabled { get; set; } = true;
        public bool Debug { get; set; } = false;

        public string WelcomeMessage { get; set; } = "Привет, {player}! Удачной игры на сервере!";
        public ushort WelcomeDurationSeconds { get; set; } = 5;

        public bool AnnounceRoundStart { get; set; } = true;
    }
}
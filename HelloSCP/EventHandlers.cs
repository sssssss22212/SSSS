using Exiled.API.Features;
using PlayerRoles;

namespace HelloSCP
{
    public sealed class EventHandlers
    {
        public void OnPlayerVerified(Exiled.Events.EventArgs.Player.VerifiedEventArgs ev)
        {
            var config = Plugin.Instance?.Config;
            if (config == null || !config.IsEnabled)
                return;

            string message = config.WelcomeMessage
                .Replace("{player}", ev.Player.Nickname);

            ev.Player.Broadcast(config.WelcomeDurationSeconds, message);
        }

        public void OnRoundStarted()
        {
            var config = Plugin.Instance?.Config;
            if (config == null || !config.IsEnabled || !config.AnnounceRoundStart)
                return;

            Map.Broadcast(6, "Раунд начался! Удачи всем игрокам.");
        }
    }
}
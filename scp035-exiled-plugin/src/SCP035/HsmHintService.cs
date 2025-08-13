using Exiled.API.Features;

namespace SCP035
{
    internal static class HsmHintService
    {
        public static void Show(Player player, string message, float durationSeconds, bool enabled)
        {
            if (!enabled || player == null || !player.IsConnected || string.IsNullOrEmpty(message))
                return;

            player.ShowHint(message, durationSeconds);
        }
    }
}
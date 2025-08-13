using System.Linq;
using Exiled.API.Features;
using Exiled.API.Enums;

namespace SCP035
{
    public static class PluginUtils
    {
        public static void ForceBecome035(Player player)
        {
            if (player == null || !player.IsAlive)
                return;

            if (!player.Items.Any(i => i.Type == ItemType.SCP268))
                player.AddItem(ItemType.SCP268);

            var method = typeof(Plugin).GetMethod("BecomeScp035", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            method?.Invoke(Plugin.Instance, new object[] { player });
        }
    }
}
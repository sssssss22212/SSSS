using System;
using HarmonyLib;
using Exiled.API.Features;
using PlayerRoles.PlayableScps.Scp096;

namespace Scp096Mask.Patches
{
    [HarmonyPatch(typeof(Scp096TargetsTracker), nameof(Scp096TargetsTracker.AddTarget))]
    public static class Scp096AddTargetPatch
    {
        public static bool Prefix(Scp096TargetsTracker __instance, ReferenceHub target)
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return true;

                var scp096Player = Player.Get(__instance.Owner);
                if (scp096Player == null)
                    return true;

                if (Plugin.Instance._eventHandlers.IsScp096Masked(scp096Player))
                {
                    if (Plugin.Instance.Config.Debug)
                        Log.Debug($"SCP-096 {scp096Player.Nickname} с маской не агрится на {Player.Get(target)?.Nickname}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в Scp096AddTargetPatch: {ex}");
                return true;
            }
        }
    }

    [HarmonyPatch(typeof(Scp096TargetsTracker), nameof(Scp096TargetsTracker.IsObservedBy))]
    public static class Scp096IsObservedByPatch
    {
        public static bool Prefix(Scp096TargetsTracker __instance, ReferenceHub target, ref bool __result)
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return true;

                var scp096Player = Player.Get(__instance.Owner);
                if (scp096Player == null)
                    return true;

                if (Plugin.Instance._eventHandlers.IsScp096Masked(scp096Player))
                {
                    __result = false;
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в Scp096IsObservedByPatch: {ex}");
                return true;
            }
        }
    }

    [HarmonyPatch(typeof(Scp096RageManager), nameof(Scp096RageManager.ServerEnrage))]
    public static class Scp096RagePatch
    {
        public static bool Prefix(Scp096RageManager __instance, float duration = -1f)
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return true;

                var scp096Player = Player.Get(__instance.Owner);
                if (scp096Player == null)
                    return true;

                if (Plugin.Instance._eventHandlers.IsScp096Masked(scp096Player))
                {
                    if (Plugin.Instance.Config.Debug)
                        Log.Debug($"SCP-096 {scp096Player.Nickname} с маской не может агриться");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в Scp096RagePatch: {ex}");
                return true;
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using Exiled.API.Features;
using Exiled.API.Features.Pickups;
using Exiled.API.Features.Items;
using UnityEngine;
using Scp096Mask.Events;

namespace Scp096Mask.API
{
    /// <summary>
    /// API для работы с масками SCP-096
    /// </summary>
    public static class MaskAPI
    {
        /// <summary>
        /// Событие подбора маски
        /// </summary>
        public static event Action<MaskPickedUpEventArgs> MaskPickedUp;

        /// <summary>
        /// Событие выбрасывания маски
        /// </summary>
        public static event Action<MaskDroppedEventArgs> MaskDropped;

        /// <summary>
        /// Событие начала одевания маски
        /// </summary>
        public static event Action<MaskEquippingStartedEventArgs> MaskEquippingStarted;

        /// <summary>
        /// Событие успешного одевания маски
        /// </summary>
        public static event Action<MaskEquippedEventArgs> MaskEquipped;

        /// <summary>
        /// Событие снятия маски
        /// </summary>
        public static event Action<MaskRemovedEventArgs> MaskRemoved;

        /// <summary>
        /// Событие спавна маски
        /// </summary>
        public static event Action<MaskSpawnedEventArgs> MaskSpawned;

        /// <summary>
        /// Событие уничтожения маски
        /// </summary>
        public static event Action<MaskDestroyedEventArgs> MaskDestroyed;

        /// <summary>
        /// Проверяет, есть ли у игрока маска
        /// </summary>
        /// <param name="player">Игрок для проверки</param>
        /// <returns>True если у игрока есть маска</returns>
        public static bool HasMask(Player player)
        {
            try
            {
                if (player == null || Plugin.Instance?._eventHandlers == null)
                    return false;

                return Plugin.Instance._eventHandlers.HasMask(player);
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.HasMask: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Проверяет, замаскирован ли SCP-096
        /// </summary>
        /// <param name="scp096">SCP-096 для проверки</param>
        /// <returns>True если SCP-096 замаскирован</returns>
        public static bool IsScp096Masked(Player scp096)
        {
            try
            {
                if (scp096 == null || Plugin.Instance?._eventHandlers == null)
                    return false;

                return Plugin.Instance._eventHandlers.IsScp096Masked(scp096);
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.IsScp096Masked: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Выдает маску игроку в инвентарь
        /// </summary>
        /// <param name="player">Игрок</param>
        /// <returns>True если маска успешно выдана</returns>
        public static bool GiveMask(Player player)
        {
            try
            {
                if (player == null || !player.IsAlive || Plugin.Instance?._eventHandlers == null)
                    return false;

                if (HasMask(player))
                    return false;

                var medkit = player.AddItem(ItemType.Medkit);
                Plugin.Instance._eventHandlers.AddPlayerMask(player, medkit);
                return true;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.GiveMask: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Создает маску в указанной позиции
        /// </summary>
        /// <param name="position">Позиция для создания</param>
        /// <returns>Pickup маски или null при ошибке</returns>
        public static Pickup SpawnMask(Vector3 position)
        {
            try
            {
                var pickup = Pickup.CreateAndSpawn(ItemType.Medkit, position, Quaternion.identity);
                
                if (pickup != null && Plugin.Instance?._eventHandlers != null)
                {
                    Plugin.Instance._eventHandlers.spawnedMasks.Add(pickup);
                    
                    // Применяем визуальные эффекты
                    var methodInfo = typeof(EventHandlers).GetMethod("ApplyMaskVisualEffects", 
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                    methodInfo?.Invoke(Plugin.Instance._eventHandlers, new object[] { pickup });

                    // Вызываем событие
                    var room = Room.FindParentRoom(position);
                    OnMaskSpawned(new MaskSpawnedEventArgs(pickup, room));
                }

                return pickup;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.SpawnMask: " + ex.ToString());
                return null;
            }
        }

        /// <summary>
        /// Снимает маску с SCP-096
        /// </summary>
        /// <param name="scp096">SCP-096</param>
        /// <returns>True если маска успешно снята</returns>
        public static bool RemoveMask(Player scp096)
        {
            try
            {
                if (scp096 == null || Plugin.Instance?._eventHandlers == null)
                    return false;

                if (!IsScp096Masked(scp096))
                    return false;

                Plugin.Instance._eventHandlers.RemoveMaskFromScp096(scp096);
                OnMaskRemoved(new MaskRemovedEventArgs(scp096));
                return true;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.RemoveMask: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Получает количество масок на карте
        /// </summary>
        /// <returns>Количество масок</returns>
        public static int GetMaskCount()
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return 0;

                return Plugin.Instance._eventHandlers.GetMaskCount();
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.GetMaskCount: " + ex.ToString());
                return 0;
            }
        }

        /// <summary>
        /// Получает количество замаскированных SCP-096
        /// </summary>
        /// <returns>Количество замаскированных SCP-096</returns>
        public static int GetMaskedScp096Count()
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return 0;

                return Plugin.Instance._eventHandlers.GetMaskedScp096Count();
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.GetMaskedScp096Count: " + ex.ToString());
                return 0;
            }
        }

        /// <summary>
        /// Получает список всех замаскированных SCP-096
        /// </summary>
        /// <returns>Список замаскированных SCP-096</returns>
        public static List<Player> GetMaskedScp096s()
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return new List<Player>();

                return Plugin.Instance._eventHandlers.GetMaskedScp096s();
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.GetMaskedScp096s: " + ex.ToString());
                return new List<Player>();
            }
        }

        /// <summary>
        /// Получает список всех масок на карте
        /// </summary>
        /// <returns>Список пикапов масок</returns>
        public static List<Pickup> GetAllMasks()
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return new List<Pickup>();

                return new List<Pickup>(Plugin.Instance._eventHandlers.spawnedMasks);
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.GetAllMasks: " + ex.ToString());
                return new List<Pickup>();
            }
        }

        /// <summary>
        /// Очищает все маски с карты
        /// </summary>
        /// <returns>True если очистка успешна</returns>
        public static bool ClearAllMasks()
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return false;

                Plugin.Instance._eventHandlers.ClearAllMasks();
                return true;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.ClearAllMasks: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Принудительно спавнит маски
        /// </summary>
        /// <param name="count">Количество масок для спавна (если не указано, используется из конфига)</param>
        /// <returns>True если спавн успешен</returns>
        public static bool ForceSpawnMasks(int? count = null)
        {
            try
            {
                if (Plugin.Instance?._eventHandlers == null)
                    return false;

                if (count.HasValue)
                {
                    int originalCount = Plugin.Instance.Config.MasksToSpawn;
                    Plugin.Instance.Config.MasksToSpawn = count.Value;
                    Plugin.Instance._eventHandlers.SpawnMasks();
                    Plugin.Instance.Config.MasksToSpawn = originalCount;
                }
                else
                {
                    Plugin.Instance._eventHandlers.SpawnMasks();
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.ForceSpawnMasks: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Проверяет, является ли пикап маской
        /// </summary>
        /// <param name="pickup">Пикап для проверки</param>
        /// <returns>True если это маска</returns>
        public static bool IsMask(Pickup pickup)
        {
            try
            {
                if (pickup == null || pickup.Type != ItemType.Medkit || Plugin.Instance?._eventHandlers == null)
                    return false;

                return Plugin.Instance._eventHandlers.spawnedMasks.Contains(pickup);
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.IsMask: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Получает игроков с масками в инвентаре
        /// </summary>
        /// <returns>Список игроков с масками</returns>
        public static List<Player> GetPlayersWithMasks()
        {
            try
            {
                return Player.List.Where(HasMask).ToList();
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в MaskAPI.GetPlayersWithMasks: " + ex.ToString());
                return new List<Player>();
            }
        }

        // Методы для вызова событий
        internal static void OnMaskPickedUp(MaskPickedUpEventArgs ev) => MaskPickedUp?.Invoke(ev);
        internal static void OnMaskDropped(MaskDroppedEventArgs ev) => MaskDropped?.Invoke(ev);
        internal static void OnMaskEquippingStarted(MaskEquippingStartedEventArgs ev) => MaskEquippingStarted?.Invoke(ev);
        internal static void OnMaskEquipped(MaskEquippedEventArgs ev) => MaskEquipped?.Invoke(ev);
        internal static void OnMaskRemoved(MaskRemovedEventArgs ev) => MaskRemoved?.Invoke(ev);
        internal static void OnMaskSpawned(MaskSpawnedEventArgs ev) => MaskSpawned?.Invoke(ev);
        internal static void OnMaskDestroyed(MaskDestroyedEventArgs ev) => MaskDestroyed?.Invoke(ev);
    }
}
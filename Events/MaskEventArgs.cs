using System;
using Exiled.API.Features;
using Exiled.API.Features.Pickups;
using Exiled.Events.EventArgs.Interfaces;

namespace Scp096Mask.Events
{
    /// <summary>
    /// Базовый класс для событий маски
    /// </summary>
    public abstract class MaskEventArgs : IEventArgs
    {
        /// <summary>
        /// Игрок, связанный с событием
        /// </summary>
        public Player Player { get; }

        /// <summary>
        /// Конструктор базового события маски
        /// </summary>
        /// <param name="player">Игрок</param>
        protected MaskEventArgs(Player player)
        {
            Player = player ?? throw new ArgumentNullException(nameof(player));
        }
    }

    /// <summary>
    /// Событие подбора маски
    /// </summary>
    public class MaskPickedUpEventArgs : MaskEventArgs
    {
        /// <summary>
        /// Пикап маски
        /// </summary>
        public Pickup MaskPickup { get; }

        /// <summary>
        /// Конструктор события подбора маски
        /// </summary>
        /// <param name="player">Игрок</param>
        /// <param name="maskPickup">Пикап маски</param>
        public MaskPickedUpEventArgs(Player player, Pickup maskPickup) : base(player)
        {
            MaskPickup = maskPickup ?? throw new ArgumentNullException(nameof(maskPickup));
        }
    }

    /// <summary>
    /// Событие выбрасывания маски
    /// </summary>
    public class MaskDroppedEventArgs : MaskEventArgs
    {
        /// <summary>
        /// Пикап маски
        /// </summary>
        public Pickup MaskPickup { get; }

        /// <summary>
        /// Конструктор события выбрасывания маски
        /// </summary>
        /// <param name="player">Игрок</param>
        /// <param name="maskPickup">Пикап маски</param>
        public MaskDroppedEventArgs(Player player, Pickup maskPickup) : base(player)
        {
            MaskPickup = maskPickup ?? throw new ArgumentNullException(nameof(maskPickup));
        }
    }

    /// <summary>
    /// Событие начала одевания маски
    /// </summary>
    public class MaskEquippingStartedEventArgs : MaskEventArgs
    {
        /// <summary>
        /// SCP-096, на который одевают маску
        /// </summary>
        public Player Scp096 { get; }

        /// <summary>
        /// Время одевания
        /// </summary>
        public float EquipTime { get; }

        /// <summary>
        /// Можно ли отменить событие
        /// </summary>
        public bool IsAllowed { get; set; } = true;

        /// <summary>
        /// Конструктор события начала одевания маски
        /// </summary>
        /// <param name="player">Игрок</param>
        /// <param name="scp096">SCP-096</param>
        /// <param name="equipTime">Время одевания</param>
        public MaskEquippingStartedEventArgs(Player player, Player scp096, float equipTime) : base(player)
        {
            Scp096 = scp096 ?? throw new ArgumentNullException(nameof(scp096));
            EquipTime = equipTime;
        }
    }

    /// <summary>
    /// Событие успешного одевания маски
    /// </summary>
    public class MaskEquippedEventArgs : MaskEventArgs
    {
        /// <summary>
        /// SCP-096, на который надели маску
        /// </summary>
        public Player Scp096 { get; }

        /// <summary>
        /// Конструктор события одевания маски
        /// </summary>
        /// <param name="player">Игрок</param>
        /// <param name="scp096">SCP-096</param>
        public MaskEquippedEventArgs(Player player, Player scp096) : base(player)
        {
            Scp096 = scp096 ?? throw new ArgumentNullException(nameof(scp096));
        }
    }

    /// <summary>
    /// Событие снятия маски
    /// </summary>
    public class MaskRemovedEventArgs : MaskEventArgs
    {
        /// <summary>
        /// Конструктор события снятия маски
        /// </summary>
        /// <param name="scp096">SCP-096</param>
        public MaskRemovedEventArgs(Player scp096) : base(scp096)
        {
        }
    }

    /// <summary>
    /// Событие спавна маски
    /// </summary>
    public class MaskSpawnedEventArgs : IEventArgs
    {
        /// <summary>
        /// Пикап маски
        /// </summary>
        public Pickup MaskPickup { get; }

        /// <summary>
        /// Комната, в которой заспавнена маска
        /// </summary>
        public Room Room { get; }

        /// <summary>
        /// Конструктор события спавна маски
        /// </summary>
        /// <param name="maskPickup">Пикап маски</param>
        /// <param name="room">Комната</param>
        public MaskSpawnedEventArgs(Pickup maskPickup, Room room)
        {
            MaskPickup = maskPickup ?? throw new ArgumentNullException(nameof(maskPickup));
            Room = room;
        }
    }

    /// <summary>
    /// Событие уничтожения маски
    /// </summary>
    public class MaskDestroyedEventArgs : IEventArgs
    {
        /// <summary>
        /// Пикап маски
        /// </summary>
        public Pickup MaskPickup { get; }

        /// <summary>
        /// Причина уничтожения
        /// </summary>
        public string Reason { get; }

        /// <summary>
        /// Конструктор события уничтожения маски
        /// </summary>
        /// <param name="maskPickup">Пикап маски</param>
        /// <param name="reason">Причина</param>
        public MaskDestroyedEventArgs(Pickup maskPickup, string reason)
        {
            MaskPickup = maskPickup ?? throw new ArgumentNullException(nameof(maskPickup));
            Reason = reason ?? "Unknown";
        }
    }
}
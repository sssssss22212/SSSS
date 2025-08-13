using System.Collections.Generic;
using Exiled.API.Interfaces;
using InventorySystem.Items;
using PlayerRoles;

namespace SCP035
{
    public sealed class Config : IConfig
    {
        public bool IsEnabled { get; set; } = true;
        public bool Debug { get; set; } = false;

        // General chances and toggles
        public bool EnableDirectAssignment { get; set; } = true;
        public float DirectAssignmentChance { get; set; } = 0.1f; // 10%
        public List<RoleTypeId> DirectAssignmentRoles { get; set; } = new() { RoleTypeId.ClassD, RoleTypeId.Scientist };

        public bool EnableMaskPickupTransformation { get; set; } = true;
        public int MaskCount { get; set; } = 2;
        public List<ItemType> MaskEligibleItemTypes { get; set; } = new() { ItemType.Coin, ItemType.ArmorLight, ItemType.SCP500, ItemType.Medkit };

        // Role stats
        public int Scp035MaxHealth { get; set; } = 180;
        public int Scp035ArtificialHp { get; set; } = 25;
        public float MovementSpeedMultiplier { get; set; } = 1.05f;

        // Friendly fire and alignment
        public bool TreatAsScpForDamageRules { get; set; } = true;
        public bool AllowDamageToScps { get; set; } = false;
        public bool AllowDamageToHumans { get; set; } = true;

        // HSM hints (toggle + templates)
        public bool UseHsmHints { get; set; } = true;

        public string TransformHint { get; set; } = "<size=30><color=#ff4444><b>SCP-035</b></color></size>\nВы чувствуете древнюю силу маски...";
        public float TransformHintDuration { get; set; } = 6f;

        public string ProximityHint { get; set; } = "<b><color=#ff4444>SCP-035</color></b> рядом. Вам нехорошо...";
        public float ProximityHintDuration { get; set; } = 2.0f;
        public float ProximityHintIntervalSeconds { get; set; } = 2.0f;
        public float ProximityHintRadius { get; set; } = 10.0f;

        public string IdentityTag { get; set; } = "<color=#ff2222>SCP-035</color>";
        public bool OverrideBadgeWhile035 { get; set; } = true;

        // Optional: drop a new mask when SCP-035 dies
        public bool DropMaskOnDeath { get; set; } = true;
        public ItemType DroppedMaskItemType { get; set; } = ItemType.Coin;

        // Cleanup
        public bool ClearCustomInfoOnRoleChange { get; set; } = true;
    }
}
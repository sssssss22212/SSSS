# SCP-035 Exiled Plugin

Custom role SCP-035 for SCP: Secret Laboratory using Exiled. Supports:
- Direct assignment chance or transformation on picking up configured mask items
- HSM-style hints (Player.ShowHint) with fully configurable texts and durations
- Friendly fire rules and basic stat tweaks

## Build

This plugin targets `net48` because Exiled runs on the game server runtime. Build on Windows with Visual Studio, or on Linux using mono-msbuild.

Place the following assemblies in `lib/` (from your server/Exiled installation):
- `Exiled.API.dll`
- `Exiled.Events.dll`
- `Exiled.Loader.dll`
- `Assembly-CSharp.dll`
- `Mirror.dll`
- `NorthwoodLib.dll`
- `PluginAPI.dll`

Then build the project in `src/SCP035`.

## Install

Copy `SCP035.dll` to your server `Exiled/Plugins/` folder. Start the server once to generate config.

## Configuration (Exiled .yml)

Key options (defaults shown):

```yaml
SCP035:
  IsEnabled: true
  Debug: false

  EnableDirectAssignment: true
  DirectAssignmentChance: 0.1
  DirectAssignmentRoles:
    - ClassD
    - Scientist

  EnableMaskPickupTransformation: true
  MaskCount: 2
  MaskEligibleItemTypes:
    - Coin
    - ArmorLight
    - SCP500
    - Medkit

  Scp035MaxHealth: 180
  Scp035ArtificialHp: 25
  MovementSpeedMultiplier: 1.05

  TreatAsScpForDamageRules: true
  AllowDamageToScps: false
  AllowDamageToHumans: true

  UseHsmHints: true
  TransformHint: "<size=30><color=#ff4444><b>SCP-035</b></color></size>\\nВы чувствуете древнюю силу маски..."
  TransformHintDuration: 6

  ProximityHint: "<b><color=#ff4444>SCP-035</color></b> рядом. Вам нехорошо..."
  ProximityHintDuration: 2
  ProximityHintIntervalSeconds: 2
  ProximityHintRadius: 10

  IdentityTag: "<color=#ff2222>SCP-035</color>"
  OverrideBadgeWhile035: true

  DropMaskOnDeath: true
  DroppedMaskItemType: Coin

  ClearCustomInfoOnRoleChange: true
```

## Notes
- This implementation does not rely on `Exiled.CustomRoles` and marks players internally as SCP-035, adjusting damage rules accordingly.
- If you want a fully fledged custom role with team integration, consider adding a dependency on `Exiled.CustomRoles` and replacing the transform with `CustomRole` spawn.
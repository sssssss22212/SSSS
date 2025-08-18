using System;
using System.Linq;
using System.Text;
using CommandSystem;
using Exiled.API.Features;
using Exiled.API.Features.Items;
using Exiled.Permissions.Extensions;

namespace Scp096Mask.Commands
{
	[CommandHandler(typeof(RemoteAdminCommandHandler))]
	[CommandHandler(typeof(GameConsoleCommandHandler))]
	public sealed class MaskCommands : ICommand
	{
		public string Command { get; } = "mask096";
		public string[] Aliases { get; } = new[] { "mask", "scp096mask" };
		public string Description { get; } = "Управление масками SCP-096";
        public bool SanitizeResponse => false;

		public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
		{
			if (!sender.CheckPermission("mask096.admin"))
			{
				response = "У вас нет прав на использование этой команды!";
				return false;
			}

			if (arguments.Count == 0)
			{
				response = "Использование:\n" +
						  "mask096 spawn - заспавнить маски\n" +
						  "mask096 info - информация о масках\n" +
						  "mask096 give <userid> - выдать маску в инвентарь\n" +
						  "mask096 givepickup <userid> - создать маску-пикап рядом с игроком\n" +
						  "mask096 remove <userid> - снять маску с SCP-096\n" +
						  "mask096 list - список замаскированных SCP-096";
				return false;
			}

			switch (arguments.At(0).ToLower())
			{
				case "spawn":
					return SpawnMasks(out response);

				case "info":
					return ShowMasksInfo(out response);

				case "give":
					if (arguments.Count < 2)
					{
						response = "Используйте: mask096 give <userid>";
						return false;
					}
					return GiveMaskInventory(arguments.At(1), out response);

				case "remove":
					if (arguments.Count < 2)
					{
						response = "Используйте: mask096 remove <userid>";
						return false;
					}
					return RemoveMask(arguments.At(1), out response);

				case "list":
					return ListMaskedScps(out response);

				case "givepickup":
					if (arguments.Count < 2)
					{
						response = "Используйте: mask096 givepickup <userid>";
						return false;
					}
					return GivePickup(arguments.At(1), out response);

				default:
					response = "Неизвестная подкоманда. Доступно: spawn, info, give, givepickup, remove, list";
					return false;
			}
		}

		private bool SpawnMasks(out string response)
		{
			if (Plugin.Instance?._eventHandlers == null)
			{
				response = "Плагин не работает";
				return false;
			}

			Plugin.Instance._eventHandlers.SpawnMasks();
			response = $"{Plugin.Instance.Config.MasksToSpawn} масок SCP-096 заспавнено!";
			return true;
		}

		private bool ShowMasksInfo(out string response)
		{
			if (Plugin.Instance?._eventHandlers == null)
			{
				response = "Плагин не работает";
				return false;
			}

			var masks = Plugin.Instance._eventHandlers.spawnedMasks;
			var sb = new StringBuilder();
			sb.AppendLine("<color=yellow>Информация о масках SCP-096:</color>");
			sb.AppendLine($"Заспавнено масок: {masks.Count}");
			sb.AppendLine($"Время одевания: {Plugin.Instance.Config.MaskEquipTime} сек");
			sb.AppendLine($"Дистанция взаимодействия: {Plugin.Instance.Config.InteractionDistance} м");
			sb.AppendLine($"Автоспавн: {(Plugin.Instance.Config.AutoSpawnEnabled ? "да" : "нет")}");
			response = sb.ToString();
			return true;
		}

		private bool GiveMaskInventory(string userId, out string response)
		{
			Player player = Player.Get(userId);
			if (player == null)
			{
				response = $"Игрок с ID {userId} не найден!";
				return false;
			}

			if (Plugin.Instance?._eventHandlers != null &&
				Plugin.Instance._eventHandlers.HasMask(player))
			{
				response = $"У игрока {player.Nickname} уже есть маска!";
				return false;
			}

			var medkit = player.AddItem(ItemType.Medkit);
			Plugin.Instance?._eventHandlers?.AddPlayerMask(player, medkit);

			response = $"Выдана маска SCP-096 в инвентарь игроку <color=green>{player.Nickname}</color> (<color=#aaaaaa>{player.Id}</color>)";
			return true;
		}

		private bool RemoveMask(string userId, out string response)
		{
			Player player = Player.Get(userId);
			if (player == null)
			{
				response = $"Игрок с ID {userId} не найден!";
				return false;
			}

			if (player.Role.Type != PlayerRoles.RoleTypeId.Scp096)
			{
				response = $"Игрок {player.Nickname} не является SCP-096!";
				return false;
			}

			if (Plugin.Instance?._eventHandlers == null)
			{
				response = "Плагин не работает";
				return false;
			}

			if (!Plugin.Instance._eventHandlers.IsScp096Masked(player))
			{
				response = $"На SCP-096 {player.Nickname} нет маски!";
				return false;
			}

			Plugin.Instance._eventHandlers.RemoveMaskFromScp096(player);
			response = $"Маска снята с SCP-096 <color=green>{player.Nickname}</color>";
			return true;
		}

		private bool ListMaskedScps(out string response)
		{
			if (Plugin.Instance?._eventHandlers == null)
			{
				response = "Плагин не работает";
				return false;
			}

			var maskedScps = Player.List
				.Where(p => p.Role.Type == PlayerRoles.RoleTypeId.Scp096 &&
						   Plugin.Instance._eventHandlers.IsScp096Masked(p))
				.ToList();

			if (maskedScps.Count == 0)
			{
				response = "Нет масок на SCP-096";
				return true;
			}

			var sb = new StringBuilder();
			sb.AppendLine($"<color=yellow>Маски на SCP-096 ({maskedScps.Count}):</color>");
			foreach (var scp in maskedScps)
				sb.AppendLine($"• <color=green>{scp.Nickname}</color> (ID: {scp.Id})");
			response = sb.ToString();
			return true;
		}

		private bool GivePickup(string userId, out string response)
		{
			Player player = Player.Get(userId);
			if (player == null)
			{
				response = $"Игрок с ID {userId} не найден!";
				return false;
			}

			var medkit = Item.Create(ItemType.Medkit);
			var pickup = medkit.CreatePickup(player.Position);
			Plugin.Instance?._eventHandlers?.spawnedMasks.Add(pickup);
			try
			{
				pickup.Scale = Plugin.Instance.Config.MaskPickupScale;
				pickup.Base.GetComponentInChildren<UnityEngine.MeshRenderer>()?.material?.SetColor("_Color", Plugin.Instance.Config.MaskTint);
			}
			catch { }

			response = $"Создана маска-пикап рядом с <color=green>{player.Nickname}</color>";
			return true;
		}
	}
}
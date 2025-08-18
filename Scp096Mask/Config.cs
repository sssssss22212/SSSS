using System.Collections.Generic;
using System.ComponentModel;
using Exiled.API.Enums;
using Exiled.API.Interfaces;
using Scp096Mask.Enums;
using UnityEngine;

namespace Scp096Mask
{
	public sealed class Config : IConfig
	{
		[Description("Включает/выключает плагин")] public bool IsEnabled { get; set; } = true;
		[Description("Включает отладочные логи")] public bool Debug { get; set; } = false;

		[Description("Время одевания маски, сек")] public float MaskEquipTime { get; set; } = 4.0f;
		[Description("Дистанция взаимодействия с SCP-096, м")] public float InteractionDistance { get; set; } = 2.2f;
		[Description("Требовать держать маску в руке при одевании")] public bool RequireMaskInHand { get; set; } = true;

		[Description("Автоспавн масок в начале раунда")] public bool AutoSpawnEnabled { get; set; } = true;
		[Description("Количество масок для спавна")] public int MasksToSpawn { get; set; } = 3;

		[Description("Тип активации взаимодействия с маской")] public ActivationType ActivationType { get; set; } = ActivationType.ServerSpecificSettings;

		// Server Specific Settings
		[Description("ID хоткея (ServerSpecificSettings)")] public string KeybindId { get; set; } = "scp096mask_key";
		[Description("Лейбл хоткея (ServerSpecificSettings)")] public string KeybindLabel { get; set; } = "Маска SCP-096";
		[Description("Подсказка хоткея (ServerSpecificSettings)")] public string KeybindHint { get; set; } = "Нажмите, чтобы надеть маску на ближайшего SCP-096";
		[Description("Заголовок настроек (ServerSpecificSettings)")] public string SettingHeaderLabel { get; set; } = "Scp096Mask";

		// Спавн по зонам с весами шанса (в процентах)
		[Description("Шансы (в %) появления маски по зонам")] public Dictionary<ZoneType, float> SpawnWeights { get; set; } = new Dictionary<ZoneType, float>
		{
			{ ZoneType.Surface, 15f },
			{ ZoneType.Entrance, 35f },
			{ ZoneType.HeavyContainment, 60f },
			{ ZoneType.LightContainment, 65f },
		};

		// Белый список комнат. Если пуст, используется выбор по зонам. Если указан, спавн масок происходит только в этих комнатах с шансом по именам комнат
		[Description("Включить спавн по конкретным комнатам (Override зон)")] public bool UseRoomWhitelist { get; set; } = false;
		[Description("Вес шанса (в %) по именам комнат при UseRoomWhitelist = true")] public Dictionary<string, float> RoomSpawnChances { get; set; } = new Dictionary<string, float>
		{
			// { "LCZ_WC", 50f },
			// { "HCZ_096", 80f },
		};

		// Смещение/растяжение пикапа, чтобы отличался от обычной аптечки
		[Description("Визуальное растяжение маски (scale)")] public Vector3 MaskPickupScale { get; set; } = new Vector3(1.0f, 1.25f, 1.0f);
		[Description("Цвет подсветки маски (RGBA 0..1)")] public Color MaskTint { get; set; } = new Color(0.9f, 0.9f, 1.0f, 1.0f);

		// Настройки хинтов
		[Description("Настройки отображения подсказок")] public HintUiSettings HintSettings { get; set; } = new HintUiSettings();
		[Description("Тексты сообщений")] public MessagesConfig Messages { get; set; } = new MessagesConfig();
	}

	public sealed class HintUiSettings
	{
		[Description("Размер текста")] public int TextSize { get; set; } = 28;
		[Description("Позиция X")] public float XPosition { get; set; } = 0;
		[Description("Позиция Y")] public float YPosition { get; set; } = -300;
	}

	public sealed class MessagesConfig
	{
		[Description("Нет маски")] public string NoMask { get; set; } = "<color=orange>У вас нет маски SCP-096!</color>";
		[Description("Маска не в руке")] public string MaskNotInHand { get; set; } = "<color=orange>Возьмите маску в руку!</color>";
		[Description("Слишком далеко")] public string TooFarAway { get; set; } = "<color=orange>Подойдите ближе к SCP-096.</color>";
		[Description("Уже замаскирован")] public string AlreadyMasked { get; set; } = "<color=yellow>На этом SCP-096 уже надета маска.</color>";
		[Description("Подобрано")] public string MaskPickedUp { get; set; } = "<color=green>Вы подобрали маску SCP-096.</color>";
		[Description("Процесс одевания")] public string MaskEquipping { get; set; } = "Одевание маски...";
		[Description("Маска надета")] public string MaskEquipped { get; set; } = "<color=green>Маска успешно надета!</color>";
		[Description("Маска снята")] public string MaskRemoved { get; set; } = "<color=yellow>Маска снята.</color>";
	}
}

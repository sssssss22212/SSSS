using CommandSystem;
using Exiled.API.Features;
using Exiled.Permissions.Extensions;
using System;
using System.Linq;

namespace SCPRoleplayPlugin.Commands
{
    /// <summary>
    /// Команда для медицинской системы
    /// </summary>
    [CommandHandler(typeof(ClientCommandHandler))]
    public class MedicalCommand : ICommand
    {
        public string Command => "medical";
        public string[] Aliases => new[] { "med", "лечение", "медицина" };
        public string Description => "Медицинская система";

        public bool Execute(ArraySegment<string> arguments, ICommandSender sender, out string response)
        {
            try
            {
                var player = Player.Get(sender);
                if (player == null)
                {
                    response = "Эта команда доступна только игрокам!";
                    return false;
                }

                if (!Plugin.PluginConfig.EnableMedicalSystem)
                {
                    response = "Медицинская система отключена!";
                    return false;
                }

                if (Plugin.Instance.MedicalSystem == null)
                {
                    response = "Медицинская система недоступна!";
                    return false;
                }

                if (arguments.Count == 0)
                {
                    response = GetMedicalHelp();
                    return true;
                }

                var action = arguments.At(0).ToLower();

                switch (action)
                {
                    case "checkup":
                    case "осмотр":
                        return HandleCheckup(player, arguments, out response);

                    case "heal":
                    case "лечить":
                        return HandleHeal(player, arguments, out response);

                    case "injure":
                    case "травма":
                        return HandleInjure(player, arguments, out response);

                    case "status":
                    case "состояние":
                        return HandleStatus(player, arguments, out response);

                    default:
                        response = "Неизвестное действие! Используйте: !medical для помощи";
                        return false;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка в команде medical: {ex}");
                response = "Произошла ошибка при выполнении команды!";
                return false;
            }
        }

        /// <summary>
        /// Получить справку по команде
        /// </summary>
        private string GetMedicalHelp()
        {
            return "=== КОМАНДЫ МЕДИЦИНСКОЙ СИСТЕМЫ ===\n" +
                   "!medical checkup <игрок> - провести осмотр\n" +
                   "!medical heal <игрок> <номер_травмы> - лечить травму\n" +
                   "!medical status [игрок] - состояние здоровья\n" +
                   "=== КОМАНДЫ АДМИНИСТРАТОРА ===\n" +
                   "!medical injure <игрок> <тип> <серьезность> [описание] - добавить травму\n" +
                   "Типы травм: bruise, cut, fracture, burn, bleeding, poisoning, infection, other\n" +
                   "Серьезность: minor, moderate, serious, critical\n" +
                   "=====================================";
        }

        /// <summary>
        /// Обработать медицинский осмотр
        /// </summary>
        private bool HandleCheckup(Player player, ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 2)
            {
                response = "Использование: !medical checkup <игрок>";
                return false;
            }

            var targetName = arguments.At(1);
            var target = Player.Get(targetName);
            
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            // Проверка близости к пациенту
            if (UnityEngine.Vector3.Distance(player.Position, target.Position) > 3f)
            {
                response = "Вы слишком далеко от пациента для проведения осмотра!";
                return false;
            }

            Plugin.Instance.MedicalSystem.PerformCheckup(target, player);
            response = $"Медицинский осмотр пациента {target.Nickname} проведен!";
            return true;
        }

        /// <summary>
        /// Обработать лечение травмы
        /// </summary>
        private bool HandleHeal(Player player, ArraySegment<string> arguments, out string response)
        {
            if (arguments.Count < 3)
            {
                response = "Использование: !medical heal <игрок> <номер_травмы>";
                return false;
            }

            var targetName = arguments.At(1);
            if (!int.TryParse(arguments.At(2), out int injuryIndex))
            {
                response = "Некорректный номер травмы!";
                return false;
            }

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            // Проверка близости к пациенту
            if (UnityEngine.Vector3.Distance(player.Position, target.Position) > 3f)
            {
                response = "Вы слишком далеко от пациента для проведения лечения!";
                return false;
            }

            // Конвертируем в 0-based индекс
            injuryIndex -= 1;

            var success = Plugin.Instance.MedicalSystem.HealInjury(target, player, injuryIndex);
            if (success)
            {
                response = $"Травма успешно вылечена у пациента {target.Nickname}!";
                return true;
            }
            else
            {
                response = "Не удалось вылечить травму! Проверьте номер травмы и ваши навыки.";
                return false;
            }
        }

        /// <summary>
        /// Обработать добавление травмы (админ)
        /// </summary>
        private bool HandleInjure(Player player, ArraySegment<string> arguments, out string response)
        {
            if (!player.CheckPermission("scp_rp.medical.injure"))
            {
                response = "У вас нет прав для добавления травм!";
                return false;
            }

            if (arguments.Count < 4)
            {
                response = "Использование: !medical injure <игрок> <тип> <серьезность> [описание]";
                return false;
            }

            var targetName = arguments.At(1);
            var typeStr = arguments.At(2).ToLower();
            var severityStr = arguments.At(3).ToLower();

            var target = Player.Get(targetName);
            if (target == null)
            {
                response = $"Игрок '{targetName}' не найден!";
                return false;
            }

            // Парсинг типа травмы
            if (!Enum.TryParse<InjuryType>(typeStr, true, out var injuryType))
            {
                response = "Некорректный тип травмы! Доступные: bruise, cut, fracture, burn, bleeding, poisoning, infection, other";
                return false;
            }

            // Парсинг серьезности
            if (!Enum.TryParse<InjurySeverity>(severityStr, true, out var severity))
            {
                response = "Некорректная серьезность! Доступные: minor, moderate, serious, critical";
                return false;
            }

            var description = arguments.Count > 4 ? string.Join(" ", arguments.Skip(4)) : "";

            Plugin.Instance.MedicalSystem.AddInjury(target, injuryType, severity, description);
            response = $"Травма '{injuryType}' ({severity}) добавлена игроку {target.Nickname}!";
            return true;
        }

        /// <summary>
        /// Обработать состояние здоровья
        /// </summary>
        private bool HandleStatus(Player player, ArraySegment<string> arguments, out string response)
        {
            Player target = player;

            if (arguments.Count > 1)
            {
                var targetName = arguments.At(1);
                target = Player.Get(targetName);
                
                if (target == null)
                {
                    response = $"Игрок '{targetName}' не найден!";
                    return false;
                }

                // Проверка прав на просмотр состояния других игроков
                if (target != player && !player.CheckPermission("scp_rp.medical.status.others"))
                {
                    response = "У вас нет прав для просмотра состояния других игроков!";
                    return false;
                }
            }

            var medicalInfo = Plugin.Instance.MedicalSystem.GetMedicalInfo(target);
            var activeInjuries = medicalInfo.Injuries.Where(i => !i.IsHealed).ToList();

            response = $"=== СОСТОЯНИЕ ЗДОРОВЬЯ ===\n";
            response += $"Игрок: {target.Nickname}\n";
            response += $"Здоровье: {target.Health}/100\n";
            response += $"Группа крови: {medicalInfo.BloodType}\n";
            response += $"Последний осмотр: {medicalInfo.LastCheckup:dd.MM.yyyy HH:mm}\n\n";

            if (activeInjuries.Any())
            {
                response += "АКТИВНЫЕ ТРАВМЫ:\n";
                for (int i = 0; i < activeInjuries.Count; i++)
                {
                    var injury = activeInjuries[i];
                    var severityText = GetSeverityText(injury.Severity);
                    var typeText = GetInjuryTypeText(injury.Type);
                    response += $"{i + 1}. {severityText} {typeText}\n";
                    if (!string.IsNullOrEmpty(injury.Description))
                        response += $"   Описание: {injury.Description}\n";
                    response += $"   Получена: {injury.OccurredAt:dd.MM.yyyy HH:mm}\n";
                }
            }
            else
            {
                response += "Активных травм нет.\n";
            }

            var healedCount = medicalInfo.Injuries.Count(i => i.IsHealed);
            if (healedCount > 0)
            {
                response += $"\nВылечено травм: {healedCount}";
            }

            return true;
        }

        /// <summary>
        /// Получить текст серьезности травмы
        /// </summary>
        private string GetSeverityText(InjurySeverity severity)
        {
            return severity switch
            {
                InjurySeverity.Minor => "Легкая",
                InjurySeverity.Moderate => "Умеренная",
                InjurySeverity.Serious => "Серьезная",
                InjurySeverity.Critical => "Критическая",
                _ => "Неизвестная"
            };
        }

        /// <summary>
        /// Получить текст типа травмы
        /// </summary>
        private string GetInjuryTypeText(InjuryType type)
        {
            return type switch
            {
                InjuryType.Bruise => "синяк",
                InjuryType.Cut => "порез",
                InjuryType.Fracture => "перелом",
                InjuryType.Burn => "ожог",
                InjuryType.Bleeding => "кровотечение",
                InjuryType.Poisoning => "отравление",
                InjuryType.Infection => "инфекция",
                InjuryType.Other => "прочая травма",
                _ => "неизвестная травма"
            };
        }
    }
}
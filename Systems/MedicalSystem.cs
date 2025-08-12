using Exiled.API.Features;
using System;
using System.Collections.Generic;
using System.Linq;
using MEC;
using UnityEngine;

namespace SCPRoleplayPlugin
{
    /// <summary>
    /// Медицинская система для RP сервера
    /// </summary>
    public class MedicalSystem
    {
        private Dictionary<string, PlayerMedicalInfo> playerMedicalData = new Dictionary<string, PlayerMedicalInfo>();
        private CoroutineHandle healingCoroutine;

        public MedicalSystem()
        {
            StartHealingCoroutine();
            Log.Debug("Медицинская система инициализирована");
        }

        /// <summary>
        /// Получить медицинскую информацию о игроке
        /// </summary>
        public PlayerMedicalInfo GetMedicalInfo(Player player)
        {
            var key = player.UserId;
            if (!playerMedicalData.ContainsKey(key))
            {
                playerMedicalData[key] = new PlayerMedicalInfo
                {
                    UserId = key,
                    PlayerName = player.Nickname,
                    Injuries = new List<Injury>(),
                    LastCheckup = DateTime.Now,
                    BloodType = GetRandomBloodType()
                };
            }
            return playerMedicalData[key];
        }

        /// <summary>
        /// Добавить травму игроку
        /// </summary>
        public void AddInjury(Player player, InjuryType type, InjurySeverity severity, string description = "")
        {
            try
            {
                var medicalInfo = GetMedicalInfo(player);
                
                var injury = new Injury
                {
                    Type = type,
                    Severity = severity,
                    Description = description,
                    OccurredAt = DateTime.Now,
                    IsHealed = false
                };

                medicalInfo.Injuries.Add(injury);

                // Применяем эффекты травмы
                ApplyInjuryEffects(player, injury);

                var severityText = GetSeverityText(severity);
                var typeText = GetInjuryTypeText(type);
                
                player.ShowHint($"<color=red>Получена травма:</color>\n{severityText} {typeText}", 5);
                
                Log.Info($"Игрок {player.Nickname} получил травму: {severityText} {typeText}");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при добавлении травмы: {ex}");
            }
        }

        /// <summary>
        /// Вылечить травму
        /// </summary>
        public bool HealInjury(Player patient, Player doctor, int injuryIndex)
        {
            try
            {
                var medicalInfo = GetMedicalInfo(patient);
                
                if (injuryIndex < 0 || injuryIndex >= medicalInfo.Injuries.Count)
                    return false;

                var injury = medicalInfo.Injuries[injuryIndex];
                if (injury.IsHealed)
                    return false;

                // Проверяем, может ли врач лечить эту травму
                if (!CanTreatInjury(doctor, injury))
                {
                    doctor.ShowHint("У вас недостаточно навыков для лечения этой травмы!", 5);
                    return false;
                }

                injury.IsHealed = true;
                injury.HealedAt = DateTime.Now;
                injury.HealedBy = doctor.Nickname;

                // Убираем эффекты травмы
                RemoveInjuryEffects(patient, injury);

                var typeText = GetInjuryTypeText(injury.Type);
                patient.ShowHint($"<color=green>Травма вылечена:</color> {typeText}", 5);
                doctor.ShowHint($"Вы вылечили травму у {patient.Nickname}", 3);

                Log.Info($"Врач {doctor.Nickname} вылечил травму у {patient.Nickname}: {typeText}");
                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при лечении травмы: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Провести медицинский осмотр
        /// </summary>
        public void PerformCheckup(Player patient, Player doctor)
        {
            try
            {
                var medicalInfo = GetMedicalInfo(patient);
                medicalInfo.LastCheckup = DateTime.Now;

                var report = GenerateMedicalReport(medicalInfo);
                
                doctor.SendConsoleMessage($"\n=== МЕДИЦИНСКИЙ ОТЧЕТ ===", "white");
                doctor.SendConsoleMessage($"Пациент: {patient.Nickname}", "white");
                doctor.SendConsoleMessage($"Группа крови: {medicalInfo.BloodType}", "white");
                doctor.SendConsoleMessage($"Здоровье: {patient.Health}/100", "white");
                doctor.SendConsoleMessage(report, "white");
                doctor.SendConsoleMessage("=========================\n", "white");

                patient.ShowHint("Вам проводят медицинский осмотр...", 3);
                doctor.ShowHint($"Осмотр пациента {patient.Nickname} завершен", 3);

                Log.Info($"Врач {doctor.Nickname} провел осмотр пациента {patient.Nickname}");
            }
            catch (Exception ex)
            {
                Log.Error($"Ошибка при проведении осмотра: {ex}");
            }
        }

        /// <summary>
        /// Применить эффекты травмы
        /// </summary>
        private void ApplyInjuryEffects(Player player, Injury injury)
        {
            // В зависимости от типа и серьезности травмы применяем эффекты
            switch (injury.Type)
            {
                case InjuryType.Fracture:
                    if (injury.Severity >= InjurySeverity.Serious)
                    {
                        // Замедление движения при переломе
                        player.EnableEffect(EffectType.Disabled);
                    }
                    break;

                case InjuryType.Bleeding:
                    if (injury.Severity >= InjurySeverity.Moderate)
                    {
                        // Кровотечение - постепенная потеря здоровья
                        player.EnableEffect(EffectType.Bleeding);
                    }
                    break;

                case InjuryType.Poisoning:
                    player.EnableEffect(EffectType.Poisoned);
                    break;

                case InjuryType.Burn:
                    if (injury.Severity >= InjurySeverity.Serious)
                    {
                        player.EnableEffect(EffectType.Burned);
                    }
                    break;
            }
        }

        /// <summary>
        /// Убрать эффекты травмы
        /// </summary>
        private void RemoveInjuryEffects(Player player, Injury injury)
        {
            switch (injury.Type)
            {
                case InjuryType.Fracture:
                    player.DisableEffect(EffectType.Disabled);
                    break;

                case InjuryType.Bleeding:
                    player.DisableEffect(EffectType.Bleeding);
                    break;

                case InjuryType.Poisoning:
                    player.DisableEffect(EffectType.Poisoned);
                    break;

                case InjuryType.Burn:
                    player.DisableEffect(EffectType.Burned);
                    break;
            }
        }

        /// <summary>
        /// Проверить, может ли врач лечить травму
        /// </summary>
        private bool CanTreatInjury(Player doctor, Injury injury)
        {
            var roles = Plugin.Instance.RoleSystem?.GetPlayerRoles(doctor);
            if (roles?.Any() != true)
                return false;

            var doctorRole = roles.First().Template;

            // Проверяем медицинские навыки по роли
            switch (injury.Severity)
            {
                case InjurySeverity.Minor:
                    return true; // Любой может лечить мелкие травмы

                case InjurySeverity.Moderate:
                    return doctorRole.Permissions.Contains("medical_basic") || 
                           doctorRole.Id.Contains("scientist") ||
                           doctorRole.Id.Contains("admin");

                case InjurySeverity.Serious:
                case InjurySeverity.Critical:
                    return doctorRole.Permissions.Contains("medical_advanced") ||
                           doctorRole.Id.Contains("scientist_senior") ||
                           doctorRole.Id.Contains("admin");

                default:
                    return false;
            }
        }

        /// <summary>
        /// Генерировать медицинский отчет
        /// </summary>
        private string GenerateMedicalReport(PlayerMedicalInfo medicalInfo)
        {
            var report = "СОСТОЯНИЕ ПАЦИЕНТА:\n";
            
            var activeInjuries = medicalInfo.Injuries.Where(i => !i.IsHealed).ToList();
            
            if (activeInjuries.Any())
            {
                report += "Активные травмы:\n";
                for (int i = 0; i < activeInjuries.Count; i++)
                {
                    var injury = activeInjuries[i];
                    var severityText = GetSeverityText(injury.Severity);
                    var typeText = GetInjuryTypeText(injury.Type);
                    report += $"  {i + 1}. {severityText} {typeText}\n";
                    if (!string.IsNullOrEmpty(injury.Description))
                        report += $"     Описание: {injury.Description}\n";
                }
            }
            else
            {
                report += "Активных травм не обнаружено.\n";
            }

            var healedInjuries = medicalInfo.Injuries.Where(i => i.IsHealed).ToList();
            if (healedInjuries.Any())
            {
                report += $"\nВылеченных травм: {healedInjuries.Count}";
            }

            return report;
        }

        /// <summary>
        /// Получить случайную группу крови
        /// </summary>
        private string GetRandomBloodType()
        {
            var bloodTypes = new[] { "O+", "O-", "A+", "A-", "B+", "B-", "AB+", "AB-" };
            return bloodTypes[UnityEngine.Random.Range(0, bloodTypes.Length)];
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

        /// <summary>
        /// Запустить корутину лечения
        /// </summary>
        private void StartHealingCoroutine()
        {
            healingCoroutine = Timing.RunCoroutine(HealingLoop());
        }

        /// <summary>
        /// Цикл постепенного лечения
        /// </summary>
        private IEnumerator<float> HealingLoop()
        {
            while (true)
            {
                yield return Timing.WaitForSeconds(Plugin.PluginConfig.HealthRegenTime);

                foreach (var player in Player.List)
                {
                    if (player?.IsAlive == true && player.Health < 100)
                    {
                        var medicalInfo = GetMedicalInfo(player);
                        var activeInjuries = medicalInfo.Injuries.Where(i => !i.IsHealed).ToList();

                        // Если нет серьезных травм, здоровье восстанавливается
                        if (!activeInjuries.Any(i => i.Severity >= InjurySeverity.Serious))
                        {
                            var healAmount = 5f;
                            player.Health = Math.Min(100f, player.Health + healAmount);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Очистка системы
        /// </summary>
        public void Cleanup()
        {
            if (healingCoroutine.IsRunning)
            {
                Timing.KillCoroutines(healingCoroutine);
            }
            
            playerMedicalData.Clear();
            Log.Debug("Медицинская система очищена");
        }
    }

    /// <summary>
    /// Медицинская информация о игроке
    /// </summary>
    public class PlayerMedicalInfo
    {
        public string UserId { get; set; }
        public string PlayerName { get; set; }
        public List<Injury> Injuries { get; set; } = new List<Injury>();
        public DateTime LastCheckup { get; set; }
        public string BloodType { get; set; }
    }

    /// <summary>
    /// Травма
    /// </summary>
    public class Injury
    {
        public InjuryType Type { get; set; }
        public InjurySeverity Severity { get; set; }
        public string Description { get; set; }
        public DateTime OccurredAt { get; set; }
        public bool IsHealed { get; set; }
        public DateTime? HealedAt { get; set; }
        public string HealedBy { get; set; }
    }

    /// <summary>
    /// Тип травмы
    /// </summary>
    public enum InjuryType
    {
        Bruise,     // Синяк
        Cut,        // Порез
        Fracture,   // Перелом
        Burn,       // Ожог
        Bleeding,   // Кровотечение
        Poisoning,  // Отравление
        Infection,  // Инфекция
        Other       // Прочее
    }

    /// <summary>
    /// Серьезность травмы
    /// </summary>
    public enum InjurySeverity
    {
        Minor,      // Легкая
        Moderate,   // Умеренная
        Serious,    // Серьезная
        Critical    // Критическая
    }
}
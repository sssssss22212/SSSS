using System;
using System.Collections.Generic;
using System.Linq;
using Exiled.API.Features;
using Exiled.API.Enums;
using UnityEngine;

namespace Scp096Mask.Utils
{
    /// <summary>
    /// Утилиты для работы с масками
    /// </summary>
    public static class MaskUtils
    {
        /// <summary>
        /// Проверяет, находится ли позиция в безопасной зоне для спавна
        /// </summary>
        /// <param name="position">Позиция для проверки</param>
        /// <returns>True если позиция безопасна</returns>
        public static bool IsSafeSpawnPosition(Vector3 position)
        {
            try
            {
                // Проверка на коллизии
                if (Physics.CheckSphere(position, 0.5f, LayerMask.GetMask("Default", "Player", "Ragdoll")))
                    return false;

                // Проверка высоты
                if (position.y < -10f || position.y > 50f)
                    return false;

                // Проверка на нахождение в комнате
                var room = Room.FindParentRoom(position);
                if (room == null)
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в IsSafeSpawnPosition: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Получает случайную позицию в комнате
        /// </summary>
        /// <param name="room">Комната</param>
        /// <param name="attempts">Количество попыток</param>
        /// <returns>Случайная позиция или null</returns>
        public static Vector3? GetRandomPositionInRoom(Room room, int attempts = 10)
        {
            try
            {
                var random = new System.Random();
                
                for (int i = 0; i < attempts; i++)
                {
                    Vector3 testPos = room.Position + new Vector3(
                        (float)(random.NextDouble() * 8 - 4),
                        1.2f,
                        (float)(random.NextDouble() * 8 - 4));

                    if (IsSafeSpawnPosition(testPos))
                        return testPos;
                }

                return null;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в GetRandomPositionInRoom: " + ex.ToString());
                return null;
            }
        }

        /// <summary>
        /// Получает список всех комнат в зоне
        /// </summary>
        /// <param name="zone">Тип зоны</param>
        /// <param name="excludeForbidden">Исключить запрещенные комнаты</param>
        /// <param name="forbiddenRooms">Список запрещенных комнат</param>
        /// <returns>Список комнат</returns>
        public static List<Room> GetRoomsInZone(ZoneType zone, bool excludeForbidden = true, List<RoomType> forbiddenRooms = null)
        {
            try
            {
                var rooms = Room.List.Where(r => r.Zone == zone).ToList();

                if (excludeForbidden && forbiddenRooms != null)
                {
                    rooms = rooms.Where(r => !forbiddenRooms.Contains(r.Type)).ToList();
                }

                return rooms;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в GetRoomsInZone: " + ex.ToString());
                return new List<Room>();
            }
        }

        /// <summary>
        /// Вычисляет расстояние между двумя игроками
        /// </summary>
        /// <param name="player1">Первый игрок</param>
        /// <param name="player2">Второй игрок</param>
        /// <returns>Расстояние в метрах</returns>
        public static float GetDistanceBetweenPlayers(Player player1, Player player2)
        {
            try
            {
                if (player1 == null || player2 == null)
                    return float.MaxValue;

                return Vector3.Distance(player1.Position, player2.Position);
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в GetDistanceBetweenPlayers: " + ex.ToString());
                return float.MaxValue;
            }
        }

        /// <summary>
        /// Проверяет, может ли игрок взаимодействовать с SCP-096
        /// </summary>
        /// <param name="player">Игрок</param>
        /// <param name="scp096">SCP-096</param>
        /// <param name="maxDistance">Максимальная дистанция</param>
        /// <returns>True если может взаимодействовать</returns>
        public static bool CanInteractWithScp096(Player player, Player scp096, float maxDistance)
        {
            try
            {
                if (player == null || scp096 == null)
                    return false;

                if (!player.IsAlive || !scp096.IsAlive)
                    return false;

                if (scp096.Role.Type != RoleTypeId.Scp096)
                    return false;

                float distance = GetDistanceBetweenPlayers(player, scp096);
                return distance <= maxDistance;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в CanInteractWithScp096: " + ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Находит ближайший SCP-096 к игроку
        /// </summary>
        /// <param name="player">Игрок</param>
        /// <param name="maxDistance">Максимальная дистанция поиска</param>
        /// <returns>Ближайший SCP-096 или null</returns>
        public static Player FindNearestScp096(Player player, float maxDistance)
        {
            try
            {
                if (player == null)
                    return null;

                Player nearest = null;
                float nearestDistance = float.MaxValue;

                foreach (var scp in Player.List.Where(p => p.Role.Type == RoleTypeId.Scp096))
                {
                    float distance = GetDistanceBetweenPlayers(player, scp);
                    if (distance < nearestDistance && distance <= maxDistance)
                    {
                        nearestDistance = distance;
                        nearest = scp;
                    }
                }

                return nearest;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в FindNearestScp096: " + ex.ToString());
                return null;
            }
        }

        /// <summary>
        /// Создает прогресс-бар для отображения
        /// </summary>
        /// <param name="progress">Прогресс от 0 до 1</param>
        /// <param name="width">Ширина прогресс-бара</param>
        /// <param name="filledChar">Символ заполненной части</param>
        /// <param name="emptyChar">Символ пустой части</param>
        /// <returns>Строка прогресс-бара</returns>
        public static string CreateProgressBar(float progress, int width = 10, char filledChar = '█', char emptyChar = '░')
        {
            try
            {
                progress = Mathf.Clamp01(progress);
                int filledWidth = Mathf.RoundToInt(progress * width);
                int emptyWidth = width - filledWidth;

                string filled = new string(filledChar, filledWidth);
                string empty = new string(emptyChar, emptyWidth);

                return filled + empty;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в CreateProgressBar: " + ex.ToString());
                return new string('?', width);
            }
        }

        /// <summary>
        /// Парсит RGB цвет из строки
        /// </summary>
        /// <param name="colorString">Строка цвета в формате "R,G,B"</param>
        /// <returns>Color или белый цвет при ошибке</returns>
        public static Color ParseColor(string colorString)
        {
            try
            {
                if (string.IsNullOrEmpty(colorString))
                    return Color.white;

                string[] parts = colorString.Split(',');
                if (parts.Length != 3)
                    return Color.white;

                if (float.TryParse(parts[0], out float r) &&
                    float.TryParse(parts[1], out float g) &&
                    float.TryParse(parts[2], out float b))
                {
                    return new Color(r / 255f, g / 255f, b / 255f);
                }

                return Color.white;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в ParseColor: " + ex.ToString());
                return Color.white;
            }
        }

        /// <summary>
        /// Форматирует время в читабельный вид
        /// </summary>
        /// <param name="seconds">Секунды</param>
        /// <returns>Отформатированная строка</returns>
        public static string FormatTime(float seconds)
        {
            try
            {
                if (seconds < 60)
                    return seconds.ToString("F1") + "с";

                int minutes = (int)(seconds / 60);
                int remainingSeconds = (int)(seconds % 60);

                return minutes.ToString() + "м " + remainingSeconds.ToString() + "с";
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в FormatTime: " + ex.ToString());
                return "?";
            }
        }

        /// <summary>
        /// Проверяет версию совместимости
        /// </summary>
        /// <param name="requiredVersion">Требуемая версия</param>
        /// <param name="currentVersion">Текущая версия</param>
        /// <returns>True если совместимо</returns>
        public static bool IsCompatibleVersion(Version requiredVersion, Version currentVersion)
        {
            try
            {
                if (requiredVersion == null || currentVersion == null)
                    return false;

                return currentVersion >= requiredVersion;
            }
            catch (Exception ex)
            {
                Log.Error("Ошибка в IsCompatibleVersion: " + ex.ToString());
                return false;
            }
        }
    }
}
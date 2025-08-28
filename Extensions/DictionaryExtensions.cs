using System.Collections.Generic;

namespace Scp096Mask.Extensions
{
    /// <summary>
    /// Расширения для словарей
    /// </summary>
    public static class DictionaryExtensions
    {
        /// <summary>
        /// Получает значение из словаря или возвращает значение по умолчанию
        /// </summary>
        /// <typeparam name="TKey">Тип ключа</typeparam>
        /// <typeparam name="TValue">Тип значения</typeparam>
        /// <param name="dictionary">Словарь</param>
        /// <param name="key">Ключ</param>
        /// <param name="defaultValue">Значение по умолчанию</param>
        /// <returns>Значение из словаря или значение по умолчанию</returns>
        public static TValue GetValueOrDefault<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key, TValue defaultValue = default(TValue))
        {
            return dictionary.TryGetValue(key, out TValue value) ? value : defaultValue;
        }
    }
}
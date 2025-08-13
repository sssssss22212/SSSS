# DX Project Mobile App

Мобильное приложение для сообщества SCP: Secret Laboratory проекта DX Project.

## 📱 Описание

Это гибридное мобильное приложение, созданное на основе веб-технологий с использованием Apache Cordova. Приложение включает в себя все функции оригинального веб-сайта:

- 🔐 Авторизация через email или Steam
- 🖥️ Информация о серверах в реальном времени
- 💎 Система доната с интеграцией ЮMoney
- 📰 Новости проекта
- 👤 Личный кабинет пользователя
- 📋 Правила и заявки на администрацию

## 🛠️ Технологии

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Build System**: Webpack 5
- **Mobile Framework**: Apache Cordova
- **Libraries**: 
  - Axios (HTTP клиент)
  - LocalForage (локальное хранилище)
  - Animate.css (анимации)
- **Styling**: CSS Custom Properties, Flexbox, Grid

## 📋 Требования

### Для разработки:
- Node.js 16+ 
- npm 8+
- Java JDK 8+
- Android SDK (API Level 22+)
- Apache Cordova CLI

### Для сборки APK:
- Android Studio или Android SDK Tools
- Gradle 7+

## 🚀 Установка и настройка

### 1. Клонирование и установка зависимостей

```bash
# Клонируйте репозиторий
git clone https://github.com/your-username/dx-project-mobile.git
cd dx-project-mobile

# Установите зависимости
npm install

# Установите Cordova CLI глобально (если не установлен)
npm install -g cordova
```

### 2. Настройка Android SDK

```bash
# Установите Android SDK через Android Studio или командную строку
# Убедитесь, что переменные окружения настроены:
export ANDROID_HOME=/path/to/android-sdk
export PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools

# Проверьте настройки
cordova requirements android
```

### 3. Настройка проекта

```bash
# Добавьте платформу Android
cordova platform add android

# Установите плагины
cordova plugin add cordova-plugin-whitelist
cordova plugin add cordova-plugin-statusbar
cordova plugin add cordova-plugin-device
cordova plugin add cordova-plugin-splashscreen
cordova plugin add cordova-plugin-inappbrowser
cordova plugin add cordova-plugin-network-information
cordova plugin add cordova-plugin-file
cordova plugin add cordova-plugin-file-transfer
```

### 4. Конфигурация API

Отредактируйте файл `src/js/app.js` и настройте конфигурацию:

```javascript
const CONFIG = {
    API_BASE_URL: 'https://your-backend-url.com/api', // Ваш бэкенд URL
    STEAM_API_KEY: 'YOUR_STEAM_API_KEY',
    YOOMONEY_WALLET: 'YOUR_YOOMONEY_WALLET',
    VERSION: '1.0.0',
    DEBUG: false // Установите false для продакшена
};
```

## 🔨 Разработка

### Запуск в режиме разработки

```bash
# Запуск dev сервера для веб-разработки
npm run dev

# Приложение будет доступно по адресу http://localhost:8080
```

### Тестирование на устройстве

```bash
# Сборка для разработки
npm run build

# Подготовка Cordova
npm run cordova-prepare

# Запуск на подключенном Android устройстве
npm run cordova-run

# Или запуск в эмуляторе
cordova emulate android
```

### Отладка

```bash
# Включите отладку в Chrome DevTools
# После запуска приложения на устройстве:
# 1. Откройте Chrome
# 2. Перейдите на chrome://inspect
# 3. Найдите ваше устройство и нажмите "inspect"
```

## 📦 Сборка для продакшена

### 1. Подготовка к сборке

```bash
# Убедитесь, что DEBUG: false в конфигурации
# Обновите версию в config.xml и package.json
# Проверьте все настройки API
```

### 2. Сборка APK

```bash
# Сборка production версии
npm run build-apk

# Или поэтапно:
npm run build
cordova build android --release
```

### 3. Подпись APK

```bash
# Создайте keystore (только один раз)
keytool -genkey -v -keystore dx-project.keystore -alias dx-project -keyalg RSA -keysize 2048 -validity 10000

# Подпишите APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore dx-project.keystore platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk dx-project

# Выровняйте APK
zipalign -v 4 platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk dx-project-release.apk
```

### 4. Проверка APK

```bash
# Установите на тестовое устройство
adb install dx-project-release.apk

# Проверьте работоспособность всех функций
```

## 🎨 Кастомизация

### Изменение темы и стилей

1. Отредактируйте CSS переменные в `src/css/styles.css`:

```css
:root {
    --primary-color: #dc143c;    /* Основной цвет */
    --secondary-color: #8b0000;  /* Вторичный цвет */
    --background-color: #0a0a0a; /* Цвет фона */
    /* ... другие переменные */
}
```

2. Измените иконки и изображения в папке `src/assets/`

### Добавление новых экранов

1. Добавьте HTML разметку в `src/index.html`
2. Создайте метод загрузки в классе `ScreenManager`
3. Добавьте навигацию в меню

### Интеграция с API

1. Создайте методы в классе `APIService`
2. Добавьте обработку данных в соответствующие сервисы
3. Обновите UI компоненты

## 📱 Структура проекта

```
dx-project-mobile/
├── src/                    # Исходный код
│   ├── css/               # Стили
│   ├── js/                # JavaScript
│   ├── assets/            # Ресурсы (изображения, иконки)
│   ├── index.html         # Основной HTML файл
│   └── manifest.json      # PWA манифест
├── www/                   # Собранные файлы
├── platforms/             # Платформо-специфичные файлы
├── plugins/               # Cordova плагины
├── res/                   # Ресурсы для сборки
├── config.xml             # Конфигурация Cordova
├── package.json           # Зависимости и скрипты
└── webpack.config.js      # Конфигурация Webpack
```

## 🔧 Настройка в Rider

### 1. Открытие проекта

1. Запустите JetBrains Rider
2. Выберите "Open" и укажите папку проекта
3. Rider автоматически определит проект как Node.js

### 2. Настройка Run Configurations

1. **Для веб-разработки:**
   - Тип: npm
   - Команда: run
   - Скрипт: dev

2. **Для сборки:**
   - Тип: npm  
   - Команда: run
   - Скрипт: build-apk

3. **Для тестирования на устройстве:**
   - Тип: npm
   - Команда: run  
   - Скрипт: cordova-run

### 3. Настройка отладки

1. Создайте конфигурацию "JavaScript Debug"
2. URL: http://localhost:8080
3. Запустите dev сервер и конфигурацию отладки

### 4. Полезные плагины для Rider

- **Cordova/PhoneGap** - поддержка Cordova
- **CSS Support** - улучшенная поддержка CSS
- **JavaScript and TypeScript** - уже встроен

## 🚀 Развертывание

### Play Store

1. Создайте аккаунт разработчика Google Play
2. Подготовьте метаданные приложения:
   - Описание
   - Скриншоты (1080x1920)
   - Иконка (512x512)
   - Feature Graphic (1024x500)
3. Загрузите подписанный APK
4. Заполните информацию о приложении
5. Отправьте на модерацию

### Прямое распространение

1. Разместите APK файл на вашем сервере
2. Создайте страницу загрузки с инструкциями
3. Предупредите пользователей о необходимости разрешить установку из неизвестных источников

## 🔍 Отладка и решение проблем

### Частые проблемы

1. **Ошибка сборки Android:**
   ```bash
   # Проверьте версии
   cordova requirements android
   
   # Очистите кэш
   cordova clean android
   rm -rf platforms/android
   cordova platform add android
   ```

2. **Проблемы с сетью:**
   - Проверьте настройки CORS на сервере
   - Убедитесь в правильности URL API
   - Проверьте CSP политики в index.html

3. **Проблемы с плагинами:**
   ```bash
   # Переустановите плагины
   cordova plugin remove [plugin-name]
   cordova plugin add [plugin-name]
   ```

### Логи и отладка

```bash
# Просмотр логов Android
adb logcat | grep -i "chromium\|cordova\|dx-project"

# Отладка через Chrome DevTools
chrome://inspect/#devices
```

## 📋 Чеклист перед релизом

- [ ] Обновлены все версии в config.xml и package.json
- [ ] Настроены правильные URL API для продакшена
- [ ] DEBUG установлен в false
- [ ] Протестированы все функции на реальном устройстве
- [ ] Проверена работа без интернета (offline режим)
- [ ] Созданы все необходимые иконки и скриншоты
- [ ] APK подписан релизным ключом
- [ ] Проведено тестирование на разных версиях Android

## 🤝 Участие в разработке

1. Создайте fork репозитория
2. Создайте ветку для новой функции
3. Внесите изменения
4. Создайте Pull Request

## 📄 Лицензия

MIT License - см. файл LICENSE для деталей.

## 📞 Поддержка

- **Discord**: https://discord.gg/YtZjRTbX
- **Email**: admin@dxproject.com
- **Telegram**: @DXSTRUCTION

## 🎯 Планы развития

- [ ] Push уведомления
- [ ] Темная/светлая тема
- [ ] Поддержка iOS
- [ ] Интеграция с Discord API
- [ ] Система достижений
- [ ] Встроенный чат

---

**DX Project Team** © 2025
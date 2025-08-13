# 🚀 Пошаговое руководство по настройке DX Project Mobile в JetBrains Rider

Это подробное руководство поможет вам настроить проект DX Project Mobile в JetBrains Rider и собрать APK файл.

## 📋 Предварительные требования

### 1. Установка необходимого ПО

#### Java Development Kit (JDK)
```bash
# Скачайте и установите JDK 8 или новее
# https://www.oracle.com/java/technologies/downloads/

# Проверьте установку
java -version
javac -version
```

#### Node.js и npm
```bash
# Скачайте и установите Node.js 16+ с официального сайта
# https://nodejs.org/

# Проверьте установку
node --version
npm --version
```

#### Android Studio и SDK
1. Скачайте Android Studio с https://developer.android.com/studio
2. Установите Android Studio
3. Запустите Android Studio и пройдите первоначальную настройку
4. В SDK Manager установите:
   - Android SDK Platform 22 (минимум)
   - Android SDK Platform 33 (рекомендуется)
   - Android SDK Build-Tools
   - Android SDK Platform-Tools
   - Android SDK Tools

#### Apache Cordova
```bash
# Установите Cordova глобально
npm install -g cordova

# Проверьте установку
cordova --version
```

### 2. Настройка переменных окружения

#### Windows
1. Откройте "Переменные среды"
2. Добавьте переменные:
   - `JAVA_HOME`: путь к JDK (например, `C:\Program Files\Java\jdk-11.0.1`)
   - `ANDROID_HOME`: путь к Android SDK (например, `C:\Users\YourName\AppData\Local\Android\Sdk`)
3. Добавьте в PATH:
   - `%JAVA_HOME%\bin`
   - `%ANDROID_HOME%\tools`
   - `%ANDROID_HOME%\platform-tools`

#### macOS/Linux
```bash
# Добавьте в ~/.bashrc или ~/.zshrc
export JAVA_HOME=/path/to/jdk
export ANDROID_HOME=/path/to/android-sdk
export PATH=$PATH:$JAVA_HOME/bin:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools

# Перезагрузите терминал или выполните
source ~/.bashrc
```

## 🛠️ Настройка проекта в Rider

### 1. Создание проекта

1. **Откройте JetBrains Rider**
2. **Создайте новую папку** для проекта или клонируйте репозиторий:
   ```bash
   git clone https://github.com/your-username/dx-project-mobile.git
   cd dx-project-mobile
   ```
3. **Откройте проект в Rider:**
   - File → Open
   - Выберите папку проекта
   - Rider автоматически определит его как Node.js проект

### 2. Установка зависимостей

1. **Откройте терминал в Rider** (Alt+F12)
2. **Установите зависимости:**
   ```bash
   npm install
   ```

### 3. Инициализация Cordova

```bash
# Добавьте платформу Android
cordova platform add android

# Установите необходимые плагины
cordova plugin add cordova-plugin-whitelist
cordova plugin add cordova-plugin-statusbar
cordova plugin add cordova-plugin-device
cordova plugin add cordova-plugin-splashscreen
cordova plugin add cordova-plugin-inappbrowser
cordova plugin add cordova-plugin-network-information
cordova plugin add cordova-plugin-file
cordova plugin add cordova-plugin-file-transfer

# Проверьте требования
cordova requirements android
```

### 4. Настройка Run Configurations в Rider

#### A. Конфигурация для разработки

1. **Откройте Run/Debug Configurations:**
   - Run → Edit Configurations...
   - Или нажмите на выпадающий список конфигураций и выберите "Edit Configurations..."

2. **Создайте новую npm конфигурацию:**
   - Нажмите "+" → npm
   - Name: `Dev Server`
   - Command: `run`
   - Scripts: `dev`
   - Arguments: (оставьте пустым)

3. **Нажмите Apply и OK**

#### B. Конфигурация для сборки

1. **Создайте еще одну npm конфигурацию:**
   - Name: `Build Production`
   - Command: `run`
   - Scripts: `build`

2. **Создайте конфигурацию для сборки APK:**
   - Name: `Build APK`
   - Command: `run`
   - Scripts: `build-apk`

#### C. Конфигурация для запуска на устройстве

1. **Создайте конфигурацию:**
   - Name: `Run on Device`
   - Command: `run`
   - Scripts: `cordova-run`

### 5. Настройка отладки

#### A. JavaScript отладка

1. **Создайте новую конфигурацию:**
   - "+" → JavaScript Debug
   - Name: `Debug Web App`
   - URL: `http://localhost:8080`
   - Browser: Chrome

2. **Для отладки:**
   - Запустите `Dev Server`
   - Затем запустите `Debug Web App`

#### B. Отладка на устройстве

1. **Подключите Android устройство**
2. **Включите отладку по USB** в настройках разработчика
3. **Запустите приложение на устройстве:**
   ```bash
   npm run cordova-run
   ```
4. **Откройте Chrome:**
   - Перейдите на `chrome://inspect/#devices`
   - Найдите ваше приложение и нажмите "inspect"

## 🔧 Конфигурация проекта

### 1. Настройка API

Отредактируйте `src/js/app.js`:

```javascript
const CONFIG = {
    API_BASE_URL: 'https://your-domain.com/api', // Замените на ваш URL
    STEAM_API_KEY: 'YOUR_STEAM_API_KEY',
    YOOMONEY_WALLET: '4100117158431008', // Ваш кошелек ЮMoney
    VERSION: '1.0.0',
    DEBUG: true // false для продакшена
};
```

### 2. Настройка Cordova

Отредактируйте `config.xml`:

```xml
<widget id="com.dxproject.mobile" version="1.0.0">
    <name>DX Project</name>
    <description>
        DX Project Mobile App - SCP: Secret Laboratory Community
    </description>
    <author email="admin@dxproject.com" href="https://dxproject.com">
        DX Project Team
    </author>
    <!-- Остальные настройки -->
</widget>
```

### 3. Добавление иконок и ресурсов

1. **Создайте папку `res/`** в корне проекта
2. **Добавьте иконки** в `res/icon/android/`:
   - `ldpi.png` (36x36)
   - `mdpi.png` (48x48)
   - `hdpi.png` (72x72)
   - `xhdpi.png` (96x96)
   - `xxhdpi.png` (144x144)
   - `xxxhdpi.png` (192x192)

3. **Добавьте splash screens** в `res/screen/android/`:
   - Различные разрешения для portrait и landscape

## 🏗️ Сборка проекта

### 1. Разработка

```bash
# Запуск dev сервера (для веб-разработки)
npm run dev

# Сборка для разработки
npm run build

# Подготовка Cordova
npm run cordova-prepare

# Запуск на устройстве
npm run cordova-run
```

### 2. Продакшен

#### A. Подготовка

1. **Обновите версию** в `config.xml` и `package.json`
2. **Установите DEBUG: false** в конфигурации
3. **Проверьте все URL API**

#### B. Сборка APK

```bash
# Полная сборка APK
npm run build-apk

# Или поэтапно:
npm run build
cordova build android --release
```

#### C. Подпись APK

1. **Создайте keystore** (только один раз):
   ```bash
   keytool -genkey -v -keystore dx-project.keystore -alias dx-project -keyalg RSA -keysize 2048 -validity 10000
   ```

2. **Подпишите APK:**
   ```bash
   jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore dx-project.keystore platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk dx-project
   ```

3. **Выровняйте APK:**
   ```bash
   zipalign -v 4 platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk dx-project-release.apk
   ```

## 🐛 Решение проблем

### Частые ошибки и их решения

#### 1. "ANDROID_HOME not set"
```bash
# Убедитесь, что переменная окружения установлена
echo $ANDROID_HOME  # Linux/Mac
echo %ANDROID_HOME% # Windows

# Если не установлена, добавьте в ~/.bashrc или переменные среды Windows
```

#### 2. "Java not found"
```bash
# Проверьте установку Java
java -version

# Убедитесь, что JAVA_HOME установлена
echo $JAVA_HOME
```

#### 3. "License not accepted"
```bash
# Примите лицензии Android SDK
yes | sdkmanager --licenses
```

#### 4. Ошибки сборки Cordova
```bash
# Очистите проект
cordova clean android

# Удалите и пересоздайте платформу
cordova platform remove android
cordova platform add android

# Переустановите плагины
cordova plugin remove cordova-plugin-whitelist
cordova plugin add cordova-plugin-whitelist
```

#### 5. Проблемы с Gradle
```bash
# Очистите Gradle кэш
cd platforms/android
./gradlew clean

# Или на Windows
gradlew.bat clean
```

### Отладка в Rider

#### 1. Просмотр логов
- **View → Tool Windows → Terminal**
- Используйте команды для просмотра логов:
  ```bash
  # Android логи
  adb logcat | grep -i "chromium\|cordova\|dx-project"
  
  # Cordova логи
  cordova run android --verbose
  ```

#### 2. Breakpoints
- Установите breakpoints в JavaScript коде
- Запустите отладку через конфигурацию `Debug Web App`

#### 3. Network inspection
- Используйте Chrome DevTools для анализа сетевых запросов
- Проверяйте API вызовы и ошибки

## 📱 Тестирование

### 1. На эмуляторе

```bash
# Создайте AVD в Android Studio
# Затем запустите:
cordova emulate android
```

### 2. На реальном устройстве

```bash
# Подключите устройство по USB
# Включите отладку по USB
# Запустите:
cordova run android
```

### 3. Тестирование функций

- ✅ Авторизация (email и Steam)
- ✅ Навигация между экранами
- ✅ Загрузка данных с API
- ✅ Система доната
- ✅ Офлайн режим
- ✅ Push уведомления (если реализованы)

## 📦 Подготовка к релизу

### Чеклист

- [ ] Все функции протестированы
- [ ] API URLs настроены для продакшена
- [ ] DEBUG = false
- [ ] Версия обновлена в config.xml и package.json
- [ ] Иконки и splash screens добавлены
- [ ] APK подписан релизным ключом
- [ ] Протестировано на разных устройствах
- [ ] Проверена работа без интернета

### Финальная сборка

```bash
# 1. Обновите конфигурацию для продакшена
# 2. Соберите проект
npm run build-apk

# 3. Подпишите APK
# (команды выше)

# 4. Протестируйте финальную версию
adb install dx-project-release.apk
```

## 🎯 Дополнительные возможности Rider

### 1. Code Completion
- Rider предоставляет отличное автодополнение для JavaScript
- Используйте Ctrl+Space для вызова подсказок

### 2. Refactoring
- F6 - перемещение файлов
- Shift+F6 - переименование
- Ctrl+Alt+M - извлечение метода

### 3. Version Control
- Встроенная поддержка Git
- View → Tool Windows → Git

### 4. Task Management
- Интеграция с системами задач
- Tools → Tasks & Contexts

## 📞 Поддержка

Если возникли проблемы:

1. **Проверьте логи** в терминале Rider
2. **Используйте Chrome DevTools** для отладки веб-части
3. **Обратитесь к документации Cordova**: https://cordova.apache.org/docs/
4. **Свяжитесь с командой DX Project**: admin@dxproject.com

---

**Удачи в разработке!** 🚀
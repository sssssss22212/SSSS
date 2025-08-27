@echo off
title Мафия 2.0 - Сервер
echo.
echo  ====================================
echo   🕵️ МАФИЯ 2.0 - Запуск сервера
echo  ====================================
echo.

echo [1/3] Проверка Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js не найден! Установите Node.js с официального сайта.
    pause
    exit /b 1
)
echo ✅ Node.js найден

echo.
echo [2/3] Установка зависимостей...
call npm install
if errorlevel 1 (
    echo ❌ Ошибка установки зависимостей
    pause
    exit /b 1
)
echo ✅ Зависимости установлены

echo.
echo [3/3] Запуск сервера...
echo.
echo 🎮 Сервер запускается на http://localhost:3000
echo 📱 Откройте этот адрес в браузере
echo ⚠️  Для остановки нажмите Ctrl+C
echo.

call npm start

pause
@echo off
chcp 65001 >nul
title Умный бот для Minecraft 1.21.8

echo 🤖 Умный бот для Minecraft 1.21.8
echo ==================================
echo.

:: Проверка Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Node.js не установлен!
    echo Установите Node.js: https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js установлен
node --version
echo.

:: Проверка зависимостей
if not exist "node_modules" (
    echo 📦 Установка зависимостей...
    call npm install
    echo.
)

:: Запуск бота
echo 🚀 Запуск бота...
echo Для остановки нажмите Ctrl+C
echo.

node minecraft_bot.js

pause

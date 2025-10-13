#!/bin/bash

# Скрипт запуска умного бота для Minecraft
# Для Linux/Mac/Termux

echo "🤖 Умный бот для Minecraft 1.21.8"
echo "=================================="
echo ""

# Проверка установки Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js не установлен!"
    echo "Установите Node.js: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js версия: $(node --version)"
echo ""

# Проверка установки зависимостей
if [ ! -d "node_modules" ]; then
    echo "📦 Установка зависимостей..."
    npm install
    echo ""
fi

# Запуск бота
echo "🚀 Запуск бота..."
echo "Для остановки нажмите Ctrl+C"
echo ""

node minecraft_bot.js

#!/bin/bash

echo ""
echo " ===================================="
echo "  🕵️ МАФИЯ 2.0 - Запуск сервера"
echo " ===================================="
echo ""

echo "[1/3] Проверка Node.js..."
if ! command -v node &> /dev/null; then
    echo "❌ Node.js не найден! Установите Node.js"
    exit 1
fi
echo "✅ Node.js найден: $(node --version)"

echo ""
echo "[2/3] Установка зависимостей..."
npm install
if [ $? -ne 0 ]; then
    echo "❌ Ошибка установки зависимостей"
    exit 1
fi
echo "✅ Зависимости установлены"

echo ""
echo "[3/3] Запуск сервера..."
echo ""
echo "🎮 Сервер запускается на http://localhost:3000"
echo "📱 Откройте этот адрес в браузере"
echo "⚠️  Для остановки нажмите Ctrl+C"
echo ""

npm start
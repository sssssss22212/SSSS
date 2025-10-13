#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запуск Minecraft AI Bot с расширениями
Скрипт для удобного запуска бота
"""

import asyncio
import sys
import os
import logging
import argparse
from minecraft_ai_bot import MinecraftAIBot
from bot_extensions import enhance_bot_with_extensions

def setup_logging(log_level="INFO"):
    """Настройка логирования"""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Неверный уровень логирования: {log_level}')
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('minecraft_bot.log', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_dependencies():
    """Проверка зависимостей"""
    required_packages = [
        'mineflayer', 'javascript', 'numpy', 'asyncio'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Отсутствуют зависимости:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\n📦 Установите зависимости командой:")
        print("pip install -r requirements.txt")
        return False
    
    print("✅ Все зависимости установлены")
    return True

def print_banner():
    """Вывод баннера"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🤖 MINECRAFT AI BOT v2.0                 ║
║                                                              ║
║  🎯 Продвинутый ИИ-бот для Minecraft 1.21.8                ║
║  🧠 Машинное обучение и адаптивное поведение                ║
║  ⚔️  Автоматическая добыча, строительство, бой              ║
║  🏗️  Умное строительство и планирование                     ║
║  💬 Голосовое управление через чат                          ║
║                                                              ║
║  Сервер: n1.netronyx.pro:4007                              ║
║  Автор: AI Assistant                                         ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def parse_arguments():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(description='Minecraft AI Bot')
    
    parser.add_argument('--username', '-u', 
                       default='SmartBot',
                       help='Имя пользователя бота (по умолчанию: SmartBot)')
    
    parser.add_argument('--server', '-s',
                       default='n1.netronyx.pro',
                       help='Адрес сервера (по умолчанию: n1.netronyx.pro)')
    
    parser.add_argument('--port', '-p',
                       type=int,
                       default=4007,
                       help='Порт сервера (по умолчанию: 4007)')
    
    parser.add_argument('--log-level', '-l',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO',
                       help='Уровень логирования (по умолчанию: INFO)')
    
    parser.add_argument('--no-learning',
                       action='store_true',
                       help='Отключить машинное обучение')
    
    parser.add_argument('--no-auto-eat',
                       action='store_true', 
                       help='Отключить автоматическое питание')
    
    parser.add_argument('--no-auto-equip',
                       action='store_true',
                       help='Отключить автоматическое экипирование')
    
    parser.add_argument('--strategy',
                       choices=['aggressive', 'cautious', 'balanced'],
                       default='balanced',
                       help='Стратегия поведения (по умолчанию: balanced)')
    
    return parser.parse_args()

async def create_and_run_bot(args):
    """Создание и запуск бота"""
    try:
        # Создание экземпляра бота
        bot = MinecraftAIBot(
            username=args.username,
            server_host=args.server,
            server_port=args.port
        )
        
        # Настройка параметров
        bot.learning_enabled = not args.no_learning
        bot.auto_eat = not args.no_auto_eat
        bot.auto_equip = not args.no_auto_equip
        
        # Настройка стратегии
        if args.strategy == 'aggressive':
            bot.epsilon = 0.3
        elif args.strategy == 'cautious':
            bot.epsilon = 0.05
        else:  # balanced
            bot.epsilon = 0.1
        
        # Добавление расширений
        enhance_bot_with_extensions(bot)
        
        # Добавление новых команд
        bot.command_macro = lambda u, a: asyncio.create_task(
            bot.advanced_commands.execute_macro(a[0]) if a else bot.bot.chat("Укажите макрос")
        )
        
        print(f"🚀 Запуск бота '{args.username}' на сервере {args.server}:{args.port}")
        print(f"📊 Машинное обучение: {'Включено' if bot.learning_enabled else 'Отключено'}")
        print(f"🍖 Автопитание: {'Включено' if bot.auto_eat else 'Отключено'}")
        print(f"⚔️ Автоэкипировка: {'Включено' if bot.auto_equip else 'Отключено'}")
        print(f"🎯 Стратегия: {args.strategy}")
        print("\n💡 Используйте 'помощь' в чате для списка команд")
        print("🛑 Нажмите Ctrl+C для остановки бота\n")
        
        # Запуск бота
        await bot.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Остановка бота по запросу пользователя")
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        logging.error(f"Критическая ошибка: {e}", exc_info=True)

def main():
    """Главная функция"""
    print_banner()
    
    # Парсинг аргументов
    args = parse_arguments()
    
    # Настройка логирования
    setup_logging(args.log_level)
    
    # Проверка зависимостей
    if not check_dependencies():
        sys.exit(1)
    
    # Проверка Python версии
    if sys.version_info < (3, 8):
        print("❌ Требуется Python 3.8 или выше")
        sys.exit(1)
    
    print("✅ Проверки пройдены успешно\n")
    
    # Запуск бота
    try:
        asyncio.run(create_and_run_bot(args))
    except KeyboardInterrupt:
        print("\n👋 До свидания!")
    except Exception as e:
        print(f"❌ Ошибка запуска: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
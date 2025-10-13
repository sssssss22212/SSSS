#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Продвинутый ИИ-бот для Minecraft 1.21.8
Автор: AI Assistant
Версия: 2.0.0

Функциональность:
- Подключение к серверу Minecraft
- Автоматическое движение и навигация
- Добыча всех видов ресурсов
- Автоматический крафт предметов
- Боевая система с ИИ
- Строительство домов и структур
- Машинное обучение и адаптация
- Голосовые команды через чат
- Автоматическое экипирование
- Избегание опасностей
"""

import asyncio
import json
import math
import random
import time
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import numpy as np
from collections import defaultdict, deque
import threading
import pickle
import os
import re

try:
    from mineflayer import mineflayer
    from mineflayer.pathfinder import Movements, goals
    from javascript import require
except ImportError:
    print("Устанавливаю необходимые зависимости...")
    import subprocess
    subprocess.run(["pip", "install", "mineflayer", "javascript", "numpy"])
    from mineflayer import mineflayer
    from mineflayer.pathfinder import Movements, goals
    from javascript import require

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('minecraft_bot.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BotState(Enum):
    """Состояния бота"""
    IDLE = "idle"
    MINING = "mining"
    FIGHTING = "fighting"
    BUILDING = "building"
    FOLLOWING = "following"
    CRAFTING = "crafting"
    EXPLORING = "exploring"
    EATING = "eating"
    EQUIPING = "equiping"
    FLEEING = "fleeing"

class Priority(Enum):
    """Приоритеты задач"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class Task:
    """Класс задачи для бота"""
    name: str
    priority: Priority
    action: callable
    params: Dict[str, Any]
    created_at: float
    timeout: float = 300.0  # 5 минут по умолчанию

@dataclass
class LearningData:
    """Данные для машинного обучения"""
    state: str
    action: str
    reward: float
    next_state: str
    timestamp: float

class MinecraftAIBot:
    """Главный класс ИИ-бота для Minecraft"""
    
    def __init__(self, username: str = "AIBot", server_host: str = "n1.netronyx.pro", server_port: int = 4007):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.bot = None
        
        # Состояние бота
        self.current_state = BotState.IDLE
        self.health = 20
        self.hunger = 20
        self.position = {"x": 0, "y": 0, "z": 0}
        self.inventory = {}
        
        # Система задач
        self.task_queue = deque()
        self.current_task = None
        self.task_lock = threading.Lock()
        
        # ИИ и обучение
        self.q_table = defaultdict(lambda: defaultdict(float))
        self.learning_rate = 0.1
        self.discount_factor = 0.95
        self.epsilon = 0.1  # Exploration rate
        self.learning_data = []
        
        # Карта мира
        self.world_map = {}
        self.known_blocks = set()
        self.dangerous_areas = set()
        self.safe_areas = set()
        
        # Цели и стратегии
        self.current_target = None
        self.follow_target = None
        self.building_plan = None
        
        # Статистика
        self.stats = {
            "blocks_mined": 0,
            "mobs_killed": 0,
            "items_crafted": 0,
            "distance_traveled": 0,
            "deaths": 0,
            "playtime": 0
        }
        
        # Настройки поведения
        self.auto_eat = True
        self.auto_equip = True
        self.auto_defend = True
        self.learning_enabled = True
        
        # Блоки и предметы
        self.block_hardness = self._init_block_hardness()
        self.tool_effectiveness = self._init_tool_effectiveness()
        self.crafting_recipes = self._init_crafting_recipes()
        
        # Команды чата
        self.chat_commands = {
            "иди": self.command_goto,
            "копай": self.command_mine,
            "строй": self.command_build,
            "дом": self.command_build_house,
            "следуй": self.command_follow,
            "стоп": self.command_stop,
            "статус": self.command_status,
            "дроп": self.command_drop,
            "крафт": self.command_craft,
            "атака": self.command_attack,
            "ешь": self.command_eat,
            "одевайся": self.command_equip,
            "добывай": self.command_mine_resource,
            "помощь": self.command_help
        }
        
        self.start_time = time.time()
        logger.info(f"Инициализация бота {username} завершена")

    def _init_block_hardness(self) -> Dict[str, float]:
        """Инициализация твердости блоков"""
        return {
            "stone": 1.5, "cobblestone": 2.0, "dirt": 0.5, "grass_block": 0.6,
            "sand": 0.5, "gravel": 0.6, "wood": 2.0, "oak_log": 2.0,
            "coal_ore": 3.0, "iron_ore": 3.0, "gold_ore": 3.0, "diamond_ore": 3.0,
            "emerald_ore": 3.0, "redstone_ore": 3.0, "lapis_ore": 3.0,
            "obsidian": 50.0, "bedrock": -1, "water": -1, "lava": -1
        }

    def _init_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Инициализация эффективности инструментов"""
        return {
            "pickaxe": {
                "stone": 4.0, "cobblestone": 4.0, "coal_ore": 4.0,
                "iron_ore": 4.0, "gold_ore": 4.0, "diamond_ore": 4.0,
                "emerald_ore": 4.0, "redstone_ore": 4.0, "lapis_ore": 4.0
            },
            "axe": {
                "wood": 4.0, "oak_log": 4.0, "birch_log": 4.0,
                "spruce_log": 4.0, "jungle_log": 4.0
            },
            "shovel": {
                "dirt": 4.0, "grass_block": 4.0, "sand": 4.0, "gravel": 4.0
            },
            "sword": {"mob": 4.0},
            "hoe": {"farmland": 4.0}
        }

    def _init_crafting_recipes(self) -> Dict[str, Dict]:
        """Инициализация рецептов крафта"""
        return {
            "wooden_pickaxe": {
                "ingredients": {"stick": 2, "planks": 3},
                "result": {"wooden_pickaxe": 1}
            },
            "stone_pickaxe": {
                "ingredients": {"stick": 2, "cobblestone": 3},
                "result": {"stone_pickaxe": 1}
            },
            "iron_pickaxe": {
                "ingredients": {"stick": 2, "iron_ingot": 3},
                "result": {"iron_pickaxe": 1}
            },
            "wooden_sword": {
                "ingredients": {"stick": 1, "planks": 2},
                "result": {"wooden_sword": 1}
            },
            "stone_sword": {
                "ingredients": {"stick": 1, "cobblestone": 2},
                "result": {"stone_sword": 1}
            },
            "iron_sword": {
                "ingredients": {"stick": 1, "iron_ingot": 2},
                "result": {"iron_sword": 1}
            },
            "bread": {
                "ingredients": {"wheat": 3},
                "result": {"bread": 1}
            },
            "stick": {
                "ingredients": {"planks": 2},
                "result": {"stick": 4}
            },
            "planks": {
                "ingredients": {"log": 1},
                "result": {"planks": 4}
            }
        }

    async def connect(self):
        """Подключение к серверу Minecraft"""
        try:
            logger.info(f"Подключение к серверу {self.server_host}:{self.server_port}")
            
            self.bot = mineflayer.createBot({
                'host': self.server_host,
                'port': self.server_port,
                'username': self.username,
                'version': '1.21.1'  # Ближайшая поддерживаемая версия
            })
            
            # Загрузка плагинов
            self.bot.loadPlugin(require('mineflayer-pathfinder').pathfinder)
            
            # Настройка событий
            self._setup_events()
            
            logger.info("Успешное подключение к серверу!")
            
            # Запуск основного цикла
            await self._main_loop()
            
        except Exception as e:
            logger.error(f"Ошибка подключения: {e}")
            raise

    def _setup_events(self):
        """Настройка обработчиков событий"""
        
        @self.bot.on('login')
        def on_login():
            logger.info(f"Бот {self.username} вошел в игру")
            self.bot.chat("Привет! Я ИИ-бот. Используйте 'помощь' для списка команд.")

        @self.bot.on('spawn')
        def on_spawn():
            logger.info("Бот заспавнился в мире")
            self._update_position()
            self._scan_environment()

        @self.bot.on('chat')
        def on_chat(username, message):
            if username != self.bot.username:
                self._process_chat_command(username, message)

        @self.bot.on('health')
        def on_health():
            self.health = self.bot.health
            self.hunger = self.bot.food
            
            if self.health < 10 and self.auto_defend:
                self._add_task("flee", Priority.CRITICAL, self._flee_from_danger, {})
            
            if self.hunger < 6 and self.auto_eat:
                self._add_task("eat", Priority.HIGH, self._eat_food, {})

        @self.bot.on('entityHurt')
        def on_entity_hurt(entity):
            if entity == self.bot.entity:
                logger.warning(f"Бот получил урон! Здоровье: {self.health}")
                self._learn_from_damage()

        @self.bot.on('death')
        def on_death():
            logger.error("Бот умер!")
            self.stats["deaths"] += 1
            self._learn_from_death()

        @self.bot.on('kicked')
        def on_kicked(reason):
            logger.error(f"Бот был кикнут: {reason}")

        @self.bot.on('error')
        def on_error(err):
            logger.error(f"Ошибка бота: {err}")

    async def _main_loop(self):
        """Основной цикл работы бота"""
        logger.info("Запуск основного цикла бота")
        
        while True:
            try:
                # Обновление состояния
                self._update_state()
                
                # Обработка задач
                await self._process_tasks()
                
                # ИИ принятие решений
                await self._ai_decision_making()
                
                # Обучение
                if self.learning_enabled:
                    self._update_learning()
                
                # Сохранение данных
                if int(time.time()) % 60 == 0:  # Каждую минуту
                    self._save_learning_data()
                
                await asyncio.sleep(0.1)  # 100ms цикл
                
            except Exception as e:
                logger.error(f"Ошибка в основном цикле: {e}")
                await asyncio.sleep(1)

    def _update_state(self):
        """Обновление состояния бота"""
        if self.bot and self.bot.entity:
            self._update_position()
            self._update_inventory()
            self.stats["playtime"] = time.time() - self.start_time

    def _update_position(self):
        """Обновление позиции бота"""
        if self.bot and self.bot.entity:
            pos = self.bot.entity.position
            old_pos = self.position.copy()
            self.position = {"x": pos.x, "y": pos.y, "z": pos.z}
            
            # Подсчет пройденного расстояния
            if old_pos:
                distance = math.sqrt(
                    (pos.x - old_pos["x"])**2 + 
                    (pos.z - old_pos["z"])**2
                )
                self.stats["distance_traveled"] += distance

    def _update_inventory(self):
        """Обновление инвентаря"""
        if self.bot:
            self.inventory = {}
            for item in self.bot.inventory.items():
                if item:
                    self.inventory[item.name] = item.count

    def _scan_environment(self):
        """Сканирование окружающей среды"""
        if not self.bot:
            return
            
        try:
            # Сканирование блоков в радиусе 16 блоков
            for x in range(-16, 17):
                for y in range(-8, 9):
                    for z in range(-16, 17):
                        pos = self.bot.entity.position.offset(x, y, z)
                        block = self.bot.blockAt(pos)
                        
                        if block and block.name != 'air':
                            block_pos = (int(pos.x), int(pos.y), int(pos.z))
                            self.world_map[block_pos] = block.name
                            self.known_blocks.add(block.name)
                            
                            # Определение опасных зон
                            if block.name in ['lava', 'fire', 'cactus']:
                                self.dangerous_areas.add(block_pos)
                            
                            # Определение безопасных зон
                            if block.name in ['bed', 'torch', 'lantern']:
                                self.safe_areas.add(block_pos)
                                
        except Exception as e:
            logger.error(f"Ошибка сканирования среды: {e}")

    async def _process_tasks(self):
        """Обработка очереди задач"""
        with self.task_lock:
            if not self.current_task and self.task_queue:
                self.current_task = self.task_queue.popleft()
                logger.info(f"Начинаю выполнение задачи: {self.current_task.name}")
            
            if self.current_task:
                try:
                    # Проверка таймаута
                    if time.time() - self.current_task.created_at > self.current_task.timeout:
                        logger.warning(f"Задача {self.current_task.name} превысила таймаут")
                        self.current_task = None
                        return
                    
                    # Выполнение задачи
                    result = await self.current_task.action(**self.current_task.params)
                    
                    if result:
                        logger.info(f"Задача {self.current_task.name} выполнена успешно")
                        self.current_task = None
                        
                except Exception as e:
                    logger.error(f"Ошибка выполнения задачи {self.current_task.name}: {e}")
                    self.current_task = None

    async def _ai_decision_making(self):
        """ИИ принятие решений"""
        if self.current_task:
            return  # Уже выполняется задача
        
        state = self._get_current_state()
        
        # Epsilon-greedy стратегия
        if random.random() < self.epsilon:
            action = self._get_random_action()
        else:
            action = self._get_best_action(state)
        
        # Выполнение действия
        await self._execute_ai_action(action)

    def _get_current_state(self) -> str:
        """Получение текущего состояния для ИИ"""
        state_features = [
            f"health_{min(20, max(0, int(self.health)))}", 
            f"hunger_{min(20, max(0, int(self.hunger)))}",
            f"time_{int(time.time() % 24000 / 1000)}",  # Время суток
            f"items_{len(self.inventory)}",
            f"state_{self.current_state.value}"
        ]
        
        # Добавление информации о ближайших блоках
        nearby_blocks = self._get_nearby_blocks()
        for block_type, count in nearby_blocks.items():
            if count > 0:
                state_features.append(f"near_{block_type}_{min(10, count)}")
        
        return "_".join(state_features)

    def _get_nearby_blocks(self) -> Dict[str, int]:
        """Получение информации о ближайших блоках"""
        nearby = defaultdict(int)
        
        if not self.bot:
            return nearby
        
        try:
            for x in range(-5, 6):
                for y in range(-2, 3):
                    for z in range(-5, 6):
                        pos = self.bot.entity.position.offset(x, y, z)
                        block = self.bot.blockAt(pos)
                        if block and block.name != 'air':
                            nearby[block.name] += 1
        except:
            pass
            
        return nearby

    def _get_random_action(self) -> str:
        """Получение случайного действия для исследования"""
        actions = [
            "explore", "mine_nearby", "craft_tools", "eat", 
            "equip_better", "build_shelter", "collect_wood", "hunt_mobs"
        ]
        return random.choice(actions)

    def _get_best_action(self, state: str) -> str:
        """Получение лучшего действия на основе Q-таблицы"""
        if state not in self.q_table:
            return self._get_random_action()
        
        return max(self.q_table[state], key=self.q_table[state].get)

    async def _execute_ai_action(self, action: str):
        """Выполнение ИИ действия"""
        action_map = {
            "explore": self._ai_explore,
            "mine_nearby": self._ai_mine_nearby,
            "craft_tools": self._ai_craft_tools,
            "eat": self._eat_food,
            "equip_better": self._equip_best_items,
            "build_shelter": self._ai_build_shelter,
            "collect_wood": self._ai_collect_wood,
            "hunt_mobs": self._ai_hunt_mobs
        }
        
        if action in action_map:
            try:
                await action_map[action]()
            except Exception as e:
                logger.error(f"Ошибка выполнения ИИ действия {action}: {e}")

    async def _ai_explore(self):
        """ИИ исследование"""
        if not self.bot:
            return
        
        # Случайное направление для исследования
        angle = random.uniform(0, 2 * math.pi)
        distance = random.uniform(10, 30)
        
        target_x = self.position["x"] + distance * math.cos(angle)
        target_z = self.position["z"] + distance * math.sin(angle)
        
        await self._move_to_position(target_x, self.position["y"], target_z)

    async def _ai_mine_nearby(self):
        """ИИ добыча ближайших ресурсов"""
        valuable_blocks = ["coal_ore", "iron_ore", "gold_ore", "diamond_ore", "emerald_ore"]
        
        target_block = self._find_nearest_block(valuable_blocks)
        if target_block:
            await self._mine_block(target_block)

    async def _ai_craft_tools(self):
        """ИИ крафт инструментов"""
        needed_tools = ["pickaxe", "sword", "axe", "shovel"]
        
        for tool in needed_tools:
            if not self._has_tool(tool):
                await self._craft_best_tool(tool)
                break

    async def _ai_build_shelter(self):
        """ИИ постройка укрытия"""
        if not self._has_shelter_nearby():
            await self._build_simple_shelter()

    async def _ai_collect_wood(self):
        """ИИ сбор дерева"""
        wood_blocks = ["oak_log", "birch_log", "spruce_log", "jungle_log"]
        target_block = self._find_nearest_block(wood_blocks)
        
        if target_block:
            await self._mine_block(target_block)

    async def _ai_hunt_mobs(self):
        """ИИ охота на мобов"""
        if self._has_weapon():
            target_mob = self._find_nearest_hostile_mob()
            if target_mob:
                await self._attack_mob(target_mob)

    def _learn_from_damage(self):
        """Обучение после получения урона"""
        current_state = self._get_current_state()
        
        # Негативная награда за получение урона
        reward = -10
        
        learning_data = LearningData(
            state=current_state,
            action="received_damage",
            reward=reward,
            next_state=current_state,
            timestamp=time.time()
        )
        
        self.learning_data.append(learning_data)
        self._update_q_table(current_state, "received_damage", reward, current_state)

    def _learn_from_death(self):
        """Обучение после смерти"""
        current_state = self._get_current_state()
        
        # Очень негативная награда за смерть
        reward = -100
        
        learning_data = LearningData(
            state=current_state,
            action="died",
            reward=reward,
            next_state="dead",
            timestamp=time.time()
        )
        
        self.learning_data.append(learning_data)
        self._update_q_table(current_state, "died", reward, "dead")

    def _update_learning(self):
        """Обновление системы обучения"""
        # Положительные награды за выживание
        if self.health > 15 and self.hunger > 15:
            current_state = self._get_current_state()
            reward = 1
            
            learning_data = LearningData(
                state=current_state,
                action="survive",
                reward=reward,
                next_state=current_state,
                timestamp=time.time()
            )
            
            self.learning_data.append(learning_data)

    def _update_q_table(self, state: str, action: str, reward: float, next_state: str):
        """Обновление Q-таблицы"""
        if next_state not in self.q_table:
            self.q_table[next_state] = defaultdict(float)
        
        # Q-learning формула
        old_value = self.q_table[state][action]
        next_max = max(self.q_table[next_state].values()) if self.q_table[next_state] else 0
        
        new_value = old_value + self.learning_rate * (
            reward + self.discount_factor * next_max - old_value
        )
        
        self.q_table[state][action] = new_value

    def _save_learning_data(self):
        """Сохранение данных обучения"""
        try:
            with open('bot_learning_data.pkl', 'wb') as f:
                pickle.dump({
                    'q_table': dict(self.q_table),
                    'stats': self.stats,
                    'learning_data': self.learning_data[-1000:]  # Последние 1000 записей
                }, f)
        except Exception as e:
            logger.error(f"Ошибка сохранения данных обучения: {e}")

    def _load_learning_data(self):
        """Загрузка данных обучения"""
        try:
            if os.path.exists('bot_learning_data.pkl'):
                with open('bot_learning_data.pkl', 'rb') as f:
                    data = pickle.load(f)
                    self.q_table = defaultdict(lambda: defaultdict(float), data.get('q_table', {}))
                    self.stats.update(data.get('stats', {}))
                    self.learning_data = data.get('learning_data', [])
                logger.info("Данные обучения загружены успешно")
        except Exception as e:
            logger.error(f"Ошибка загрузки данных обучения: {e}")

    def _add_task(self, name: str, priority: Priority, action: callable, params: Dict[str, Any]):
        """Добавление задачи в очередь"""
        task = Task(
            name=name,
            priority=priority,
            action=action,
            params=params,
            created_at=time.time()
        )
        
        with self.task_lock:
            # Вставка с учетом приоритета
            inserted = False
            for i, existing_task in enumerate(self.task_queue):
                if task.priority.value < existing_task.priority.value:
                    self.task_queue.insert(i, task)
                    inserted = True
                    break
            
            if not inserted:
                self.task_queue.append(task)
        
        logger.info(f"Добавлена задача: {name} (приоритет: {priority.name})")

    def _process_chat_command(self, username: str, message: str):
        """Обработка команд из чата"""
        message = message.lower().strip()
        
        for command, handler in self.chat_commands.items():
            if message.startswith(command):
                try:
                    args = message[len(command):].strip().split()
                    handler(username, args)
                except Exception as e:
                    logger.error(f"Ошибка выполнения команды {command}: {e}")
                    if self.bot:
                        self.bot.chat(f"Ошибка выполнения команды: {e}")
                break

    # Команды чата
    def command_goto(self, username: str, args: List[str]):
        """Команда перемещения"""
        if len(args) >= 3:
            try:
                x, y, z = float(args[0]), float(args[1]), float(args[2])
                self._add_task("goto", Priority.HIGH, self._move_to_position, {"x": x, "y": y, "z": z})
                if self.bot:
                    self.bot.chat(f"Иду к координатам {x}, {y}, {z}")
            except ValueError:
                if self.bot:
                    self.bot.chat("Неверный формат координат. Используйте: иди x y z")
        else:
            if self.bot:
                self.bot.chat("Укажите координаты: иди x y z")

    def command_mine(self, username: str, args: List[str]):
        """Команда добычи"""
        if args:
            block_type = " ".join(args)
            self._add_task("mine", Priority.MEDIUM, self._mine_specific_block, {"block_type": block_type})
            if self.bot:
                self.bot.chat(f"Начинаю добычу {block_type}")
        else:
            self._add_task("mine_auto", Priority.MEDIUM, self._auto_mine, {})
            if self.bot:
                self.bot.chat("Начинаю автоматическую добычу")

    def command_build(self, username: str, args: List[str]):
        """Команда строительства"""
        if args:
            structure = " ".join(args)
            self._add_task("build", Priority.MEDIUM, self._build_structure, {"structure": structure})
            if self.bot:
                self.bot.chat(f"Начинаю строительство: {structure}")
        else:
            if self.bot:
                self.bot.chat("Укажите что строить")

    def command_build_house(self, username: str, args: List[str]):
        """Команда строительства дома"""
        self._add_task("build_house", Priority.MEDIUM, self._build_house, {})
        if self.bot:
            self.bot.chat("Начинаю строительство дома")

    def command_follow(self, username: str, args: List[str]):
        """Команда следования"""
        self.follow_target = username
        self._add_task("follow", Priority.HIGH, self._follow_player, {"username": username})
        if self.bot:
            self.bot.chat(f"Следую за {username}")

    def command_stop(self, username: str, args: List[str]):
        """Команда остановки"""
        with self.task_lock:
            self.task_queue.clear()
            self.current_task = None
        self.follow_target = None
        if self.bot:
            self.bot.chat("Все задачи остановлены")

    def command_status(self, username: str, args: List[str]):
        """Команда статуса"""
        if self.bot:
            status = f"Здоровье: {self.health}/20, Голод: {self.hunger}/20, "
            status += f"Состояние: {self.current_state.value}, "
            status += f"Задач в очереди: {len(self.task_queue)}"
            self.bot.chat(status)

    def command_drop(self, username: str, args: List[str]):
        """Команда сброса предметов"""
        self._add_task("drop", Priority.LOW, self._drop_all_items, {})
        if self.bot:
            self.bot.chat("Сбрасываю все предметы")

    def command_craft(self, username: str, args: List[str]):
        """Команда крафта"""
        if args:
            item = " ".join(args)
            self._add_task("craft", Priority.MEDIUM, self._craft_item, {"item": item})
            if self.bot:
                self.bot.chat(f"Крафчу {item}")
        else:
            if self.bot:
                self.bot.chat("Укажите что крафтить")

    def command_attack(self, username: str, args: List[str]):
        """Команда атаки"""
        self._add_task("attack", Priority.HIGH, self._attack_nearest_mob, {})
        if self.bot:
            self.bot.chat("Атакую ближайшего моба")

    def command_eat(self, username: str, args: List[str]):
        """Команда еды"""
        self._add_task("eat", Priority.HIGH, self._eat_food, {})
        if self.bot:
            self.bot.chat("Ем еду")

    def command_equip(self, username: str, args: List[str]):
        """Команда экипировки"""
        self._add_task("equip", Priority.MEDIUM, self._equip_best_items, {})
        if self.bot:
            self.bot.chat("Экипирую лучшие предметы")

    def command_mine_resource(self, username: str, args: List[str]):
        """Команда добычи ресурса"""
        if args:
            resource = args[0].lower()
            resource_map = {
                "камень": "stone",
                "железо": "iron_ore", 
                "уголь": "coal_ore",
                "золото": "gold_ore",
                "алмаз": "diamond_ore",
                "дерево": "oak_log"
            }
            
            block_type = resource_map.get(resource, resource)
            self._add_task("mine_resource", Priority.MEDIUM, self._mine_specific_block, {"block_type": block_type})
            if self.bot:
                self.bot.chat(f"Добываю {resource}")
        else:
            if self.bot:
                self.bot.chat("Укажите что добывать")

    def command_help(self, username: str, args: List[str]):
        """Команда помощи"""
        if self.bot:
            commands = [
                "Доступные команды:",
                "иди x y z - перейти к координатам",
                "копай [блок] - добыча блоков", 
                "строй [структура] - строительство",
                "дом - построить дом",
                "следуй - следовать за игроком",
                "стоп - остановить все задачи",
                "статус - показать статус",
                "дроп - сбросить предметы",
                "крафт [предмет] - скрафтить предмет",
                "атака - атаковать мобов",
                "ешь - поесть",
                "одевайся - экипировать предметы",
                "добывай [ресурс] - добыть ресурс"
            ]
            
            for cmd in commands:
                self.bot.chat(cmd)
                await asyncio.sleep(0.5)

    # Основные функции бота
    async def _move_to_position(self, x: float, y: float, z: float) -> bool:
        """Перемещение к позиции"""
        if not self.bot:
            return False
        
        try:
            mcData = require('minecraft-data')(self.bot.version)
            movements = Movements(self.bot, mcData)
            
            goal = goals.GoalNear(x, y, z, 1)
            self.bot.pathfinder.setGoal(goal)
            
            # Ожидание достижения цели
            timeout = 30  # 30 секунд
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                current_pos = self.bot.entity.position
                distance = math.sqrt(
                    (current_pos.x - x)**2 + 
                    (current_pos.y - y)**2 + 
                    (current_pos.z - z)**2
                )
                
                if distance < 2:
                    return True
                
                await asyncio.sleep(0.5)
            
            return False
            
        except Exception as e:
            logger.error(f"Ошибка перемещения: {e}")
            return False

    async def _mine_block(self, block_position: Tuple[int, int, int]) -> bool:
        """Добыча блока"""
        if not self.bot:
            return False
        
        try:
            x, y, z = block_position
            block = self.bot.blockAt(self.bot.vec3(x, y, z))
            
            if not block or block.name == 'air':
                return False
            
            # Подбор подходящего инструмента
            best_tool = self._get_best_tool_for_block(block.name)
            if best_tool:
                await self._equip_item(best_tool)
            
            # Перемещение к блоку
            await self._move_to_position(x, y + 1, z)
            
            # Добыча блока
            await self.bot.dig(block)
            
            self.stats["blocks_mined"] += 1
            logger.info(f"Добыт блок {block.name} на позиции {x}, {y}, {z}")
            
            return True
            
        except Exception as e:
            logger.error(f"Ошибка добычи блока: {e}")
            return False

    async def _mine_specific_block(self, block_type: str) -> bool:
        """Добыча определенного типа блока"""
        target_block = self._find_nearest_block([block_type])
        if target_block:
            return await self._mine_block(target_block)
        else:
            if self.bot:
                self.bot.chat(f"Не найден блок типа {block_type}")
            return False

    async def _auto_mine(self) -> bool:
        """Автоматическая добыча ценных блоков"""
        valuable_blocks = [
            "diamond_ore", "emerald_ore", "gold_ore", 
            "iron_ore", "coal_ore", "redstone_ore", "lapis_ore"
        ]
        
        target_block = self._find_nearest_block(valuable_blocks)
        if target_block:
            return await self._mine_block(target_block)
        
        # Если ценных блоков нет, добываем камень
        stone_block = self._find_nearest_block(["stone", "cobblestone"])
        if stone_block:
            return await self._mine_block(stone_block)
        
        return False

    def _find_nearest_block(self, block_types: List[str]) -> Optional[Tuple[int, int, int]]:
        """Поиск ближайшего блока определенного типа"""
        if not self.bot:
            return None
        
        try:
            min_distance = float('inf')
            nearest_block = None
            current_pos = self.bot.entity.position
            
            # Поиск в радиусе 32 блока
            for x in range(-32, 33):
                for y in range(-16, 17):
                    for z in range(-32, 33):
                        pos = current_pos.offset(x, y, z)
                        block = self.bot.blockAt(pos)
                        
                        if block and block.name in block_types:
                            distance = math.sqrt(x*x + y*y + z*z)
                            if distance < min_distance:
                                min_distance = distance
                                nearest_block = (int(pos.x), int(pos.y), int(pos.z))
            
            return nearest_block
            
        except Exception as e:
            logger.error(f"Ошибка поиска блока: {e}")
            return None

    def _get_best_tool_for_block(self, block_name: str) -> Optional[str]:
        """Получение лучшего инструмента для блока"""
        tool_priorities = {
            "pickaxe": ["diamond_pickaxe", "iron_pickaxe", "stone_pickaxe", "wooden_pickaxe"],
            "axe": ["diamond_axe", "iron_axe", "stone_axe", "wooden_axe"],
            "shovel": ["diamond_shovel", "iron_shovel", "stone_shovel", "wooden_shovel"],
            "sword": ["diamond_sword", "iron_sword", "stone_sword", "wooden_sword"]
        }
        
        # Определение типа инструмента для блока
        tool_type = None
        for tool, blocks in self.tool_effectiveness.items():
            if block_name in blocks:
                tool_type = tool
                break
        
        if not tool_type:
            return None
        
        # Поиск лучшего доступного инструмента
        for tool_name in tool_priorities.get(tool_type, []):
            if tool_name in self.inventory and self.inventory[tool_name] > 0:
                return tool_name
        
        return None

    async def _equip_item(self, item_name: str) -> bool:
        """Экипировка предмета"""
        if not self.bot:
            return False
        
        try:
            item = self.bot.inventory.findInventoryItem(item_name)
            if item:
                await self.bot.equip(item, 'hand')
                return True
            return False
        except Exception as e:
            logger.error(f"Ошибка экипировки {item_name}: {e}")
            return False

    async def _equip_best_items(self) -> bool:
        """Экипировка лучших доступных предметов"""
        if not self.bot:
            return False
        
        try:
            # Экипировка лучшего оружия
            weapons = ["diamond_sword", "iron_sword", "stone_sword", "wooden_sword"]
            for weapon in weapons:
                if weapon in self.inventory and self.inventory[weapon] > 0:
                    await self._equip_item(weapon)
                    break
            
            # Экипировка брони
            armor_slots = {
                "head": ["diamond_helmet", "iron_helmet", "chainmail_helmet", "leather_helmet"],
                "torso": ["diamond_chestplate", "iron_chestplate", "chainmail_chestplate", "leather_chestplate"],
                "legs": ["diamond_leggings", "iron_leggings", "chainmail_leggings", "leather_leggings"],
                "feet": ["diamond_boots", "iron_boots", "chainmail_boots", "leather_boots"]
            }
            
            for slot, armor_types in armor_slots.items():
                for armor in armor_types:
                    if armor in self.inventory and self.inventory[armor] > 0:
                        try:
                            item = self.bot.inventory.findInventoryItem(armor)
                            if item:
                                await self.bot.equip(item, slot)
                                break
                        except:
                            continue
            
            return True
            
        except Exception as e:
            logger.error(f"Ошибка экипировки предметов: {e}")
            return False

    async def _eat_food(self) -> bool:
        """Поедание еды"""
        if not self.bot or self.hunger >= 20:
            return True
        
        try:
            food_items = [
                "cooked_beef", "cooked_porkchop", "cooked_chicken", "cooked_salmon",
                "bread", "apple", "carrot", "potato", "beetroot"
            ]
            
            for food in food_items:
                if food in self.inventory and self.inventory[food] > 0:
                    item = self.bot.inventory.findInventoryItem(food)
                    if item:
                        await self.bot.equip(item, 'hand')
                        await self.bot.consume()
                        logger.info(f"Съел {food}")
                        return True
            
            if self.bot:
                self.bot.chat("У меня нет еды!")
            return False
            
        except Exception as e:
            logger.error(f"Ошибка поедания еды: {e}")
            return False

    async def _craft_item(self, item: str) -> bool:
        """Крафт предмета"""
        if not self.bot:
            return False
        
        try:
            if item not in self.crafting_recipes:
                if self.bot:
                    self.bot.chat(f"Не знаю рецепт для {item}")
                return False
            
            recipe = self.crafting_recipes[item]
            
            # Проверка наличия ингредиентов
            for ingredient, count in recipe["ingredients"].items():
                if ingredient not in self.inventory or self.inventory[ingredient] < count:
                    if self.bot:
                        self.bot.chat(f"Не хватает {ingredient} для крафта {item}")
                    return False
            
            # Поиск верстака
            crafting_table = self._find_nearest_block(["crafting_table"])
            if not crafting_table and item not in ["stick", "planks"]:
                if self.bot:
                    self.bot.chat("Нужен верстак для крафта")
                return False
            
            # Крафт предмета
            mcData = require('minecraft-data')(self.bot.version)
            recipe_item = mcData.recipesByName[item]
            
            if recipe_item:
                await self.bot.craft(recipe_item[0], 1)
                self.stats["items_crafted"] += 1
                logger.info(f"Скрафчен предмет: {item}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Ошибка крафта {item}: {e}")
            return False

    async def _craft_best_tool(self, tool_type: str) -> bool:
        """Крафт лучшего доступного инструмента"""
        tool_materials = ["diamond", "iron", "stone", "wooden"]
        
        for material in tool_materials:
            tool_name = f"{material}_{tool_type}"
            if await self._craft_item(tool_name):
                return True
        
        return False

    async def _attack_mob(self, mob_entity) -> bool:
        """Атака моба"""
        if not self.bot or not mob_entity:
            return False
        
        try:
            # Экипировка лучшего оружия
            await self._equip_best_weapon()
            
            # Приближение к мобу
            mob_pos = mob_entity.position
            await self._move_to_position(mob_pos.x, mob_pos.y, mob_pos.z)
            
            # Атака
            await self.bot.attack(mob_entity)
            self.stats["mobs_killed"] += 1
            
            logger.info(f"Атаковал моба: {mob_entity.name}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка атаки моба: {e}")
            return False

    async def _attack_nearest_mob(self) -> bool:
        """Атака ближайшего враждебного моба"""
        target_mob = self._find_nearest_hostile_mob()
        if target_mob:
            return await self._attack_mob(target_mob)
        return False

    def _find_nearest_hostile_mob(self):
        """Поиск ближайшего враждебного моба"""
        if not self.bot:
            return None
        
        try:
            hostile_mobs = [
                "zombie", "skeleton", "creeper", "spider", "enderman",
                "witch", "slime", "magma_cube", "blaze", "ghast"
            ]
            
            nearest_mob = None
            min_distance = float('inf')
            
            for entity in self.bot.entities.values():
                if hasattr(entity, 'name') and entity.name in hostile_mobs:
                    distance = self.bot.entity.position.distanceTo(entity.position)
                    if distance < min_distance and distance < 16:  # В радиусе 16 блоков
                        min_distance = distance
                        nearest_mob = entity
            
            return nearest_mob
            
        except Exception as e:
            logger.error(f"Ошибка поиска враждебного моба: {e}")
            return None

    async def _equip_best_weapon(self) -> bool:
        """Экипировка лучшего оружия"""
        weapons = ["diamond_sword", "iron_sword", "stone_sword", "wooden_sword", "diamond_axe", "iron_axe"]
        
        for weapon in weapons:
            if weapon in self.inventory and self.inventory[weapon] > 0:
                return await self._equip_item(weapon)
        
        return False

    async def _build_structure(self, structure: str) -> bool:
        """Строительство структуры"""
        structure_lower = structure.lower()
        
        if "дом" in structure_lower or "house" in structure_lower:
            return await self._build_house()
        elif "мост" in structure_lower or "bridge" in structure_lower:
            return await self._build_bridge()
        elif "башня" in structure_lower or "tower" in structure_lower:
            return await self._build_tower()
        else:
            if self.bot:
                self.bot.chat(f"Не знаю как строить {structure}")
            return False

    async def _build_house(self) -> bool:
        """Строительство дома"""
        if not self.bot:
            return False
        
        try:
            # Проверка материалов
            required_materials = {"cobblestone": 64, "oak_planks": 32, "glass": 8}
            
            for material, count in required_materials.items():
                if material not in self.inventory or self.inventory[material] < count:
                    if self.bot:
                        self.bot.chat(f"Нужно больше {material} для строительства дома")
                    return False
            
            # Начальная позиция для строительства
            start_pos = self.bot.entity.position
            base_x, base_y, base_z = int(start_pos.x), int(start_pos.y), int(start_pos.z)
            
            # Строительство фундамента (5x5)
            for x in range(5):
                for z in range(5):
                    pos = self.bot.vec3(base_x + x, base_y, base_z + z)
                    await self._place_block("cobblestone", pos)
            
            # Строительство стен
            for y in range(1, 4):  # Высота 3 блока
                # Передняя и задняя стены
                for x in range(5):
                    await self._place_block("cobblestone", self.bot.vec3(base_x + x, base_y + y, base_z))
                    await self._place_block("cobblestone", self.bot.vec3(base_x + x, base_y + y, base_z + 4))
                
                # Левая и правая стены
                for z in range(1, 4):
                    await self._place_block("cobblestone", self.bot.vec3(base_x, base_y + y, base_z + z))
                    await self._place_block("cobblestone", self.bot.vec3(base_x + 4, base_y + y, base_z + z))
            
            # Крыша
            for x in range(5):
                for z in range(5):
                    await self._place_block("oak_planks", self.bot.vec3(base_x + x, base_y + 4, base_z + z))
            
            # Дверь (убираем блоки для входа)
            await self._break_block(self.bot.vec3(base_x + 2, base_y + 1, base_z))
            await self._break_block(self.bot.vec3(base_x + 2, base_y + 2, base_z))
            
            # Окна
            await self._place_block("glass", self.bot.vec3(base_x + 1, base_y + 2, base_z + 4))
            await self._place_block("glass", self.bot.vec3(base_x + 3, base_y + 2, base_z + 4))
            
            if self.bot:
                self.bot.chat("Дом построен!")
            
            logger.info("Дом успешно построен")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка строительства дома: {e}")
            return False

    async def _place_block(self, block_type: str, position) -> bool:
        """Размещение блока"""
        if not self.bot:
            return False
        
        try:
            # Проверка наличия блока в инвентаре
            if block_type not in self.inventory or self.inventory[block_type] <= 0:
                return False
            
            # Экипировка блока
            item = self.bot.inventory.findInventoryItem(block_type)
            if not item:
                return False
            
            await self.bot.equip(item, 'hand')
            
            # Перемещение к позиции
            await self._move_to_position(position.x, position.y + 1, position.z)
            
            # Размещение блока
            reference_block = self.bot.blockAt(position.offset(0, -1, 0))
            if reference_block:
                await self.bot.placeBlock(reference_block, self.bot.vec3(0, 1, 0))
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Ошибка размещения блока {block_type}: {e}")
            return False

    async def _break_block(self, position) -> bool:
        """Разрушение блока"""
        if not self.bot:
            return False
        
        try:
            block = self.bot.blockAt(position)
            if block and block.name != 'air':
                await self.bot.dig(block)
                return True
            return False
        except Exception as e:
            logger.error(f"Ошибка разрушения блока: {e}")
            return False

    async def _build_bridge(self) -> bool:
        """Строительство моста"""
        # Простая реализация моста
        if not self.bot:
            return False
        
        try:
            start_pos = self.bot.entity.position
            
            # Строим мост длиной 10 блоков в направлении взгляда
            for i in range(10):
                pos = self.bot.vec3(start_pos.x + i, start_pos.y, start_pos.z)
                await self._place_block("cobblestone", pos)
            
            if self.bot:
                self.bot.chat("Мост построен!")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка строительства моста: {e}")
            return False

    async def _build_tower(self) -> bool:
        """Строительство башни"""
        if not self.bot:
            return False
        
        try:
            start_pos = self.bot.entity.position
            base_x, base_y, base_z = int(start_pos.x), int(start_pos.y), int(start_pos.z)
            
            # Строим башню 3x3x10
            for y in range(10):
                for x in range(3):
                    for z in range(3):
                        # Полые стены
                        if x == 0 or x == 2 or z == 0 or z == 2:
                            pos = self.bot.vec3(base_x + x, base_y + y, base_z + z)
                            await self._place_block("cobblestone", pos)
            
            if self.bot:
                self.bot.chat("Башня построена!")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка строительства башни: {e}")
            return False

    async def _build_simple_shelter(self) -> bool:
        """Строительство простого укрытия"""
        if not self.bot:
            return False
        
        try:
            # Простое укрытие 3x3x2
            start_pos = self.bot.entity.position
            base_x, base_y, base_z = int(start_pos.x), int(start_pos.y), int(start_pos.z)
            
            # Стены
            for x in range(3):
                for z in range(3):
                    if x == 0 or x == 2 or z == 0 or z == 2:
                        await self._place_block("dirt", self.bot.vec3(base_x + x, base_y + 1, base_z + z))
            
            # Крыша
            for x in range(3):
                for z in range(3):
                    await self._place_block("dirt", self.bot.vec3(base_x + x, base_y + 2, base_z + z))
            
            return True
            
        except Exception as e:
            logger.error(f"Ошибка строительства укрытия: {e}")
            return False

    async def _follow_player(self, username: str) -> bool:
        """Следование за игроком"""
        if not self.bot:
            return False
        
        try:
            player = self.bot.players[username]
            if not player or not player.entity:
                return False
            
            player_pos = player.entity.position
            distance = self.bot.entity.position.distanceTo(player_pos)
            
            # Следуем, если игрок далеко
            if distance > 3:
                await self._move_to_position(player_pos.x, player_pos.y, player_pos.z)
            
            return True
            
        except Exception as e:
            logger.error(f"Ошибка следования за игроком {username}: {e}")
            return False

    async def _drop_all_items(self) -> bool:
        """Сброс всех предметов"""
        if not self.bot:
            return False
        
        try:
            for item in self.bot.inventory.items():
                if item:
                    await self.bot.toss(item.type, None, item.count)
            
            if self.bot:
                self.bot.chat("Все предметы сброшены")
            
            return True
            
        except Exception as e:
            logger.error(f"Ошибка сброса предметов: {e}")
            return False

    async def _flee_from_danger(self) -> bool:
        """Бегство от опасности"""
        if not self.bot:
            return False
        
        try:
            # Поиск ближайшей опасности
            dangers = []
            
            # Враждебные мобы
            hostile_mob = self._find_nearest_hostile_mob()
            if hostile_mob:
                dangers.append(hostile_mob.position)
            
            # Опасные блоки
            for pos in self.dangerous_areas:
                block_pos = self.bot.vec3(pos[0], pos[1], pos[2])
                distance = self.bot.entity.position.distanceTo(block_pos)
                if distance < 10:
                    dangers.append(block_pos)
            
            if not dangers:
                return True
            
            # Вычисление направления бегства
            current_pos = self.bot.entity.position
            flee_x, flee_z = 0, 0
            
            for danger_pos in dangers:
                dx = current_pos.x - danger_pos.x
                dz = current_pos.z - danger_pos.z
                distance = math.sqrt(dx*dx + dz*dz)
                
                if distance > 0:
                    flee_x += dx / distance
                    flee_z += dz / distance
            
            # Нормализация направления
            flee_length = math.sqrt(flee_x*flee_x + flee_z*flee_z)
            if flee_length > 0:
                flee_x /= flee_length
                flee_z /= flee_length
            
            # Бегство на 20 блоков
            target_x = current_pos.x + flee_x * 20
            target_z = current_pos.z + flee_z * 20
            
            await self._move_to_position(target_x, current_pos.y, target_z)
            
            logger.info("Бегство от опасности выполнено")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка бегства от опасности: {e}")
            return False

    def _has_tool(self, tool_type: str) -> bool:
        """Проверка наличия инструмента"""
        tool_names = [f"{material}_{tool_type}" for material in ["diamond", "iron", "stone", "wooden"]]
        
        for tool_name in tool_names:
            if tool_name in self.inventory and self.inventory[tool_name] > 0:
                return True
        
        return False

    def _has_weapon(self) -> bool:
        """Проверка наличия оружия"""
        weapons = ["diamond_sword", "iron_sword", "stone_sword", "wooden_sword"]
        
        for weapon in weapons:
            if weapon in self.inventory and self.inventory[weapon] > 0:
                return True
        
        return False

    def _has_shelter_nearby(self) -> bool:
        """Проверка наличия укрытия поблизости"""
        # Простая проверка - есть ли крыша над головой
        if not self.bot:
            return False
        
        try:
            pos = self.bot.entity.position
            for y in range(1, 5):
                block = self.bot.blockAt(pos.offset(0, y, 0))
                if block and block.name != 'air':
                    return True
            
            return False
            
        except:
            return False

    async def start(self):
        """Запуск бота"""
        try:
            # Загрузка данных обучения
            self._load_learning_data()
            
            logger.info("Запуск ИИ-бота для Minecraft...")
            await self.connect()
            
        except KeyboardInterrupt:
            logger.info("Остановка бота по запросу пользователя")
        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
        finally:
            # Сохранение данных при выходе
            self._save_learning_data()

# Функция для запуска бота
async def main():
    """Главная функция"""
    print("=== Minecraft AI Bot v2.0 ===")
    print("Продвинутый ИИ-бот для Minecraft 1.21.8")
    print("Сервер: n1.netronyx.pro:4007")
    print("=====================================")
    
    # Создание и запуск бота
    bot = MinecraftAIBot(
        username="SmartBot",
        server_host="n1.netronyx.pro",
        server_port=4007
    )
    
    await bot.start()

if __name__ == "__main__":
    # Запуск бота
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nБот остановлен пользователем")
    except Exception as e:
        print(f"Ошибка запуска: {e}")
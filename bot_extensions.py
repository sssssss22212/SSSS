#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Расширенные модули для Minecraft AI Bot
Дополнительный функционал и улучшения
"""

import asyncio
import json
import math
import random
import time
import logging
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
from collections import defaultdict, deque
import threading

logger = logging.getLogger(__name__)

class AdvancedPathfinding:
    """Продвинутая система навигации с A* алгоритмом"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.world_map = {}
        self.obstacles = set()
        self.cache = {}
        
    def heuristic(self, a: Tuple[int, int, int], b: Tuple[int, int, int]) -> float:
        """Эвристическая функция для A*"""
        return math.sqrt((a[0] - b[0])**2 + (a[1] - b[1])**2 + (a[2] - b[2])**2)
    
    def get_neighbors(self, pos: Tuple[int, int, int]) -> List[Tuple[int, int, int]]:
        """Получение соседних позиций"""
        x, y, z = pos
        neighbors = []
        
        # 26 направлений (включая диагонали и вертикальные)
        for dx in [-1, 0, 1]:
            for dy in [-1, 0, 1]:
                for dz in [-1, 0, 1]:
                    if dx == 0 and dy == 0 and dz == 0:
                        continue
                    
                    new_pos = (x + dx, y + dy, z + dz)
                    if self.is_walkable(new_pos):
                        neighbors.append(new_pos)
        
        return neighbors
    
    def is_walkable(self, pos: Tuple[int, int, int]) -> bool:
        """Проверка проходимости позиции"""
        x, y, z = pos
        
        # Проверка на препятствия
        if pos in self.obstacles:
            return False
        
        # Проверка границ мира
        if y < 0 or y > 256:
            return False
        
        try:
            if self.bot.bot:
                block = self.bot.bot.blockAt(self.bot.bot.vec3(x, y, z))
                if block and block.name in ['air', 'water', 'tall_grass', 'grass']:
                    return True
        except:
            pass
        
        return True
    
    async def find_path(self, start: Tuple[int, int, int], goal: Tuple[int, int, int]) -> List[Tuple[int, int, int]]:
        """Поиск пути с использованием A* алгоритма"""
        cache_key = (start, goal)
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        open_set = [(0, start)]
        came_from = {}
        g_score = {start: 0}
        f_score = {start: self.heuristic(start, goal)}
        
        while open_set:
            current = min(open_set, key=lambda x: f_score.get(x[1], float('inf')))[1]
            open_set = [x for x in open_set if x[1] != current]
            
            if current == goal:
                # Восстановление пути
                path = []
                while current in came_from:
                    path.append(current)
                    current = came_from[current]
                path.append(start)
                path.reverse()
                
                self.cache[cache_key] = path
                return path
            
            for neighbor in self.get_neighbors(current):
                tentative_g_score = g_score[current] + 1
                
                if neighbor not in g_score or tentative_g_score < g_score[neighbor]:
                    came_from[neighbor] = current
                    g_score[neighbor] = tentative_g_score
                    f_score[neighbor] = g_score[neighbor] + self.heuristic(neighbor, goal)
                    
                    if (f_score[neighbor], neighbor) not in open_set:
                        open_set.append((f_score[neighbor], neighbor))
        
        return []  # Путь не найден

class ResourceManager:
    """Управление ресурсами и инвентарем"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.resource_priorities = {
            "diamond": 100, "emerald": 95, "gold_ingot": 90,
            "iron_ingot": 85, "coal": 70, "redstone": 65,
            "lapis_lazuli": 60, "food": 80, "wood": 50,
            "stone": 30, "dirt": 10
        }
        
    def get_inventory_value(self) -> int:
        """Подсчет ценности инвентаря"""
        total_value = 0
        
        for item, count in self.bot.inventory.items():
            item_value = self.resource_priorities.get(item, 1)
            total_value += item_value * count
        
        return total_value
    
    def should_keep_item(self, item_name: str) -> bool:
        """Определение нужности предмета"""
        essential_items = [
            "diamond", "emerald", "gold_ingot", "iron_ingot",
            "coal", "food", "tools", "weapons", "armor"
        ]
        
        for essential in essential_items:
            if essential in item_name:
                return True
        
        return False
    
    async def optimize_inventory(self):
        """Оптимизация инвентаря"""
        if not self.bot.bot:
            return
        
        try:
            # Сортировка предметов по ценности
            items_by_value = []
            
            for item in self.bot.bot.inventory.items():
                if item:
                    value = self.resource_priorities.get(item.name, 1)
                    items_by_value.append((value, item))
            
            items_by_value.sort(key=lambda x: x[0], reverse=True)
            
            # Удаление наименее ценных предметов при переполнении
            if len(items_by_value) > 32:  # Оставляем место в инвентаре
                for _, item in items_by_value[32:]:
                    if not self.should_keep_item(item.name):
                        await self.bot.bot.toss(item.type, None, item.count)
            
        except Exception as e:
            logger.error(f"Ошибка оптимизации инвентаря: {e}")

class CombatSystem:
    """Продвинутая боевая система"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.combat_stats = {
            "total_fights": 0,
            "wins": 0,
            "losses": 0,
            "damage_dealt": 0,
            "damage_taken": 0
        }
        
    def analyze_threat(self, entity) -> int:
        """Анализ угрозы от сущности"""
        threat_levels = {
            "zombie": 3, "skeleton": 4, "creeper": 8, "spider": 2,
            "enderman": 6, "witch": 5, "blaze": 7, "ghast": 6,
            "wither_skeleton": 9, "wither": 10, "ender_dragon": 10
        }
        
        base_threat = threat_levels.get(entity.name, 1)
        
        # Учет расстояния
        if hasattr(entity, 'position') and self.bot.bot:
            distance = self.bot.bot.entity.position.distanceTo(entity.position)
            if distance < 3:
                base_threat *= 2
            elif distance < 6:
                base_threat *= 1.5
        
        return base_threat
    
    async def execute_combat_strategy(self, target_entity):
        """Выполнение боевой стратегии"""
        if not self.bot.bot or not target_entity:
            return False
        
        try:
            threat_level = self.analyze_threat(target_entity)
            
            # Выбор стратегии на основе угрозы
            if threat_level >= 8:
                return await self._kite_strategy(target_entity)
            elif threat_level >= 5:
                return await self._hit_and_run_strategy(target_entity)
            else:
                return await self._direct_combat_strategy(target_entity)
                
        except Exception as e:
            logger.error(f"Ошибка выполнения боевой стратегии: {e}")
            return False
    
    async def _kite_strategy(self, target_entity):
        """Стратегия кайтинга (атака на расстоянии)"""
        # Поддержание дистанции и атака
        target_pos = target_entity.position
        bot_pos = self.bot.bot.entity.position
        
        # Отступление если слишком близко
        distance = bot_pos.distanceTo(target_pos)
        if distance < 5:
            flee_x = bot_pos.x + (bot_pos.x - target_pos.x) * 2
            flee_z = bot_pos.z + (bot_pos.z - target_pos.z) * 2
            await self.bot._move_to_position(flee_x, bot_pos.y, flee_z)
        
        # Атака луком если есть
        bow_item = self.bot.bot.inventory.findInventoryItem("bow")
        if bow_item:
            await self.bot.bot.equip(bow_item, 'hand')
            # Логика стрельбы из лука
        
        return True
    
    async def _hit_and_run_strategy(self, target_entity):
        """Стратегия ударил-убежал"""
        # Атака и отступление
        await self.bot._attack_mob(target_entity)
        
        # Быстрое отступление
        target_pos = target_entity.position
        bot_pos = self.bot.bot.entity.position
        
        retreat_x = bot_pos.x + (bot_pos.x - target_pos.x)
        retreat_z = bot_pos.z + (bot_pos.z - target_pos.z)
        
        await self.bot._move_to_position(retreat_x, bot_pos.y, retreat_z)
        await asyncio.sleep(1)  # Пауза перед следующей атакой
        
        return True
    
    async def _direct_combat_strategy(self, target_entity):
        """Прямая боевая стратегия"""
        # Прямая атака в ближнем бою
        return await self.bot._attack_mob(target_entity)

class BuildingPlanner:
    """Планировщик строительства"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.building_templates = {
            "house": self._get_house_template(),
            "tower": self._get_tower_template(),
            "bridge": self._get_bridge_template(),
            "farm": self._get_farm_template(),
            "mine_shaft": self._get_mine_shaft_template()
        }
    
    def _get_house_template(self) -> Dict:
        """Шаблон дома"""
        return {
            "size": (7, 4, 7),
            "materials": {
                "cobblestone": 80,
                "oak_planks": 40,
                "glass": 12,
                "oak_door": 1,
                "torch": 8
            },
            "structure": [
                # Фундамент
                {"layer": 0, "pattern": "solid", "material": "cobblestone"},
                # Стены
                {"layer": 1, "pattern": "walls", "material": "cobblestone"},
                {"layer": 2, "pattern": "walls", "material": "cobblestone"},
                {"layer": 3, "pattern": "walls", "material": "cobblestone"},
                # Крыша
                {"layer": 4, "pattern": "solid", "material": "oak_planks"}
            ],
            "features": [
                {"type": "door", "position": (3, 1, 0)},
                {"type": "window", "position": (1, 2, 6)},
                {"type": "window", "position": (5, 2, 6)},
                {"type": "torch", "position": (2, 3, 2)},
                {"type": "torch", "position": (4, 3, 4)}
            ]
        }
    
    def _get_tower_template(self) -> Dict:
        """Шаблон башни"""
        return {
            "size": (5, 15, 5),
            "materials": {
                "stone_bricks": 200,
                "oak_planks": 50,
                "ladder": 20,
                "torch": 15
            },
            "structure": [
                # Многослойная башня
                *[{"layer": i, "pattern": "hollow_walls", "material": "stone_bricks"} 
                  for i in range(15)]
            ],
            "features": [
                {"type": "ladder", "position": (2, 1, 2), "height": 14},
                {"type": "door", "position": (2, 1, 0)},
                *[{"type": "torch", "position": (1, i*3+2, 1)} for i in range(5)]
            ]
        }
    
    def _get_bridge_template(self) -> Dict:
        """Шаблон моста"""
        return {
            "size": (3, 1, 20),
            "materials": {
                "oak_planks": 60,
                "oak_fence": 40
            },
            "structure": [
                {"layer": 0, "pattern": "bridge", "material": "oak_planks"}
            ],
            "features": [
                {"type": "railings", "material": "oak_fence"}
            ]
        }
    
    def _get_farm_template(self) -> Dict:
        """Шаблон фермы"""
        return {
            "size": (9, 1, 9),
            "materials": {
                "dirt": 81,
                "water_bucket": 1,
                "wheat_seeds": 64,
                "oak_fence": 32
            },
            "structure": [
                {"layer": 0, "pattern": "farmland", "material": "dirt"}
            ],
            "features": [
                {"type": "water_source", "position": (4, 0, 4)},
                {"type": "fence_perimeter", "material": "oak_fence"}
            ]
        }
    
    def _get_mine_shaft_template(self) -> Dict:
        """Шаблон шахты"""
        return {
            "size": (3, 20, 3),
            "materials": {
                "ladder": 20,
                "torch": 10,
                "chest": 2
            },
            "structure": [
                # Вертикальная шахта
                *[{"layer": -i, "pattern": "hollow", "material": "air"} 
                  for i in range(20)]
            ],
            "features": [
                {"type": "ladder", "position": (1, 0, 1), "height": -20},
                {"type": "storage_room", "position": (0, -19, 0)}
            ]
        }
    
    async def build_from_template(self, template_name: str, start_pos: Tuple[int, int, int]):
        """Строительство по шаблону"""
        if template_name not in self.building_templates:
            logger.error(f"Неизвестный шаблон: {template_name}")
            return False
        
        template = self.building_templates[template_name]
        
        # Проверка материалов
        if not await self._check_materials(template["materials"]):
            logger.warning("Недостаточно материалов для строительства")
            return False
        
        # Строительство по слоям
        for layer_info in template["structure"]:
            await self._build_layer(start_pos, layer_info, template["size"])
        
        # Добавление особенностей
        for feature in template.get("features", []):
            await self._add_feature(start_pos, feature)
        
        logger.info(f"Строительство {template_name} завершено")
        return True
    
    async def _check_materials(self, required_materials: Dict[str, int]) -> bool:
        """Проверка наличия материалов"""
        for material, count in required_materials.items():
            if material not in self.bot.inventory or self.bot.inventory[material] < count:
                return False
        return True
    
    async def _build_layer(self, start_pos: Tuple[int, int, int], layer_info: Dict, size: Tuple[int, int, int]):
        """Строительство слоя"""
        x_start, y_start, z_start = start_pos
        width, height, length = size
        layer = layer_info["layer"]
        pattern = layer_info["pattern"]
        material = layer_info["material"]
        
        y = y_start + layer
        
        for x in range(width):
            for z in range(length):
                should_place = False
                
                if pattern == "solid":
                    should_place = True
                elif pattern == "walls":
                    should_place = (x == 0 or x == width-1 or z == 0 or z == length-1)
                elif pattern == "hollow_walls":
                    should_place = (x == 0 or x == width-1 or z == 0 or z == length-1)
                elif pattern == "bridge":
                    should_place = (z % length == length//2)  # Центральная линия
                elif pattern == "farmland":
                    should_place = True
                
                if should_place:
                    pos = self.bot.bot.vec3(x_start + x, y, z_start + z)
                    await self.bot._place_block(material, pos)
    
    async def _add_feature(self, start_pos: Tuple[int, int, int], feature: Dict):
        """Добавление особенности"""
        feature_type = feature["type"]
        
        if feature_type == "door":
            x, y, z = feature["position"]
            pos = self.bot.bot.vec3(start_pos[0] + x, start_pos[1] + y, start_pos[2] + z)
            await self.bot._break_block(pos)  # Создаем проем
            
        elif feature_type == "window":
            x, y, z = feature["position"]
            pos = self.bot.bot.vec3(start_pos[0] + x, start_pos[1] + y, start_pos[2] + z)
            await self.bot._place_block("glass", pos)
            
        elif feature_type == "torch":
            x, y, z = feature["position"]
            pos = self.bot.bot.vec3(start_pos[0] + x, start_pos[1] + y, start_pos[2] + z)
            await self.bot._place_block("torch", pos)

class LearningSystem:
    """Расширенная система машинного обучения"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.experience_buffer = deque(maxlen=10000)
        self.action_success_rates = defaultdict(lambda: {"success": 0, "total": 0})
        self.environmental_memory = {}
        
    def record_experience(self, state: str, action: str, reward: float, next_state: str, success: bool):
        """Запись опыта"""
        experience = {
            "state": state,
            "action": action,
            "reward": reward,
            "next_state": next_state,
            "success": success,
            "timestamp": time.time()
        }
        
        self.experience_buffer.append(experience)
        
        # Обновление статистики успешности
        self.action_success_rates[action]["total"] += 1
        if success:
            self.action_success_rates[action]["success"] += 1
    
    def get_action_success_rate(self, action: str) -> float:
        """Получение коэффициента успешности действия"""
        stats = self.action_success_rates[action]
        if stats["total"] == 0:
            return 0.5  # Нейтральная оценка для неизвестных действий
        
        return stats["success"] / stats["total"]
    
    def analyze_patterns(self) -> Dict[str, Any]:
        """Анализ паттернов поведения"""
        if len(self.experience_buffer) < 100:
            return {}
        
        # Анализ последних 1000 записей
        recent_experiences = list(self.experience_buffer)[-1000:]
        
        # Группировка по состояниям
        state_actions = defaultdict(list)
        for exp in recent_experiences:
            state_actions[exp["state"]].append(exp["action"])
        
        # Поиск наиболее успешных действий для каждого состояния
        best_actions = {}
        for state, actions in state_actions.items():
            action_rewards = defaultdict(list)
            for exp in recent_experiences:
                if exp["state"] == state:
                    action_rewards[exp["action"]].append(exp["reward"])
            
            # Вычисление средней награды для каждого действия
            avg_rewards = {}
            for action, rewards in action_rewards.items():
                avg_rewards[action] = sum(rewards) / len(rewards)
            
            if avg_rewards:
                best_actions[state] = max(avg_rewards, key=avg_rewards.get)
        
        return {
            "total_experiences": len(self.experience_buffer),
            "recent_experiences": len(recent_experiences),
            "unique_states": len(state_actions),
            "best_actions": best_actions,
            "action_success_rates": dict(self.action_success_rates)
        }
    
    def remember_location(self, location_name: str, coordinates: Tuple[int, int, int], description: str = ""):
        """Запоминание важной локации"""
        self.environmental_memory[location_name] = {
            "coordinates": coordinates,
            "description": description,
            "discovered_at": time.time(),
            "visit_count": self.environmental_memory.get(location_name, {}).get("visit_count", 0) + 1
        }
    
    def get_known_locations(self) -> Dict[str, Dict]:
        """Получение списка известных локаций"""
        return self.environmental_memory.copy()
    
    def find_nearest_known_location(self, current_pos: Tuple[int, int, int]) -> Optional[Tuple[str, Dict]]:
        """Поиск ближайшей известной локации"""
        if not self.environmental_memory:
            return None
        
        min_distance = float('inf')
        nearest_location = None
        
        for name, info in self.environmental_memory.items():
            coords = info["coordinates"]
            distance = math.sqrt(
                (current_pos[0] - coords[0])**2 + 
                (current_pos[1] - coords[1])**2 + 
                (current_pos[2] - coords[2])**2
            )
            
            if distance < min_distance:
                min_distance = distance
                nearest_location = (name, info)
        
        return nearest_location

class AdvancedCommands:
    """Расширенные команды для бота"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.macro_commands = {}
        
    def register_macro(self, name: str, commands: List[str]):
        """Регистрация макро-команды"""
        self.macro_commands[name] = commands
        logger.info(f"Зарегистрирована макро-команда: {name}")
    
    async def execute_macro(self, name: str) -> bool:
        """Выполнение макро-команды"""
        if name not in self.macro_commands:
            return False
        
        commands = self.macro_commands[name]
        
        for command in commands:
            # Парсинг и выполнение команды
            parts = command.strip().split()
            if not parts:
                continue
            
            cmd = parts[0].lower()
            args = parts[1:]
            
            # Выполнение команды через систему команд бота
            if hasattr(self.bot, f"command_{cmd}"):
                handler = getattr(self.bot, f"command_{cmd}")
                handler("system", args)
            
            await asyncio.sleep(0.5)  # Пауза между командами
        
        return True
    
    def setup_default_macros(self):
        """Настройка стандартных макро-команд"""
        # Макро для подготовки к ночи
        self.register_macro("prepare_night", [
            "ешь",
            "одевайся", 
            "крафт torch",
            "строй shelter"
        ])
        
        # Макро для добычи ресурсов
        self.register_macro("mining_session", [
            "крафт stone_pickaxe",
            "одевайся",
            "добывай iron_ore",
            "добывай coal_ore",
            "добывай diamond_ore"
        ])
        
        # Макро для строительства базы
        self.register_macro("build_base", [
            "добывай stone",
            "добывай wood", 
            "крафт chest",
            "строй house",
            "строй farm"
        ])

# Функции для интеграции с основным ботом
def enhance_bot_with_extensions(bot_instance):
    """Улучшение бота расширениями"""
    
    # Добавление расширенных систем
    bot_instance.pathfinding = AdvancedPathfinding(bot_instance)
    bot_instance.resource_manager = ResourceManager(bot_instance)
    bot_instance.combat_system = CombatSystem(bot_instance)
    bot_instance.building_planner = BuildingPlanner(bot_instance)
    bot_instance.learning_system = LearningSystem(bot_instance)
    bot_instance.advanced_commands = AdvancedCommands(bot_instance)
    
    # Настройка макро-команд
    bot_instance.advanced_commands.setup_default_macros()
    
    # Добавление новых команд в чат
    bot_instance.chat_commands.update({
        "макро": bot_instance.command_macro,
        "анализ": bot_instance.command_analysis,
        "локации": bot_instance.command_locations,
        "оптимизация": bot_instance.command_optimize,
        "стратегия": bot_instance.command_strategy
    })
    
    logger.info("Расширения бота успешно загружены")

# Дополнительные команды для бота
async def command_macro(bot_instance, username: str, args: List[str]):
    """Команда выполнения макроса"""
    if args:
        macro_name = args[0]
        success = await bot_instance.advanced_commands.execute_macro(macro_name)
        
        if success and bot_instance.bot:
            bot_instance.bot.chat(f"Выполняю макрос: {macro_name}")
        elif bot_instance.bot:
            bot_instance.bot.chat(f"Неизвестный макрос: {macro_name}")
    elif bot_instance.bot:
        macros = list(bot_instance.advanced_commands.macro_commands.keys())
        bot_instance.bot.chat(f"Доступные макросы: {', '.join(macros)}")

async def command_analysis(bot_instance, username: str, args: List[str]):
    """Команда анализа поведения"""
    if bot_instance.bot:
        analysis = bot_instance.learning_system.analyze_patterns()
        
        if analysis:
            bot_instance.bot.chat(f"Опыт: {analysis['total_experiences']} записей")
            bot_instance.bot.chat(f"Уникальных состояний: {analysis['unique_states']}")
        else:
            bot_instance.bot.chat("Недостаточно данных для анализа")

async def command_locations(bot_instance, username: str, args: List[str]):
    """Команда управления локациями"""
    if bot_instance.bot:
        locations = bot_instance.learning_system.get_known_locations()
        
        if locations:
            for name, info in list(locations.items())[:5]:  # Показываем первые 5
                coords = info["coordinates"]
                bot_instance.bot.chat(f"{name}: {coords[0]}, {coords[1]}, {coords[2]}")
        else:
            bot_instance.bot.chat("Известных локаций нет")

async def command_optimize(bot_instance, username: str, args: List[str]):
    """Команда оптимизации"""
    if bot_instance.bot:
        bot_instance.bot.chat("Оптимизирую инвентарь...")
        await bot_instance.resource_manager.optimize_inventory()
        bot_instance.bot.chat("Оптимизация завершена")

async def command_strategy(bot_instance, username: str, args: List[str]):
    """Команда изменения стратегии"""
    if args and bot_instance.bot:
        strategy = args[0].lower()
        
        if strategy == "агрессивная":
            bot_instance.epsilon = 0.3  # Больше исследований
            bot_instance.bot.chat("Переключился на агрессивную стратегию")
        elif strategy == "осторожная":
            bot_instance.epsilon = 0.05  # Меньше рисков
            bot_instance.bot.chat("Переключился на осторожную стратегию")
        elif strategy == "сбалансированная":
            bot_instance.epsilon = 0.1  # Баланс
            bot_instance.bot.chat("Переключился на сбалансированную стратегию")
        else:
            bot_instance.bot.chat("Доступные стратегии: агрессивная, осторожная, сбалансированная")
    elif bot_instance.bot:
        bot_instance.bot.chat("Укажите стратегию: агрессивная, осторожная, сбалансированная")
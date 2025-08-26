import discord
from discord.ext import commands, tasks
import asyncio
import sqlite3
import random
import time
import json
from datetime import datetime, timedelta
import math
from typing import Optional

# Bot configuration
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True

bot = commands.Bot(command_prefix='/', intents=intents)

# Database setup
DB_FILE = 'military_bot.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Countries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS countries (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            owner_id TEXT NOT NULL,
            founded_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            population INTEGER DEFAULT 1000,
            territory INTEGER DEFAULT 100,
            gdp REAL DEFAULT 10000.0,
            stability REAL DEFAULT 50.0,
            military_power REAL DEFAULT 100.0
        )
    ''')
    
    # Players table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS players (
            id INTEGER PRIMARY KEY,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            country_id INTEGER,
            balance REAL DEFAULT 10000.0,
            level INTEGER DEFAULT 1,
            exp INTEGER DEFAULT 0,
            rank TEXT DEFAULT 'Рядовой',
            last_collect TIMESTAMP,
            total_battles INTEGER DEFAULT 0,
            battles_won INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (country_id) REFERENCES countries(id)
        )
    ''')
    
    # Military assets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS military_assets (
            id INTEGER PRIMARY KEY,
            player_id INTEGER NOT NULL,
            asset_type TEXT NOT NULL,
            asset_name TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            level INTEGER DEFAULT 1,
            power INTEGER DEFAULT 10,
            cost INTEGER DEFAULT 1000,
            maintenance_cost INTEGER DEFAULT 100,
            purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (player_id) REFERENCES players(id)
        )
    ''')
    
    # Infrastructure table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS infrastructure (
            id INTEGER PRIMARY KEY,
            country_id INTEGER NOT NULL,
            building_type TEXT NOT NULL,
            level INTEGER DEFAULT 1,
            power INTEGER DEFAULT 10,
            cost INTEGER DEFAULT 5000,
            income_boost REAL DEFAULT 1.0,
            built_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (country_id) REFERENCES countries(id)
        )
    ''')
    
    # Battle history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS battles (
            id INTEGER PRIMARY KEY,
            attacker_id INTEGER NOT NULL,
            defender_id INTEGER NOT NULL,
            attacker_power INTEGER NOT NULL,
            defender_power INTEGER NOT NULL,
            winner_id INTEGER NOT NULL,
            rewards TEXT,
            battle_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attacker_id) REFERENCES players(id),
            FOREIGN KEY (defender_id) REFERENCES players(id),
            FOREIGN KEY (winner_id) REFERENCES players(id)
        )
    ''')
    
    # Global stats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS global_stats (
            id INTEGER PRIMARY KEY,
            total_countries INTEGER DEFAULT 0,
            total_players INTEGER DEFAULT 0,
            total_battles INTEGER DEFAULT 0,
            strongest_country TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Game constants
WEAPON_TYPES = {
    'rifle': {'name': 'Винтовка', 'cost': 500, 'power': 5, 'maintenance': 50},
    'machine_gun': {'name': 'Пулемёт', 'cost': 2000, 'power': 15, 'maintenance': 150},
    'sniper': {'name': 'Снайперская винтовка', 'cost': 3000, 'power': 25, 'maintenance': 200},
    'rocket_launcher': {'name': 'Гранатомёт', 'cost': 5000, 'power': 40, 'maintenance': 300},
    'cannon': {'name': 'Пушка', 'cost': 10000, 'power': 60, 'maintenance': 500},
}

TANK_TYPES = {
    'light_tank': {'name': 'Лёгкий танк', 'cost': 15000, 'power': 80, 'maintenance': 800},
    'medium_tank': {'name': 'Средний танк', 'cost': 30000, 'power': 150, 'maintenance': 1200},
    'heavy_tank': {'name': 'Тяжёлый танк', 'cost': 50000, 'power': 250, 'maintenance': 2000},
    'modern_tank': {'name': 'Современный танк', 'cost': 100000, 'power': 400, 'maintenance': 3000},
    'super_tank': {'name': 'Супер танк', 'cost': 200000, 'power': 600, 'maintenance': 5000},
}

AIRCRAFT_TYPES = {
    'fighter': {'name': 'Истребитель', 'cost': 25000, 'power': 120, 'maintenance': 1500},
    'bomber': {'name': 'Бомбардировщик', 'cost': 40000, 'power': 200, 'maintenance': 2500},
    'helicopter': {'name': 'Вертолёт', 'cost': 20000, 'power': 100, 'maintenance': 1200},
    'drone': {'name': 'Дрон', 'cost': 10000, 'power': 60, 'maintenance': 600},
}

INFRASTRUCTURE_TYPES = {
    'factory': {'name': 'Завод', 'cost': 20000, 'income_boost': 1.2, 'power': 0},
    'military_base': {'name': 'Военная база', 'cost': 30000, 'income_boost': 1.0, 'power': 100},
    'research_lab': {'name': 'Лаборатория', 'cost': 25000, 'income_boost': 1.15, 'power': 0},
    'power_plant': {'name': 'Электростанция', 'cost': 35000, 'income_boost': 1.3, 'power': 0},
    'fortress': {'name': 'Крепость', 'cost': 50000, 'income_boost': 1.0, 'power': 200},
}

RANKS = [
    {'name': 'Рядовой', 'exp': 0},
    {'name': 'Ефрейтор', 'exp': 100},
    {'name': 'Младший сержант', 'exp': 300},
    {'name': 'Сержант', 'exp': 600},
    {'name': 'Старший сержант', 'exp': 1000},
    {'name': 'Прапорщик', 'exp': 1500},
    {'name': 'Лейтенант', 'exp': 2500},
    {'name': 'Капитан', 'exp': 4000},
    {'name': 'Майор', 'exp': 6000},
    {'name': 'Полковник', 'exp': 10000},
    {'name': 'Генерал', 'exp': 15000},
]

# Helper functions
def get_player(discord_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM players WHERE discord_id = ?', (str(discord_id),))
    player = cursor.fetchone()
    conn.close()
    return player

def create_player(discord_id, username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO players (discord_id, username, balance)
        VALUES (?, ?, 10000.0)
    ''', (str(discord_id), username))
    conn.commit()
    conn.close()

def get_player_country(player_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.* FROM countries c 
        JOIN players p ON c.id = p.country_id 
        WHERE p.id = ?
    ''', (player_id,))
    country = cursor.fetchone()
    conn.close()
    return country

def update_player_balance(discord_id, amount):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE players SET balance = balance + ? WHERE discord_id = ?
    ''', (amount, str(discord_id)))
    conn.commit()
    conn.close()

def calculate_military_power(player_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT SUM(power * quantity) FROM military_assets WHERE player_id = ?
    ''', (player_id,))
    result = cursor.fetchone()
    
    # Add infrastructure power
    cursor.execute('''
        SELECT SUM(i.power * i.level) FROM infrastructure i
        JOIN players p ON i.country_id = p.country_id
        WHERE p.id = ?
    ''', (player_id,))
    infra_power = cursor.fetchone()
    
    conn.close()
    
    military_power = result[0] if result[0] else 0
    infrastructure_power = infra_power[0] if infra_power[0] else 0
    
    return military_power + infrastructure_power

def get_rank_by_exp(exp):
    for i in range(len(RANKS) - 1, -1, -1):
        if exp >= RANKS[i]['exp']:
            return RANKS[i]['name']
    return RANKS[0]['name']

def add_exp(player_id, exp_amount):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT exp FROM players WHERE id = ?', (player_id,))
    current_exp = cursor.fetchone()[0]
    new_exp = current_exp + exp_amount
    new_rank = get_rank_by_exp(new_exp)
    
    cursor.execute('''
        UPDATE players SET exp = ?, rank = ? WHERE id = ?
    ''', (new_exp, new_rank, player_id))
    conn.commit()
    conn.close()

# Bot events
@bot.event
async def on_ready():
    print(f'{bot.user} подключился к Discord!')
    collect_income.start()

@bot.event
async def on_member_join(member):
    embed = discord.Embed(
        title="⚔️ Добро пожаловать в Military Empire!",
        description=f"Привет {member.mention}! Начни свою военную карьеру с команды `/register`",
        color=0x8B4513
    )
    embed.add_field(name="🏛️ Создай страну", value="`/create_country <название>`", inline=False)
    embed.add_field(name="💰 Начальный капитал", value="$10,000", inline=False)
    embed.add_field(name="🎯 Команды", value="`/help` для списка команд", inline=False)
    
    channel = member.guild.system_channel
    if channel:
        await channel.send(embed=embed)

# Registration commands
@bot.command(name='register')
async def register_player(ctx):
    """Регистрация в игре"""
    player = get_player(ctx.author.id)
    if player:
        await ctx.send("❌ Вы уже зарегистрированы!")
        return
    
    create_player(ctx.author.id, str(ctx.author))
    
    embed = discord.Embed(
        title="✅ Добро пожаловать в Military Empire!",
        description=f"{ctx.author.mention}, вы успешно зарегистрированы!",
        color=0x00ff00
    )
    embed.add_field(name="💰 Стартовый капитал", value="$10,000", inline=True)
    embed.add_field(name="🎖️ Звание", value="Рядовой", inline=True)
    embed.add_field(name="🏛️ Следующий шаг", value="Создайте страну: `/create_country <название>`", inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='create_country')
async def create_country(ctx, *, country_name: str):
    """Создать страну"""
    player = get_player(ctx.author.id)
    if not player:
        await ctx.send("❌ Сначала зарегистрируйтесь: `/register`")
        return
    
    if player[3]:  # Already has country
        await ctx.send("❌ У вас уже есть страна!")
        return
    
    if len(country_name) > 50:
        await ctx.send("❌ Название страны слишком длинное!")
        return
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Check if country name exists
    cursor.execute('SELECT id FROM countries WHERE name = ?', (country_name,))
    if cursor.fetchone():
        await ctx.send("❌ Страна с таким названием уже существует!")
        conn.close()
        return
    
    # Create country
    cursor.execute('''
        INSERT INTO countries (name, owner_id)
        VALUES (?, ?)
    ''', (country_name, str(ctx.author.id)))
    
    country_id = cursor.lastrowid
    
    # Update player
    cursor.execute('''
        UPDATE players SET country_id = ? WHERE discord_id = ?
    ''', (country_id, str(ctx.author.id)))
    
    conn.commit()
    conn.close()
    
    embed = discord.Embed(
        title="🏛️ Страна основана!",
        description=f"Поздравляем! Вы основали страну **{country_name}**!",
        color=0x00ff00
    )
    embed.add_field(name="👥 Население", value="1,000", inline=True)
    embed.add_field(name="🗺️ Территория", value="100 км²", inline=True)
    embed.add_field(name="💰 ВВП", value="$10,000", inline=True)
    embed.add_field(name="📊 Стабильность", value="50%", inline=True)
    embed.add_field(name="⚔️ Военная мощь", value="100", inline=True)
    embed.set_footer(text="Используйте /country_info для подробной информации")
    
    await ctx.send(embed=embed)

# Economy commands
@bot.command(name='balance')
async def check_balance(ctx):
    """Проверить баланс"""
    player = get_player(ctx.author.id)
    if not player:
        create_player(ctx.author.id, str(ctx.author))
        balance = 10000.0
        rank = "Рядовой"
        exp = 0
    else:
        balance = player[4]
        rank = player[7]
        exp = player[6]
    
    embed = discord.Embed(
        title="💰 Ваш профиль",
        color=0x8B4513
    )
    embed.add_field(name="💵 Баланс", value=f"${balance:,.2f}", inline=True)
    embed.add_field(name="🎖️ Звание", value=rank, inline=True)
    embed.add_field(name="⭐ Опыт", value=f"{exp} XP", inline=True)
    embed.set_author(name=str(ctx.author), icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
    
    if player and player[3]:  # Has country
        country = get_player_country(player[0])
        if country:
            embed.add_field(name="🏛️ Страна", value=country[1], inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='collect')
async def collect_income(ctx):
    """Собрать доход"""
    player = get_player(ctx.author.id)
    if not player:
        await ctx.send("❌ Сначала зарегистрируйтесь: `/register`")
        return
    
    # Check cooldown (1 hour)
    if player[8]:  # last_collect
        last_collect = datetime.fromisoformat(player[8])
        if datetime.now() - last_collect < timedelta(hours=1):
            remaining = timedelta(hours=1) - (datetime.now() - last_collect)
            minutes = int(remaining.total_seconds() / 60)
            await ctx.send(f"⏰ Сбор дохода доступен через {minutes} минут!")
            return
    
    # Calculate base income
    base_income = 1000
    
    # Apply infrastructure bonuses
    if player[3]:  # Has country
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT SUM(income_boost * level) FROM infrastructure 
            WHERE country_id = ?
        ''', (player[3],))
        result = cursor.fetchone()
        conn.close()
        
        infrastructure_bonus = result[0] if result[0] else 1.0
        income = int(base_income * infrastructure_bonus)
    else:
        income = base_income
    
    # Apply rank bonus
    rank_multiplier = 1.0 + (player[5] - 1) * 0.1  # Level-based bonus
    income = int(income * rank_multiplier)
    
    # Update balance and last collect time
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE players 
        SET balance = balance + ?, last_collect = ? 
        WHERE discord_id = ?
    ''', (income, datetime.now().isoformat(), str(ctx.author.id)))
    conn.commit()
    conn.close()
    
    # Add experience
    add_exp(player[0], 10)
    
    embed = discord.Embed(
        title="💰 Доход собран!",
        description=f"Вы получили **${income:,}**!",
        color=0x00ff00
    )
    embed.add_field(name="⭐ Опыт", value="+10 XP", inline=True)
    embed.add_field(name="⏰ Следующий сбор", value="Через 1 час", inline=True)
    
    await ctx.send(embed=embed)

# Military commands
@bot.command(name='buy_weapon')
async def buy_weapon(ctx, weapon_type: str, quantity: int = 1):
    """Купить оружие"""
    player = get_player(ctx.author.id)
    if not player:
        await ctx.send("❌ Сначала зарегистрируйтесь: `/register`")
        return
    
    if weapon_type not in WEAPON_TYPES:
        weapons_list = ", ".join(WEAPON_TYPES.keys())
        await ctx.send(f"❌ Неверный тип оружия! Доступно: {weapons_list}")
        return
    
    if quantity < 1 or quantity > 1000:
        await ctx.send("❌ Количество должно быть от 1 до 1000!")
        return
    
    weapon = WEAPON_TYPES[weapon_type]
    total_cost = weapon['cost'] * quantity
    
    if player[4] < total_cost:
        await ctx.send(f"❌ Недостаточно средств! Нужно ${total_cost:,}")
        return
    
    # Deduct money
    update_player_balance(ctx.author.id, -total_cost)
    
    # Add weapon to inventory
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO military_assets 
        (player_id, asset_type, asset_name, quantity, power, cost, maintenance_cost)
        VALUES (?, 'weapon', ?, 
                COALESCE((SELECT quantity FROM military_assets 
                         WHERE player_id = ? AND asset_name = ?), 0) + ?,
                ?, ?, ?)
    ''', (player[0], weapon_type, player[0], weapon_type, quantity, 
          weapon['power'], weapon['cost'], weapon['maintenance']))
    conn.commit()
    conn.close()
    
    # Add experience
    add_exp(player[0], quantity * 2)
    
    embed = discord.Embed(
        title="🔫 Оружие приобретено!",
        description=f"Куплено: **{quantity}x {weapon['name']}**",
        color=0x00ff00
    )
    embed.add_field(name="💰 Стоимость", value=f"${total_cost:,}", inline=True)
    embed.add_field(name="⚔️ Мощность", value=f"{weapon['power'] * quantity}", inline=True)
    embed.add_field(name="⭐ Опыт", value=f"+{quantity * 2} XP", inline=True)
    
    await ctx.send(embed=embed)

@bot.command(name='buy_tank')
async def buy_tank(ctx, tank_type: str, quantity: int = 1):
    """Купить танк"""
    player = get_player(ctx.author.id)
    if not player:
        await ctx.send("❌ Сначала зарегистрируйтесь: `/register`")
        return
    
    if tank_type not in TANK_TYPES:
        tanks_list = ", ".join(TANK_TYPES.keys())
        await ctx.send(f"❌ Неверный тип танка! Доступно: {tanks_list}")
        return
    
    if quantity < 1 or quantity > 100:
        await ctx.send("❌ Количество должно быть от 1 до 100!")
        return
    
    tank = TANK_TYPES[tank_type]
    total_cost = tank['cost'] * quantity
    
    if player[4] < total_cost:
        await ctx.send(f"❌ Недостаточно средств! Нужно ${total_cost:,}")
        return
    
    # Deduct money
    update_player_balance(ctx.author.id, -total_cost)
    
    # Add tank to inventory
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO military_assets 
        (player_id, asset_type, asset_name, quantity, power, cost, maintenance_cost)
        VALUES (?, 'tank', ?, 
                COALESCE((SELECT quantity FROM military_assets 
                         WHERE player_id = ? AND asset_name = ?), 0) + ?,
                ?, ?, ?)
    ''', (player[0], tank_type, player[0], tank_type, quantity, 
          tank['power'], tank['cost'], tank['maintenance']))
    conn.commit()
    conn.close()
    
    # Add experience
    add_exp(player[0], quantity * 5)
    
    embed = discord.Embed(
        title="🚗 Танк приобретён!",
        description=f"Куплено: **{quantity}x {tank['name']}**",
        color=0x00ff00
    )
    embed.add_field(name="💰 Стоимость", value=f"${total_cost:,}", inline=True)
    embed.add_field(name="⚔️ Мощность", value=f"{tank['power'] * quantity}", inline=True)
    embed.add_field(name="⭐ Опыт", value=f"+{quantity * 5} XP", inline=True)
    
    await ctx.send(embed=embed)

@bot.command(name='buy_aircraft')
async def buy_aircraft(ctx, aircraft_type: str, quantity: int = 1):
    """Купить авиацию"""
    player = get_player(ctx.author.id)
    if not player:
        await ctx.send("❌ Сначала зарегистрируйтесь: `/register`")
        return
    
    if aircraft_type not in AIRCRAFT_TYPES:
        aircraft_list = ", ".join(AIRCRAFT_TYPES.keys())
        await ctx.send(f"❌ Неверный тип авиации! Доступно: {aircraft_list}")
        return
    
    if quantity < 1 or quantity > 50:
        await ctx.send("❌ Количество должно быть от 1 до 50!")
        return
    
    aircraft = AIRCRAFT_TYPES[aircraft_type]
    total_cost = aircraft['cost'] * quantity
    
    if player[4] < total_cost:
        await ctx.send(f"❌ Недостаточно средств! Нужно ${total_cost:,}")
        return
    
    # Deduct money
    update_player_balance(ctx.author.id, -total_cost)
    
    # Add aircraft to inventory
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO military_assets 
        (player_id, asset_type, asset_name, quantity, power, cost, maintenance_cost)
        VALUES (?, 'aircraft', ?, 
                COALESCE((SELECT quantity FROM military_assets 
                         WHERE player_id = ? AND asset_name = ?), 0) + ?,
                ?, ?, ?)
    ''', (player[0], aircraft_type, player[0], aircraft_type, quantity, 
          aircraft['power'], aircraft['cost'], aircraft['maintenance']))
    conn.commit()
    conn.close()
    
    # Add experience
    add_exp(player[0], quantity * 8)
    
    embed = discord.Embed(
        title="✈️ Авиация приобретена!",
        description=f"Куплено: **{quantity}x {aircraft['name']}**",
        color=0x00ff00
    )
    embed.add_field(name="💰 Стоимость", value=f"${total_cost:,}", inline=True)
    embed.add_field(name="⚔️ Мощность", value=f"{aircraft['power'] * quantity}", inline=True)
    embed.add_field(name="⭐ Опыт", value=f"+{quantity * 8} XP", inline=True)
    
    await ctx.send(embed=embed)

@bot.command(name='arsenal')
async def show_arsenal(ctx, member: discord.Member = None):
    """Показать арсенал"""
    target = member or ctx.author
    player = get_player(target.id)
    
    if not player:
        await ctx.send("❌ Игрок не зарегистрирован!")
        return
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT asset_type, asset_name, quantity, power 
        FROM military_assets 
        WHERE player_id = ?
        ORDER BY asset_type, power DESC
    ''', (player[0],))
    
    assets = cursor.fetchall()
    conn.close()
    
    if not assets:
        await ctx.send("🔫 Арсенал пуст! Используйте команды покупки.")
        return
    
    embed = discord.Embed(
        title=f"🔫 Арсенал {target.display_name}",
        color=0x8B4513
    )
    
    # Group by asset type
    weapons = []
    tanks = []
    aircraft = []
    
    total_power = 0
    
    for asset_type, asset_name, quantity, power in assets:
        total_power += power * quantity
        
        if asset_type == 'weapon':
            weapon_name = WEAPON_TYPES.get(asset_name, {}).get('name', asset_name)
            weapons.append(f"• {weapon_name}: {quantity} (⚔️ {power * quantity})")
        elif asset_type == 'tank':
            tank_name = TANK_TYPES.get(asset_name, {}).get('name', asset_name)
            tanks.append(f"• {tank_name}: {quantity} (⚔️ {power * quantity})")
        elif asset_type == 'aircraft':
            aircraft_name = AIRCRAFT_TYPES.get(asset_name, {}).get('name', asset_name)
            aircraft.append(f"• {aircraft_name}: {quantity} (⚔️ {power * quantity})")
    
    if weapons:
        embed.add_field(name="🔫 Оружие", value="\n".join(weapons), inline=False)
    if tanks:
        embed.add_field(name="🚗 Танки", value="\n".join(tanks), inline=False)
    if aircraft:
        embed.add_field(name="✈️ Авиация", value="\n".join(aircraft), inline=False)
    
    embed.add_field(name="⚔️ Общая мощь", value=f"{total_power:,}", inline=True)
    
    await ctx.send(embed=embed)

# Infrastructure commands
@bot.command(name='build')
async def build_infrastructure(ctx, building_type: str):
    """Построить инфраструктуру"""
    player = get_player(ctx.author.id)
    if not player:
        await ctx.send("❌ Сначала зарегистрируйтесь: `/register`")
        return
    
    if not player[3]:  # No country
        await ctx.send("❌ Сначала создайте страну: `/create_country <название>`")
        return
    
    if building_type not in INFRASTRUCTURE_TYPES:
        buildings_list = ", ".join(INFRASTRUCTURE_TYPES.keys())
        await ctx.send(f"❌ Неверный тип здания! Доступно: {buildings_list}")
        return
    
    building = INFRASTRUCTURE_TYPES[building_type]
    cost = building['cost']
    
    if player[4] < cost:
        await ctx.send(f"❌ Недостаточно средств! Нужно ${cost:,}")
        return
    
    # Deduct money
    update_player_balance(ctx.author.id, -cost)
    
    # Add building
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO infrastructure 
        (country_id, building_type, level, power, cost, income_boost)
        VALUES (?, ?, 
                COALESCE((SELECT level FROM infrastructure 
                         WHERE country_id = ? AND building_type = ?), 0) + 1,
                ?, ?, ?)
    ''', (player[3], building_type, player[3], building_type, 
          building['power'], building['cost'], building['income_boost']))
    conn.commit()
    conn.close()
    
    # Add experience
    add_exp(player[0], 15)
    
    embed = discord.Embed(
        title="🏗️ Здание построено!",
        description=f"Построено: **{building['name']}**",
        color=0x00ff00
    )
    embed.add_field(name="💰 Стоимость", value=f"${cost:,}", inline=True)
    embed.add_field(name="📈 Бонус дохода", value=f"x{building['income_boost']}", inline=True)
    embed.add_field(name="⭐ Опыт", value="+15 XP", inline=True)
    
    await ctx.send(embed=embed)

# Battle commands
@bot.command(name='attack')
async def attack_player(ctx, target: discord.Member):
    """Атаковать игрока"""
    if target.id == ctx.author.id:
        await ctx.send("❌ Нельзя атаковать самого себя!")
        return
    
    attacker = get_player(ctx.author.id)
    defender = get_player(target.id)
    
    if not attacker:
        await ctx.send("❌ Вы не зарегистрированы!")
        return
    
    if not defender:
        await ctx.send("❌ Цель не зарегистрирована!")
        return
    
    # Calculate military power
    attacker_power = calculate_military_power(attacker[0])
    defender_power = calculate_military_power(defender[0])
    
    if attacker_power == 0:
        await ctx.send("❌ У вас нет военных сил!")
        return
    
    if defender_power == 0:
        await ctx.send("❌ У цели нет военных сил!")
        return
    
    # Battle calculation with random factor
    attacker_roll = random.randint(80, 120) / 100
    defender_roll = random.randint(80, 120) / 100
    
    final_attacker_power = attacker_power * attacker_roll
    final_defender_power = defender_power * defender_roll
    
    # Determine winner
    if final_attacker_power > final_defender_power:
        winner = attacker
        loser = defender
        winner_name = ctx.author.display_name
        loser_name = target.display_name
        
        # Calculate rewards
        reward = min(defender[4] * 0.1, 5000)  # 10% of balance, max 5000
        exp_reward = 25
        
        # Transfer money
        update_player_balance(ctx.author.id, reward)
        update_player_balance(target.id, -reward)
        
        # Update battle stats
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE players SET total_battles = total_battles + 1, battles_won = battles_won + 1
            WHERE id = ?
        ''', (attacker[0],))
        cursor.execute('''
            UPDATE players SET total_battles = total_battles + 1
            WHERE id = ?
        ''', (defender[0],))
        conn.commit()
        conn.close()
        
        color = 0x00ff00
        result_text = f"🎉 **{winner_name}** победил!"
        reward_text = f"💰 Награда: ${reward:,.0f}"
    else:
        winner = defender
        loser = attacker
        winner_name = target.display_name
        loser_name = ctx.author.display_name
        
        reward = 0
        exp_reward = 5
        
        # Update battle stats
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE players SET total_battles = total_battles + 1
            WHERE id = ?
        ''', (attacker[0],))
        cursor.execute('''
            UPDATE players SET total_battles = total_battles + 1, battles_won = battles_won + 1
            WHERE id = ?
        ''', (defender[0],))
        conn.commit()
        conn.close()
        
        color = 0xff0000
        result_text = f"💥 **{winner_name}** отразил атаку!"
        reward_text = "💸 Награда: Нет"
    
    # Add experience
    add_exp(attacker[0], exp_reward)
    
    # Record battle
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO battles 
        (attacker_id, defender_id, attacker_power, defender_power, winner_id, rewards)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (attacker[0], defender[0], int(final_attacker_power), int(final_defender_power), 
          winner[0], json.dumps({'money': reward, 'exp': exp_reward})))
    conn.commit()
    conn.close()
    
    embed = discord.Embed(
        title="⚔️ Результат битвы",
        description=result_text,
        color=color
    )
    embed.add_field(name="👤 Атакующий", value=f"{ctx.author.display_name}\n⚔️ {int(final_attacker_power)}", inline=True)
    embed.add_field(name="🛡️ Защитник", value=f"{target.display_name}\n⚔️ {int(final_defender_power)}", inline=True)
    embed.add_field(name="🏆 Результат", value=f"{reward_text}\n⭐ Опыт: +{exp_reward}", inline=False)
    
    await ctx.send(embed=embed)

# Information commands
@bot.command(name='country_info')
async def country_info(ctx, member: discord.Member = None):
    """Информация о стране"""
    target = member or ctx.author
    player = get_player(target.id)
    
    if not player:
        await ctx.send("❌ Игрок не зарегистрирован!")
        return
    
    if not player[3]:
        await ctx.send("❌ У игрока нет страны!")
        return
    
    country = get_player_country(player[0])
    if not country:
        await ctx.send("❌ Страна не найдена!")
        return
    
    # Get infrastructure
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT building_type, level FROM infrastructure 
        WHERE country_id = ?
    ''', (country[0],))
    buildings = cursor.fetchall()
    conn.close()
    
    military_power = calculate_military_power(player[0])
    
    embed = discord.Embed(
        title=f"🏛️ {country[1]}",
        description=f"Основана {country[3][:10]}",
        color=0x8B4513
    )
    embed.add_field(name="👥 Население", value=f"{country[4]:,}", inline=True)
    embed.add_field(name="🗺️ Территория", value=f"{country[5]:,} км²", inline=True)
    embed.add_field(name="💰 ВВП", value=f"${country[6]:,.0f}", inline=True)
    embed.add_field(name="📊 Стабильность", value=f"{country[7]:.1f}%", inline=True)
    embed.add_field(name="⚔️ Военная мощь", value=f"{military_power:,}", inline=True)
    embed.add_field(name="👑 Правитель", value=target.display_name, inline=True)
    
    if buildings:
        building_text = []
        for building_type, level in buildings:
            building_name = INFRASTRUCTURE_TYPES.get(building_type, {}).get('name', building_type)
            building_text.append(f"• {building_name}: Уровень {level}")
        embed.add_field(name="🏗️ Инфраструктура", value="\n".join(building_text), inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='leaderboard')
async def show_leaderboard(ctx, category: str = 'power'):
    """Таблица лидеров"""
    valid_categories = ['power', 'balance', 'level', 'battles']
    
    if category not in valid_categories:
        await ctx.send(f"❌ Неверная категория! Доступно: {', '.join(valid_categories)}")
        return
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if category == 'power':
        # Get military power leaderboard
        cursor.execute('''
            SELECT p.username, COALESCE(SUM(ma.power * ma.quantity), 0) as total_power
            FROM players p
            LEFT JOIN military_assets ma ON p.id = ma.player_id
            GROUP BY p.id, p.username
            ORDER BY total_power DESC
            LIMIT 10
        ''')
        title = "⚔️ Лидеры по военной мощи"
        field_name = "Мощь"
    elif category == 'balance':
        cursor.execute('''
            SELECT username, balance FROM players 
            ORDER BY balance DESC LIMIT 10
        ''')
        title = "💰 Лидеры по богатству"
        field_name = "Баланс"
    elif category == 'level':
        cursor.execute('''
            SELECT username, exp FROM players 
            ORDER BY exp DESC LIMIT 10
        ''')
        title = "⭐ Лидеры по опыту"
        field_name = "Опыт"
    elif category == 'battles':
        cursor.execute('''
            SELECT username, battles_won, total_battles FROM players 
            WHERE total_battles > 0
            ORDER BY battles_won DESC LIMIT 10
        ''')
        title = "🏆 Лидеры по победам"
        field_name = "Победы"
    
    results = cursor.fetchall()
    conn.close()
    
    if not results:
        await ctx.send(f"📊 Таблица лидеров ({category}) пуста!")
        return
    
    embed = discord.Embed(title=title, color=0xffd700)
    
    leaderboard_text = ""
    for i, result in enumerate(results, 1):
        trophy = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
        
        if category == 'battles':
            username, wins, total = result
            win_rate = (wins / total * 100) if total > 0 else 0
            leaderboard_text += f"{trophy} **{username}**\n{field_name}: {wins}/{total} ({win_rate:.1f}%)\n\n"
        elif category == 'balance':
            username, value = result
            leaderboard_text += f"{trophy} **{username}**\n{field_name}: ${value:,.0f}\n\n"
        else:
            username, value = result
            leaderboard_text += f"{trophy} **{username}**\n{field_name}: {value:,}\n\n"
    
    embed.description = leaderboard_text
    await ctx.send(embed=embed)

# Background tasks
@tasks.loop(hours=1)
async def collect_income():
    """Automatic income collection for infrastructure"""
    pass  # Placeholder for automatic processes

# Help and shop commands
@bot.command(name='shop')
async def show_shop(ctx, category: str = 'weapons'):
    """Показать магазин"""
    valid_categories = ['weapons', 'tanks', 'aircraft', 'infrastructure']
    
    if category not in valid_categories:
        await ctx.send(f"❌ Неверная категория! Доступно: {', '.join(valid_categories)}")
        return
    
    embed = discord.Embed(
        title=f"🛒 Магазин - {category.title()}",
        color=0x8B4513
    )
    
    if category == 'weapons':
        for key, weapon in WEAPON_TYPES.items():
            embed.add_field(
                name=f"🔫 {weapon['name']}",
                value=f"💰 ${weapon['cost']:,}\n⚔️ Мощность: {weapon['power']}\n💸 Обслуживание: ${weapon['maintenance']}/час",
                inline=True
            )
        embed.set_footer(text="Команда: /buy_weapon <тип> [количество]")
    
    elif category == 'tanks':
        for key, tank in TANK_TYPES.items():
            embed.add_field(
                name=f"🚗 {tank['name']}",
                value=f"💰 ${tank['cost']:,}\n⚔️ Мощность: {tank['power']}\n💸 Обслуживание: ${tank['maintenance']}/час",
                inline=True
            )
        embed.set_footer(text="Команда: /buy_tank <тип> [количество]")
    
    elif category == 'aircraft':
        for key, aircraft in AIRCRAFT_TYPES.items():
            embed.add_field(
                name=f"✈️ {aircraft['name']}",
                value=f"💰 ${aircraft['cost']:,}\n⚔️ Мощность: {aircraft['power']}\n💸 Обслуживание: ${aircraft['maintenance']}/час",
                inline=True
            )
        embed.set_footer(text="Команда: /buy_aircraft <тип> [количество]")
    
    elif category == 'infrastructure':
        for key, building in INFRASTRUCTURE_TYPES.items():
            embed.add_field(
                name=f"🏗️ {building['name']}",
                value=f"💰 ${building['cost']:,}\n📈 Бонус дохода: x{building['income_boost']}\n⚔️ Мощность: {building['power']}",
                inline=True
            )
        embed.set_footer(text="Команда: /build <тип>")
    
    await ctx.send(embed=embed)

# Error handling
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Отсутствует обязательный аргумент: `{error.param.name}`")
    elif isinstance(error, commands.BadArgument):
        await ctx.send("❌ Неверный формат аргумента! Проверьте команду.")
    elif isinstance(error, commands.CommandNotFound):
        pass  # Ignore unknown commands
    else:
        print(f"Unexpected error: {error}")
        await ctx.send("❌ Произошла ошибка при выполнении команды!")

# Custom help command
bot.remove_command('help')

@bot.command(name='help')
async def custom_help(ctx, category: str = None):
    """Помощь по командам"""
    embed = discord.Embed(
        title="⚔️ Military Empire - Команды",
        description="Список всех доступных команд",
        color=0x8B4513
    )
    
    embed.add_field(name="🏁 Начало игры", 
                   value="/register - Регистрация\n/create_country <название> - Создать страну\n/balance - Проверить баланс", 
                   inline=False)
    
    embed.add_field(name="💰 Экономика", 
                   value="/collect - Собрать доход\n/shop <категория> - Магазин", 
                   inline=False)
    
    embed.add_field(name="🔫 Военное дело", 
                   value="/buy_weapon <тип> [кол-во] - Купить оружие\n/buy_tank <тип> [кол-во] - Купить танк\n/buy_aircraft <тип> [кол-во] - Купить авиацию\n/arsenal [игрок] - Показать арсенал", 
                   inline=False)
    
    embed.add_field(name="🏗️ Строительство", 
                   value="/build <тип> - Построить здание", 
                   inline=False)
    
    embed.add_field(name="⚔️ Битвы", 
                   value="/attack <игрок> - Атаковать игрока", 
                   inline=False)
    
    embed.add_field(name="📊 Информация", 
                   value="/country_info [игрок] - Информация о стране\n/leaderboard [категория] - Таблица лидеров", 
                   inline=False)
    
    embed.set_footer(text="Используйте /shop для просмотра доступных товаров")
    await ctx.send(embed=embed)

if __name__ == "__main__":
    # Replace with your bot token
    TOKEN = 'YOUR_BOT_TOKEN_HERE'
    
    print("Starting Military Empire Discord Bot...")
    print("Make sure to set your bot token in the TOKEN variable!")
    
    # Uncomment the line below and add your actual bot token
    # bot.run(TOKEN)
    print("Bot configuration complete. Set your token and uncomment bot.run() to start!")
import discord
from discord.ext import commands, tasks
import asyncio
import aiohttp
import json
import sqlite3
import random
import time
from datetime import datetime, timedelta
import os
from typing import Optional

# Bot configuration
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents)

# Database setup
DB_FILE = 'casino_bot.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Discord users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS discord_users (
            id INTEGER PRIMARY KEY,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            casino_user_id INTEGER,
            balance REAL DEFAULT 1000.0,
            daily_claimed DATE,
            total_bets REAL DEFAULT 0,
            total_wins REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Casino stats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS casino_stats (
            id INTEGER PRIMARY KEY,
            total_users INTEGER DEFAULT 0,
            online_users INTEGER DEFAULT 0,
            total_bets REAL DEFAULT 0,
            total_winnings REAL DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Game sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bot_game_sessions (
            id INTEGER PRIMARY KEY,
            discord_id TEXT NOT NULL,
            game_type TEXT NOT NULL,
            bet_amount REAL NOT NULL,
            result_amount REAL NOT NULL,
            game_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Helper functions
def get_user(discord_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM discord_users WHERE discord_id = ?', (str(discord_id),))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(discord_id, username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO discord_users (discord_id, username, balance)
        VALUES (?, ?, 1000.0)
    ''', (str(discord_id), username))
    conn.commit()
    conn.close()

def update_balance(discord_id, amount):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE discord_users 
        SET balance = balance + ? 
        WHERE discord_id = ?
    ''', (amount, str(discord_id)))
    conn.commit()
    conn.close()

def get_balance(discord_id):
    user = get_user(discord_id)
    return user[4] if user else 0

def record_game_session(discord_id, game_type, bet_amount, result_amount, game_data=None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO bot_game_sessions (discord_id, game_type, bet_amount, result_amount, game_data)
        VALUES (?, ?, ?, ?, ?)
    ''', (str(discord_id), game_type, bet_amount, result_amount, json.dumps(game_data) if game_data else None))
    conn.commit()
    conn.close()

# Casino API functions
async def fetch_casino_stats():
    """Fetch real-time stats from casino website"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post('http://localhost/casino.php', 
                                  data={'action': 'get_stats'}) as response:
                if response.status == 200:
                    return await response.json()
    except Exception as e:
        print(f"Error fetching casino stats: {e}")
    return None

# Bot events
@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    update_stats.start()
    
@bot.event
async def on_member_join(member):
    embed = discord.Embed(
        title="🎰 Добро пожаловать в Royal Casino!",
        description=f"Привет {member.mention}! Получи свой стартовый бонус в $1000 с командой `!daily`",
        color=0xdc143c
    )
    embed.add_field(name="🎮 Команды игр", value="`!roulette`, `!mines`, `!balance`", inline=False)
    embed.add_field(name="🌐 Веб-сайт", value="[Играть онлайн](http://localhost/casino.php)", inline=False)
    embed.set_thumbnail(url="https://cdn.discordapp.com/icons/guild_id/guild_icon.png")
    
    channel = member.guild.system_channel
    if channel:
        await channel.send(embed=embed)

# User commands
@bot.command(name='register')
async def register_user(ctx):
    """Register a new user"""
    user = get_user(ctx.author.id)
    if user:
        await ctx.send("❌ Вы уже зарегистрированы!")
        return
    
    create_user(ctx.author.id, str(ctx.author))
    
    embed = discord.Embed(
        title="✅ Регистрация успешна!",
        description=f"{ctx.author.mention}, вы получили стартовый бонус $1000!",
        color=0x00ff00
    )
    embed.add_field(name="💰 Баланс", value="$1000.00", inline=True)
    embed.add_field(name="🎮 Команды", value="`!help casino`", inline=True)
    
    await ctx.send(embed=embed)

@bot.command(name='balance')
async def check_balance(ctx):
    """Check user balance"""
    user = get_user(ctx.author.id)
    if not user:
        create_user(ctx.author.id, str(ctx.author))
        balance = 1000.0
    else:
        balance = user[4]
    
    embed = discord.Embed(
        title="💰 Ваш баланс",
        description=f"**${balance:.2f}**",
        color=0xdc143c
    )
    embed.set_author(name=str(ctx.author), icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
    
    await ctx.send(embed=embed)

@bot.command(name='daily')
async def daily_bonus(ctx):
    """Claim daily bonus"""
    user = get_user(ctx.author.id)
    if not user:
        create_user(ctx.author.id, str(ctx.author))
        user = get_user(ctx.author.id)
    
    today = datetime.now().date()
    last_claimed = user[5]
    
    if last_claimed and str(today) == last_claimed:
        embed = discord.Embed(
            title="⏰ Ежедневный бонус",
            description="Вы уже получили ежедневный бонус сегодня!",
            color=0xff0000
        )
        await ctx.send(embed=embed)
        return
    
    bonus = random.randint(100, 500)
    update_balance(ctx.author.id, bonus)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE discord_users SET daily_claimed = ? WHERE discord_id = ?', 
                   (str(today), str(ctx.author.id)))
    conn.commit()
    conn.close()
    
    new_balance = get_balance(ctx.author.id)
    
    embed = discord.Embed(
        title="🎉 Ежедневный бонус получен!",
        description=f"Вы получили **${bonus}**!",
        color=0x00ff00
    )
    embed.add_field(name="💰 Новый баланс", value=f"${new_balance:.2f}", inline=True)
    embed.add_field(name="⏰ Следующий бонус", value="Завтра", inline=True)
    
    await ctx.send(embed=embed)

# Game commands
@bot.command(name='roulette')
async def roulette_game(ctx, bet_amount: float, bet_type: str, bet_value: Optional[int] = None):
    """Play roulette - Usage: !roulette <amount> <red/black/even/odd/number> [number 0-36]"""
    user = get_user(ctx.author.id)
    if not user:
        create_user(ctx.author.id, str(ctx.author))
        user = get_user(ctx.author.id)
    
    balance = user[4]
    
    if bet_amount <= 0:
        await ctx.send("❌ Ставка должна быть больше 0!")
        return
    
    if balance < bet_amount:
        await ctx.send("❌ Недостаточно средств!")
        return
    
    bet_type = bet_type.lower()
    valid_types = ['red', 'black', 'even', 'odd', 'number']
    
    if bet_type not in valid_types:
        await ctx.send("❌ Неверный тип ставки! Используйте: red, black, even, odd, number")
        return
    
    if bet_type == 'number':
        if bet_value is None or bet_value < 0 or bet_value > 36:
            await ctx.send("❌ Для ставки на число укажите значение от 0 до 36!")
            return
    
    # Generate winning number
    winning_number = random.randint(0, 36)
    red_numbers = [1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]
    
    is_red = winning_number in red_numbers
    is_black = winning_number != 0 and not is_red
    is_even = winning_number % 2 == 0 and winning_number != 0
    is_odd = winning_number % 2 == 1
    
    won = False
    multiplier = 0
    
    if bet_type == 'number' and bet_value == winning_number:
        won = True
        multiplier = 35
    elif bet_type == 'red' and is_red:
        won = True
        multiplier = 1
    elif bet_type == 'black' and is_black:
        won = True
        multiplier = 1
    elif bet_type == 'even' and is_even:
        won = True
        multiplier = 1
    elif bet_type == 'odd' and is_odd:
        won = True
        multiplier = 1
    
    win_amount = bet_amount * multiplier if won else -bet_amount
    update_balance(ctx.author.id, win_amount)
    new_balance = get_balance(ctx.author.id)
    
    # Record game session
    game_data = {
        'winning_number': winning_number,
        'bet_type': bet_type,
        'bet_value': bet_value,
        'won': won
    }
    record_game_session(ctx.author.id, 'roulette', bet_amount, bet_amount + win_amount if won else 0, game_data)
    
    # Create result embed
    color = "🔴" if is_red else "⚫" if is_black else "🟢"
    
    embed = discord.Embed(
        title="🎰 Рулетка",
        description=f"Выпавшее число: **{color} {winning_number}**",
        color=0x00ff00 if won else 0xff0000
    )
    
    embed.add_field(name="🎯 Ваша ставка", value=f"${bet_amount} на {bet_type}" + (f" ({bet_value})" if bet_value is not None else ""), inline=False)
    
    if won:
        embed.add_field(name="🎉 Выигрыш", value=f"${win_amount:.2f}", inline=True)
        embed.add_field(name="📊 Множитель", value=f"{multiplier + 1}x", inline=True)
    else:
        embed.add_field(name="💸 Проигрыш", value=f"${bet_amount:.2f}", inline=True)
    
    embed.add_field(name="💰 Новый баланс", value=f"${new_balance:.2f}", inline=True)
    embed.set_author(name=str(ctx.author), icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
    
    await ctx.send(embed=embed)

@bot.command(name='mines')
async def minesweeper_game(ctx, bet_amount: float, mines: int = 3):
    """Play minesweeper - Usage: !mines <amount> [mines_count]"""
    user = get_user(ctx.author.id)
    if not user:
        create_user(ctx.author.id, str(ctx.author))
        user = get_user(ctx.author.id)
    
    balance = user[4]
    
    if bet_amount <= 0:
        await ctx.send("❌ Ставка должна быть больше 0!")
        return
    
    if balance < bet_amount:
        await ctx.send("❌ Недостаточно средств!")
        return
    
    if mines < 1 or mines > 20:
        await ctx.send("❌ Количество мин должно быть от 1 до 20!")
        return
    
    # Simulate minesweeper game
    total_tiles = 25
    safe_tiles = total_tiles - mines
    tiles_revealed = random.randint(1, min(10, safe_tiles))
    
    # Calculate multiplier based on risk
    risk_factor = mines / total_tiles
    multiplier = 1 + (tiles_revealed * risk_factor * 2)
    
    # Random chance of hitting mine (higher with more mines)
    hit_mine = random.random() < (mines / total_tiles * 0.7)
    
    if hit_mine:
        win_amount = -bet_amount
        result_amount = 0
        update_balance(ctx.author.id, win_amount)
        
        embed = discord.Embed(
            title="💣 Сапёр",
            description="**БУМ!** Вы наткнулись на мину!",
            color=0xff0000
        )
        embed.add_field(name="💸 Проигрыш", value=f"${bet_amount:.2f}", inline=True)
    else:
        win_amount = bet_amount * (multiplier - 1)
        result_amount = bet_amount + win_amount
        update_balance(ctx.author.id, win_amount)
        
        embed = discord.Embed(
            title="💎 Сапёр",
            description="**Успех!** Вы избежали всех мин!",
            color=0x00ff00
        )
        embed.add_field(name="🎉 Выигрыш", value=f"${win_amount:.2f}", inline=True)
        embed.add_field(name="📊 Множитель", value=f"{multiplier:.2f}x", inline=True)
    
    new_balance = get_balance(ctx.author.id)
    embed.add_field(name="🕳️ Открыто клеток", value=f"{tiles_revealed}", inline=True)
    embed.add_field(name="💣 Мин на поле", value=f"{mines}", inline=True)
    embed.add_field(name="💰 Новый баланс", value=f"${new_balance:.2f}", inline=True)
    embed.set_author(name=str(ctx.author), icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
    
    # Record game session
    game_data = {
        'mines': mines,
        'tiles_revealed': tiles_revealed,
        'hit_mine': hit_mine,
        'multiplier': multiplier
    }
    record_game_session(ctx.author.id, 'minesweeper', bet_amount, result_amount, game_data)
    
    await ctx.send(embed=embed)

@bot.command(name='slots')
async def slots_game(ctx, bet_amount: float):
    """Play slot machine - Usage: !slots <amount>"""
    user = get_user(ctx.author.id)
    if not user:
        create_user(ctx.author.id, str(ctx.author))
        user = get_user(ctx.author.id)
    
    balance = user[4]
    
    if bet_amount <= 0:
        await ctx.send("❌ Ставка должна быть больше 0!")
        return
    
    if balance < bet_amount:
        await ctx.send("❌ Недостаточно средств!")
        return
    
    # Slot symbols
    symbols = ['🍒', '🍋', '🍊', '🍇', '🔔', '💎', '7️⃣']
    weights = [30, 25, 20, 15, 7, 2, 1]  # Probability weights
    
    # Spin reels
    reel1 = random.choices(symbols, weights=weights)[0]
    reel2 = random.choices(symbols, weights=weights)[0]
    reel3 = random.choices(symbols, weights=weights)[0]
    
    # Calculate winnings
    multiplier = 0
    if reel1 == reel2 == reel3:
        if reel1 == '7️⃣':
            multiplier = 100  # Jackpot
        elif reel1 == '💎':
            multiplier = 50
        elif reel1 == '🔔':
            multiplier = 25
        elif reel1 == '🍇':
            multiplier = 10
        elif reel1 == '🍊':
            multiplier = 5
        elif reel1 == '🍋':
            multiplier = 3
        elif reel1 == '🍒':
            multiplier = 2
    elif reel1 == reel2 or reel2 == reel3 or reel1 == reel3:
        if '💎' in [reel1, reel2, reel3] or '7️⃣' in [reel1, reel2, reel3]:
            multiplier = 2
        else:
            multiplier = 1
    
    won = multiplier > 0
    win_amount = bet_amount * multiplier if won else -bet_amount
    update_balance(ctx.author.id, win_amount)
    new_balance = get_balance(ctx.author.id)
    
    # Create result embed
    embed = discord.Embed(
        title="🎰 Слоты",
        description=f"**{reel1} | {reel2} | {reel3}**",
        color=0x00ff00 if won else 0xff0000
    )
    
    if won:
        if multiplier >= 50:
            embed.add_field(name="🎉 ДЖЕКПОТ!", value=f"${win_amount:.2f}", inline=True)
        else:
            embed.add_field(name="🎉 Выигрыш", value=f"${win_amount:.2f}", inline=True)
        embed.add_field(name="📊 Множитель", value=f"{multiplier}x", inline=True)
    else:
        embed.add_field(name="💸 Проигрыш", value=f"${bet_amount:.2f}", inline=True)
    
    embed.add_field(name="💰 Новый баланс", value=f"${new_balance:.2f}", inline=True)
    embed.set_author(name=str(ctx.author), icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
    
    # Record game session
    game_data = {
        'reel1': reel1,
        'reel2': reel2,
        'reel3': reel3,
        'multiplier': multiplier,
        'won': won
    }
    record_game_session(ctx.author.id, 'slots', bet_amount, bet_amount + win_amount if won else 0, game_data)
    
    await ctx.send(embed=embed)

# Statistics commands
@bot.command(name='stats')
async def casino_stats(ctx):
    """Show casino statistics"""
    # Get bot stats
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM discord_users')
    total_bot_users = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(total_bets), SUM(total_wins) FROM discord_users')
    bot_stats = cursor.fetchone()
    total_bot_bets = bot_stats[0] or 0
    total_bot_wins = bot_stats[1] or 0
    
    cursor.execute('SELECT COUNT(*) FROM bot_game_sessions WHERE created_at > datetime("now", "-24 hours")')
    games_today = cursor.fetchone()[0]
    
    conn.close()
    
    # Try to get website stats
    casino_stats = await fetch_casino_stats()
    
    embed = discord.Embed(
        title="📊 Статистика Royal Casino",
        color=0xdc143c
    )
    
    # Bot stats
    embed.add_field(name="🤖 Discord бот", value=f"👥 Пользователей: {total_bot_users}\n🎮 Игр за 24ч: {games_today}", inline=True)
    
    # Website stats (if available)
    if casino_stats:
        embed.add_field(name="🌐 Веб-сайт", 
                       value=f"👥 Онлайн: {casino_stats.get('online_users', 0)}\n💰 Общие ставки: ${casino_stats.get('total_bets', 0):,.0f}", 
                       inline=True)
    
    embed.add_field(name="🎯 Общая статистика", 
                   value=f"💸 Ставок в боте: ${total_bot_bets:,.2f}\n🎉 Выигрышей: ${total_bot_wins:,.2f}", 
                   inline=False)
    
    embed.set_footer(text="Обновляется в реальном времени")
    embed.timestamp = datetime.now()
    
    await ctx.send(embed=embed)

@bot.command(name='leaderboard', aliases=['top'])
async def leaderboard(ctx):
    """Show top players"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT username, balance, total_bets, total_wins 
        FROM discord_users 
        ORDER BY balance DESC 
        LIMIT 10
    ''')
    
    top_players = cursor.fetchall()
    conn.close()
    
    if not top_players:
        await ctx.send("📊 Таблица лидеров пуста!")
        return
    
    embed = discord.Embed(
        title="🏆 Таблица лидеров",
        description="Топ игроков по балансу",
        color=0xffd700
    )
    
    leaderboard_text = ""
    for i, (username, balance, total_bets, total_wins) in enumerate(top_players, 1):
        trophy = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
        leaderboard_text += f"{trophy} **{username}**\n💰 ${balance:.2f} | 🎯 Ставок: ${total_bets:.0f}\n\n"
    
    embed.description = leaderboard_text
    await ctx.send(embed=embed)

# Admin commands
@bot.command(name='give_money')
@commands.has_permissions(administrator=True)
async def give_money(ctx, member: discord.Member, amount: float):
    """Give money to a user (Admin only)"""
    user = get_user(member.id)
    if not user:
        create_user(member.id, str(member))
    
    update_balance(member.id, amount)
    new_balance = get_balance(member.id)
    
    embed = discord.Embed(
        title="💰 Средства добавлены",
        description=f"Пользователю {member.mention} добавлено **${amount:.2f}**",
        color=0x00ff00
    )
    embed.add_field(name="💳 Новый баланс", value=f"${new_balance:.2f}", inline=True)
    
    await ctx.send(embed=embed)

@bot.command(name='casino_info')
async def casino_info(ctx):
    """Show casino information and links"""
    embed = discord.Embed(
        title="🎰 Royal Casino",
        description="Добро пожаловать в лучшее онлайн-казино!",
        color=0xdc143c
    )
    
    embed.add_field(name="🎮 Игры в боте", 
                   value="• `!roulette` - Рулетка\n• `!mines` - Сапёр\n• `!slots` - Слоты", 
                   inline=True)
    
    embed.add_field(name="💰 Экономика", 
                   value="• `!balance` - Баланс\n• `!daily` - Ежедневный бонус\n• `!stats` - Статистика", 
                   inline=True)
    
    embed.add_field(name="🌐 Веб-сайт", 
                   value="[Играть онлайн](http://localhost/casino.php)\nБольше игр и возможностей!", 
                   inline=False)
    
    embed.add_field(name="🏆 Рейтинг", 
                   value="• `!leaderboard` - Топ игроков", 
                   inline=True)
    
    embed.set_footer(text="Играйте ответственно!")
    await ctx.send(embed=embed)

# Background tasks
@tasks.loop(minutes=5)
async def update_stats():
    """Update casino stats every 5 minutes"""
    try:
        stats = await fetch_casino_stats()
        if stats:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO casino_stats 
                (id, total_users, online_users, total_bets, total_winnings, last_updated)
                VALUES (1, ?, ?, ?, ?, ?)
            ''', (stats.get('total_users', 0), stats.get('online_users', 0), 
                  stats.get('total_bets', 0), stats.get('total_winnings', 0), 
                  datetime.now().isoformat()))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Error updating stats: {e}")

# Error handling
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Отсутствует обязательный аргумент: `{error.param.name}`")
    elif isinstance(error, commands.BadArgument):
        await ctx.send("❌ Неверный формат аргумента! Проверьте команду.")
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ У вас нет прав для выполнения этой команды!")
    elif isinstance(error, commands.CommandNotFound):
        pass  # Ignore unknown commands
    else:
        print(f"Unexpected error: {error}")
        await ctx.send("❌ Произошла ошибка при выполнении команды!")

# Help command customization
bot.remove_command('help')

@bot.command(name='help')
async def custom_help(ctx, category: str = None):
    """Custom help command"""
    if category == 'casino' or category is None:
        embed = discord.Embed(
            title="🎰 Команды казино",
            description="Список всех доступных команд",
            color=0xdc143c
        )
        
        embed.add_field(name="🎮 Игры", 
                       value="`!roulette <ставка> <тип> [число]`\n`!mines <ставка> [мины]`\n`!slots <ставка>`", 
                       inline=False)
        
        embed.add_field(name="💰 Экономика", 
                       value="`!balance` - Проверить баланс\n`!daily` - Ежедневный бонус\n`!register` - Регистрация", 
                       inline=False)
        
        embed.add_field(name="📊 Статистика", 
                       value="`!stats` - Статистика казино\n`!leaderboard` - Топ игроков", 
                       inline=False)
        
        embed.add_field(name="ℹ️ Информация", 
                       value="`!casino_info` - Информация о казино", 
                       inline=False)
        
        embed.set_footer(text="Используйте !help <команда> для подробной информации")
        await ctx.send(embed=embed)

if __name__ == "__main__":
    # Replace with your bot token
    TOKEN = 'YOUR_BOT_TOKEN_HERE'
    
    print("Starting Casino Discord Bot...")
    print("Make sure to set your bot token in the TOKEN variable!")
    
    # Uncomment the line below and add your actual bot token
    # bot.run(TOKEN)
    print("Bot configuration complete. Set your token and uncomment bot.run() to start!")
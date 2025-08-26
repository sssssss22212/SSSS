#!/bin/bash

echo "🚀 Installing Casino Website and Discord Bots..."
echo "=================================================="

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install discord.py aiohttp requests python-dotenv

# Create databases
echo "🗄️ Creating database schemas..."
python3 << 'EOF'
import sqlite3
import os

# Create casino bot database
casino_conn = sqlite3.connect('casino_bot.db')
casino_cursor = casino_conn.cursor()

casino_cursor.execute('''
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

casino_cursor.execute('''
    CREATE TABLE IF NOT EXISTS casino_stats (
        id INTEGER PRIMARY KEY,
        total_users INTEGER DEFAULT 0,
        online_users INTEGER DEFAULT 0,
        total_bets REAL DEFAULT 0,
        total_winnings REAL DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

casino_cursor.execute('''
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

casino_conn.commit()
casino_conn.close()
print("✅ Casino bot database created!")

# Create military bot database
military_conn = sqlite3.connect('military_bot.db')
military_cursor = military_conn.cursor()

military_cursor.execute('''
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

military_cursor.execute('''
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

military_cursor.execute('''
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

military_cursor.execute('''
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

military_cursor.execute('''
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

military_conn.commit()
military_conn.close()
print("✅ Military bot database created!")
EOF

# Create .env file
echo "⚙️ Creating configuration files..."
cat > .env << 'EOF'
# Discord Bot Tokens
CASINO_BOT_TOKEN=your_casino_bot_token_here
MILITARY_BOT_TOKEN=your_military_bot_token_here

# Database Configuration
DB_HOST=localhost
DB_NAME=casino_db
DB_USER=root
DB_PASSWORD=

# Casino Website Configuration
WEBSITE_URL=http://localhost/casino.php
ADMIN_PASSWORD=admin123

# Development Settings
DEBUG=True
EOF

# Create startup scripts
cat > start_casino_bot.sh << 'EOF'
#!/bin/bash
echo "Starting Casino Discord Bot..."
source venv/bin/activate
python3 casino_bot.py
EOF

cat > start_military_bot.sh << 'EOF'
#!/bin/bash
echo "Starting Military Discord Bot..."
source venv/bin/activate
python3 military_bot.py
EOF

chmod +x start_casino_bot.sh
chmod +x start_military_bot.sh

echo "=================================================="
echo "✅ Installation completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file and add your Discord bot tokens"
echo "2. Set up a web server (Apache/Nginx) for the casino website"
echo "3. Create a MySQL database for the casino website"
echo "4. Run the casino website: Access casino.php via web browser"
echo "5. Start casino bot: ./start_casino_bot.sh"
echo "6. Start military bot: ./start_military_bot.sh"
echo ""
echo "🎮 Features included:"
echo "• Casino website with roulette, minesweeper, user system"
echo "• Casino Discord bot with games and real-time integration"
echo "• Military Discord bot with countries, battles, infrastructure"
echo "• Admin panels and comprehensive statistics"
echo "• Real-time money tracking and leaderboards"
echo ""
echo "📖 Read README.md for detailed usage instructions!"
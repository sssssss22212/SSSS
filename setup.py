#!/usr/bin/env python3
"""
Setup script for Casino Website and Discord Bots
"""

import subprocess
import sys
import os
import sqlite3

def install_python_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Python dependencies installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing Python dependencies: {e}")
        return False
    return True

def create_database_schemas():
    """Create database schemas for both bots"""
    print("🗄️ Creating database schemas...")
    
    # Create casino bot database
    try:
        casino_conn = sqlite3.connect('casino_bot.db')
        casino_cursor = casino_conn.cursor()
        
        # Discord users table
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
        
        # Casino stats table
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
        
        # Game sessions table
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
        print("✅ Casino bot database created successfully!")
        
    except Exception as e:
        print(f"❌ Error creating casino bot database: {e}")
        return False
    
    # Create military bot database
    try:
        military_conn = sqlite3.connect('military_bot.db')
        military_cursor = military_conn.cursor()
        
        # Countries table
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
        
        # Players table
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
        
        # Military assets table
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
        
        # Infrastructure table
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
        
        # Battle history table
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
        print("✅ Military bot database created successfully!")
        
    except Exception as e:
        print(f"❌ Error creating military bot database: {e}")
        return False
    
    return True

def create_config_files():
    """Create configuration files"""
    print("⚙️ Creating configuration files...")
    
    # Create .env file template
    env_content = """# Discord Bot Tokens
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
"""
    
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ Created .env configuration file!")
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False
    
    # Create start scripts
    start_casino_bot = """#!/bin/bash
echo "Starting Casino Discord Bot..."
python3 casino_bot.py
"""
    
    start_military_bot = """#!/bin/bash
echo "Starting Military Discord Bot..."
python3 military_bot.py
"""
    
    try:
        with open('start_casino_bot.sh', 'w') as f:
            f.write(start_casino_bot)
        os.chmod('start_casino_bot.sh', 0o755)
        
        with open('start_military_bot.sh', 'w') as f:
            f.write(start_military_bot)
        os.chmod('start_military_bot.sh', 0o755)
        
        print("✅ Created startup scripts!")
    except Exception as e:
        print(f"❌ Error creating startup scripts: {e}")
        return False
    
    return True

def main():
    """Main setup function"""
    print("🚀 Setting up Casino Website and Discord Bots...")
    print("=" * 50)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("❌ Setup failed during dependency installation!")
        return
    
    # Create databases
    if not create_database_schemas():
        print("❌ Setup failed during database creation!")
        return
    
    # Create config files
    if not create_config_files():
        print("❌ Setup failed during configuration!")
        return
    
    print("=" * 50)
    print("✅ Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Edit .env file and add your Discord bot tokens")
    print("2. Set up a web server (Apache/Nginx) for the casino website")
    print("3. Create a MySQL database for the casino website")
    print("4. Run the casino website: Access casino.php via web browser")
    print("5. Start casino bot: python3 casino_bot.py")
    print("6. Start military bot: python3 military_bot.py")
    print("\n🎮 Features included:")
    print("• Casino website with roulette, minesweeper, user system")
    print("• Casino Discord bot with games and real-time integration")
    print("• Military Discord bot with countries, battles, infrastructure")
    print("• Admin panels and comprehensive statistics")
    print("• Real-time money tracking and leaderboards")

if __name__ == "__main__":
    main()
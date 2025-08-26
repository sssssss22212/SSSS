<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Database configuration
$db_config = [
    'host' => 'localhost',
    'dbname' => 'casino_db',
    'username' => 'root',
    'password' => ''
];

// Initialize database connection
try {
    $pdo = new PDO("mysql:host={$db_config['host']};dbname={$db_config['dbname']}", 
                   $db_config['username'], $db_config['password']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Create tables if they don't exist
$sql = "
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    balance DECIMAL(10,2) DEFAULT 1000.00,
    role ENUM('user', 'admin') DEFAULT 'user',
    steam_id VARCHAR(20) NULL,
    avatar VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM('deposit', 'withdrawal', 'bet_win', 'bet_loss') NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS game_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    game_type ENUM('roulette', 'minesweeper', 'slots') NOT NULL,
    bet_amount DECIMAL(10,2) NOT NULL,
    result_amount DECIMAL(10,2) NOT NULL,
    game_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS site_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    total_users INT DEFAULT 0,
    total_bets DECIMAL(15,2) DEFAULT 0,
    total_winnings DECIMAL(15,2) DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT IGNORE INTO site_stats (id, total_users, total_bets, total_winnings) VALUES (1, 0, 0, 0);

INSERT IGNORE INTO users (username, email, password, balance, role) 
VALUES ('admin', 'admin@casino.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 10000.00, 'admin');
";

$pdo->exec($sql);

// User management functions
function registerUser($username, $email, $password) {
    global $pdo;
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    
    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->execute([$username, $email, $hashedPassword]);
        return true;
    } catch(PDOException $e) {
        return false;
    }
}

function loginUser($username, $password) {
    global $pdo;
    
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND is_active = 1");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        
        // Update last login
        $stmt = $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
        $stmt->execute([$user['id']]);
        
        return true;
    }
    return false;
}

function getUserBalance($userId) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT balance FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result ? $result['balance'] : 0;
}

function updateUserBalance($userId, $amount, $type, $description = '') {
    global $pdo;
    
    $pdo->beginTransaction();
    try {
        // Update user balance
        $stmt = $pdo->prepare("UPDATE users SET balance = balance + ? WHERE id = ?");
        $stmt->execute([$amount, $userId]);
        
        // Record transaction
        $stmt = $pdo->prepare("INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)");
        $stmt->execute([$userId, $type, abs($amount), $description]);
        
        $pdo->commit();
        return true;
    } catch(Exception $e) {
        $pdo->rollback();
        return false;
    }
}

// Game logic functions
function playRoulette($userId, $betAmount, $betType, $betValue) {
    if (getUserBalance($userId) < $betAmount) {
        return ['success' => false, 'message' => 'Insufficient balance'];
    }
    
    $winningNumber = rand(0, 36);
    $isRed = in_array($winningNumber, [1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);
    $isBlack = $winningNumber != 0 && !$isRed;
    $isEven = $winningNumber % 2 == 0 && $winningNumber != 0;
    $isOdd = $winningNumber % 2 == 1;
    
    $won = false;
    $multiplier = 0;
    
    switch($betType) {
        case 'number':
            if ($betValue == $winningNumber) {
                $won = true;
                $multiplier = 35;
            }
            break;
        case 'red':
            if ($isRed) {
                $won = true;
                $multiplier = 1;
            }
            break;
        case 'black':
            if ($isBlack) {
                $won = true;
                $multiplier = 1;
            }
            break;
        case 'even':
            if ($isEven) {
                $won = true;
                $multiplier = 1;
            }
            break;
        case 'odd':
            if ($isOdd) {
                $won = true;
                $multiplier = 1;
            }
            break;
    }
    
    $winAmount = $won ? $betAmount * $multiplier : -$betAmount;
    $resultAmount = $won ? $betAmount + $winAmount : 0;
    
    // Update balance
    updateUserBalance($userId, $winAmount, $won ? 'bet_win' : 'bet_loss', "Roulette bet on $betType");
    
    // Record game session
    global $pdo;
    $gameData = json_encode([
        'winning_number' => $winningNumber,
        'bet_type' => $betType,
        'bet_value' => $betValue,
        'won' => $won
    ]);
    
    $stmt = $pdo->prepare("INSERT INTO game_sessions (user_id, game_type, bet_amount, result_amount, game_data) VALUES (?, 'roulette', ?, ?, ?)");
    $stmt->execute([$userId, $betAmount, $resultAmount, $gameData]);
    
    return [
        'success' => true,
        'winning_number' => $winningNumber,
        'won' => $won,
        'win_amount' => $winAmount,
        'new_balance' => getUserBalance($userId)
    ];
}

function playMinesweeper($userId, $betAmount, $mines, $tilesRevealed) {
    if (getUserBalance($userId) < $betAmount) {
        return ['success' => false, 'message' => 'Insufficient balance'];
    }
    
    $totalTiles = 25;
    $safeTiles = $totalTiles - $mines;
    
    // Calculate multiplier based on risk
    $multiplier = 1 + ($tilesRevealed * $mines / $safeTiles);
    
    // Random chance of hitting mine
    $hitMine = rand(1, 100) <= ($mines * 4);
    
    if ($hitMine) {
        $winAmount = -$betAmount;
        $resultAmount = 0;
        updateUserBalance($userId, $winAmount, 'bet_loss', "Minesweeper - hit mine");
    } else {
        $winAmount = $betAmount * ($multiplier - 1);
        $resultAmount = $betAmount + $winAmount;
        updateUserBalance($userId, $winAmount, 'bet_win', "Minesweeper - safe tiles");
    }
    
    // Record game session
    global $pdo;
    $gameData = json_encode([
        'mines' => $mines,
        'tiles_revealed' => $tilesRevealed,
        'hit_mine' => $hitMine,
        'multiplier' => $multiplier
    ]);
    
    $stmt = $pdo->prepare("INSERT INTO game_sessions (user_id, game_type, bet_amount, result_amount, game_data) VALUES (?, 'minesweeper', ?, ?, ?)");
    $stmt->execute([$userId, $betAmount, $resultAmount, $gameData]);
    
    return [
        'success' => true,
        'hit_mine' => $hitMine,
        'win_amount' => $winAmount,
        'multiplier' => $multiplier,
        'new_balance' => getUserBalance($userId)
    ];
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not logged in']);
        exit;
    }
    
    switch($_POST['action']) {
        case 'play_roulette':
            $result = playRoulette($_SESSION['user_id'], $_POST['bet_amount'], $_POST['bet_type'], $_POST['bet_value'] ?? 0);
            echo json_encode($result);
            break;
            
        case 'play_minesweeper':
            $result = playMinesweeper($_SESSION['user_id'], $_POST['bet_amount'], $_POST['mines'], $_POST['tiles_revealed']);
            echo json_encode($result);
            break;
            
        case 'get_balance':
            echo json_encode(['balance' => getUserBalance($_SESSION['user_id'])]);
            break;
    }
    exit;
}

// Handle login/register
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if (loginUser($_POST['username'], $_POST['password'])) {
        header('Location: casino.php');
    } else {
        $error = "Invalid username or password";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    if (registerUser($_POST['username'], $_POST['email'], $_POST['password'])) {
        $success = "Registration successful! Please login.";
    } else {
        $error = "Registration failed. Username or email may already exist.";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: casino.php');
    exit;
}

// Get stats for display
function getSiteStats() {
    global $pdo;
    $stmt = $pdo->query("SELECT * FROM site_stats WHERE id = 1");
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function getOnlineUsers() {
    global $pdo;
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM users WHERE last_login > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result['count'];
}

$stats = getSiteStats();
$onlineUsers = getOnlineUsers();
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Royal Casino - Лучшее онлайн казино</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #0f0f0f, #1a1a1a);
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0,0,0,0.9);
            padding: 1rem 0;
            border-bottom: 2px solid #dc143c;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        
        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 2rem;
            font-weight: bold;
            color: #dc143c;
            text-decoration: none;
        }
        
        .nav-links {
            display: flex;
            gap: 2rem;
            align-items: center;
        }
        
        .nav-links a {
            color: #fff;
            text-decoration: none;
            transition: color 0.3s;
        }
        
        .nav-links a:hover {
            color: #dc143c;
        }
        
        .user-info {
            background: rgba(220, 20, 60, 0.1);
            padding: 0.5rem 1rem;
            border-radius: 25px;
            border: 1px solid #dc143c;
        }
        
        .balance {
            color: #00ff00;
            font-weight: bold;
            margin-left: 1rem;
        }
        
        .main-content {
            padding: 2rem 0;
        }
        
        .stats-bar {
            background: rgba(0,0,0,0.8);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .stat-item {
            text-align: center;
            padding: 1rem;
            background: rgba(220, 20, 60, 0.1);
            border-radius: 8px;
            border: 1px solid #dc143c;
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: #dc143c;
        }
        
        .games-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .game-card {
            background: rgba(0,0,0,0.8);
            border-radius: 15px;
            padding: 1.5rem;
            border: 1px solid #333;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .game-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(220, 20, 60, 0.3);
        }
        
        .game-title {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: #dc143c;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .roulette-wheel {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(
                #dc143c 0deg 9.7deg,
                #000 9.7deg 19.4deg,
                #dc143c 19.4deg 29.1deg,
                #000 29.1deg 38.8deg
            );
            margin: 1rem auto;
            position: relative;
            transition: transform 3s cubic-bezier(0.25, 0.1, 0.25, 1);
        }
        
        .roulette-pointer {
            position: absolute;
            top: -10px;
            left: 50%;
            transform: translateX(-50%);
            width: 0;
            height: 0;
            border-left: 10px solid transparent;
            border-right: 10px solid transparent;
            border-top: 20px solid #fff;
        }
        
        .roulette-center {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 40px;
            height: 40px;
            background: #fff;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: #000;
            font-size: 1rem;
        }
        
        .betting-section {
            margin-top: 1rem;
        }
        
        .bet-input {
            width: 100%;
            padding: 0.5rem;
            margin-bottom: 1rem;
            background: rgba(255,255,255,0.1);
            border: 1px solid #333;
            border-radius: 5px;
            color: #fff;
        }
        
        .bet-buttons {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0.5rem;
            margin-bottom: 1rem;
        }
        
        .bet-btn {
            padding: 0.75rem;
            background: rgba(220, 20, 60, 0.2);
            border: 1px solid #dc143c;
            border-radius: 5px;
            color: #fff;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .bet-btn:hover, .bet-btn.active {
            background: #dc143c;
            transform: scale(1.05);
        }
        
        .play-btn {
            width: 100%;
            padding: 1rem;
            background: linear-gradient(45deg, #dc143c, #ff4569);
            border: none;
            border-radius: 10px;
            color: #fff;
            font-size: 1.1rem;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .play-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(220, 20, 60, 0.4);
        }
        
        .play-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .minesweeper-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 2px;
            margin: 1rem 0;
            max-width: 250px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .mine-tile {
            width: 40px;
            height: 40px;
            background: rgba(255,255,255,0.1);
            border: 1px solid #333;
            border-radius: 3px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
        }
        
        .mine-tile:hover {
            background: rgba(220, 20, 60, 0.3);
        }
        
        .mine-tile.revealed {
            background: #00ff00;
            color: #000;
        }
        
        .mine-tile.mine {
            background: #dc143c;
        }
        
        .login-form {
            max-width: 400px;
            margin: 2rem auto;
            padding: 2rem;
            background: rgba(0,0,0,0.8);
            border-radius: 15px;
            border: 1px solid #333;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #dc143c;
        }
        
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            background: rgba(255,255,255,0.1);
            border: 1px solid #333;
            border-radius: 5px;
            color: #fff;
        }
        
        .alert {
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 5px;
            text-align: center;
        }
        
        .alert.error {
            background: rgba(220, 20, 60, 0.2);
            border: 1px solid #dc143c;
            color: #fff;
        }
        
        .alert.success {
            background: rgba(0, 255, 0, 0.2);
            border: 1px solid #00ff00;
            color: #fff;
        }
        
        .admin-panel {
            margin-top: 2rem;
            padding: 2rem;
            background: rgba(0,0,0,0.8);
            border-radius: 15px;
            border: 1px solid #dc143c;
        }
        
        .admin-title {
            color: #dc143c;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }
        
        .tabs {
            display: flex;
            margin-bottom: 1rem;
            border-bottom: 1px solid #333;
        }
        
        .tab {
            padding: 1rem 2rem;
            background: none;
            border: none;
            color: #fff;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
        }
        
        .tab.active, .tab:hover {
            color: #dc143c;
            border-bottom-color: #dc143c;
        }
        
        @media (max-width: 768px) {
            .navbar {
                flex-direction: column;
                gap: 1rem;
            }
            
            .games-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-bar {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="container">
            <nav class="navbar">
                <a href="casino.php" class="logo"><i class="fas fa-crown"></i> Royal Casino</a>
                <div class="nav-links">
                    <?php if (isset($_SESSION['user_id'])): ?>
                        <div class="user-info">
                            <i class="fas fa-user"></i> <?php echo htmlspecialchars($_SESSION['username']); ?>
                            <span class="balance">💰 $<span id="user-balance"><?php echo number_format(getUserBalance($_SESSION['user_id']), 2); ?></span></span>
                        </div>
                        <?php if ($_SESSION['role'] === 'admin'): ?>
                            <a href="#admin" onclick="toggleAdmin()"><i class="fas fa-cog"></i> Admin</a>
                        <?php endif; ?>
                        <a href="?logout=1"><i class="fas fa-sign-out-alt"></i> Выход</a>
                    <?php else: ?>
                        <a href="#login" onclick="toggleLogin()"><i class="fas fa-sign-in-alt"></i> Вход</a>
                        <a href="#register" onclick="toggleRegister()"><i class="fas fa-user-plus"></i> Регистрация</a>
                    <?php endif; ?>
                </div>
            </nav>
        </div>
    </header>

    <main class="main-content">
        <div class="container">
            <?php if (isset($error)): ?>
                <div class="alert error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if (isset($success)): ?>
                <div class="alert success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

            <div class="stats-bar">
                <div class="stat-item">
                    <div class="stat-value"><?php echo $onlineUsers; ?></div>
                    <div>Онлайн игроков</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">$<?php echo number_format($stats['total_bets'], 0); ?></div>
                    <div>Общие ставки</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">$<?php echo number_format($stats['total_winnings'], 0); ?></div>
                    <div>Общие выигрыши</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value"><?php echo $stats['total_users']; ?></div>
                    <div>Всего игроков</div>
                </div>
            </div>

            <?php if (isset($_SESSION['user_id'])): ?>
                <div class="games-grid">
                    <!-- Roulette Game -->
                    <div class="game-card">
                        <div class="game-title">
                            <i class="fas fa-circle-notch"></i> Рулетка
                        </div>
                        <div class="roulette-wheel" id="roulette-wheel">
                            <div class="roulette-pointer"></div>
                            <div class="roulette-center" id="roulette-result">0</div>
                        </div>
                        <div class="betting-section">
                            <input type="number" class="bet-input" id="roulette-bet" placeholder="Сумма ставки" min="1" value="10">
                            <div class="bet-buttons">
                                <button class="bet-btn" data-bet="red">Красное</button>
                                <button class="bet-btn" data-bet="black">Чёрное</button>
                                <button class="bet-btn" data-bet="even">Чётное</button>
                                <button class="bet-btn" data-bet="odd">Нечётное</button>
                                <button class="bet-btn" data-bet="number">Число</button>
                                <input type="number" class="bet-input" id="number-bet" placeholder="0-36" min="0" max="36" style="display: none;">
                            </div>
                            <button class="play-btn" onclick="playRoulette()">Крутить рулетку</button>
                        </div>
                    </div>

                    <!-- Minesweeper Game -->
                    <div class="game-card">
                        <div class="game-title">
                            <i class="fas fa-bomb"></i> Сапёр
                        </div>
                        <div class="betting-section">
                            <input type="number" class="bet-input" id="mines-bet" placeholder="Сумма ставки" min="1" value="10">
                            <div>
                                <label>Количество мин: <span id="mines-count">3</span></label>
                                <input type="range" id="mines-slider" min="1" max="10" value="3" style="width: 100%;">
                            </div>
                            <div class="minesweeper-grid" id="mines-grid"></div>
                            <button class="play-btn" onclick="playMinesweeper()">Играть в сапёр</button>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <!-- Login Form -->
                <div class="login-form" id="login-form">
                    <h2 style="text-align: center; color: #dc143c; margin-bottom: 2rem;">Вход в казино</h2>
                    <form method="POST">
                        <div class="form-group">
                            <label>Имя пользователя:</label>
                            <input type="text" name="username" required>
                        </div>
                        <div class="form-group">
                            <label>Пароль:</label>
                            <input type="password" name="password" required>
                        </div>
                        <button type="submit" name="login" class="play-btn">Войти</button>
                    </form>
                    <p style="text-align: center; margin-top: 1rem;">
                        Нет аккаунта? <a href="#" onclick="toggleRegister()" style="color: #dc143c;">Зарегистрироваться</a>
                    </p>
                </div>

                <!-- Register Form -->
                <div class="login-form" id="register-form" style="display: none;">
                    <h2 style="text-align: center; color: #dc143c; margin-bottom: 2rem;">Регистрация</h2>
                    <form method="POST">
                        <div class="form-group">
                            <label>Имя пользователя:</label>
                            <input type="text" name="username" required>
                        </div>
                        <div class="form-group">
                            <label>Email:</label>
                            <input type="email" name="email" required>
                        </div>
                        <div class="form-group">
                            <label>Пароль:</label>
                            <input type="password" name="password" required>
                        </div>
                        <button type="submit" name="register" class="play-btn">Зарегистрироваться</button>
                    </form>
                    <p style="text-align: center; margin-top: 1rem;">
                        Уже есть аккаунт? <a href="#" onclick="toggleLogin()" style="color: #dc143c;">Войти</a>
                    </p>
                </div>
            <?php endif; ?>

            <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                <div class="admin-panel" id="admin-panel" style="display: none;">
                    <h2 class="admin-title">Панель администратора</h2>
                    <div class="tabs">
                        <button class="tab active" onclick="showTab('users')">Пользователи</button>
                        <button class="tab" onclick="showTab('transactions')">Транзакции</button>
                        <button class="tab" onclick="showTab('games')">Игры</button>
                        <button class="tab" onclick="showTab('settings')">Настройки</button>
                    </div>
                    <div id="admin-content">
                        <!-- Admin content will be loaded here -->
                        <div id="users-tab">
                            <h3>Управление пользователями</h3>
                            <p>Здесь будет список пользователей и возможность управления ими.</p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </main>

    <script>
        let selectedBet = null;
        let minesCount = 3;
        let gameActive = false;

        // Roulette functions
        function playRoulette() {
            if (gameActive) return;
            
            const betAmount = document.getElementById('roulette-bet').value;
            const betType = selectedBet;
            let betValue = 0;
            
            if (!betType) {
                alert('Выберите тип ставки!');
                return;
            }
            
            if (betType === 'number') {
                betValue = document.getElementById('number-bet').value;
                if (!betValue || betValue < 0 || betValue > 36) {
                    alert('Введите число от 0 до 36!');
                    return;
                }
            }
            
            gameActive = true;
            const wheel = document.getElementById('roulette-wheel');
            
            // Animate wheel
            const rotation = Math.random() * 3600 + 1800; // 5-15 full rotations
            wheel.style.transform = `rotate(${rotation}deg)`;
            
            // Send bet to server
            fetch('casino.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `action=play_roulette&bet_amount=${betAmount}&bet_type=${betType}&bet_value=${betValue}`
            })
            .then(response => response.json())
            .then(data => {
                setTimeout(() => {
                    document.getElementById('roulette-result').textContent = data.winning_number;
                    updateBalance(data.new_balance);
                    
                    if (data.won) {
                        alert(`Поздравляем! Вы выиграли $${data.win_amount.toFixed(2)}!`);
                    } else {
                        alert(`Удача не на вашей стороне. Попробуйте ещё раз!`);
                    }
                    
                    gameActive = false;
                }, 3000);
            })
            .catch(error => {
                console.error('Error:', error);
                gameActive = false;
            });
        }

        // Minesweeper functions
        function initMinesweeper() {
            const grid = document.getElementById('mines-grid');
            grid.innerHTML = '';
            
            for (let i = 0; i < 25; i++) {
                const tile = document.createElement('div');
                tile.className = 'mine-tile';
                tile.dataset.index = i;
                tile.onclick = () => revealTile(i);
                grid.appendChild(tile);
            }
        }

        function playMinesweeper() {
            if (gameActive) return;
            
            const betAmount = document.getElementById('mines-bet').value;
            const tilesRevealed = document.querySelectorAll('.mine-tile.revealed').length;
            
            if (tilesRevealed === 0) {
                alert('Откройте хотя бы одну клетку!');
                return;
            }
            
            gameActive = true;
            
            fetch('casino.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `action=play_minesweeper&bet_amount=${betAmount}&mines=${minesCount}&tiles_revealed=${tilesRevealed}`
            })
            .then(response => response.json())
            .then(data => {
                updateBalance(data.new_balance);
                
                if (data.hit_mine) {
                    alert(`Бум! Вы наткнулись на мину и потеряли $${betAmount}!`);
                    // Show mines
                    const tiles = document.querySelectorAll('.mine-tile');
                    for (let i = 0; i < minesCount; i++) {
                        const randomTile = tiles[Math.floor(Math.random() * tiles.length)];
                        if (!randomTile.classList.contains('mine')) {
                            randomTile.classList.add('mine');
                            randomTile.innerHTML = '<i class="fas fa-bomb"></i>';
                        }
                    }
                } else {
                    alert(`Отлично! Вы выиграли $${data.win_amount.toFixed(2)}! Множитель: ${data.multiplier.toFixed(2)}x`);
                }
                
                setTimeout(() => {
                    initMinesweeper();
                    gameActive = false;
                }, 2000);
            })
            .catch(error => {
                console.error('Error:', error);
                gameActive = false;
            });
        }

        function revealTile(index) {
            if (gameActive) return;
            
            const tile = document.querySelector(`[data-index="${index}"]`);
            if (tile.classList.contains('revealed')) return;
            
            tile.classList.add('revealed');
            tile.innerHTML = '<i class="fas fa-gem"></i>';
        }

        function updateBalance(newBalance) {
            document.getElementById('user-balance').textContent = newBalance.toFixed(2);
        }

        // UI functions
        function toggleLogin() {
            document.getElementById('login-form').style.display = 'block';
            document.getElementById('register-form').style.display = 'none';
        }

        function toggleRegister() {
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('register-form').style.display = 'block';
        }

        function toggleAdmin() {
            const panel = document.getElementById('admin-panel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }

        function showTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            event.target.classList.add('active');
            
            // Show tab content
            document.getElementById('admin-content').innerHTML = `<div id="${tabName}-tab"><h3>${tabName.charAt(0).toUpperCase() + tabName.slice(1)}</h3><p>Содержимое вкладки ${tabName}</p></div>`;
        }

        // Event listeners
        document.addEventListener('DOMContentLoaded', function() {
            // Roulette bet buttons
            document.querySelectorAll('.bet-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    document.querySelectorAll('.bet-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    selectedBet = this.dataset.bet;
                    
                    const numberInput = document.getElementById('number-bet');
                    if (selectedBet === 'number') {
                        numberInput.style.display = 'block';
                    } else {
                        numberInput.style.display = 'none';
                    }
                });
            });

            // Mines slider
            document.getElementById('mines-slider').addEventListener('input', function() {
                minesCount = this.value;
                document.getElementById('mines-count').textContent = minesCount;
            });

            // Initialize minesweeper
            initMinesweeper();

            // Update balance every 30 seconds
            setInterval(() => {
                if (document.getElementById('user-balance')) {
                    fetch('casino.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: 'action=get_balance'
                    })
                    .then(response => response.json())
                    .then(data => {
                        updateBalance(data.balance);
                    });
                }
            }, 30000);
        });
    </script>
</body>
</html>
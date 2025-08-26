<?php
session_start();

// Configuration
define('DATA_DIR', 'data/');
define('USERS_FILE', DATA_DIR . 'users.json');
define('GAMES_FILE', DATA_DIR . 'games.json');
define('TRANSACTIONS_FILE', DATA_DIR . 'transactions.json');
define('STATS_FILE', DATA_DIR . 'stats.json');

// Create data directory if it doesn't exist
if (!file_exists(DATA_DIR)) {
    mkdir(DATA_DIR, 0777, true);
}

// Initialize data files
function initializeDataFiles() {
    if (!file_exists(USERS_FILE)) {
        $defaultUsers = [
            'admin' => [
                'id' => 1,
                'username' => 'admin',
                'password' => password_hash('admin123', PASSWORD_DEFAULT),
                'email' => 'admin@steamtime.casino',
                'balance' => 10000,
                'role' => 'admin',
                'created_at' => date('Y-m-d H:i:s'),
                'last_login' => null,
                'total_wagered' => 0,
                'total_won' => 0,
                'games_played' => 0
            ]
        ];
        file_put_contents(USERS_FILE, json_encode($defaultUsers, JSON_PRETTY_PRINT));
    }
    
    if (!file_exists(GAMES_FILE)) {
        file_put_contents(GAMES_FILE, json_encode([], JSON_PRETTY_PRINT));
    }
    
    if (!file_exists(TRANSACTIONS_FILE)) {
        file_put_contents(TRANSACTIONS_FILE, json_encode([], JSON_PRETTY_PRINT));
    }
    
    if (!file_exists(STATS_FILE)) {
        $defaultStats = [
            'total_users' => 1,
            'total_games_played' => 0,
            'total_wagered' => 0,
            'total_won' => 0,
            'online_users' => 0
        ];
        file_put_contents(STATS_FILE, json_encode($defaultStats, JSON_PRETTY_PRINT));
    }
}

initializeDataFiles();

// Utility functions
function loadData($file) {
    if (file_exists($file)) {
        return json_decode(file_get_contents($file), true) ?: [];
    }
    return [];
}

function saveData($file, $data) {
    return file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

function generateId() {
    return uniqid() . rand(1000, 9999);
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isLoggedIn() && $_SESSION['role'] === 'admin';
}

function getCurrentUser() {
    if (!isLoggedIn()) return null;
    $users = loadData(USERS_FILE);
    return $users[$_SESSION['username']] ?? null;
}

function updateUserBalance($username, $amount) {
    $users = loadData(USERS_FILE);
    if (isset($users[$username])) {
        $users[$username]['balance'] += $amount;
        saveData(USERS_FILE, $users);
        return true;
    }
    return false;
}

function addTransaction($userId, $type, $amount, $game = null, $details = '') {
    $transactions = loadData(TRANSACTIONS_FILE);
    $transaction = [
        'id' => generateId(),
        'user_id' => $userId,
        'type' => $type, // 'bet', 'win', 'deposit', 'withdrawal'
        'amount' => $amount,
        'game' => $game,
        'details' => $details,
        'timestamp' => date('Y-m-d H:i:s')
    ];
    $transactions[] = $transaction;
    saveData(TRANSACTIONS_FILE, $transactions);
}

function updateStats($gamesPlayed = 0, $wagered = 0, $won = 0) {
    $stats = loadData(STATS_FILE);
    $stats['total_games_played'] += $gamesPlayed;
    $stats['total_wagered'] += $wagered;
    $stats['total_won'] += $won;
    saveData(STATS_FILE, $stats);
}

// Handle AJAX requests
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['action']) {
        case 'login':
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            
            $users = loadData(USERS_FILE);
            if (isset($users[$username]) && password_verify($password, $users[$username]['password'])) {
                $_SESSION['user_id'] = $users[$username]['id'];
                $_SESSION['username'] = $username;
                $_SESSION['role'] = $users[$username]['role'];
                
                // Update last login
                $users[$username]['last_login'] = date('Y-m-d H:i:s');
                saveData(USERS_FILE, $users);
                
                echo json_encode(['success' => true, 'role' => $users[$username]['role']]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Invalid credentials']);
            }
            exit;
            
        case 'register':
            $username = $_POST['username'] ?? '';
            $email = $_POST['email'] ?? '';
            $password = $_POST['password'] ?? '';
            
            if (strlen($username) < 3 || strlen($password) < 6) {
                echo json_encode(['success' => false, 'message' => 'Username must be 3+ chars, password 6+ chars']);
                exit;
            }
            
            $users = loadData(USERS_FILE);
            if (isset($users[$username])) {
                echo json_encode(['success' => false, 'message' => 'Username already exists']);
                exit;
            }
            
            $users[$username] = [
                'id' => count($users) + 1,
                'username' => $username,
                'email' => $email,
                'password' => password_hash($password, PASSWORD_DEFAULT),
                'balance' => 1000, // Starting bonus
                'role' => 'user',
                'created_at' => date('Y-m-d H:i:s'),
                'last_login' => null,
                'total_wagered' => 0,
                'total_won' => 0,
                'games_played' => 0
            ];
            
            saveData(USERS_FILE, $users);
            
            // Update stats
            $stats = loadData(STATS_FILE);
            $stats['total_users']++;
            saveData(STATS_FILE, $stats);
            
            echo json_encode(['success' => true]);
            exit;
            
        case 'logout':
            session_destroy();
            echo json_encode(['success' => true]);
            exit;
            
        case 'get_balance':
            $user = getCurrentUser();
            echo json_encode(['balance' => $user['balance'] ?? 0]);
            exit;
            
        case 'play_roulette':
            if (!isLoggedIn()) {
                echo json_encode(['success' => false, 'message' => 'Not logged in']);
                exit;
            }
            
            $bet = (float)($_POST['bet'] ?? 0);
            $number = (int)($_POST['number'] ?? -1);
            $color = $_POST['color'] ?? '';
            
            $user = getCurrentUser();
            if ($bet > $user['balance']) {
                echo json_encode(['success' => false, 'message' => 'Insufficient balance']);
                exit;
            }
            
            // Generate winning number
            $winningNumber = rand(0, 36);
            $winningColor = ($winningNumber == 0) ? 'green' : (($winningNumber % 2 == 0) ? 'black' : 'red');
            
            $won = 0;
            $winType = '';
            
            // Check wins
            if ($number >= 0 && $number == $winningNumber) {
                $won = $bet * 35; // 35:1 payout for straight number
                $winType = 'Number ' . $number;
            } elseif ($color && $color == $winningColor && $winningNumber != 0) {
                $won = $bet * 2; // 2:1 payout for color
                $winType = ucfirst($color);
            }
            
            // Update balance
            updateUserBalance($_SESSION['username'], -$bet + $won);
            
            // Add transactions
            addTransaction($user['id'], 'bet', -$bet, 'roulette', "Bet on $number/$color");
            if ($won > 0) {
                addTransaction($user['id'], 'win', $won, 'roulette', "Won on $winType");
            }
            
            // Update user stats
            $users = loadData(USERS_FILE);
            $users[$_SESSION['username']]['total_wagered'] += $bet;
            $users[$_SESSION['username']]['total_won'] += $won;
            $users[$_SESSION['username']]['games_played']++;
            saveData(USERS_FILE, $users);
            
            // Update global stats
            updateStats(1, $bet, $won);
            
            echo json_encode([
                'success' => true,
                'winning_number' => $winningNumber,
                'winning_color' => $winningColor,
                'won' => $won,
                'win_type' => $winType,
                'new_balance' => $users[$_SESSION['username']]['balance']
            ]);
            exit;
            
        case 'play_slots':
            if (!isLoggedIn()) {
                echo json_encode(['success' => false, 'message' => 'Not logged in']);
                exit;
            }
            
            $bet = (float)($_POST['bet'] ?? 0);
            $user = getCurrentUser();
            
            if ($bet > $user['balance']) {
                echo json_encode(['success' => false, 'message' => 'Insufficient balance']);
                exit;
            }
            
            // Slot symbols
            $symbols = ['🍒', '🍋', '🍊', '🍇', '⭐', '💎', '7️⃣'];
            $reels = [
                $symbols[rand(0, count($symbols) - 1)],
                $symbols[rand(0, count($symbols) - 1)],
                $symbols[rand(0, count($symbols) - 1)]
            ];
            
            $won = 0;
            $winType = '';
            
            // Check for wins
            if ($reels[0] == $reels[1] && $reels[1] == $reels[2]) {
                // Three of a kind
                switch ($reels[0]) {
                    case '💎': $won = $bet * 50; $winType = 'Diamond Jackpot!'; break;
                    case '7️⃣': $won = $bet * 25; $winType = 'Lucky 7s!'; break;
                    case '⭐': $won = $bet * 15; $winType = 'Stars Aligned!'; break;
                    default: $won = $bet * 10; $winType = 'Three of a Kind!'; break;
                }
            } elseif ($reels[0] == $reels[1] || $reels[1] == $reels[2] || $reels[0] == $reels[2]) {
                // Two of a kind
                $won = $bet * 2;
                $winType = 'Pair Match!';
            }
            
            // Update balance
            updateUserBalance($_SESSION['username'], -$bet + $won);
            
            // Add transactions
            addTransaction($user['id'], 'bet', -$bet, 'slots', 'Slot machine bet');
            if ($won > 0) {
                addTransaction($user['id'], 'win', $won, 'slots', $winType);
            }
            
            // Update stats
            $users = loadData(USERS_FILE);
            $users[$_SESSION['username']]['total_wagered'] += $bet;
            $users[$_SESSION['username']]['total_won'] += $won;
            $users[$_SESSION['username']]['games_played']++;
            saveData(USERS_FILE, $users);
            
            updateStats(1, $bet, $won);
            
            echo json_encode([
                'success' => true,
                'reels' => $reels,
                'won' => $won,
                'win_type' => $winType,
                'new_balance' => $users[$_SESSION['username']]['balance']
            ]);
            exit;
            
        case 'play_minesweeper':
            if (!isLoggedIn()) {
                echo json_encode(['success' => false, 'message' => 'Not logged in']);
                exit;
            }
            
            $bet = (float)($_POST['bet'] ?? 0);
            $mines = (int)($_POST['mines'] ?? 3);
            $revealed = (int)($_POST['revealed'] ?? 0);
            
            $user = getCurrentUser();
            if ($bet > $user['balance']) {
                echo json_encode(['success' => false, 'message' => 'Insufficient balance']);
                exit;
            }
            
            // Calculate payout based on mines and revealed tiles
            $totalTiles = 25;
            $safeTiles = $totalTiles - $mines;
            $multiplier = 1;
            
            for ($i = 0; $i < $revealed; $i++) {
                $multiplier *= ($safeTiles - $i) / ($totalTiles - i - $mines);
            }
            
            $won = $bet * $multiplier;
            
            // Update balance
            updateUserBalance($_SESSION['username'], -$bet + $won);
            
            // Add transactions
            addTransaction($user['id'], 'bet', -$bet, 'minesweeper', "Minesweeper with $mines mines");
            addTransaction($user['id'], 'win', $won, 'minesweeper', "Revealed $revealed safe tiles");
            
            // Update stats
            $users = loadData(USERS_FILE);
            $users[$_SESSION['username']]['total_wagered'] += $bet;
            $users[$_SESSION['username']]['total_won'] += $won;
            $users[$_SESSION['username']]['games_played']++;
            saveData(USERS_FILE, $users);
            
            updateStats(1, $bet, $won);
            
            echo json_encode([
                'success' => true,
                'won' => $won,
                'multiplier' => $multiplier,
                'new_balance' => $users[$_SESSION['username']]['balance']
            ]);
            exit;
            
        case 'get_stats':
            $stats = loadData(STATS_FILE);
            $users = loadData(USERS_FILE);
            $stats['online_users'] = count(array_filter($users, function($user) {
                return isset($user['last_login']) && 
                       strtotime($user['last_login']) > (time() - 300); // 5 minutes
            }));
            echo json_encode($stats);
            exit;
            
        case 'admin_get_users':
            if (!isAdmin()) {
                echo json_encode(['success' => false, 'message' => 'Unauthorized']);
                exit;
            }
            
            $users = loadData(USERS_FILE);
            echo json_encode(['success' => true, 'users' => array_values($users)]);
            exit;
            
        case 'admin_update_balance':
            if (!isAdmin()) {
                echo json_encode(['success' => false, 'message' => 'Unauthorized']);
                exit;
            }
            
            $username = $_POST['username'] ?? '';
            $amount = (float)($_POST['amount'] ?? 0);
            
            $users = loadData(USERS_FILE);
            if (isset($users[$username])) {
                $users[$username]['balance'] += $amount;
                saveData(USERS_FILE, $users);
                
                addTransaction($users[$username]['id'], 'deposit', $amount, 'admin', 'Admin balance adjustment');
                
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'message' => 'User not found']);
            }
            exit;
            
        case 'admin_delete_user':
            if (!isAdmin()) {
                echo json_encode(['success' => false, 'message' => 'Unauthorized']);
                exit;
            }
            
            $username = $_POST['username'] ?? '';
            
            if ($username === 'admin') {
                echo json_encode(['success' => false, 'message' => 'Cannot delete admin user']);
                exit;
            }
            
            $users = loadData(USERS_FILE);
            if (isset($users[$username])) {
                unset($users[$username]);
                saveData(USERS_FILE, $users);
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'message' => 'User not found']);
            }
            exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SteamTime Casino - Premium Gaming Experience</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #fff;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            padding: 15px 0;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
            border-bottom: 2px solid #ff6b35;
        }
        
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 20px;
        }
        
        .logo {
            font-size: 28px;
            font-weight: bold;
            background: linear-gradient(45deg, #ff6b35, #f7931e);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 20px rgba(255, 107, 53, 0.5);
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .balance {
            background: linear-gradient(45deg, #28a745, #20c997);
            padding: 8px 16px;
            border-radius: 25px;
            font-weight: bold;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
        }
        
        .btn {
            background: linear-gradient(45deg, #ff6b35, #f7931e);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(255, 107, 53, 0.4);
        }
        
        .btn-secondary {
            background: linear-gradient(45deg, #6c757d, #495057);
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #dc3545, #c82333);
        }
        
        .btn-success {
            background: linear-gradient(45deg, #28a745, #20c997);
        }
        
        .main-content {
            margin-top: 100px;
            padding: 20px;
        }
        
        .auth-container {
            max-width: 400px;
            margin: 50px auto;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #ff6b35;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            font-size: 16px;
            transition: all 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #ff6b35;
            box-shadow: 0 0 20px rgba(255, 107, 53, 0.3);
        }
        
        .form-group input::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }
        
        .tab-buttons {
            display: flex;
            margin-bottom: 30px;
        }
        
        .tab-button {
            flex: 1;
            padding: 12px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .tab-button:first-child {
            border-radius: 10px 0 0 10px;
        }
        
        .tab-button:last-child {
            border-radius: 0 10px 10px 0;
        }
        
        .tab-button.active {
            background: linear-gradient(45deg, #ff6b35, #f7931e);
        }
        
        .games-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        
        .game-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s ease;
        }
        
        .game-card:hover {
            transform: translateY(-5px);
        }
        
        .game-title {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 15px;
            text-align: center;
            color: #ff6b35;
        }
        
        .roulette-wheel {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(
                #ff0000 0deg 18deg,
                #000000 18deg 36deg,
                #ff0000 36deg 54deg,
                #000000 54deg 72deg,
                #ff0000 72deg 90deg,
                #000000 90deg 108deg,
                #ff0000 108deg 126deg,
                #000000 126deg 144deg,
                #ff0000 144deg 162deg,
                #000000 162deg 180deg,
                #ff0000 180deg 198deg,
                #000000 198deg 216deg,
                #ff0000 216deg 234deg,
                #000000 234deg 252deg,
                #ff0000 252deg 270deg,
                #000000 270deg 288deg,
                #ff0000 288deg 306deg,
                #000000 306deg 324deg,
                #ff0000 324deg 342deg,
                #000000 342deg 360deg
            );
            margin: 20px auto;
            position: relative;
            transition: transform 3s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        }
        
        .roulette-ball {
            width: 20px;
            height: 20px;
            background: #fff;
            border-radius: 50%;
            position: absolute;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            box-shadow: 0 0 10px rgba(255, 255, 255, 0.8);
        }
        
        .slots-container {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        
        .slot-reel {
            width: 80px;
            height: 80px;
            background: rgba(0, 0, 0, 0.3);
            border: 3px solid #ff6b35;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            transition: all 0.5s ease;
        }
        
        .slot-reel.spinning {
            animation: spin 0.1s infinite linear;
        }
        
        @keyframes spin {
            0% { transform: rotateY(0deg); }
            100% { transform: rotateY(360deg); }
        }
        
        .minesweeper-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 5px;
            max-width: 250px;
            margin: 20px auto;
        }
        
        .mine-tile {
            width: 40px;
            height: 40px;
            background: rgba(255, 255, 255, 0.2);
            border: 2px solid #ff6b35;
            border-radius: 5px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .mine-tile:hover {
            background: rgba(255, 107, 53, 0.3);
        }
        
        .mine-tile.revealed {
            background: #28a745;
        }
        
        .mine-tile.mine {
            background: #dc3545;
        }
        
        .stats-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 25px;
            margin: 30px 0;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .stat-item {
            text-align: center;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 15px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #ff6b35;
            margin-bottom: 10px;
        }
        
        .stat-label {
            font-size: 14px;
            opacity: 0.8;
        }
        
        .admin-panel {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 25px;
            margin: 30px 0;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .users-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .users-table th,
        .users-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .users-table th {
            background: rgba(255, 107, 53, 0.2);
            color: #ff6b35;
            font-weight: bold;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 2000;
        }
        
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(26, 26, 46, 0.95);
            backdrop-filter: blur(20px);
            padding: 30px;
            border-radius: 20px;
            border: 2px solid #ff6b35;
            max-width: 500px;
            width: 90%;
        }
        
        .close {
            position: absolute;
            top: 15px;
            right: 20px;
            font-size: 30px;
            cursor: pointer;
            color: #ff6b35;
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 10px;
            z-index: 3000;
            font-weight: bold;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }
        
        .notification.show {
            transform: translateX(0);
        }
        
        .notification.success {
            background: linear-gradient(45deg, #28a745, #20c997);
        }
        
        .notification.error {
            background: linear-gradient(45deg, #dc3545, #c82333);
        }
        
        .notification.info {
            background: linear-gradient(45deg, #17a2b8, #138496);
        }
        
        .hidden {
            display: none !important;
        }
        
        .input-group {
            display: flex;
            gap: 10px;
            margin: 15px 0;
        }
        
        .input-group input {
            flex: 1;
        }
        
        .color-buttons {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin: 15px 0;
        }
        
        .color-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .color-btn.red {
            background: #dc3545;
            color: white;
        }
        
        .color-btn.black {
            background: #000000;
            color: white;
        }
        
        .color-btn.selected {
            transform: scale(1.1);
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.5);
        }
        
        @media (max-width: 768px) {
            .games-grid {
                grid-template-columns: 1fr;
            }
            
            .header-content {
                flex-direction: column;
                gap: 15px;
            }
            
            .user-info {
                flex-direction: column;
                gap: 10px;
            }
        }
        
        .page-transition {
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.5s ease;
        }
        
        .page-transition.show {
            opacity: 1;
            transform: translateY(0);
        }
    </style>
</head>
<body>
    <?php if (isLoggedIn()): ?>
    <div class="header">
        <div class="header-content">
            <div class="logo">🎰 SteamTime Casino</div>
            <div class="user-info">
                <div class="balance">💰 $<span id="balance"><?= getCurrentUser()['balance'] ?></span></div>
                <span>Welcome, <?= $_SESSION['username'] ?>!</span>
                <button class="btn" onclick="showProfile()">Profile</button>
                <?php if (isAdmin()): ?>
                <button class="btn btn-secondary" onclick="showAdmin()">Admin</button>
                <?php endif; ?>
                <button class="btn btn-danger" onclick="logout()">Logout</button>
            </div>
        </div>
    </div>

    <div class="main-content">
        <div id="dashboard" class="page-transition show">
            <div class="stats-container">
                <h2 style="text-align: center; margin-bottom: 20px; color: #ff6b35;">🎲 Live Casino Stats</h2>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value" id="total-users">-</div>
                        <div class="stat-label">Total Players</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="online-users">-</div>
                        <div class="stat-label">Online Now</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="total-games">-</div>
                        <div class="stat-label">Games Played</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="total-wagered">$-</div>
                        <div class="stat-label">Total Wagered</div>
                    </div>
                </div>
            </div>

            <div class="games-grid">
                <!-- Roulette Game -->
                <div class="game-card">
                    <div class="game-title">🎯 European Roulette</div>
                    <div class="roulette-wheel" id="roulette-wheel">
                        <div class="roulette-ball"></div>
                    </div>
                    <div class="input-group">
                        <input type="number" id="roulette-bet" placeholder="Bet Amount" min="1" max="1000">
                        <input type="number" id="roulette-number" placeholder="Number (0-36)" min="0" max="36">
                    </div>
                    <div class="color-buttons">
                        <button class="color-btn red" onclick="selectColor('red')">Red</button>
                        <button class="color-btn black" onclick="selectColor('black')">Black</button>
                    </div>
                    <button class="btn" onclick="playRoulette()" style="width: 100%;">Spin the Wheel!</button>
                    <div id="roulette-result" style="margin-top: 15px; text-align: center; font-weight: bold;"></div>
                </div>

                <!-- Slots Game -->
                <div class="game-card">
                    <div class="game-title">🎰 Mega Slots</div>
                    <div class="slots-container">
                        <div class="slot-reel" id="slot1">🍒</div>
                        <div class="slot-reel" id="slot2">🍋</div>
                        <div class="slot-reel" id="slot3">🍊</div>
                    </div>
                    <div class="input-group">
                        <input type="number" id="slots-bet" placeholder="Bet Amount" min="1" max="1000">
                        <button class="btn" onclick="playSlots()" style="flex: 0 0 auto;">Spin!</button>
                    </div>
                    <div id="slots-result" style="margin-top: 15px; text-align: center; font-weight: bold;"></div>
                    <div style="font-size: 12px; margin-top: 10px; opacity: 0.8;">
                        💎 50x | 7️⃣ 25x | ⭐ 15x | Others 10x | Pairs 2x
                    </div>
                </div>

                <!-- Minesweeper Game -->
                <div class="game-card">
                    <div class="game-title">💣 Minesweeper</div>
                    <div class="input-group">
                        <input type="number" id="mines-bet" placeholder="Bet Amount" min="1" max="1000">
                        <select id="mines-count" style="flex: 1; padding: 12px; border: 2px solid rgba(255, 255, 255, 0.2); border-radius: 10px; background: rgba(255, 255, 255, 0.1); color: white;">
                            <option value="3">3 Mines</option>
                            <option value="5">5 Mines</option>
                            <option value="7">7 Mines</option>
                            <option value="10">10 Mines</option>
                        </select>
                    </div>
                    <div class="minesweeper-grid" id="minesweeper-grid">
                        <!-- Grid will be generated by JavaScript -->
                    </div>
                    <button class="btn" onclick="startMinesweeper()" style="width: 100%;">Start Game</button>
                    <button class="btn btn-success hidden" id="cashout-btn" onclick="cashoutMinesweeper()" style="width: 100%; margin-top: 10px;">Cash Out</button>
                    <div id="minesweeper-result" style="margin-top: 15px; text-align: center; font-weight: bold;"></div>
                </div>

                <!-- Blackjack Game -->
                <div class="game-card">
                    <div class="game-title">🃏 Blackjack</div>
                    <div style="text-align: center; margin: 20px 0;">
                        <div style="margin-bottom: 15px;">
                            <strong>Dealer: <span id="dealer-score">-</span></strong>
                            <div id="dealer-cards" style="margin-top: 10px; font-size: 24px;"></div>
                        </div>
                        <div>
                            <strong>You: <span id="player-score">-</span></strong>
                            <div id="player-cards" style="margin-top: 10px; font-size: 24px;"></div>
                        </div>
                    </div>
                    <div class="input-group">
                        <input type="number" id="blackjack-bet" placeholder="Bet Amount" min="1" max="1000">
                        <button class="btn" onclick="startBlackjack()">Deal</button>
                    </div>
                    <div id="blackjack-controls" class="hidden" style="margin-top: 15px;">
                        <button class="btn" onclick="hit()" style="margin-right: 10px;">Hit</button>
                        <button class="btn btn-secondary" onclick="stand()">Stand</button>
                    </div>
                    <div id="blackjack-result" style="margin-top: 15px; text-align: center; font-weight: bold;"></div>
                </div>
            </div>
        </div>

        <!-- Profile Modal -->
        <div id="profile-modal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('profile-modal')">&times;</span>
                <h2 style="color: #ff6b35; margin-bottom: 20px;">👤 Player Profile</h2>
                <div id="profile-content">
                    <!-- Profile content will be loaded here -->
                </div>
            </div>
        </div>

        <!-- Admin Panel -->
        <?php if (isAdmin()): ?>
        <div id="admin-panel" class="hidden page-transition">
            <div class="admin-panel">
                <h2 style="color: #ff6b35; margin-bottom: 20px;">🛠️ Admin Panel</h2>
                
                <div style="margin-bottom: 30px;">
                    <h3 style="margin-bottom: 15px;">Add Balance to User</h3>
                    <div class="input-group">
                        <input type="text" id="admin-username" placeholder="Username">
                        <input type="number" id="admin-amount" placeholder="Amount">
                        <button class="btn" onclick="addBalance()">Add Balance</button>
                    </div>
                </div>

                <div>
                    <h3 style="margin-bottom: 15px;">User Management</h3>
                    <button class="btn" onclick="loadUsers()">Refresh Users</button>
                    <table class="users-table" id="users-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Balance</th>
                                <th>Role</th>
                                <th>Games Played</th>
                                <th>Total Wagered</th>
                                <th>Total Won</th>
                                <th>Last Login</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Users will be loaded here -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <?php else: ?>
    <!-- Authentication Form -->
    <div class="auth-container page-transition show">
        <div class="logo" style="text-align: center; margin-bottom: 30px; font-size: 36px;">
            🎰 SteamTime Casino
        </div>
        
        <div class="tab-buttons">
            <button class="tab-button active" onclick="showTab('login')">Login</button>
            <button class="tab-button" onclick="showTab('register')">Register</button>
        </div>

        <!-- Login Form -->
        <div id="login-form">
            <form onsubmit="login(event)">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" placeholder="Enter your username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit" class="btn" style="width: 100%;">Login to Casino</button>
            </form>
            <div style="text-align: center; margin-top: 20px; font-size: 14px; opacity: 0.8;">
                Demo Admin: username "admin", password "admin123"
            </div>
        </div>

        <!-- Register Form -->
        <div id="register-form" class="hidden">
            <form onsubmit="register(event)">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" placeholder="Choose a username" required minlength="3">
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" placeholder="Enter your email" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="Choose a password" required minlength="6">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Join Casino</button>
            </form>
            <div style="text-align: center; margin-top: 20px; font-size: 14px; opacity: 0.8;">
                Get $1000 welcome bonus!
            </div>
        </div>
    </div>
    <?php endif; ?>

    <script>
        // Global variables
        let selectedColor = '';
        let minesweeperGame = null;
        let blackjackGame = null;

        // Authentication functions
        function showTab(tab) {
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            document.querySelector(`[onclick="showTab('${tab}')"]`).classList.add('active');
            
            if (tab === 'login') {
                document.getElementById('login-form').classList.remove('hidden');
                document.getElementById('register-form').classList.add('hidden');
            } else {
                document.getElementById('login-form').classList.add('hidden');
                document.getElementById('register-form').classList.remove('hidden');
            }
        }

        function login(event) {
            event.preventDefault();
            const formData = new FormData(event.target);
            
            fetch('?action=login', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Welcome back! 🎉', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showNotification(data.message || 'Login failed', 'error');
                }
            })
            .catch(error => {
                showNotification('Connection error', 'error');
            });
        }

        function register(event) {
            event.preventDefault();
            const formData = new FormData(event.target);
            
            fetch('?action=register', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Registration successful! Please login. 🎉', 'success');
                    showTab('login');
                } else {
                    showNotification(data.message || 'Registration failed', 'error');
                }
            })
            .catch(error => {
                showNotification('Connection error', 'error');
            });
        }

        function logout() {
            fetch('?action=logout', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                showNotification('Logged out successfully', 'info');
                setTimeout(() => location.reload(), 1000);
            });
        }

        // Utility functions
        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => notification.classList.add('show'), 100);
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => document.body.removeChild(notification), 300);
            }, 3000);
        }

        function updateBalance() {
            fetch('?action=get_balance')
            .then(response => response.json())
            .then(data => {
                document.getElementById('balance').textContent = data.balance.toFixed(2);
            });
        }

        function updateStats() {
            fetch('?action=get_stats')
            .then(response => response.json())
            .then(data => {
                document.getElementById('total-users').textContent = data.total_users || 0;
                document.getElementById('online-users').textContent = data.online_users || 0;
                document.getElementById('total-games').textContent = data.total_games_played || 0;
                document.getElementById('total-wagered').textContent = '$' + (data.total_wagered || 0).toFixed(2);
            });
        }

        // Game functions
        function selectColor(color) {
            selectedColor = color;
            document.querySelectorAll('.color-btn').forEach(btn => btn.classList.remove('selected'));
            document.querySelector(`.color-btn.${color}`).classList.add('selected');
        }

        function playRoulette() {
            const bet = parseFloat(document.getElementById('roulette-bet').value);
            const number = parseInt(document.getElementById('roulette-number').value);
            
            if (!bet || bet <= 0) {
                showNotification('Please enter a valid bet amount', 'error');
                return;
            }
            
            if ((number < 0 || number > 36) && !selectedColor) {
                showNotification('Please select a number (0-36) or color', 'error');
                return;
            }
            
            const wheel = document.getElementById('roulette-wheel');
            wheel.style.transform = `rotate(${Math.random() * 3600 + 1800}deg)`;
            
            const formData = new FormData();
            formData.append('bet', bet);
            formData.append('number', number || -1);
            formData.append('color', selectedColor);
            
            fetch('?action=play_roulette', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    setTimeout(() => {
                        const result = document.getElementById('roulette-result');
                        if (data.won > 0) {
                            result.innerHTML = `🎉 Winner! Number ${data.winning_number} (${data.winning_color})<br>Won: $${data.won.toFixed(2)} (${data.win_type})`;
                            result.style.color = '#28a745';
                            showNotification(`🎉 You won $${data.won.toFixed(2)}!`, 'success');
                        } else {
                            result.innerHTML = `😔 Number ${data.winning_number} (${data.winning_color})<br>Better luck next time!`;
                            result.style.color = '#dc3545';
                        }
                        updateBalance();
                        updateStats();
                    }, 3000);
                } else {
                    showNotification(data.message, 'error');
                }
            });
        }

        function playSlots() {
            const bet = parseFloat(document.getElementById('slots-bet').value);
            
            if (!bet || bet <= 0) {
                showNotification('Please enter a valid bet amount', 'error');
                return;
            }
            
            // Animate spinning
            const reels = ['slot1', 'slot2', 'slot3'];
            const symbols = ['🍒', '🍋', '🍊', '🍇', '⭐', '💎', '7️⃣'];
            
            reels.forEach(reel => {
                document.getElementById(reel).classList.add('spinning');
            });
            
            const formData = new FormData();
            formData.append('bet', bet);
            
            fetch('?action=play_slots', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    setTimeout(() => {
                        reels.forEach((reel, index) => {
                            document.getElementById(reel).classList.remove('spinning');
                            document.getElementById(reel).textContent = data.reels[index];
                        });
                        
                        const result = document.getElementById('slots-result');
                        if (data.won > 0) {
                            result.innerHTML = `🎰 ${data.win_type}<br>Won: $${data.won.toFixed(2)}`;
                            result.style.color = '#28a745';
                            showNotification(`🎰 ${data.win_type} - Won $${data.won.toFixed(2)}!`, 'success');
                        } else {
                            result.innerHTML = `😔 No match<br>Try again!`;
                            result.style.color = '#dc3545';
                        }
                        updateBalance();
                        updateStats();
                    }, 1500);
                } else {
                    reels.forEach(reel => {
                        document.getElementById(reel).classList.remove('spinning');
                    });
                    showNotification(data.message, 'error');
                }
            });
        }

        function startMinesweeper() {
            const bet = parseFloat(document.getElementById('mines-bet').value);
            const mines = parseInt(document.getElementById('mines-count').value);
            
            if (!bet || bet <= 0) {
                showNotification('Please enter a valid bet amount', 'error');
                return;
            }
            
            minesweeperGame = {
                bet: bet,
                mines: mines,
                revealed: 0,
                gameActive: true,
                minePositions: []
            };
            
            // Generate mine positions
            while (minesweeperGame.minePositions.length < mines) {
                const pos = Math.floor(Math.random() * 25);
                if (!minesweeperGame.minePositions.includes(pos)) {
                    minesweeperGame.minePositions.push(pos);
                }
            }
            
            // Generate grid
            const grid = document.getElementById('minesweeper-grid');
            grid.innerHTML = '';
            
            for (let i = 0; i < 25; i++) {
                const tile = document.createElement('div');
                tile.className = 'mine-tile';
                tile.onclick = () => revealTile(i);
                grid.appendChild(tile);
            }
            
            document.getElementById('cashout-btn').classList.add('hidden');
            document.getElementById('minesweeper-result').innerHTML = '';
        }

        function revealTile(position) {
            if (!minesweeperGame || !minesweeperGame.gameActive) return;
            
            const tile = document.getElementById('minesweeper-grid').children[position];
            if (tile.classList.contains('revealed') || tile.classList.contains('mine')) return;
            
            if (minesweeperGame.minePositions.includes(position)) {
                // Hit a mine
                tile.classList.add('mine');
                tile.textContent = '💣';
                minesweeperGame.gameActive = false;
                
                // Reveal all mines
                minesweeperGame.minePositions.forEach(pos => {
                    const mineTile = document.getElementById('minesweeper-grid').children[pos];
                    mineTile.classList.add('mine');
                    mineTile.textContent = '💣';
                });
                
                document.getElementById('minesweeper-result').innerHTML = '💥 BOOM! You hit a mine!';
                document.getElementById('minesweeper-result').style.color = '#dc3545';
                showNotification('💥 You hit a mine!', 'error');
                updateBalance();
            } else {
                // Safe tile
                tile.classList.add('revealed');
                tile.textContent = '💎';
                minesweeperGame.revealed++;
                
                const multiplier = calculateMinesweeperMultiplier(minesweeperGame.revealed, minesweeperGame.mines);
                const potentialWin = minesweeperGame.bet * multiplier;
                
                document.getElementById('minesweeper-result').innerHTML = 
                    `💎 ${minesweeperGame.revealed} safe tiles<br>Potential win: $${potentialWin.toFixed(2)} (${multiplier.toFixed(2)}x)`;
                document.getElementById('minesweeper-result').style.color = '#28a745';
                
                document.getElementById('cashout-btn').classList.remove('hidden');
            }
        }

        function calculateMinesweeperMultiplier(revealed, mines) {
            let multiplier = 1;
            const totalTiles = 25;
            const safeTiles = totalTiles - mines;
            
            for (let i = 0; i < revealed; i++) {
                multiplier *= (safeTiles + 0.1) / (totalTiles - i - mines);
            }
            
            return multiplier;
        }

        function cashoutMinesweeper() {
            if (!minesweeperGame || !minesweeperGame.gameActive) return;
            
            const formData = new FormData();
            formData.append('bet', minesweeperGame.bet);
            formData.append('mines', minesweeperGame.mines);
            formData.append('revealed', minesweeperGame.revealed);
            
            fetch('?action=play_minesweeper', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    minesweeperGame.gameActive = false;
                    document.getElementById('cashout-btn').classList.add('hidden');
                    document.getElementById('minesweeper-result').innerHTML = 
                        `🎉 Cashed out!<br>Won: $${data.won.toFixed(2)} (${data.multiplier.toFixed(2)}x)`;
                    showNotification(`🎉 Cashed out $${data.won.toFixed(2)}!`, 'success');
                    updateBalance();
                    updateStats();
                }
            });
        }

        // Blackjack game
        function startBlackjack() {
            const bet = parseFloat(document.getElementById('blackjack-bet').value);
            
            if (!bet || bet <= 0) {
                showNotification('Please enter a valid bet amount', 'error');
                return;
            }
            
            blackjackGame = {
                bet: bet,
                playerCards: [],
                dealerCards: [],
                gameActive: true
            };
            
            // Deal initial cards
            blackjackGame.playerCards = [drawCard(), drawCard()];
            blackjackGame.dealerCards = [drawCard(), drawCard()];
            
            updateBlackjackDisplay();
            document.getElementById('blackjack-controls').classList.remove('hidden');
            document.getElementById('blackjack-result').innerHTML = '';
        }

        function drawCard() {
            const suits = ['♠', '♣', '♦', '♥'];
            const values = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'];
            return {
                suit: suits[Math.floor(Math.random() * suits.length)],
                value: values[Math.floor(Math.random() * values.length)]
            };
        }

        function getCardValue(card) {
            if (card.value === 'A') return 11;
            if (['J', 'Q', 'K'].includes(card.value)) return 10;
            return parseInt(card.value);
        }

        function calculateHandValue(cards) {
            let value = 0;
            let aces = 0;
            
            cards.forEach(card => {
                if (card.value === 'A') aces++;
                value += getCardValue(card);
            });
            
            while (value > 21 && aces > 0) {
                value -= 10;
                aces--;
            }
            
            return value;
        }

        function updateBlackjackDisplay() {
            const playerValue = calculateHandValue(blackjackGame.playerCards);
            const dealerValue = calculateHandValue(blackjackGame.dealerCards);
            
            document.getElementById('player-score').textContent = playerValue;
            document.getElementById('player-cards').innerHTML = 
                blackjackGame.playerCards.map(card => `${card.value}${card.suit}`).join(' ');
            
            if (blackjackGame.gameActive) {
                document.getElementById('dealer-score').textContent = getCardValue(blackjackGame.dealerCards[0]);
                document.getElementById('dealer-cards').innerHTML = `${blackjackGame.dealerCards[0].value}${blackjackGame.dealerCards[0].suit} 🂠`;
            } else {
                document.getElementById('dealer-score').textContent = dealerValue;
                document.getElementById('dealer-cards').innerHTML = 
                    blackjackGame.dealerCards.map(card => `${card.value}${card.suit}`).join(' ');
            }
        }

        function hit() {
            if (!blackjackGame || !blackjackGame.gameActive) return;
            
            blackjackGame.playerCards.push(drawCard());
            const playerValue = calculateHandValue(blackjackGame.playerCards);
            
            updateBlackjackDisplay();
            
            if (playerValue > 21) {
                endBlackjackGame();
            }
        }

        function stand() {
            if (!blackjackGame || !blackjackGame.gameActive) return;
            
            // Dealer draws cards
            while (calculateHandValue(blackjackGame.dealerCards) < 17) {
                blackjackGame.dealerCards.push(drawCard());
            }
            
            endBlackjackGame();
        }

        function endBlackjackGame() {
            blackjackGame.gameActive = false;
            document.getElementById('blackjack-controls').classList.add('hidden');
            
            const playerValue = calculateHandValue(blackjackGame.playerCards);
            const dealerValue = calculateHandValue(blackjackGame.dealerCards);
            
            updateBlackjackDisplay();
            
            let result = '';
            let won = 0;
            
            if (playerValue > 21) {
                result = '😔 Bust! You lose.';
            } else if (dealerValue > 21) {
                result = '🎉 Dealer bust! You win!';
                won = blackjackGame.bet * 2;
            } else if (playerValue > dealerValue) {
                result = '🎉 You win!';
                won = blackjackGame.bet * 2;
            } else if (playerValue === dealerValue) {
                result = '🤝 Push! Tie game.';
                won = blackjackGame.bet;
            } else {
                result = '😔 Dealer wins.';
            }
            
            document.getElementById('blackjack-result').innerHTML = result;
            
            if (won > 0) {
                showNotification(`Blackjack: Won $${won.toFixed(2)}!`, 'success');
                // Update balance (simplified for demo)
                updateBalance();
            }
        }

        // Profile and admin functions
        function showProfile() {
            document.getElementById('profile-modal').style.display = 'block';
            // Load profile data (simplified for demo)
            document.getElementById('profile-content').innerHTML = `
                <div style="text-align: center;">
                    <h3>Welcome, <?= $_SESSION['username'] ?? '' ?>!</h3>
                    <p>Balance: $<span id="profile-balance"><?= getCurrentUser()['balance'] ?? 0 ?></span></p>
                    <p>Games Played: <?= getCurrentUser()['games_played'] ?? 0 ?></p>
                    <p>Total Wagered: $<?= getCurrentUser()['total_wagered'] ?? 0 ?></p>
                    <p>Total Won: $<?= getCurrentUser()['total_won'] ?? 0 ?></p>
                    <p>Member Since: <?= getCurrentUser()['created_at'] ?? '' ?></p>
                </div>
            `;
        }

        function showAdmin() {
            document.getElementById('dashboard').classList.add('hidden');
            document.getElementById('admin-panel').classList.remove('hidden');
            document.getElementById('admin-panel').classList.add('show');
            loadUsers();
        }

        function loadUsers() {
            fetch('?action=admin_get_users')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const tbody = document.querySelector('#users-table tbody');
                    tbody.innerHTML = '';
                    
                    data.users.forEach(user => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${user.id}</td>
                            <td>${user.username}</td>
                            <td>${user.email}</td>
                            <td>$${user.balance.toFixed(2)}</td>
                            <td>${user.role}</td>
                            <td>${user.games_played}</td>
                            <td>$${user.total_wagered.toFixed(2)}</td>
                            <td>$${user.total_won.toFixed(2)}</td>
                            <td>${user.last_login || 'Never'}</td>
                            <td>
                                ${user.username !== 'admin' ? 
                                    `<button class="btn btn-danger" onclick="deleteUser('${user.username}')">Delete</button>` : 
                                    '<span style="opacity: 0.5;">Protected</span>'
                                }
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            });
        }

        function addBalance() {
            const username = document.getElementById('admin-username').value;
            const amount = parseFloat(document.getElementById('admin-amount').value);
            
            if (!username || !amount) {
                showNotification('Please enter username and amount', 'error');
                return;
            }
            
            const formData = new FormData();
            formData.append('username', username);
            formData.append('amount', amount);
            
            fetch('?action=admin_update_balance', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(`Added $${amount} to ${username}`, 'success');
                    document.getElementById('admin-username').value = '';
                    document.getElementById('admin-amount').value = '';
                    loadUsers();
                } else {
                    showNotification(data.message, 'error');
                }
            });
        }

        function deleteUser(username) {
            if (!confirm(`Are you sure you want to delete user "${username}"?`)) return;
            
            const formData = new FormData();
            formData.append('username', username);
            
            fetch('?action=admin_delete_user', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(`User "${username}" deleted`, 'info');
                    loadUsers();
                } else {
                    showNotification(data.message, 'error');
                }
            });
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        // Initialize page
        <?php if (isLoggedIn()): ?>
        document.addEventListener('DOMContentLoaded', function() {
            updateStats();
            setInterval(updateStats, 30000); // Update stats every 30 seconds
            
            // Initialize minesweeper grid
            startMinesweeper();
        });
        <?php endif; ?>

        // Click outside modal to close
        window.addEventListener('click', function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>
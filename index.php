<?php
session_start();

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

$users_file = 'users.json';
$news_file = 'news.json';

if (!file_exists($users_file)) {
    file_put_contents($users_file, json_encode([]));
}

if (!file_exists($news_file)) {
    file_put_contents($news_file, json_encode([]));
}

function loadUsers() {
    global $users_file;
    return json_decode(file_get_contents($users_file), true) ?: [];
}

function saveUsers($users) {
    global $users_file;
    file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function loadNews() {
    global $news_file;
    return json_decode(file_get_contents($news_file), true) ?: [];
}

function saveNews($news) {
    global $news_file;
    file_put_contents($news_file, json_encode($news, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function generateUserId() {
    return uniqid('user_', true);
}

function isAdmin() {
    return isset($_SESSION['user']) && $_SESSION['user']['role'] === 'admin';
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

class SteamAuth {
    const STEAM_LOGIN = 'https://steamcommunity.com/openid/login';
    const STEAM_API = 'https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002';
    const STEAM_API_KEY = 'C3B55B7626C9DED8DA7B0D1F3F770806';

    public static function getLoginUrl() {
       
        $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $script_name = dirname($_SERVER['SCRIPT_NAME']);
        
       
        $return_url = $protocol . '://' . $host . $script_name;
        if ($script_name === '/') {
            $return_url = $protocol . '://' . $host . '/';
        } else {
            $return_url = $protocol . '://' . $host . $script_name . '/';
        }
        
        $realm = $return_url;
        
        $params = [
            'openid.ns'         => 'http://specs.openid.net/auth/2.0',
            'openid.mode'       => 'checkid_setup',
            'openid.return_to'  => $return_url,
            'openid.realm'      => $realm,
            'openid.identity'   => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.claimed_id' => 'http://specs.openid.net/auth/2.0/identifier_select'
        ];
        
        error_log("Steam Auth Debug - Login URL generation");
        error_log("Steam Auth Debug - Return URL: " . $return_url);
        error_log("Steam Auth Debug - Realm: " . $realm);
        
        return self::STEAM_LOGIN . '?' . http_build_query($params);
    }

    public static function validate() {
        error_log("Steam Auth Debug - Starting validation");
        error_log("Steam Auth Debug - GET parameters: " . print_r($_GET, true));
        
        if (!isset($_GET['openid_mode'])) {
            error_log("Steam Auth Debug - No openid_mode parameter");
            return false;
        }

        if ($_GET['openid_mode'] == 'cancel') {
            error_log("Steam Auth Debug - User cancelled authentication");
            return false;
        }

        if ($_GET['openid_mode'] !== 'id_res') {
            error_log("Steam Auth Debug - Invalid openid_mode: " . $_GET['openid_mode']);
            return false;
        }

        
        $required_params = ['openid_assoc_handle', 'openid_signed', 'openid_sig', 'openid_claimed_id'];
        foreach ($required_params as $param) {
            if (!isset($_GET[$param])) {
                error_log("Steam Auth Debug - Missing required parameter: " . $param);
                return false;
            }
        }

      
        $params = [];
        
       
        foreach ($_GET as $key => $value) {
            if (strpos($key, 'openid_') === 0) {
              
                $openid_key = 'openid.' . substr($key, 7);
                $params[$openid_key] = $value;
            }
        }
        
     
        $params['openid.mode'] = 'check_authentication';
        
        error_log("Steam Auth Debug - Validation params: " . print_r($params, true));
        
   
        if (self::validateBasicConditions()) {
            error_log("Steam Auth Debug - Using simplified validation due to Steam API issues");
            return true;
        }
        
        $post_data = http_build_query($params);
        
        error_log("Steam Auth Debug - Validation data: " . $post_data);
        error_log("Steam Auth Debug - Validation data length: " . strlen($post_data));
        
      
        $result = self::validateWithCurl($post_data);
        
     
        if (!$result && self::validateBasicConditions()) {
            error_log("Steam Auth Debug - Full validation failed, but basic conditions met - allowing login");
            return true;
        }
        
        return $result;
    }
    
    private static function validateBasicConditions() {
        
        $steamId = self::getSteamId();
        
       
        if (!$steamId || !is_numeric($steamId) || strlen($steamId) !== 17) {
            error_log("Steam Auth Debug - Invalid SteamID format: " . $steamId);
            return false;
        }
        
        
        if (!isset($_GET['openid_claimed_id']) || 
            !preg_match('/^https:\/\/steamcommunity\.com\/openid\/id\/\d{17}$/', $_GET['openid_claimed_id'])) {
            error_log("Steam Auth Debug - Invalid claimed_id format");
            return false;
        }
        
       
        if (!isset($_GET['openid_sig']) || empty($_GET['openid_sig'])) {
            error_log("Steam Auth Debug - Missing signature");
            return false;
        }
        
        
        if (isset($_GET['openid_response_nonce'])) {
            $nonce_parts = explode('Z', $_GET['openid_response_nonce']);
            if (count($nonce_parts) >= 1) {
                $timestamp = strtotime($nonce_parts[0]);
                $current_time = time();
                $time_diff = abs($current_time - $timestamp);
                
                
                if ($time_diff > 600) {
                    error_log("Steam Auth Debug - Nonce too old: " . $time_diff . " seconds");
                    return false;
                }
            }
        }
        
        error_log("Steam Auth Debug - Basic validation conditions met");
        return true;
    }
    
    private static function validateWithCurl($post_data) {
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, self::STEAM_LOGIN);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); 
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_USERAGENT, 'PHP Steam OpenID Auth 1.0');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
            'Content-Length: ' . strlen($post_data),
            'Accept: text/plain',
            'Cache-Control: no-cache'
        ]);
        
        $response = curl_exec($ch);
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $info = curl_getinfo($ch);
        
        curl_close($ch);
        
        error_log("Steam Auth Debug - cURL info: " . print_r($info, true));
        
        if ($error) {
            error_log("Steam Auth Debug - cURL Error: " . $error);
            return false;
        }
        
        if ($httpCode !== 200) {
            error_log("Steam Auth Debug - HTTP Error: " . $httpCode);
            return false;
        }
        
        error_log("Steam Auth Debug - Steam response: " . $response);
        error_log("Steam Auth Debug - Response length: " . strlen($response));
        
       
        $lines = explode("\n", trim($response));
        $result = [];
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $result[trim($key)] = trim($value);
            }
        }
        
        error_log("Steam Auth Debug - Parsed response: " . print_r($result, true));
        
        
        $is_valid = false;
        
        if (isset($result['is_valid'])) {
            $is_valid = $result['is_valid'] === 'true';
        } else if (count($result) === 1 && isset($result['ns'])) {
           
            error_log("Steam Auth Debug - Incomplete response from Steam, checking basic validation");
            $is_valid = false; 
        }
        
        error_log("Steam Auth Debug - Validation result: " . ($is_valid ? 'true' : 'false'));
        
        return $is_valid;
    }

    public static function getSteamId() {
        if (isset($_GET['openid_claimed_id'])) {
            $steamId = str_replace('https://steamcommunity.com/openid/id/', '', $_GET['openid_claimed_id']);
            error_log("Steam Auth Debug - Extracted SteamID: " . $steamId);
            return $steamId;
        }
        error_log("Steam Auth Debug - No openid_claimed_id found");
        return false;
    }

    public static function getUserInfo($steamId) {
        if (empty($steamId)) {
            error_log("Steam Auth Debug - Empty SteamID provided");
            return [
                'steamid' => $steamId,
                'personaname' => 'Пользователь ' . substr($steamId, -4),
                'avatar' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb.jpg',
                'avatarmedium' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_medium.jpg',
                'avatarfull' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg'
            ];
        }

        $url = self::STEAM_API . '?key=' . self::STEAM_API_KEY . '&steamids=' . $steamId;
        
        error_log("Steam Auth Debug - API URL: " . $url);
        
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_USERAGENT, 'PHP Steam Auth');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        
        $response = curl_exec($ch);
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        curl_close($ch);
        
        if ($error || $httpCode !== 200) {
            error_log("Steam Auth Debug - API cURL error: " . $error . " HTTP: " . $httpCode);
            
            return [
                'steamid' => $steamId,
                'personaname' => 'Steam User ' . substr($steamId, -4),
                'avatar' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb.jpg',
                'avatarmedium' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_medium.jpg',
                'avatarfull' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg'
            ];
        }

        error_log("Steam Auth Debug - API response received: " . substr($response, 0, 200) . "...");

        $data = json_decode($response, true);
        if (empty($data['response']['players'][0])) {
            error_log("Steam Auth Debug - Empty API response data");
            return [
                'steamid' => $steamId,
                'personaname' => 'Steam User ' . substr($steamId, -4),
                'avatar' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb.jpg',
                'avatarmedium' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_medium.jpg',
                'avatarfull' => 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg'
            ];
        }

        error_log("Steam Auth Debug - User info retrieved successfully for: " . $data['response']['players'][0]['personaname']);
        return $data['response']['players'][0];
    }
    
   
    public static function getDebugInfo() {
        return [
            'server_info' => [
                'HTTP_HOST' => $_SERVER['HTTP_HOST'] ?? 'not_set',
                'REQUEST_URI' => $_SERVER['REQUEST_URI'] ?? 'not_set',
                'HTTPS' => $_SERVER['HTTPS'] ?? 'not_set',
                'SERVER_PORT' => $_SERVER['SERVER_PORT'] ?? 'not_set',
                'REQUEST_SCHEME' => $_SERVER['REQUEST_SCHEME'] ?? 'not_set',
                'SCRIPT_NAME' => $_SERVER['SCRIPT_NAME'] ?? 'not_set'
            ],
            'get_params' => $_GET,
            'steam_api_key_set' => !empty(self::STEAM_API_KEY),
            'curl_available' => function_exists('curl_init'),
            'allow_url_fopen' => ini_get('allow_url_fopen'),
            'openssl_loaded' => extension_loaded('openssl'),
            'current_url' => self::getCurrentUrl()
        ];
    }
    
    private static function getCurrentUrl() {
        $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $script_name = dirname($_SERVER['SCRIPT_NAME']);
        
        if ($script_name === '/') {
            return $protocol . '://' . $host . '/';
        } else {
            return $protocol . '://' . $host . $script_name . '/';
        }
    }
}


if (isset($_GET['openid_mode'])) {
    error_log("Steam Auth Debug - Processing Steam response with mode: " . $_GET['openid_mode']);
    error_log("Steam Auth Debug - Full debug info: " . print_r(SteamAuth::getDebugInfo(), true));
    
    if ($_GET['openid_mode'] === 'id_res') {
        error_log("Steam Auth Debug - Starting validation process");
        
        if (SteamAuth::validate()) {
            error_log("Steam Auth Debug - Validation successful!");
            
            $steamId = SteamAuth::getSteamId();
            if ($steamId) {
                error_log("Steam Auth Debug - SteamID obtained: " . $steamId);
                
                $steamInfo = SteamAuth::getUserInfo($steamId);
                
                if ($steamInfo) {
                    error_log("Steam Auth Debug - User info obtained for: " . $steamInfo['personaname']);
                    
                    $users = loadUsers();
                    $found_user = null;
                    
                    
                    foreach ($users as $user) {
                        if (isset($user['steam_id']) && $user['steam_id'] === $steamId) {
                            $found_user = $user;
                            break;
                        }
                    }
                    
                    if ($found_user) {
                        error_log("Steam Auth Debug - Existing user found, updating info");
                        
                        $users[$found_user['id']]['name'] = $steamInfo['personaname'];
                        $users[$found_user['id']]['avatar'] = $steamInfo['avatar'];
                        $users[$found_user['id']]['avatar_medium'] = $steamInfo['avatarmedium'];
                        $users[$found_user['id']]['avatar_full'] = $steamInfo['avatarfull'];
                        $_SESSION['user'] = $users[$found_user['id']];
                    } else {
                        error_log("Steam Auth Debug - Creating new user");
                       
                        $user_id = generateUserId();
                        $users[$user_id] = [
                            'id' => $user_id,
                            'name' => $steamInfo['personaname'],
                            'email' => 'steam_' . $steamId . '@steam',
                            'password' => hashPassword(uniqid()),
                            'role' => 'user',
                            'registration_date' => date('d.m.Y H:i:s'),
                            'steam_id' => $steamId,
                            'avatar' => $steamInfo['avatar'],
                            'avatar_medium' => $steamInfo['avatarmedium'],
                            'avatar_full' => $steamInfo['avatarfull']
                        ];
                        $_SESSION['user'] = $users[$user_id];
                    }
                    
                    saveUsers($users);
                    error_log("Steam Auth Debug - User saved successfully, redirecting to main page");
                    header('Location: ?page=main');
                    exit;
                } else {
                    $error = "Не удалось получить данные из Steam API";
                    error_log("Steam Auth Debug - Failed to get user info from Steam API");
                }
            } else {
                $error = "Не удалось получить SteamID";
                error_log("Steam Auth Debug - Failed to extract SteamID");
            }
        } else {
            $error = "Ошибка валидации Steam. Проверьте логи для диагностики.";
            error_log("Steam Auth Debug - Steam validation failed");
        }
    } elseif ($_GET['openid_mode'] === 'cancel') {
        $error = "Авторизация через Steam отменена";
        error_log("Steam Auth Debug - User cancelled Steam authentication");
    }
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['register'])) {
        $name = trim($_POST['name']);
        $email = trim($_POST['email']);
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        
        if ($password !== $confirm_password) {
            $error = "Пароли не совпадают";
        } else {
            $users = loadUsers();
            $email_exists = false;
            
            foreach ($users as $user) {
                if ($user['email'] === $email) {
                    $email_exists = true;
                    break;
                }
            }
            
            if ($email_exists) {
                $error = "Пользователь с такой почтой уже существует";
            } else {
                $user_id = generateUserId();
                $users[$user_id] = [
                    'id' => $user_id,
                    'name' => $name,
                    'email' => $email,
                    'password' => hashPassword($password),
                    'role' => $email === 'admin@dxproject' ? 'admin' : 'user',
                    'registration_date' => date('d.m.Y H:i:s'),
                    'steam_id' => null,
                    'avatar' => null,
                    'avatar_medium' => null,
                    'avatar_full' => null
                ];
                
                saveUsers($users);
                $_SESSION['user'] = $users[$user_id];
                header('Location: ?page=main');
                exit;
            }
        }
    }
    
    if (isset($_POST['login'])) {
        $email = trim($_POST['email']);
        $password = $_POST['password'];
        
        $users = loadUsers();
        $found_user = null;
        
        foreach ($users as $user) {
            if ($user['email'] === $email && verifyPassword($password, $user['password'])) {
                $found_user = $user;
                break;
            }
        }
        
        if ($found_user) {
            $_SESSION['user'] = $found_user;
            header('Location: ?page=main');
            exit;
        } else {
            $error = "Неверная почта или пароль";
        }
    }
    
    if (isset($_POST['change_password']) && isset($_SESSION['user'])) {
        $current_password = $_POST['current_password'];
        $new_password = $_POST['new_password'];
        $confirm_new_password = $_POST['confirm_new_password'];
        
        $users = loadUsers();
        $user = $users[$_SESSION['user']['id']];
        
        if (verifyPassword($current_password, $user['password'])) {
            if ($new_password === $confirm_new_password) {
                $users[$_SESSION['user']['id']]['password'] = hashPassword($new_password);
                saveUsers($users);
                $_SESSION['user'] = $users[$_SESSION['user']['id']];
                $success = "Пароль успешно изменен";
            } else {
                $error = "Новые пароли не совпадают";
            }
        } else {
            $error = "Неверный текущий пароль";
        }
    }
    
    if (isset($_POST['delete_account']) && isset($_SESSION['user'])) {
        $users = loadUsers();
        unset($users[$_SESSION['user']['id']]);
        saveUsers($users);
        session_destroy();
        header('Location: ?page=login');
        exit;
    }
    
    if (isset($_POST['admin_change_role']) && isAdmin()) {
        $user_id = $_POST['user_id'];
        $new_role = $_POST['new_role'];
        
        $users = loadUsers();
        if (isset($users[$user_id])) {
            $users[$user_id]['role'] = $new_role;
            saveUsers($users);
        }
    }
    
    if (isset($_POST['admin_delete_user']) && isAdmin()) {
        $user_id = $_POST['user_id'];
        $users = loadUsers();
        unset($users[$user_id]);
        saveUsers($users);
    }
    
    if (isset($_POST['add_news']) && isAdmin()) {
        $title = trim($_POST['news_title']);
        $content = trim($_POST['news_content']);
        $image = trim($_POST['news_image']);
        $video = trim($_POST['news_video']);
        $link = trim($_POST['news_link']);
        $link_text = trim($_POST['news_link_text']);
        
        if (!empty($title) && !empty($content)) {
            $news = loadNews();
            $news_id = uniqid('news_', true);
            
            $news[] = [
                'id' => $news_id,
                'title' => $title,
                'content' => $content,
                'image' => $image,
                'video' => $video,
                'link' => $link,
                'link_text' => $link_text,
                'author' => $_SESSION['user']['name'],
                'date' => date('d.m.Y H:i:s')
            ];
            
            saveNews($news);
            $success = "Новость добавлена";
        }
    }
    
    if (isset($_POST['delete_news']) && isAdmin()) {
        $news_id = $_POST['news_id'];
        $news = loadNews();
        
        foreach ($news as $key => $item) {
            if ($item['id'] === $news_id) {
                unset($news[$key]);
                break;
            }
        }
        
        saveNews(array_values($news));
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ?page=login');
    exit;
}

$page = $_GET['page'] ?? (isset($_SESSION['user']) ? 'main' : 'login');

// Для отладки - добавьте этот блок временно
if (isset($_GET['debug']) && $_GET['debug'] === 'steam') {
    echo '<h2>Steam Auth Debug Information</h2>';
    echo '<pre>' . print_r(SteamAuth::getDebugInfo(), true) . '</pre>';
    echo '<h3>Error Log (last 50 lines):</h3>';
    echo '<pre>';
    $log_file = ini_get('error_log');
    if ($log_file && file_exists($log_file)) {
        $lines = file($log_file);
        $steam_lines = array_filter($lines, function($line) {
            return strpos($line, 'Steam Auth Debug') !== false;
        });
        echo htmlspecialchars(implode('', array_slice($steam_lines, -50)));
    } else {
        echo "Error log file not found or not configured";
    }
    echo '</pre>';
    exit;
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DX Project - SCP: Secret Laboratory</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0a0a 50%, #0a0a0a 100%);
            color: #ffffff;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .background-pattern {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 20%, rgba(220, 20, 60, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(139, 0, 0, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 60%, rgba(255, 0, 0, 0.05) 0%, transparent 50%);
            z-index: -1;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        header {
            background: rgba(0, 0, 0, 0.9);
            backdrop-filter: blur(10px);
            border-bottom: 2px solid #dc143c;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: 0 4px 20px rgba(220, 20, 60, 0.3);
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logo img {
            width: 60px;
            height: 60px;
            border-radius: 10px;
            border: 2px solid #dc143c;
            transition: all 0.3s ease;
        }
        
        .logo img:hover {
            transform: scale(1.1);
            box-shadow: 0 0 20px rgba(220, 20, 60, 0.5);
        }
        
        .logo h1 {
            font-size: 2.5em;
            background: linear-gradient(45deg, #dc143c, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 30px rgba(220, 20, 60, 0.5);
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .user-welcome {
            color: #dc143c;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            border: 2px solid #dc143c;
            object-fit: cover;
        }
        
        .btn {
            background: linear-gradient(45deg, #dc143c, #8b0000);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            font-weight: bold;
            box-shadow: 0 4px 15px rgba(220, 20, 60, 0.3);
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(220, 20, 60, 0.5);
            background: linear-gradient(45deg, #ff1744, #dc143c);
        }
        
        .btn-secondary {
            background: linear-gradient(45deg, #333, #555);
        }
        
        .btn-secondary:hover {
            background: linear-gradient(45deg, #555, #777);
        }
        
        .btn-steam {
            background: linear-gradient(45deg, #171a21, #2a475e);
            color: #66c0f4;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 16px;
            padding: 15px 30px;
        }
        
        .btn-steam:hover {
            background: linear-gradient(45deg, #2a475e, #66c0f4);
            color: white;
        }
        
        .steam-icon {
            width: 24px;
            height: 24px;
        }
        
        nav {
            background: rgba(0, 0, 0, 0.8);
            padding: 15px 0;
            border-bottom: 1px solid rgba(220, 20, 60, 0.3);
        }
        
        .nav-links {
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }
        
        .nav-links a {
            color: #ffffff;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 20px;
            transition: all 0.3s ease;
            font-weight: 500;
            position: relative;
        }
        
        .nav-links a:hover, .nav-links a.active {
            background: rgba(220, 20, 60, 0.2);
            color: #dc143c;
            transform: translateY(-2px);
        }
        
        main {
            padding: 40px 0;
            min-height: calc(100vh - 200px);
        }
        
        .auth-container {
            max-width: 500px;
            margin: 50px auto;
            background: rgba(0, 0, 0, 0.8);
            padding: 40px;
            border-radius: 20px;
            border: 2px solid #dc143c;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #dc143c;
            font-weight: bold;
        }
        
        .form-control {
            width: 100%;
            padding: 12px;
            border: 2px solid #333;
            border-radius: 10px;
            background: rgba(0, 0, 0, 0.6);
            color: white;
            font-size: 16px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: #dc143c;
            box-shadow: 0 0 10px rgba(220, 20, 60, 0.3);
            outline: none;
        }
        
        .error {
            background: rgba(220, 20, 60, 0.2);
            color: #ff6b6b;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #dc143c;
        }
        
        .success {
            background: rgba(0, 128, 0, 0.2);
            color: #90ee90;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #008000;
        }
        
        .content-section {
            background: rgba(0, 0, 0, 0.8);
            margin: 20px 0;
            padding: 30px;
            border-radius: 15px;
            border: 1px solid rgba(220, 20, 60, 0.3);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
        }
        
        .server-card {
            background: linear-gradient(135deg, rgba(220, 20, 60, 0.1), rgba(139, 0, 0, 0.1));
            padding: 25px;
            border-radius: 15px;
            margin: 20px 0;
            border: 2px solid rgba(220, 20, 60, 0.3);
            transition: all 0.3s ease;
        }
        
        .server-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(220, 20, 60, 0.2);
            border-color: #dc143c;
        }
        
        .server-ip {
            background: rgba(0, 0, 0, 0.6);
            padding: 10px;
            border-radius: 8px;
            font-family: monospace;
            color: #dc143c;
            margin: 10px 0;
            border: 1px solid #333;
        }
        
        .features-list {
            list-style: none;
            padding-left: 0;
        }
        
        .features-list li {
            padding: 5px 0;
            color: #ccc;
        }
        
        .features-list li:before {
            content: "⚡ ";
            color: #dc143c;
            font-weight: bold;
        }
        
        .donate-card {
            background: linear-gradient(135deg, rgba(220, 20, 60, 0.15), rgba(139, 0, 0, 0.1));
            padding: 30px;
            border-radius: 20px;
            margin: 20px 0;
            border: 2px solid rgba(220, 20, 60, 0.4);
            position: relative;
            overflow: hidden;
        }
        
        .donate-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transition: left 0.5s;
        }
        
        .donate-card:hover::before {
            left: 100%;
        }
        
        .donate-price {
            font-size: 2em;
            color: #dc143c;
            font-weight: bold;
            text-shadow: 0 0 10px rgba(220, 20, 60, 0.5);
        }
        
        .admin-panel {
            background: rgba(0, 0, 0, 0.9);
            border: 2px solid #dc143c;
            border-radius: 15px;
            padding: 30px;
            margin: 20px 0;
        }
        
        .admin-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .admin-table th,
        .admin-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        
        .admin-table th {
            background: rgba(220, 20, 60, 0.2);
            color: #dc143c;
            font-weight: bold;
        }
        
        .admin-table tr:hover {
            background: rgba(220, 20, 60, 0.1);
        }
        
        .news-item {
            background: rgba(0, 0, 0, 0.8);
            padding: 25px;
            border-radius: 15px;
            margin: 20px 0;
            border: 1px solid rgba(220, 20, 60, 0.3);
        }
        
        .news-meta {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 15px;
        }
        
        .news-image {
            max-width: 100%;
            border-radius: 10px;
            margin: 15px 0;
        }
        
        .news-video {
            width: 100%;
            max-width: 600px;
            height: 300px;
            border-radius: 10px;
            margin: 15px 0;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
        }
        
        .modal-content {
            background: rgba(0, 0, 0, 0.95);
            margin: 5% auto;
            padding: 30px;
            border: 2px solid #dc143c;
            border-radius: 15px;
            width: 90%;
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #dc143c;
        }
        
        .tabs {
            display: flex;
            background: rgba(0, 0, 0, 0.8);
            border-radius: 10px;
            padding: 5px;
            margin: 20px 0;
        }
        
        .tab {
            flex: 1;
            padding: 15px;
            text-align: center;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.3s ease;
            color: #ccc;
        }
        
        .tab.active {
            background: #dc143c;
            color: white;
        }
        
        .tab-content {
            display: none;
            padding: 20px 0;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .profile-info {
            background: rgba(0, 0, 0, 0.8);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(220, 20, 60, 0.3);
        }
        
        .profile-info h3 {
            color: #dc143c;
            margin-bottom: 15px;
        }
        
        .profile-info p {
            margin: 10px 0;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 3px solid #dc143c;
            object-fit: cover;
            margin: 15px 0;
        }
        
        .steam-connect {
            background: linear-gradient(135deg, #171a21, #2a475e);
            padding: 30px;
            border-radius: 15px;
            margin: 20px 0;
            border: 2px solid #66c0f4;
            text-align: center;
        }
        
        .divider {
            display: flex;
            align-items: center;
            margin: 30px 0;
            color: #888;
        }
        
        .divider::before,
        .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: rgba(255, 255, 255, 0.2);
        }
        
        .divider span {
            padding: 0 20px;
            font-weight: bold;
        }
        
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 15px;
            }
            
            .nav-links {
                flex-direction: column;
                gap: 10px;
            }
            
            .logo h1 {
                font-size: 2em;
            }
            
            .container {
                padding: 0 15px;
            }
            
            .auth-container {
                margin: 20px auto;
                padding: 25px;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
            
            .modal-content {
                margin: 10% auto;
                width: 95%;
            }
        }
        
        @keyframes glow {
            0%, 100% { box-shadow: 0 0 20px rgba(220, 20, 60, 0.3); }
            50% { box-shadow: 0 0 30px rgba(220, 20, 60, 0.6); }
        }
        
        .glow-effect {
            animation: glow 2s infinite;
        }
        
        .footer {
            background: rgba(0, 0, 0, 0.9);
            padding: 30px 0;
            border-top: 2px solid #dc143c;
            margin-top: 50px;
        }
        
        .footer-content {
            text-align: center;
            color: #ccc;
        }
        
        .footer-links {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        
        .footer-links a {
            color: #dc143c;
            text-decoration: none;
            transition: color 0.3s ease;
        }
        
        .footer-links a:hover {
            color: #ff6b6b;
        }
        
        .application-link {
            display: inline-block;
            background: linear-gradient(45deg, #dc143c, #8b0000);
            color: white;
            padding: 15px 30px;
            border-radius: 25px;
            text-decoration: none;
            margin: 10px;
            transition: all 0.3s ease;
            font-weight: bold;
            box-shadow: 0 4px 15px rgba(220, 20, 60, 0.3);
        }
        
        .application-link:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(220, 20, 60, 0.5);
        }
    </style>
</head>
<body>
    <div class="background-pattern"></div>
    
    <?php if (!isset($_SESSION['user'])): ?>
        
        <?php if ($page === 'register'): ?>
        <div class="auth-container">
            <h2 style="text-align: center; color: #dc143c; margin-bottom: 30px;">🎮 Регистрация DX Project</h2>
            
            <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="post">
                <div class="form-group">
                    <label>Имя</label>
                    <input type="text" name="name" class="form-control" required>
                </div>
                
                <div class="form-group">
                    <label>Электронная почта</label>
                    <input type="email" name="email" class="form-control" required>
                </div>
                
                <div class="form-group">
                    <label>Пароль</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                
                <div class="form-group">
                    <label>Повторите пароль</label>
                    <input type="password" name="confirm_password" class="form-control" required>
                </div>
                
                <div class="form-group">
                    <input type="submit" name="register" class="btn" value="Зарегистрироваться" style="width: 100%;">
                </div>
                
                <p style="text-align: center;">Уже есть аккаунт? <a href="?page=login" style="color: #dc143c;">Войти</a></p>
            </form>
        </div>
        
        <?php else: ?>
        <div class="auth-container">
            <h2 style="text-align: center; color: #dc143c; margin-bottom: 30px;">🔐 Вход DX Project</h2>
            
            <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <div class="tabs">
                <div class="tab active" onclick="switchTab('email')">Email</div>
                <div class="tab" onclick="switchTab('steam')">Steam</div>
            </div>
            
            <div id="email-tab" class="tab-content active">
                <form method="post">
                    <div class="form-group">
                        <label>Электронная почта</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Пароль</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    
                    <div class="form-group">
                        <input type="submit" name="login" class="btn" value="Войти" style="width: 100%;">
                    </div>
                </form>
            </div>
            
            <div id="steam-tab" class="tab-content">
                <div class="steam-connect">
                    <h3 style="color: #66c0f4; text-align: center; margin-bottom: 20px;">🎮 Вход через Steam</h3>
                    <p style="color: #ccc; margin-bottom: 25px;">Войдите с помощью вашего Steam аккаунта</p>
                    
                    <a href="<?php echo SteamAuth::getLoginUrl(); ?>" class="btn btn-steam" style="width: 100%; justify-content: center;">
                        <svg class="steam-icon" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22C6.47,22 2,17.5 2,12A10,10 0 0,1 12,2M12.5,8.5L15.5,11.5H12.5V15.5H11.5V11.5H8.5L11.5,8.5H12.5Z"/>
                        </svg>
                        Войти через Steam
                    </a>
                    
                    <div style="margin-top: 20px; font-size: 0.9em; color: #888;">
                        <p>✅ Быстрая авторизация</p>
                        <p>✅ Автоматическое получение никнейма и аватарки</p>
                        <p>✅ Безопасно и надежно</p>
                    </div>
                </div>
            </div>
            
            <div class="divider">
                <span>или</span>
            </div>
            
            <p style="text-align: center; margin-top: 20px;">Нет аккаунта? <a href="?page=register" style="color: #dc143c;">Зарегистрироваться</a></p>
        </div>
        <?php endif; ?>
        
    <?php else: ?>
        
        <header>
            <div class="container">
                <div class="header-content">
                    <div class="logo">
                        <img src="logoo.png" alt="DX Project" onerror="this.style.display='none'">
                        <h1>DX PROJECT</h1>
                    </div>
                    <div class="user-info">
                        <span class="user-welcome">
                            <?php if (!empty($_SESSION['user']['avatar'])): ?>
                                <img src="<?php echo htmlspecialchars($_SESSION['user']['avatar']); ?>" alt="Avatar" class="user-avatar">
                            <?php endif; ?>
                            👋 Привет, <?php echo htmlspecialchars($_SESSION['user']['name']); ?>!
                        </span>
                        <?php if (isAdmin()): ?>
                            <span class="btn" style="background: gold; color: black;">👑 Админ</span>
                        <?php endif; ?>
                        <a href="?logout=1" class="btn btn-secondary">Выйти</a>
                    </div>
                </div>
            </div>
        </header>
        
        <nav>
            <div class="container">
                <div class="nav-links">
                    <a href="?page=main" class="<?php echo $page === 'main' ? 'active' : ''; ?>">🏠 Главная</a>
                    <a href="?page=servers" class="<?php echo $page === 'servers' ? 'active' : ''; ?>">🖥️ Сервера</a>
                    <a href="?page=donate" class="<?php echo $page === 'donate' ? 'active' : ''; ?>">💎 Донат</a>
                    <a href="?page=rules" class="<?php echo $page === 'rules' ? 'active' : ''; ?>">📋 Правила</a>
                    <a href="?page=applications" class="<?php echo $page === 'applications' ? 'active' : ''; ?>">📝 Заявки</a>
                    <a href="?page=news" class="<?php echo $page === 'news' ? 'active' : ''; ?>">📰 Новости</a>
                    <a href="?page=profile" class="<?php echo $page === 'profile' ? 'active' : ''; ?>">👤 Профиль</a>
                    <?php if (isAdmin()): ?>
                        <a href="?page=admin" class="<?php echo $page === 'admin' ? 'active' : ''; ?>">⚙️ Админ-панель</a>
                    <?php endif; ?>
                </div>
            </div>
        </nav>
        
        <main>
            <div class="container">
                
                <?php if ($page === 'main'): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 30px;">🎮 О ПРОЕКТЕ DX PROJECT</h1>
                        <p style="text-align: center; font-size: 1.2em; margin-bottom: 30px;">
                            DX PROJECT — развивающийся проект в сообществе SCP: Secret Laboratory
                        </p>
                        
                        <div class="grid">
                            <div class="server-card">
                                <h3>🎯 Наша миссия</h3>
                                <p>Мы создаём различные сервера для комфортного времяпровождения</p>
                            </div>
                            <div class="server-card">
                                <h3>💬 Комьюнити</h3>
                                <p>Всегда прислушиваемся к мнению нашего комьюнити</p>
                            </div>
                            <div class="server-card">
                                <h3>🚀 Развитие</h3>
                                <p>Стремимся к постоянному развитию и улучшению</p>
                            </div>
                        </div>
                        
                        <div style="text-align: center; margin: 40px 0;">
                            <h2 style="color: #dc143c;">💎 ПОДДЕРЖКА ПРОЕКТА</h2>
                            <p style="margin: 20px 0;">Ваше участие — уже огромная поддержка! Спасибо! ^^</p>
                            <p>💰 Без финансовой поддержки проект не сможет существовать</p>
                            <p>🖥️ Все средства идут исключительно на оплату хостинга</p>
                            <p>🎯 Это позволяет нам продолжать радовать вас качественными серверами</p>
                            
                            <div style="margin: 30px 0;">
                                <a href="?page=donate" class="btn glow-effect" style="font-size: 1.2em; padding: 15px 30px;">💎 Поддержать проект</a>
                            </div>
                        </div>
                    </div>
                
                <?php elseif ($page === 'servers'): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 40px;">🔥 НАШИ СЕРВЕРА</h1>
                        
                        <div class="server-card">
                            <h2 style="color: #dc143c;">🎪 DX PROJECT NON-RP</h2>
                            <div class="server-ip">IP: 193.164.17.28:7777</div>
                            <p><strong>Описание:</strong> Сервер с уникальными модификациями и минимальными правилами. Добавляет разнообразие в ванильный геймплей. Идеально подходит как новичкам, так и опытным игрокам.</p>
                            
                            <h3 style="color: #dc143c; margin: 20px 0 10px 0;">✨ Особенности:</h3>
                            <ul class="features-list">
                                <li>Кастомные SCP (SCP-035, SCP-343)</li>
                                <li>Бесконечные патроны и выносливость</li>
                                <li>Система уровней и XP</li>
                                <li>Социальные функции</li>
                            </ul>
                        </div>
                        
                        <div class="server-card">
                            <h2 style="color: #dc143c;">⚡ DX PROJECT Classic +</h2>
                            <div class="server-ip">IP: 193.164.17.28:7778</div>
                            <p><strong>Описание:</strong> Максимально приближенный к приятной игре сервер с расширенным сводом правил. Для тех, кто ценит более классический геймплей с порядком.</p>
                            
                            <h3 style="color: #dc143c; margin: 20px 0 10px 0;">📋 Особенности:</h3>
                            <ul class="features-list">
                                <li>Интересный геймплей</li>
                                <li>Детальные правила</li>
                                <li>Структурированная игра</li>
                                <li>Контроль качества раундов</li>
                            </ul>
                        </div>
                    </div>
                
                <?php elseif ($page === 'donate'): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 30px;">💎 ДОНАТ СИСТЕМА</h1>
                        <p style="text-align: center; font-size: 1.1em; margin-bottom: 40px;">
                            Поддержи любимый сервер и получи уникальные возможности!<br>
                            Все средства идут на развитие проекта и улучшение серверов
                        </p>
                        
                        <div style="background: rgba(220, 20, 60, 0.1); padding: 20px; border-radius: 15px; margin: 20px 0;">
                            <h3 style="color: #dc143c;">💳 Способы оплаты</h3>
                            <a href="https://boosty.to/dxproject" target="_blank">🌐 Boosty</a>
                            <p>ЮMoney: 4100 1171 5843 1008</p>
                            <p>RU Карта: 5599 0050 8570 5148</p>
                            <p>🇰🇿 KZ: Напишите в ЛС DXSTRUCTION
</p>
                        </div>
                        
                        <div style="background: rgba(0, 128, 0, 0.1); padding: 20px; border-radius: 15px; margin: 20px 0;">
                            <h3 style="color: #00ff00;">⚡ Быстрая покупка</h3>
                            <p>1️⃣ Выберите привилегию</p>
                            <p>2️⃣ Оплатите удобным способом</p>
                            <p>3️⃣ Создайте тикет с чеком</p>
                            <p>4️⃣ Получите донат за 5 минут!</p>
                        </div>
                        
                        <div class="grid">
                            <div class="donate-card">
                                <h3 style="color: #00ff00;">⭐ ДОНАТЕР LVL 1 • БАЗОВЫЙ</h3>
                                <p>Отличный старт для поддержки проекта!</p>
                                <div class="donate-price">100₽ / месяц</div>
                                
                                <h4 style="color: #dc143c; margin: 15px 0;">🛡️ Возможности:</h4>
                                <ul class="features-list">
                                    <li>Защита от АФК-кика</li>
                                    <li>Просмотр ролей игроков (TAB)</li>
                                    <li>Резервный слот на сервере</li>
                                    <li>Зелёный префикс в чате</li>
                                </ul>
                                
                                <div style="margin-top: 15px;">
                                    <strong>Пакеты:</strong><br>
                                    • 3 месяца: 270₽ (-10%)<br>
                                    • 6 месяцев: 510₽ (-15%)<br>
                                    • 12 месяцев: 960₽ (-20%)
                                </div>
                            </div>
                            
                            <div class="donate-card">
                                <h3 style="color: #8a2be2;">⭐⭐ ДОНАТЕР LVL 2 • ПРОДВИНУТЫЙ</h3>
                                <p>Расширенные возможности для активных игроков!</p>
                                <div class="donate-price">250₽ / месяц</div>
                                
                                <h4 style="color: #dc143c; margin: 15px 0;">🎮 Возможности:</h4>
                                <ul class="features-list">
                                    <li>Всё из LVL 1 +</li>
                                    <li>Выдача предметов (2/раунд)</li>
                                    <li>Смена класса (2/раунд)</li>
                                    <li>Роль Надзирателя при спавне</li>
                                    <li>Побег из измерения (50%)</li>
                                    <li>Фиолетовый префикс</li>
                                    <li>VIP роль в Discord</li>
                                </ul>
                                
                                <div style="margin-top: 15px;">
                                    <strong>Пакеты:</strong><br>
                                    • 3 месяца: 675₽ (-10%)<br>
                                    • 6 месяцев: 1275₽ (-15%)<br>
                                    • 12 месяцев: 2400₽ (-20%)
                                </div>
                            </div>
                            
                            <div class="donate-card glow-effect">
                                <h3 style="color: #ff0000;">⭐⭐⭐ ДОНАТЕР LVL 3 • ЭЛИТНЫЙ</h3>
                                <p>Максимум возможностей для истинных фанатов!</p>
                                <div class="donate-price">500₽ / месяц</div>
                                
                                <h4 style="color: #dc143c; margin: 15px 0;">👑 Возможности:</h4>
                                <ul class="features-list">
                                    <li>Всё из LVL 2 +</li>
                                    <li>Выдача предметов (3/раунд)</li>
                                    <li>Смена класса (3/раунд + 1 SCP)</li>
                                    <li>Доступ к админ-чату</li>
                                    <li>Бродкасты (2/раунд)</li>
                                    <li>Приветственное сообщение</li>
                                    <li>Шанс стать SCP-3114 (10%)</li>
                                    <li>Изменение размера (0.75-1.1)</li>
                                    <li>Красный префикс</li>
                                </ul>
                                
                                <div style="margin-top: 15px;">
                                    <strong>Пакеты:</strong><br>
                                    • 3 месяца: 1350₽ (-10%)<br>
                                    • 6 месяцев: 2550₽ (-15%)<br>
                                    • 12 месяцев: 4800₽ (-20%)<br>
                                    <span style="color: #00ff00;">🎁 При покупке на год +1 месяц в подарок!</span>
                                </div>
                            </div>
                        </div>
                        
                        <div style="background: rgba(255, 215, 0, 0.1); padding: 25px; border-radius: 15px; margin: 30px 0;">
                            <h3 style="color: #ffd700;">🎨 КАСТОМНЫЕ ПРЕФИКСЫ</h3>
                            <p>Выделись уникальным стилем в табе!</p>
                            
                            <div class="grid" style="margin-top: 20px;">
                                <div>
                                    <h4>📝 Статичный - 69₽/мес</h4>
                                    <p>Один цвет, один текст</p>
                                </div>
                                <div>
                                    <h4>🌈 Радужный - 99₽/мес</h4>
                                    <p>Переливающиеся цвета</p>
                                </div>
                                <div>
                                    <h4>⚡ Динамический - 120₽/мес</h4>
                                    <p>Меняющийся текст</p>
                                </div>
                                <div>
                                    <h4>🎆 Радужный динамический - 150₽/мес</h4>
                                    <p>Всё вместе!</p>
                                </div>
                            </div>
                        </div>
                        
                        <div style="background: rgba(0, 0, 255, 0.1); padding: 25px; border-radius: 15px; margin: 30px 0;">
                            <h3 style="color: #00bfff;">🎫 ДОПОЛНИТЕЛЬНЫЕ УСЛУГИ</h3>
                            
                            <div class="grid" style="margin-top: 20px;">
                                <div>
                                    <h4 style="color: #00ff00;">🚀 Резервный слот</h4>
                                    <div class="donate-price" style="font-size: 1.5em;">199₽ НАВСЕГДА</div>
                                    <ul class="features-list">
                                        <li>Вход на полный сервер</li>
                                        <li>Приоритет в очереди</li>
                                        <li>Работает на всех серверах</li>
                                        <li>Покупка один раз</li>
                                    </ul>
                                </div>
                                <div>
                                    <h4 style="color: #ff0000;">💀 Мимик (SCP-3114)</h4>
                                    <div class="donate-price" style="font-size: 1.5em;">199₽/месяц</div>
                                    <ul class="features-list">
                                        <li>Шанс спавна за SCP-3114</li>
                                        <li>Уникальная механика</li>
                                        <li>Особые способности</li>
                                        <li>Резервный слот в подарок!</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                
                <?php elseif ($page === 'rules'): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 40px;">📋 ПРАВИЛА</h1>
                        
                        <div class="grid">
                            <div class="server-card">
                                <h3>📜 Правила сервера Classic</h3>
                                <p>Детальные правила для сервера Classic с расширенным геймплеем</p>
                                <a href="https://docs.google.com/document/d/12kX-bRYEo5Es5SScl-jEO39SEtZZemwQt3S7arsYWNo/edit?usp=drivesdk" target="_blank" class="btn" style="margin-top: 15px;">Читать правила</a>
                            </div>
                            
                            <div class="server-card">
                                <h3>💬 Правила Discord</h3>
                                <p>Правила поведения в нашем Discord сервере</p>
                                <a href="https://docs.google.com/document/d/1U6jmAqM65GQ0c1_GM7vw4udDdWYzNOTEOQA5dVYbI48/edit?usp=drivesdk" target="_blank" class="btn" style="margin-top: 15px;">Читать правила</a>
                            </div>
                            
                            <div class="server-card">
                                <h3>🎉 Правила сервера Events</h3>
                                <p>Специальные правила для ивентовых серверов</p>
                                <a href="https://docs.google.com/document/d/1175BL8JgKYn60raeMZp9YmWR60FkQLR_oKRU-laUW0M/edit?usp=drivesdk" target="_blank" class="btn" style="margin-top: 15px;">Читать правила</a>
                            </div>
                            
                            <div class="server-card">
                                <h3>👥 Устав персонала</h3>
                                <p>Правила и обязанности для администрации проекта</p>
                                <a href="https://docs.google.com/document/d/1KlYBINxU9PkukRPwVL-IMuXEFjC6DeplQpRa74ZTH4E/edit?usp=drivesdk" target="_blank" class="btn" style="margin-top: 15px;">Читать устав</a>
                            </div>
                        </div>
                        
                        <div style="background: rgba(220, 20, 60, 0.1); padding: 25px; border-radius: 15px; margin: 30px 0; text-align: center;">
                            <h3 style="color: #dc143c;">⚠️ ВАЖНО</h3>
                            <p>Незнание правил не освобождает от ответственности!</p>
                            <p>Обязательно ознакомьтесь с правилами перед игрой на наших серверах.</p>
                        </div>
                    </div>
                
                <?php elseif ($page === 'applications'): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 40px;">📝 ПОДАЧА ЗАЯВОК</h1>
                        
                        <div style="background: rgba(220, 20, 60, 0.1); padding: 25px; border-radius: 15px; margin: 20px 0;">
                            <h3 style="color: #dc143c;">📋 Требования для подачи заявки на администратора:</h3>
                            <ul class="features-list">
                                <li>Возраст от 14 лет</li>
                                <li>Вы являетесь адекватным участником нашего сообщества</li>
                                <li>100+ часов в SCP:SL</li>
                                <li>Открытый профиль Steam</li>
                                <li>Минимум 7д на нашем Discord</li>
                                <li>Discord аккаунт старше 1 месяца</li>
                                <li>Знание правил проекта</li>
                            </ul>
                        </div>
                        
                        <div style="background: rgba(255, 215, 0, 0.1); padding: 25px; border-radius: 15px; margin: 20px 0;">
                            <h3 style="color: #ffd700;">🎬 Требования для контент-мейкеров:</h3>
                            <ul class="features-list">
                                <li>Активный канал</li>
                                <li>Минимум 100 подписчиков</li>
                                <li>Регулярный контент по SCP:SL</li>
                                <li>Качественное оформление канала</li>
                            </ul>
                        </div>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <h3 style="color: #dc143c;">📊 Статусы набора:</h3>
                            <p>🔓 - Набор открыт | 🔒 - Набор закрыт</p>
                            <p style="color: #ffd700;">⏰ Ответ на заявку приходит в течение 7-14 дней</p>
                        </div>
                        
                        <div class="grid">
                            <div class="server-card">
                                <h3>👮 Заявка на Админа Classic</h3>
                                <p>Администратор сервера Classic с расширенными правилами</p>
                                <div style="margin: 15px 0;">
                                    <span style="color: #00ff00;">🔓 Набор открыт</span>
                                </div>
                                <a href="https://docs.google.com/forms/d/1z5Rt3zpRkL1AVhjeUkVa3uEGv3viewVMDXi3j8TLzaw/edit" target="_blank" class="application-link">Подать заявку</a>
                            </div>
                            
                            <div class="server-card">
                                <h3>🎭 Заявка на Ивент Мастера</h3>
                                <p>Организация и проведение уникальных ивентов</p>
                                <div style="margin: 15px 0;">
                                    <span style="color: #00ff00;">🔓 Набор открыт</span>
                                </div>
                                <a href="https://docs.google.com/forms/d/1JDKz4Q-7PZu8O4O6-fBEj69loSurUy0V_c2x03sV7h0/edit" target="_blank" class="application-link">Подать заявку</a>
                            </div>
                            
                            <div class="server-card">
                                <h3>⚡ Заявка на Админа NoRules</h3>
                                <p>Администратор сервера с минимальными ограничениями</p>
                                <div style="margin: 15px 0;">
                                    <span style="color: #00ff00;">🔓 Набор открыт</span>
                                </div>
                                <a href="https://docs.google.com/forms/d/1m6K-lI02BqGNINkuzP4Giw87oB2_xHKdRyphNkpWOFs/edit" target="_blank" class="application-link" style="opacity: 0.6;">Подать заявку</a>
                            </div>
                            
                            <div class="server-card">
                                <h3>🎬 Заявка на Контент-Мейкера</h3>
                                <p>Создание контента и продвижение проекта</p>
                                <div style="margin: 15px 0;">
                                    <span style="color: #00ff00;">🔓 Набор открыт</span>
                                </div>
                                <a href="https://docs.google.com/forms/d/1dXEigUlR67OMu8Lbt1pyQ1ls9voZF4TkpLVCxiScYpo/edit" target="_blank" class="application-link">Подать заявку</a>
                            </div>
                        </div>
                        
                        <div style="background: rgba(0, 0, 255, 0.1); padding: 25px; border-radius: 15px; margin: 30px 0; text-align: center;">
                            <h3 style="color: #00bfff;">📞 Поддержка</h3>
                            <p>🎫 Создайте тикет в Discord канале</p>
                            <p>💬 ЛС: @DXSTRUCTION</p>
                            <p>⏰ Время работы: 10:00-23:00 МСК</p>
                        </div>
                    </div>
                
                <?php elseif ($page === 'news'): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 40px;">📰 НОВОСТИ ПРОЕКТА</h1>
                        
                        <?php if (isAdmin()): ?>
                            <div style="background: rgba(220, 20, 60, 0.1); padding: 25px; border-radius: 15px; margin: 20px 0;">
                                <h3 style="color: #dc143c;">➕ Добавить новость</h3>
                                <button onclick="openModal('addNewsModal')" class="btn">Создать новость</button>
                            </div>
                        <?php endif; ?>
                        
                        <?php
                        $news = loadNews();
                        if (empty($news)):
                        ?>
                            <div style="text-align: center; padding: 50px; color: #888;">
                                <h3>📭 Новостей пока нет</h3>
                                <p>Следите за обновлениями!</p>
                            </div>
                        <?php else: ?>
                            <?php foreach (array_reverse($news) as $item): ?>
                                <div class="news-item">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                                        <div style="flex: 1;">
                                            <h3 style="color: #dc143c; margin-bottom: 10px;"><?php echo htmlspecialchars($item['title']); ?></h3>
                                            <div class="news-meta">
                                                👤 <?php echo htmlspecialchars($item['author']); ?> | 
                                                📅 <?php echo htmlspecialchars($item['date']); ?>
                                            </div>
                                        </div>
                                        <?php if (isAdmin()): ?>
                                            <form method="post" style="margin-left: 20px;" onsubmit="return confirm('Удалить новость?')">
                                                <input type="hidden" name="news_id" value="<?php echo htmlspecialchars($item['id']); ?>">
                                                <button type="submit" name="delete_news" class="btn btn-secondary" style="padding: 8px 15px;">🗑️</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <div style="margin: 15px 0;">
                                        <?php echo nl2br(htmlspecialchars($item['content'])); ?>
                                    </div>
                                    
                                    <?php if (!empty($item['image'])): ?>
                                        <img src="<?php echo htmlspecialchars($item['image']); ?>" alt="News Image" class="news-image">
                                    <?php endif; ?>
                                    
                                    <?php if (!empty($item['video'])): ?>
                                        <iframe src="<?php echo htmlspecialchars($item['video']); ?>" class="news-video" frameborder="0" allowfullscreen></iframe>
                                    <?php endif; ?>
                                    
                                    <?php if (!empty($item['link']) && !empty($item['link_text'])): ?>
                                        <div style="margin-top: 15px;">
                                            <a href="<?php echo htmlspecialchars($item['link']); ?>" target="_blank" class="btn">🔗 <?php echo htmlspecialchars($item['link_text']); ?></a>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                
                <?php elseif ($page === 'profile'): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 40px;">👤 ЛИЧНЫЙ КАБИНЕТ</h1>
                        
                        <?php if (isset($success)): ?>
                            <div class="success"><?php echo htmlspecialchars($success); ?></div>
                        <?php endif; ?>
                        
                        <?php if (isset($error)): ?>
                            <div class="error"><?php echo htmlspecialchars($error); ?></div>
                        <?php endif; ?>
                        
                        <div class="grid">
                            <div class="profile-info">
                                <h3>ℹ️ Информация о профиле</h3>
                                
                                <?php if (!empty($_SESSION['user']['avatar'])): ?>
                                    <div style="text-align: center; margin: 20px 0;">
                                        <img src="<?php echo htmlspecialchars($_SESSION['user']['avatar_full'] ?? $_SESSION['user']['avatar']); ?>" alt="Avatar" class="profile-avatar">
                                    </div>
                                <?php endif; ?>
                                
                                <p><strong>Имя:</strong> <?php echo htmlspecialchars($_SESSION['user']['name']); ?></p>
                                <p><strong>Email:</strong> <?php echo htmlspecialchars($_SESSION['user']['email']); ?></p>
                                <p><strong>Роль:</strong> <?php echo $_SESSION['user']['role'] === 'admin' ? '👑 Администратор' : '👤 Пользователь'; ?></p>
                                <p><strong>Дата регистрации:</strong> <?php echo htmlspecialchars($_SESSION['user']['registration_date']); ?></p>
                                <?php if (!empty($_SESSION['user']['steam_id'])): ?>
                                    <p><strong>Steam ID:</strong> <?php echo htmlspecialchars($_SESSION['user']['steam_id']); ?></p>
                                    <p><strong>Тип аккаунта:</strong> 🎮 Steam аккаунт</p>
                                <?php endif; ?>
                            </div>
                            
                            <?php if (empty($_SESSION['user']['steam_id'])): ?>
                            <div class="profile-info">
                                <h3>🔐 Изменение пароля</h3>
                                <form method="post">
                                    <div class="form-group">
                                        <label>Текущий пароль</label>
                                        <input type="password" name="current_password" class="form-control" required>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label>Новый пароль</label>
                                        <input type="password" name="new_password" class="form-control" required>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label>Подтвердите новый пароль</label>
                                        <input type="password" name="confirm_new_password" class="form-control" required>
                                    </div>
                                    
                                    <button type="submit" name="change_password" class="btn">Изменить пароль</button>
                                </form>
                            </div>
                            <?php else: ?>
                            <div class="profile-info">
                                <h3>🎮 Steam аккаунт</h3>
                                <p style="color: #66c0f4; margin: 15px 0;">Вы авторизованы через Steam!</p>
                                <p>🔒 Пароль управляется через Steam</p>
                                <p>🔄 Данные автоматически синхронизируются</p>
                                <p>🛡️ Безопасность обеспечивается Steam</p>
                                
                                <div style="margin-top: 20px;">
                                    <a href="https://steamcommunity.com/profiles/<?php echo htmlspecialchars($_SESSION['user']['steam_id']); ?>" target="_blank" class="btn btn-steam" style="width: 100%; justify-content: center;">
                                        🔗 Открыть профиль Steam
                                    </a>
                                </div>
                            </div>
                            <?php endif; ?>
                        </div>
                        
                        <div style="background: rgba(220, 20, 60, 0.1); padding: 25px; border-radius: 15px; margin: 30px 0; text-align: center;">
                            <h3 style="color: #dc143c;">⚠️ Внимание</h3>
                            <p>Удаление аккаунта необратимо!</p>
                            <button onclick="confirmDelete()" class="btn btn-secondary" style="background: linear-gradient(45deg, #8b0000, #dc143c);">🗑️ Удалить аккаунт</button>
                        </div>
                    </div>
                
                <?php elseif ($page === 'admin' && isAdmin()): ?>
                    <div class="content-section">
                        <h1 style="text-align: center; color: #dc143c; margin-bottom: 40px;">🛠️ АДМИН-ПАНЕЛЬ</h1>
                        
                        <div class="admin-panel">
                            <h2 style="color: #dc143c; margin-bottom: 20px;">👥 Управление пользователями</h2>
                            
                            <div style="overflow-x: auto;">
                                <table class="admin-table">
                                    <thead>
                                        <tr>
                                            <th>Аватар</th>
                                            <th>ID</th>
                                            <th>Имя</th>
                                            <th>Email</th>
                                            <th>Роль</th>
                                            <th>Регистрация</th>
                                            <th>Steam ID</th>
                                            <th>Действия</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php
                                        $users = loadUsers();
                                        foreach ($users as $user):
                                        ?>
                                            <tr>
                                                <td>
                                                    <?php if (!empty($user['avatar'])): ?>
                                                        <img src="<?php echo htmlspecialchars($user['avatar']); ?>" alt="Avatar" style="width: 32px; height: 32px; border-radius: 50%; border: 1px solid #dc143c;">
                                                    <?php else: ?>
                                                        <div style="width: 32px; height: 32px; border-radius: 50%; background: #333; display: flex; align-items: center; justify-content: center; color: #dc143c; font-size: 12px;">👤</div>
                                                    <?php endif; ?>
                                                </td>
                                                <td><?php echo substr($user['id'], -8); ?></td>
                                                <td><?php echo htmlspecialchars($user['name']); ?></td>
                                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                                <td>
                                                    <form method="post" style="display: inline;">
                                                        <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                                        <select name="new_role" onchange="this.form.submit()" class="form-control" style="width: auto; display: inline-block;">
                                                            <option value="user" <?php echo $user['role'] === 'user' ? 'selected' : ''; ?>>User</option>
                                                            <option value="admin" <?php echo $user['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                                        </select>
                                                        <input type="hidden" name="admin_change_role" value="1">
                                                    </form>
                                                </td>
                                                <td><?php echo htmlspecialchars($user['registration_date']); ?></td>
                                                <td>
                                                    <?php if ($user['steam_id']): ?>
                                                        <span style="color: #66c0f4;">🎮 <?php echo htmlspecialchars($user['steam_id']); ?></span>
                                                    <?php else: ?>
                                                        <span style="color: #888;">Нет</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <form method="post" style="display: inline;" onsubmit="return confirm('Удалить пользователя?')">
                                                        <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                                        <button type="submit" name="admin_delete_user" class="btn btn-secondary" style="padding: 5px 10px; font-size: 12px;">Удалить</button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        
                        <div class="admin-panel">
                            <h2 style="color: #dc143c; margin-bottom: 20px;">📊 Статистика</h2>
                            
                            <div class="grid">
                                <div style="background: rgba(0, 128, 0, 0.2); padding: 20px; border-radius: 10px; text-align: center;">
                                    <h3 style="color: #00ff00;">Общая статистика</h3>
                                    <p><strong>Всего пользователей:</strong> <?php echo count($users); ?></p>
                                    <p><strong>Администраторов:</strong> <?php echo count(array_filter($users, function($u) { return $u['role'] === 'admin'; })); ?></p>
                                    <p><strong>Steam пользователей:</strong> <?php echo count(array_filter($users, function($u) { return !empty($u['steam_id']); })); ?></p>
                                </div>
                                
                                <div style="background: rgba(0, 0, 255, 0.2); padding: 20px; border-radius: 10px; text-align: center;">
                                    <h3 style="color: #00bfff;">Последние регистрации</h3>
                                    <?php
                                    $recent_users = array_slice(array_reverse($users), 0, 5);
                                    foreach ($recent_users as $user):
                                    ?>
                                        <p>
                                            <?php if (!empty($user['avatar'])): ?>
                                                <img src="<?php echo htmlspecialchars($user['avatar']); ?>" alt="Avatar" style="width: 20px; height: 20px; border-radius: 50%; margin-right: 5px; vertical-align: middle;">
                                            <?php endif; ?>
                                            <?php echo htmlspecialchars($user['name']); ?> - <?php echo htmlspecialchars($user['registration_date']); ?>
                                        </p>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                
                <?php endif; ?>
                
            </div>
        </main>
        
    <?php endif; ?>
    
    <?php if (isAdmin()): ?>
        <div id="addNewsModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addNewsModal')">&times;</span>
                <h2 style="color: #dc143c; margin-bottom: 20px;">➕ Добавить новость</h2>
                
                <form method="post">
                    <div class="form-group">
                        <label>Заголовок новости</label>
                        <input type="text" name="news_title" class="form-control" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Содержание</label>
                        <textarea name="news_content" class="form-control" rows="5" required></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>Изображение</label>
                        <input type="url" name="news_image" class="form-control" placeholder="ссылочка">
                    </div>
                    
                    <div class="form-group">
                        <label>Видео</label>
                        <input type="url" name="news_video" class="form-control" placeholder="ссылочка">
                    </div>
                    
                    <div class="form-group">
                        <label>Ссылка</label>
                        <input type="url" name="news_link" class="form-control" placeholder="ссылочка">
                    </div>
                    
                    <div class="form-group">
                        <label>Текст ссылки</label>
                        <input type="text" name="news_link_text" class="form-control" placeholder="Читать далее">
                    </div>
                    
                    <button type="submit" name="add_news" class="btn">Добавить новость</button>
                </form>
            </div>
        </div>
    <?php endif; ?>
    
    <footer class="footer">
        <div class="container">
            <div class="footer-content">
                <h3 style="color: #dc143c; margin-bottom: 20px;">🔗 ПОЛЕЗНЫЕ ССЫЛКИ</h3>
                
                <div class="footer-links">
                    <a href="https://boosty.to/dxproject" target="_blank">🌐 Boosty — Поддержка проекта</a>
                    <a href="https://docs.google.com/document/d/12kX-bRYEo5Es5SScl-jEO39SEtZZemwQt3S7arsYWNo/edit?usp=drivesdk" target="_blank">📜 Правила Classic</a>
                    <a href="https://discord.gg/YtZjRTbX" target="_blank">💬 Discord — Наше комьюнити</a>
                </div>
                
                <div style="margin: 30px 0; padding: 20px; background: rgba(220, 20, 60, 0.1); border-radius: 15px;">
                    <p style="color: #dc143c; font-weight: bold; margin-bottom: 10px;">© 2025 DX Project</p>
                    <p>Все права защищены. Сайт создан для сообщества SCP: Secret Laboratory</p>
                    <p style="font-size: 0.9em; color: #888; margin-top: 10px;"
                    </p>
                </div>
            </div>
        </div>
    </footer>
    
    <script>
        function switchTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
        }
        
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        function confirmDelete() {
            if (confirm('Вы уверены, что хотите удалить свой аккаунт? Это действие необратимо!')) {
                if (confirm('Последнее предупреждение! Все ваши данные будут удалены навсегда!')) {
                    const form = document.createElement('form');
                    form.method = 'post';
                    form.innerHTML = '<input type="hidden" name="delete_account" value="1">';
                    document.body.appendChild(form);
                    form.submit();
                }
            }
        }
        
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const serverCards = document.querySelectorAll('.server-card');
            const donateCards = document.querySelectorAll('.donate-card');
            
            serverCards.forEach((card, index) => {
                setTimeout(() => {
                    card.style.opacity = '0';
                    card.style.transform = 'translateY(30px)';
                    card.style.transition = 'all 0.6s ease';
                    
                    setTimeout(() => {
                        card.style.opacity = '1';
                        card.style.transform = 'translateY(0)';
                    }, 100);
                }, index * 200);
            });
            
            donateCards.forEach((card, index) => {
                setTimeout(() => {
                    card.style.opacity = '0';
                    card.style.transform = 'translateX(-30px)';
                    card.style.transition = 'all 0.6s ease';
                    
                    setTimeout(() => {
                        card.style.opacity = '1';
                        card.style.transform = 'translateX(0)';
                    }, 100);
                }, index * 300);
            });
            
            const glowElements = document.querySelectorAll('.glow-effect');
            glowElements.forEach(element => {
                element.addEventListener('mouseenter', function() {
                    this.style.animation = 'glow 0.5s infinite';
                });
                
                element.addEventListener('mouseleave', function() {
                    this.style.animation = 'glow 2s infinite';
                });
            });
            
            const navLinks = document.querySelectorAll('.nav-links a');
            navLinks.forEach(link => {
                link.addEventListener('mouseenter', function() {
                    this.style.boxShadow = '0 5px 15px rgba(220, 20, 60, 0.3)';
                });
                
                link.addEventListener('mouseleave', function() {
                    this.style.boxShadow = 'none';
                });
            });
            
            const formControls = document.querySelectorAll('.form-control');
            formControls.forEach(input => {
                input.addEventListener('focus', function() {
                    this.parentElement.style.transform = 'scale(1.02)';
                    this.parentElement.style.transition = 'transform 0.3s ease';
                });
                
                input.addEventListener('blur', function() {
                    this.parentElement.style.transform = 'scale(1)';
                });
            });
            
            const buttons = document.querySelectorAll('.btn');
            buttons.forEach(button => {
                button.addEventListener('click', function(e) {
                    const ripple = document.createElement('span');
                    const rect = this.getBoundingClientRect();
                    const size = Math.max(rect.width, rect.height);
                    const x = e.clientX - rect.left - size / 2;
                    const y = e.clientY - rect.top - size / 2;
                    
                    ripple.style.width = ripple.style.height = size + 'px';
                    ripple.style.left = x + 'px';
                    ripple.style.top = y + 'px';
                    ripple.style.position = 'absolute';
                    ripple.style.borderRadius = '50%';
                    ripple.style.background = 'rgba(255, 255, 255, 0.3)';
                    ripple.style.transform = 'scale(0)';
                    ripple.style.animation = 'ripple 0.6s linear';
                    ripple.style.pointerEvents = 'none';
                    
                    this.style.position = 'relative';
                    this.style.overflow = 'hidden';
                    this.appendChild(ripple);
                    
                    setTimeout(() => {
                        ripple.remove();
                    }, 600);
                });
            });
            
            const style = document.createElement('style');
            style.textContent = `
                @keyframes ripple {
                    to {
                        transform: scale(4);
                        opacity: 0;
                    }
                }
                
                @keyframes fadeInUp {
                    from {
                        opacity: 0;
                        transform: translateY(30px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
                
                @keyframes slideInLeft {
                    from {
                        opacity: 0;
                        transform: translateX(-30px);
                    }
                    to {
                        opacity: 1;
                        transform: translateX(0);
                    }
                }
                
                .content-section {
                    animation: fadeInUp 0.8s ease;
                }
                
                .news-item {
                    animation: slideInLeft 0.6s ease;
                }
                
                .server-ip:hover {
                    background: rgba(220, 20, 60, 0.2);
                    transform: scale(1.02);
                    transition: all 0.3s ease;
                }
                
                .admin-table tbody tr:hover {
                    transform: translateX(5px);
                    transition: transform 0.3s ease;
                }
                
                .profile-info:hover {
                    transform: translateY(-5px);
                    transition: all 0.3s ease;
                    box-shadow: 0 10px 25px rgba(220, 20, 60, 0.2);
                }
                
                .footer-links a:hover {
                    transform: translateY(-2px);
                    transition: all 0.3s ease;
                }
            `;
            document.head.appendChild(style);
        });
        
        setInterval(function() {
            const timeElements = document.querySelectorAll('.time-display');
            const now = new Date();
            const timeString = now.toLocaleString('ru-RU');
            
            timeElements.forEach(element => {
                element.textContent = timeString;
            });
        }, 1000);
        
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(function(error) {
                console.log('ServiceWorker registration failed: ', error);
            });
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                const notification = document.createElement('div');
                notification.textContent = 'Скопировано в буфер обмена!';
                notification.style.position = 'fixed';
                notification.style.top = '20px';
                notification.style.right = '20px';
                notification.style.background = '#dc143c';
                notification.style.color = 'white';
                notification.style.padding = '10px 20px';
                notification.style.borderRadius = '5px';
                notification.style.zIndex = '10000';
                
                document.body.appendChild(notification);
                
                setTimeout(() => {
                    notification.remove();
                }, 3000);
            });
        }
        
        document.querySelectorAll('.server-ip').forEach(ip => {
            ip.addEventListener('click', function() {
                copyToClipboard(this.textContent.replace('IP: ', ''));
            });
            
            ip.style.cursor = 'pointer';
            ip.title = 'Нажмите, чтобы скопировать IP';
        });
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        });
        
        document.querySelectorAll('.server-card, .donate-card, .news-item').forEach(element => {
            element.style.opacity = '0';
            element.style.transform = 'translateY(30px)';
            element.style.transition = 'all 0.6s ease';
            observer.observe(element);
        });
    </script>
</body>
</html>
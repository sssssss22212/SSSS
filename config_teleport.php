<?php
/**
 * Конфигурация плагина телепортации для RP сервера
 * Все настройки и параметры системы
 */

// Основные настройки
define('TP_PLUGIN_VERSION', '1.0.0');
define('TP_PLUGIN_NAME', 'RP Телепорт Система');
define('TP_DATA_DIR', 'data');

// Настройки безопасности
define('TP_MAX_TELEPORTS_PER_USER', 50);  // Максимум телепортов на пользователя
define('TP_COOLDOWN_SECONDS', 5);         // Кулдаун между телепортациями (секунды)
define('TP_ADMIN_ONLY_CREATE', false);    // Только администраторы могут создавать телепорты

// Настройки миров
$worlds_config = [
    'default' => [
        'name' => 'Основной мир',
        'description' => 'Главный мир сервера',
        'spawn_point' => ['x' => 0, 'y' => 64, 'z' => 0],
        'teleport_enabled' => true,
        'max_teleports' => 100
    ],
    'nether' => [
        'name' => 'Ад',
        'description' => 'Опасный мир Нижнего мира',
        'spawn_point' => ['x' => 0, 'y' => 64, 'z' => 0],
        'teleport_enabled' => true,
        'max_teleports' => 20
    ],
    'end' => [
        'name' => 'Край',
        'description' => 'Мир Края с драконом',
        'spawn_point' => ['x' => 0, 'y' => 64, 'z' => 0],
        'teleport_enabled' => false, // Отключены телепорты в Край
        'max_teleports' => 5
    ],
    'creative' => [
        'name' => 'Творческий мир',
        'description' => 'Мир для строительства и креатива',
        'spawn_point' => ['x' => 0, 'y' => 100, 'z' => 0],
        'teleport_enabled' => true,
        'max_teleports' => 200
    ]
];

// Настройки ролей и разрешений
$permissions_config = [
    'admin' => [
        'can_create_teleports' => true,
        'can_delete_any_teleport' => true,
        'can_edit_any_teleport' => true,
        'can_teleport_others' => true,
        'can_apply_patches' => true,
        'can_view_stats' => true,
        'teleport_cooldown' => 0,
        'max_teleports' => -1  // Без ограничений
    ],
    'moderator' => [
        'can_create_teleports' => true,
        'can_delete_any_teleport' => false,
        'can_edit_any_teleport' => false,
        'can_teleport_others' => true,
        'can_apply_patches' => false,
        'can_view_stats' => true,
        'teleport_cooldown' => 2,
        'max_teleports' => 30
    ],
    'vip' => [
        'can_create_teleports' => true,
        'can_delete_any_teleport' => false,
        'can_edit_any_teleport' => false,
        'can_teleport_others' => false,
        'can_apply_patches' => false,
        'can_view_stats' => false,
        'teleport_cooldown' => 3,
        'max_teleports' => 20
    ],
    'player' => [
        'can_create_teleports' => false,
        'can_delete_any_teleport' => false,
        'can_edit_any_teleport' => false,
        'can_teleport_others' => false,
        'can_apply_patches' => false,
        'can_view_stats' => false,
        'teleport_cooldown' => 5,
        'max_teleports' => 5
    ]
];

// Настройки уведомлений
$notifications_config = [
    'teleport_success' => [
        'enabled' => true,
        'message' => 'Вы успешно телепортировались к точке "{name}"!',
        'sound' => 'teleport_success.mp3',
        'duration' => 3
    ],
    'teleport_error' => [
        'enabled' => true,
        'message' => 'Ошибка телепортации: {error}',
        'sound' => 'error.mp3',
        'duration' => 5
    ],
    'cooldown_active' => [
        'enabled' => true,
        'message' => 'Подождите {seconds} секунд до следующей телепортации',
        'sound' => 'cooldown.mp3',
        'duration' => 3
    ],
    'teleport_created' => [
        'enabled' => true,
        'message' => 'Новая точка телепортации "{name}" создана!',
        'sound' => 'create.mp3',
        'duration' => 4
    ]
];

// Настройки безопасности телепортации
$safety_config = [
    'check_safe_landing' => true,        // Проверять безопасность места приземления
    'min_y_level' => 0,                  // Минимальная высота для телепортации
    'max_y_level' => 256,               // Максимальная высота для телепортации
    'avoid_lava' => true,               // Избегать телепортации в лаву
    'avoid_void' => true,               // Избегать телепортации в пустоту
    'safe_radius_check' => 2,           // Радиус проверки безопасности (блоки)
    'emergency_spawn_on_fail' => true   // Телепортировать на спавн при ошибке
];

// Настройки логирования
$logging_config = [
    'enabled' => true,
    'log_file' => 'data/teleport.log',
    'log_level' => 'INFO', // DEBUG, INFO, WARNING, ERROR
    'log_teleports' => true,
    'log_creates' => true,
    'log_deletes' => true,
    'log_patches' => true,
    'max_log_size' => 10485760, // 10MB
    'log_rotation' => true
];

// Настройки производительности
$performance_config = [
    'cache_teleports' => true,
    'cache_duration' => 300,    // 5 минут
    'batch_updates' => true,
    'async_logging' => false,
    'compress_data' => true
];

// Предустановленные телепорты (будут созданы при первом запуске)
$default_teleports = [
    [
        'name' => 'Спавн',
        'x' => 0,
        'y' => 64,
        'z' => 0,
        'world' => 'default',
        'description' => 'Точка возрождения игроков',
        'is_public' => true,
        'created_by' => 'system'
    ],
    [
        'name' => 'Торговый центр',
        'x' => 100,
        'y' => 64,
        'z' => 100,
        'world' => 'default',
        'description' => 'Главный торговый центр сервера',
        'is_public' => true,
        'created_by' => 'system'
    ],
    [
        'name' => 'Арена PvP',
        'x' => -200,
        'y' => 70,
        'z' => -200,
        'world' => 'default',
        'description' => 'Арена для сражений между игроками',
        'is_public' => true,
        'created_by' => 'system'
    ],
    [
        'name' => 'Творческая зона',
        'x' => 0,
        'y' => 100,
        'z' => 0,
        'world' => 'creative',
        'description' => 'Зона для строительства и творчества',
        'is_public' => true,
        'created_by' => 'system'
    ]
];

// Настройки API
$api_config = [
    'enabled' => true,
    'rate_limit' => 60,     // Запросов в минуту
    'require_auth' => true,
    'allowed_origins' => ['*'], // CORS
    'api_key_required' => false
];

// Настройки интерфейса
$ui_config = [
    'theme' => 'dark',
    'language' => 'ru',
    'items_per_page' => 20,
    'show_coordinates' => true,
    'show_world_info' => true,
    'enable_map_view' => false,
    'auto_refresh' => 30 // секунды
];

// Экспортируем конфигурации для использования в плагине
function getTeleportConfig($section = null) {
    global $worlds_config, $permissions_config, $notifications_config, 
           $safety_config, $logging_config, $performance_config, 
           $default_teleports, $api_config, $ui_config;
    
    $config = [
        'worlds' => $worlds_config,
        'permissions' => $permissions_config,
        'notifications' => $notifications_config,
        'safety' => $safety_config,
        'logging' => $logging_config,
        'performance' => $performance_config,
        'default_teleports' => $default_teleports,
        'api' => $api_config,
        'ui' => $ui_config
    ];
    
    return $section ? ($config[$section] ?? null) : $config;
}

// Функция для получения разрешений пользователя
function getUserPermissions($role) {
    global $permissions_config;
    return $permissions_config[$role] ?? $permissions_config['player'];
}

// Функция для проверки доступности мира для телепортации
function isWorldTeleportEnabled($world) {
    global $worlds_config;
    return isset($worlds_config[$world]) && $worlds_config[$world]['teleport_enabled'];
}

// Функция логирования
function logTeleportAction($action, $details = []) {
    global $logging_config;
    
    if (!$logging_config['enabled']) {
        return;
    }
    
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'action' => $action,
        'user' => $_SESSION['user']['username'] ?? 'anonymous',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'details' => $details
    ];
    
    $log_line = json_encode($log_entry, JSON_UNESCAPED_UNICODE) . "\n";
    
    // Проверяем размер лог-файла
    if (file_exists($logging_config['log_file']) && 
        filesize($logging_config['log_file']) > $logging_config['max_log_size']) {
        
        if ($logging_config['log_rotation']) {
            rename($logging_config['log_file'], $logging_config['log_file'] . '.old');
        } else {
            unlink($logging_config['log_file']);
        }
    }
    
    file_put_contents($logging_config['log_file'], $log_line, FILE_APPEND | LOCK_EX);
}

// Функция для отправки уведомлений
function sendTeleportNotification($type, $data = []) {
    global $notifications_config;
    
    if (!isset($notifications_config[$type]) || !$notifications_config[$type]['enabled']) {
        return false;
    }
    
    $notification = $notifications_config[$type];
    $message = $notification['message'];
    
    // Заменяем плейсхолдеры в сообщении
    foreach ($data as $key => $value) {
        $message = str_replace('{' . $key . '}', $value, $message);
    }
    
    return [
        'message' => $message,
        'sound' => $notification['sound'] ?? null,
        'duration' => $notification['duration'] ?? 3
    ];
}

// Инициализация конфигурации
function initializeTeleportConfig() {
    // Создаем директорию для данных если её нет
    if (!is_dir(TP_DATA_DIR)) {
        mkdir(TP_DATA_DIR, 0755, true);
    }
    
    // Создаем лог-файл если его нет
    $log_config = getTeleportConfig('logging');
    if ($log_config['enabled'] && !file_exists($log_config['log_file'])) {
        touch($log_config['log_file']);
        chmod($log_config['log_file'], 0644);
    }
    
    logTeleportAction('CONFIG_INIT', ['version' => TP_PLUGIN_VERSION]);
}

// Автоматическая инициализация при подключении файла
initializeTeleportConfig();
?>
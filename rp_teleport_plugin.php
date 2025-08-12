<?php
/**
 * RP Сервер - Плагин Телепортации
 * Версия: 1.0.0
 * Автор: RP Developer
 * Описание: Плагин для управления телепортацией игроков на RP сервере
 */

session_start();
require_once 'config_teleport.php';

class RPTeleportPlugin {
    private $teleports_file = 'data/teleports.json';
    private $players_file = 'data/players.json';
    private $patches_file = 'data/patches.json';
    
    public function __construct() {
        $this->initializeDataFiles();
    }
    
    /**
     * Инициализация файлов данных
     */
    private function initializeDataFiles() {
        $data_dir = 'data';
        if (!is_dir($data_dir)) {
            mkdir($data_dir, 0755, true);
        }
        
        $files = [$this->teleports_file, $this->players_file, $this->patches_file];
        foreach ($files as $file) {
            if (!file_exists($file)) {
                file_put_contents($file, json_encode([], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            }
        }
    }
    
    /**
     * Загрузка телепортов
     */
    public function loadTeleports() {
        return json_decode(file_get_contents($this->teleports_file), true) ?: [];
    }
    
    /**
     * Сохранение телепортов
     */
    public function saveTeleports($teleports) {
        return file_put_contents($this->teleports_file, json_encode($teleports, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    
    /**
     * Загрузка данных игроков
     */
    public function loadPlayers() {
        return json_decode(file_get_contents($this->players_file), true) ?: [];
    }
    
    /**
     * Сохранение данных игроков
     */
    public function savePlayers($players) {
        return file_put_contents($this->players_file, json_encode($players, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    
    /**
     * Создание нового телепорта
     */
    public function createTeleport($name, $x, $y, $z, $world = 'default', $description = '') {
        $teleports = $this->loadTeleports();
        
        $teleport = [
            'id' => uniqid('tp_', true),
            'name' => $name,
            'coordinates' => [
                'x' => floatval($x),
                'y' => floatval($y),
                'z' => floatval($z)
            ],
            'world' => $world,
            'description' => $description,
            'created_at' => date('Y-m-d H:i:s'),
            'created_by' => $_SESSION['user']['username'] ?? 'system',
            'usage_count' => 0,
            'is_public' => true
        ];
        
        $teleports[] = $teleport;
        $this->saveTeleports($teleports);
        
        return $teleport;
    }
    
    /**
     * Удаление телепорта
     */
    public function deleteTeleport($teleport_id) {
        $teleports = $this->loadTeleports();
        $teleports = array_filter($teleports, function($tp) use ($teleport_id) {
            return $tp['id'] !== $teleport_id;
        });
        
        return $this->saveTeleports(array_values($teleports));
    }
    
    /**
     * Телепортация игрока
     */
    public function teleportPlayer($player_id, $teleport_id) {
        $teleports = $this->loadTeleports();
        $players = $this->loadPlayers();
        
        $teleport = null;
        foreach ($teleports as &$tp) {
            if ($tp['id'] === $teleport_id) {
                $teleport = &$tp;
                $tp['usage_count']++;
                break;
            }
        }
        
        if (!$teleport) {
            return ['success' => false, 'message' => 'Телепорт не найден'];
        }
        
        // Обновляем позицию игрока
        if (!isset($players[$player_id])) {
            $players[$player_id] = ['teleport_history' => []];
        }
        
        $players[$player_id]['last_position'] = [
            'x' => $teleport['coordinates']['x'],
            'y' => $teleport['coordinates']['y'],
            'z' => $teleport['coordinates']['z'],
            'world' => $teleport['world'],
            'timestamp' => time()
        ];
        
        $players[$player_id]['teleport_history'][] = [
            'teleport_id' => $teleport_id,
            'teleport_name' => $teleport['name'],
            'timestamp' => time(),
            'coordinates' => $teleport['coordinates']
        ];
        
        // Ограничиваем историю до 50 записей
        if (count($players[$player_id]['teleport_history']) > 50) {
            $players[$player_id]['teleport_history'] = array_slice($players[$player_id]['teleport_history'], -50);
        }
        
        $this->saveTeleports($teleports);
        $this->savePlayers($players);
        
        return [
            'success' => true, 
            'message' => "Успешная телепортация к '{$teleport['name']}'",
            'coordinates' => $teleport['coordinates'],
            'world' => $teleport['world']
        ];
    }
    
    /**
     * Получение списка телепортов с фильтрацией
     */
    public function getTeleports($filter = []) {
        $teleports = $this->loadTeleports();
        
        if (!empty($filter['world'])) {
            $teleports = array_filter($teleports, function($tp) use ($filter) {
                return $tp['world'] === $filter['world'];
            });
        }
        
        if (!empty($filter['public_only'])) {
            $teleports = array_filter($teleports, function($tp) {
                return $tp['is_public'] === true;
            });
        }
        
        if (!empty($filter['search'])) {
            $search = strtolower($filter['search']);
            $teleports = array_filter($teleports, function($tp) use ($search) {
                return strpos(strtolower($tp['name']), $search) !== false ||
                       strpos(strtolower($tp['description']), $search) !== false;
            });
        }
        
        return array_values($teleports);
    }
    
    /**
     * Система патчей для обновлений
     */
    public function applyPatch($patch_data) {
        $patches = json_decode(file_get_contents($this->patches_file), true) ?: [];
        
        $patch = [
            'id' => uniqid('patch_', true),
            'version' => $patch_data['version'],
            'description' => $patch_data['description'],
            'changes' => $patch_data['changes'],
            'applied_at' => date('Y-m-d H:i:s'),
            'applied_by' => $_SESSION['user']['username'] ?? 'system'
        ];
        
        // Применяем изменения
        foreach ($patch_data['changes'] as $change) {
            switch ($change['type']) {
                case 'add_teleport':
                    $this->createTeleport(
                        $change['data']['name'],
                        $change['data']['x'],
                        $change['data']['y'],
                        $change['data']['z'],
                        $change['data']['world'] ?? 'default',
                        $change['data']['description'] ?? ''
                    );
                    break;
                    
                case 'remove_teleport':
                    $this->deleteTeleport($change['data']['teleport_id']);
                    break;
                    
                case 'update_config':
                    // Здесь можно добавить логику обновления конфигурации
                    break;
            }
        }
        
        $patches[] = $patch;
        file_put_contents($this->patches_file, json_encode($patches, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        
        return $patch;
    }
    
    /**
     * Получение статистики использования
     */
    public function getStats() {
        $teleports = $this->loadTeleports();
        $players = $this->loadPlayers();
        
        $total_teleports = count($teleports);
        $total_usage = array_sum(array_column($teleports, 'usage_count'));
        $active_players = count(array_filter($players, function($player) {
            return isset($player['last_position']) && 
                   (time() - $player['last_position']['timestamp']) < 3600; // Активность за последний час
        }));
        
        $popular_teleports = $teleports;
        usort($popular_teleports, function($a, $b) {
            return $b['usage_count'] - $a['usage_count'];
        });
        $popular_teleports = array_slice($popular_teleports, 0, 5);
        
        return [
            'total_teleports' => $total_teleports,
            'total_usage' => $total_usage,
            'active_players' => $active_players,
            'popular_teleports' => $popular_teleports
        ];
    }
    
    /**
     * Проверка прав доступа
     */
    public function hasPermission($action) {
        if (!isset($_SESSION['user'])) {
            return false;
        }
        
        $user_role = $_SESSION['user']['role'] ?? 'player';
        
        $permissions = [
            'admin' => ['create', 'delete', 'edit', 'teleport', 'patch', 'stats'],
            'moderator' => ['create', 'edit', 'teleport', 'stats'],
            'player' => ['teleport']
        ];
        
        return in_array($action, $permissions[$user_role] ?? []);
    }
}

// Инициализация плагина
$rp_teleport = new RPTeleportPlugin();

// Обработка AJAX запросов
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    
    $response = ['success' => false, 'message' => 'Неизвестная ошибка'];
    
    switch ($_POST['action']) {
        case 'create_teleport':
            if ($rp_teleport->hasPermission('create')) {
                $teleport = $rp_teleport->createTeleport(
                    $_POST['name'],
                    $_POST['x'],
                    $_POST['y'],
                    $_POST['z'],
                    $_POST['world'] ?? 'default',
                    $_POST['description'] ?? ''
                );
                $response = ['success' => true, 'message' => 'Телепорт создан', 'data' => $teleport];
            } else {
                $response = ['success' => false, 'message' => 'Недостаточно прав'];
            }
            break;
            
        case 'teleport_player':
            if ($rp_teleport->hasPermission('teleport')) {
                $result = $rp_teleport->teleportPlayer($_POST['player_id'], $_POST['teleport_id']);
                $response = $result;
            } else {
                $response = ['success' => false, 'message' => 'Недостаточно прав'];
            }
            break;
            
        case 'delete_teleport':
            if ($rp_teleport->hasPermission('delete')) {
                $rp_teleport->deleteTeleport($_POST['teleport_id']);
                $response = ['success' => true, 'message' => 'Телепорт удален'];
            } else {
                $response = ['success' => false, 'message' => 'Недостаточно прав'];
            }
            break;
            
        case 'apply_patch':
            if ($rp_teleport->hasPermission('patch')) {
                $patch_data = json_decode($_POST['patch_data'], true);
                $patch = $rp_teleport->applyPatch($patch_data);
                $response = ['success' => true, 'message' => 'Патч применен', 'data' => $patch];
            } else {
                $response = ['success' => false, 'message' => 'Недостаточно прав'];
            }
            break;
            
        case 'get_teleports':
            $filter = [
                'world' => $_POST['world'] ?? '',
                'public_only' => $_POST['public_only'] ?? false,
                'search' => $_POST['search'] ?? ''
            ];
            $teleports = $rp_teleport->getTeleports($filter);
            $response = ['success' => true, 'data' => $teleports];
            break;
            
        case 'get_stats':
            if ($rp_teleport->hasPermission('stats')) {
                $stats = $rp_teleport->getStats();
                $response = ['success' => true, 'data' => $stats];
            } else {
                $response = ['success' => false, 'message' => 'Недостаточно прав'];
            }
            break;
    }
    
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Админ-панель - RP Телепорт Система</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            color: #fff;
        }
        
        .header {
            background: rgba(0,0,0,0.3);
            padding: 1rem;
            border-bottom: 2px solid #4a6da7;
        }
        
        .header h1 {
            text-align: center;
            color: #fff;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 2rem;
        }
        
        .sidebar {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            height: fit-content;
        }
        
        .main-content {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .nav-button {
            display: block;
            width: 100%;
            padding: 12px 15px;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
            text-align: left;
        }
        
        .nav-button:hover, .nav-button.active {
            background: linear-gradient(45deg, #764ba2 0%, #667eea 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .stat-card h3 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .stat-card p {
            opacity: 0.9;
            font-size: 0.9rem;
        }
        
        .teleport-form {
            background: rgba(255,255,255,0.05);
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 10px;
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 5px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-size: 14px;
        }
        
        .form-control::placeholder {
            color: rgba(255,255,255,0.6);
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        
        .btn-primary {
            background: linear-gradient(45deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
        }
        
        .btn-success {
            background: linear-gradient(45deg, #00b894 0%, #00a085 100%);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }
        
        .teleport-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .teleport-item {
            background: rgba(255,255,255,0.05);
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .teleport-item h4 {
            color: #fff;
            margin-bottom: 0.5rem;
        }
        
        .teleport-coords {
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: #a8b2d1;
            margin-bottom: 0.5rem;
        }
        
        .teleport-description {
            font-size: 0.85rem;
            color: #8892b0;
            margin-bottom: 1rem;
        }
        
        .teleport-actions {
            display: flex;
            gap: 0.5rem;
        }
        
        .patch-form {
            background: rgba(255,255,255,0.05);
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        
        .patch-preview {
            background: rgba(0,0,0,0.3);
            padding: 1rem;
            border-radius: 5px;
            margin-top: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
        }
        
        .notification.show {
            opacity: 1;
            transform: translateX(0);
        }
        
        .notification.success {
            background: linear-gradient(45deg, #00b894 0%, #00a085 100%);
        }
        
        .notification.error {
            background: linear-gradient(45deg, #ff6b6b 0%, #ee5a24 100%);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .search-box {
            margin-bottom: 1rem;
        }
        
        .world-filter {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        
        .world-btn {
            padding: 5px 15px;
            border: 1px solid rgba(255,255,255,0.3);
            background: rgba(255,255,255,0.1);
            color: white;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.85rem;
        }
        
        .world-btn.active {
            background: linear-gradient(45deg, #667eea 0%, #764ba2 100%);
            border-color: #667eea;
        }
        
        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
                padding: 1rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
        }
    </style>
</head>
<body>
    <?php
    require_once 'rp_teleport_plugin.php';
    
    // Проверка доступа администратора
    if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
        header('Location: index.php');
        exit;
    }
    
    $stats = $rp_teleport->getStats();
    $teleports = $rp_teleport->getTeleports();
    ?>
    
    <div class="header">
        <h1>🎮 RP Телепорт Система - Админ Панель</h1>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <h3 style="margin-bottom: 1rem;">📋 Навигация</h3>
            <button class="nav-button active" onclick="showTab('dashboard')">📊 Панель управления</button>
            <button class="nav-button" onclick="showTab('teleports')">🌐 Управление телепортами</button>
            <button class="nav-button" onclick="showTab('patches')">🔧 Система патчей</button>
            <button class="nav-button" onclick="showTab('players')">👥 Игроки</button>
            <button class="nav-button" onclick="showTab('settings')">⚙️ Настройки</button>
            <button class="nav-button" onclick="showTab('logs')">📋 Логи</button>
            
            <div style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.2);">
                <p style="font-size: 0.85rem; opacity: 0.8;">Версия: <?php echo TP_PLUGIN_VERSION; ?></p>
                <p style="font-size: 0.85rem; opacity: 0.8;">Администратор: <?php echo $_SESSION['user']['username']; ?></p>
            </div>
        </div>
        
        <div class="main-content">
            <!-- Панель управления -->
            <div id="dashboard" class="tab-content active">
                <h2 style="margin-bottom: 2rem;">📊 Статистика сервера</h2>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3><?php echo $stats['total_teleports']; ?></h3>
                        <p>Всего телепортов</p>
                    </div>
                    <div class="stat-card">
                        <h3><?php echo $stats['total_usage']; ?></h3>
                        <p>Использований</p>
                    </div>
                    <div class="stat-card">
                        <h3><?php echo $stats['active_players']; ?></h3>
                        <p>Активных игроков</p>
                    </div>
                    <div class="stat-card">
                        <h3><?php echo count($stats['popular_teleports']); ?></h3>
                        <p>Популярных точек</p>
                    </div>
                </div>
                
                <h3>🏆 Популярные телепорты</h3>
                <div class="teleport-list">
                    <?php foreach ($stats['popular_teleports'] as $tp): ?>
                        <div class="teleport-item">
                            <h4><?php echo htmlspecialchars($tp['name']); ?></h4>
                            <div class="teleport-coords">
                                📍 X: <?php echo $tp['coordinates']['x']; ?>, 
                                Y: <?php echo $tp['coordinates']['y']; ?>, 
                                Z: <?php echo $tp['coordinates']['z']; ?> 
                                (<?php echo $tp['world']; ?>)
                            </div>
                            <div class="teleport-description">
                                Использований: <?php echo $tp['usage_count']; ?> | 
                                Создан: <?php echo $tp['created_at']; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
            
            <!-- Управление телепортами -->
            <div id="teleports" class="tab-content">
                <h2 style="margin-bottom: 2rem;">🌐 Управление телепортами</h2>
                
                <!-- Форма создания телепорта -->
                <div class="teleport-form">
                    <h3>➕ Создать новый телепорт</h3>
                    <form id="createTeleportForm">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                            <div class="form-group">
                                <label>Название телепорта:</label>
                                <input type="text" class="form-control" name="name" placeholder="Например: Торговый центр" required>
                            </div>
                            <div class="form-group">
                                <label>Мир:</label>
                                <select class="form-control" name="world">
                                    <option value="default">Основной мир</option>
                                    <option value="nether">Ад</option>
                                    <option value="end">Край</option>
                                    <option value="creative">Творческий мир</option>
                                </select>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem;">
                            <div class="form-group">
                                <label>Координата X:</label>
                                <input type="number" class="form-control" name="x" placeholder="0" required>
                            </div>
                            <div class="form-group">
                                <label>Координата Y:</label>
                                <input type="number" class="form-control" name="y" placeholder="64" required>
                            </div>
                            <div class="form-group">
                                <label>Координата Z:</label>
                                <input type="number" class="form-control" name="z" placeholder="0" required>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Описание (необязательно):</label>
                            <textarea class="form-control" name="description" placeholder="Описание телепорта" rows="3"></textarea>
                        </div>
                        <button type="submit" class="btn btn-success">🚀 Создать телепорт</button>
                    </form>
                </div>
                
                <!-- Фильтры и поиск -->
                <div style="margin-bottom: 1rem;">
                    <div class="search-box">
                        <input type="text" class="form-control" id="teleportSearch" placeholder="🔍 Поиск телепортов...">
                    </div>
                    <div class="world-filter">
                        <button class="world-btn active" onclick="filterByWorld('')">Все миры</button>
                        <button class="world-btn" onclick="filterByWorld('default')">Основной</button>
                        <button class="world-btn" onclick="filterByWorld('nether')">Ад</button>
                        <button class="world-btn" onclick="filterByWorld('end')">Край</button>
                        <button class="world-btn" onclick="filterByWorld('creative')">Творческий</button>
                    </div>
                </div>
                
                <!-- Список телепортов -->
                <div class="teleport-list" id="teleportsList">
                    <?php foreach ($teleports as $tp): ?>
                        <div class="teleport-item" data-world="<?php echo $tp['world']; ?>">
                            <h4><?php echo htmlspecialchars($tp['name']); ?></h4>
                            <div class="teleport-coords">
                                📍 X: <?php echo $tp['coordinates']['x']; ?>, 
                                Y: <?php echo $tp['coordinates']['y']; ?>, 
                                Z: <?php echo $tp['coordinates']['z']; ?> 
                                (<?php echo $tp['world']; ?>)
                            </div>
                            <div class="teleport-description">
                                <?php echo htmlspecialchars($tp['description']); ?><br>
                                Использований: <?php echo $tp['usage_count']; ?> | 
                                Создан: <?php echo $tp['created_at']; ?> | 
                                Автор: <?php echo $tp['created_by']; ?>
                            </div>
                            <div class="teleport-actions">
                                <button class="btn btn-primary" onclick="testTeleport('<?php echo $tp['id']; ?>')">🔍 Тест</button>
                                <button class="btn btn-danger" onclick="deleteTeleport('<?php echo $tp['id']; ?>')">🗑️ Удалить</button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
            
            <!-- Система патчей -->
            <div id="patches" class="tab-content">
                <h2 style="margin-bottom: 2rem;">🔧 Система патчей и обновлений</h2>
                
                <div class="patch-form">
                    <h3>📦 Применить патч</h3>
                    <form id="patchForm">
                        <div class="form-group">
                            <label>Версия патча:</label>
                            <input type="text" class="form-control" name="version" placeholder="1.0.1" required>
                        </div>
                        <div class="form-group">
                            <label>Описание изменений:</label>
                            <textarea class="form-control" name="description" placeholder="Описание что делает этот патч" rows="3" required></textarea>
                        </div>
                        <div class="form-group">
                            <label>Тип изменения:</label>
                            <select class="form-control" id="patchType">
                                <option value="add_teleport">Добавить телепорт</option>
                                <option value="remove_teleport">Удалить телепорт</option>
                                <option value="update_config">Обновить конфигурацию</option>
                            </select>
                        </div>
                        
                        <!-- Форма для добавления телепорта в патче -->
                        <div id="addTeleportPatch">
                            <h4>Данные нового телепорта:</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                <input type="text" class="form-control" placeholder="Название" id="patchTeleportName">
                                <select class="form-control" id="patchTeleportWorld">
                                    <option value="default">Основной мир</option>
                                    <option value="nether">Ад</option>
                                    <option value="end">Край</option>
                                    <option value="creative">Творческий</option>
                                </select>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-top: 1rem;">
                                <input type="number" class="form-control" placeholder="X" id="patchTeleportX">
                                <input type="number" class="form-control" placeholder="Y" id="patchTeleportY">
                                <input type="number" class="form-control" placeholder="Z" id="patchTeleportZ">
                            </div>
                            <textarea class="form-control" placeholder="Описание" id="patchTeleportDesc" rows="2" style="margin-top: 1rem;"></textarea>
                        </div>
                        
                        <div class="patch-preview" id="patchPreview">
                            Предпросмотр патча появится здесь...
                        </div>
                        
                        <button type="button" class="btn btn-primary" onclick="generatePatchPreview()">👁️ Предпросмотр</button>
                        <button type="submit" class="btn btn-success">🚀 Применить патч</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <div id="notification" class="notification"></div>
    
    <script>
        // Переменные
        let currentFilter = '';
        
        // Показ вкладок
        function showTab(tabName) {
            // Скрываем все вкладки
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Убираем активность с кнопок
            document.querySelectorAll('.nav-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Показываем нужную вкладку
            document.getElementById(tabName).classList.add('active');
            
            // Активируем кнопку
            event.target.classList.add('active');
        }
        
        // Уведомления
        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = `notification ${type}`;
            notification.classList.add('show');
            
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }
        
        // Создание телепорта
        document.getElementById('createTeleportForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.append('action', 'create_teleport');
            
            try {
                const response = await fetch('rp_teleport_plugin.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('Телепорт успешно создан!');
                    this.reset();
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showNotification(result.message, 'error');
                }
            } catch (error) {
                showNotification('Ошибка при создании телепорта', 'error');
            }
        });
        
        // Удаление телепорта
        async function deleteTeleport(teleportId) {
            if (!confirm('Вы уверены, что хотите удалить этот телепорт?')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'delete_teleport');
            formData.append('teleport_id', teleportId);
            
            try {
                const response = await fetch('rp_teleport_plugin.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('Телепорт удален!');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showNotification(result.message, 'error');
                }
            } catch (error) {
                showNotification('Ошибка при удалении телепорта', 'error');
            }
        }
        
        // Тест телепорта
        async function testTeleport(teleportId) {
            const formData = new FormData();
            formData.append('action', 'teleport_player');
            formData.append('player_id', 'admin_test');
            formData.append('teleport_id', teleportId);
            
            try {
                const response = await fetch('rp_teleport_plugin.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification(`Тест прошел успешно! Координаты: ${result.coordinates.x}, ${result.coordinates.y}, ${result.coordinates.z}`);
                } else {
                    showNotification(result.message, 'error');
                }
            } catch (error) {
                showNotification('Ошибка при тестировании телепорта', 'error');
            }
        }
        
        // Фильтрация по миру
        function filterByWorld(world) {
            currentFilter = world;
            
            // Обновляем активную кнопку
            document.querySelectorAll('.world-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Фильтруем телепорты
            const teleports = document.querySelectorAll('.teleport-item');
            teleports.forEach(item => {
                if (world === '' || item.dataset.world === world) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        }
        
        // Поиск телепортов
        document.getElementById('teleportSearch').addEventListener('input', function(e) {
            const search = e.target.value.toLowerCase();
            const teleports = document.querySelectorAll('.teleport-item');
            
            teleports.forEach(item => {
                const name = item.querySelector('h4').textContent.toLowerCase();
                const description = item.querySelector('.teleport-description').textContent.toLowerCase();
                
                if (name.includes(search) || description.includes(search)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        });
        
        // Обновление формы патча в зависимости от типа
        document.getElementById('patchType').addEventListener('change', function(e) {
            const addTeleportDiv = document.getElementById('addTeleportPatch');
            if (e.target.value === 'add_teleport') {
                addTeleportDiv.style.display = 'block';
            } else {
                addTeleportDiv.style.display = 'none';
            }
        });
        
        // Генерация предпросмотра патча
        function generatePatchPreview() {
            const patchType = document.getElementById('patchType').value;
            const version = document.querySelector('[name="version"]').value;
            const description = document.querySelector('[name="description"]').value;
            
            let patchData = {
                version: version,
                description: description,
                changes: []
            };
            
            if (patchType === 'add_teleport') {
                const name = document.getElementById('patchTeleportName').value;
                const world = document.getElementById('patchTeleportWorld').value;
                const x = document.getElementById('patchTeleportX').value;
                const y = document.getElementById('patchTeleportY').value;
                const z = document.getElementById('patchTeleportZ').value;
                const desc = document.getElementById('patchTeleportDesc').value;
                
                patchData.changes.push({
                    type: 'add_teleport',
                    data: {
                        name: name,
                        world: world,
                        x: parseFloat(x),
                        y: parseFloat(y),
                        z: parseFloat(z),
                        description: desc
                    }
                });
            }
            
            document.getElementById('patchPreview').textContent = JSON.stringify(patchData, null, 2);
        }
        
        // Применение патча
        document.getElementById('patchForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const patchType = document.getElementById('patchType').value;
            const version = document.querySelector('[name="version"]').value;
            const description = document.querySelector('[name="description"]').value;
            
            let patchData = {
                version: version,
                description: description,
                changes: []
            };
            
            if (patchType === 'add_teleport') {
                const name = document.getElementById('patchTeleportName').value;
                const world = document.getElementById('patchTeleportWorld').value;
                const x = document.getElementById('patchTeleportX').value;
                const y = document.getElementById('patchTeleportY').value;
                const z = document.getElementById('patchTeleportZ').value;
                const desc = document.getElementById('patchTeleportDesc').value;
                
                patchData.changes.push({
                    type: 'add_teleport',
                    data: {
                        name: name,
                        world: world,
                        x: parseFloat(x),
                        y: parseFloat(y),
                        z: parseFloat(z),
                        description: desc
                    }
                });
            }
            
            const formData = new FormData();
            formData.append('action', 'apply_patch');
            formData.append('patch_data', JSON.stringify(patchData));
            
            try {
                const response = await fetch('rp_teleport_plugin.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('Патч успешно применен!');
                    this.reset();
                } else {
                    showNotification(result.message, 'error');
                }
            } catch (error) {
                showNotification('Ошибка при применении патча', 'error');
            }
        });
    </script>
</body>
</html>
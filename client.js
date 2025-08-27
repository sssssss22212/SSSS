// Глобальные переменные
let socket = null;
let currentUser = null;
let currentRoom = null;
let gameState = null;
let myRole = null;
let selectedPlayer = null;
let onlineCount = 0;

// Подключение к серверу
function connectToServer() {
    socket = io();
    
    socket.on('connect', () => {
        console.log('Подключено к серверу');
        showScreen('auth-screen');
        showNotification('Подключено к серверу!', 'success');
    });

    socket.on('disconnect', () => {
        console.log('Отключено от сервера');
        showNotification('Соединение потеряно!', 'error');
    });

    // Обработчики авторизации
    socket.on('register-success', (message) => {
        showNotification(message, 'success');
        showLogin();
    });

    socket.on('register-error', (error) => {
        showNotification(error, 'error');
    });

    socket.on('login-success', (data) => {
        currentUser = data.user;
        onlineCount = data.onlineCount;
        showScreen('main-menu');
        updateUI();
        showNotification(`Добро пожаловать, ${currentUser.username}!`, 'success');
        updateOnlineCount(onlineCount);
    });

    socket.on('login-error', (error) => {
        showNotification(error, 'error');
    });

    // Обработчики комнат
    socket.on('room-created', (room) => {
        currentRoom = room;
        showScreen('game-lobby');
        updateLobbyUI();
        showNotification('Комната создана!', 'success');
    });

    socket.on('room-joined', (room) => {
        currentRoom = room;
        showScreen('game-lobby');
        updateLobbyUI();
        showNotification('Присоединились к комнате!', 'success');
    });

    socket.on('join-error', (error) => {
        showNotification(error, 'error');
    });

    socket.on('player-joined', (data) => {
        currentRoom = data.room;
        updateLobbyUI();
        showNotification(`${data.player.username} присоединился к игре`, 'info');
    });

    socket.on('player-left', (data) => {
        currentRoom = data.room;
        updateLobbyUI();
        showNotification(`Игрок покинул комнату`, 'info');
    });

    socket.on('player-ready-update', (data) => {
        const player = currentRoom.players.find(p => p.id === data.playerId);
        if (player) {
            player.ready = data.ready;
            updateLobbyUI();
        }
    });

    // Игровые обработчики
    socket.on('game-started', (data) => {
        currentRoom = data.room;
        myRole = data.yourRole;
        gameState = currentRoom.gameData;
        showScreen('game-screen');
        updateGameUI();
        showRole();
        showNotification('Игра началась!', 'success');
    });

    socket.on('phase-changed', (data) => {
        gameState.phase = data.phase;
        gameState.day = data.day;
        gameState.timer = data.timer;
        updatePhaseUI();
        updateTimerUI();
        
        if (data.phase === 'night') {
            document.body.classList.add('dark-theme');
            document.getElementById('stars').style.opacity = '1';
        } else {
            document.body.classList.remove('dark-theme');
            document.getElementById('stars').style.opacity = '0';
        }
    });

    socket.on('timer-update', (data) => {
        gameState.timer = data.timer;
        updateTimerUI();
    });

    socket.on('chat-message', (message) => {
        addChatMessage(message);
    });

    socket.on('player-eliminated', (data) => {
        const player = currentRoom.players.find(p => p.id === data.player.id);
        if (player) {
            player.alive = false;
        }
        updateGameUI();
        showNotification(`${data.player.username} был исключен!`, 'info');
        addChatMessage({
            user: 'Система',
            text: `${data.player.username} был исключен голосованием! Роль: ${getRoleName(data.player.role)}`,
            type: 'system'
        });
    });

    socket.on('night-results', (results) => {
        results.forEach(result => {
            addChatMessage({
                user: 'Система',
                text: result,
                type: 'death'
            });
        });
        updateGameUI();
    });

    socket.on('check-result', (data) => {
        showNotification(`${data.target}: ${data.result === 'mafia' ? 'Мафия' : 'Не мафия'}`, 'info');
    });

    socket.on('action-confirmed', (message) => {
        showNotification(message, 'success');
    });

    socket.on('game-ended', (data) => {
        showGameResults(data);
    });

    socket.on('online-update', (count) => {
        onlineCount = count;
        updateOnlineCount(count);
    });

    // Магазин
    socket.on('buy-success', (data) => {
        currentUser = data.user;
        updateUI();
        showNotification('Предмет куплен!', 'success');
    });

    socket.on('buy-error', (error) => {
        showNotification(error, 'error');
    });
}

// Управление экранами
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

// Создание частиц
function createParticles() {
    const particlesContainer = document.getElementById('particles');
    for (let i = 0; i < 50; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.top = Math.random() * 100 + '%';
        particle.style.width = Math.random() * 4 + 2 + 'px';
        particle.style.height = particle.style.width;
        particle.style.animationDelay = Math.random() * 6 + 's';
        particle.style.animationDuration = (Math.random() * 3 + 3) + 's';
        particlesContainer.appendChild(particle);
    }
}

// Создание звезд
function createStars() {
    const starsContainer = document.getElementById('stars');
    for (let i = 0; i < 200; i++) {
        const star = document.createElement('div');
        star.className = 'star';
        star.style.left = Math.random() * 100 + '%';
        star.style.top = Math.random() * 100 + '%';
        star.style.width = Math.random() * 3 + 1 + 'px';
        star.style.height = star.style.width;
        star.style.animationDelay = Math.random() * 3 + 's';
        starsContainer.appendChild(star);
    }
}

// Авторизация
function showRegister() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

function showLogin() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
}

function register() {
    const username = document.getElementById('reg-username').value.trim();
    const password = document.getElementById('reg-password').value;
    const email = document.getElementById('reg-email').value.trim();

    if (!username || !password || !email) {
        showNotification('Заполните все поля!', 'error');
        return;
    }

    socket.emit('register', { username, password, email });
}

function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) {
        showNotification('Заполните все поля!', 'error');
        return;
    }

    socket.emit('login', { username, password });
}

function logout() {
    currentUser = null;
    currentRoom = null;
    gameState = null;
    myRole = null;
    socket.disconnect();
    showScreen('loading-screen');
    setTimeout(() => {
        connectToServer();
    }, 1000);
}

// Обновление интерфейса
function updateUI() {
    if (currentUser) {
        document.getElementById('user-name').textContent = currentUser.username;
        document.getElementById('user-coins').textContent = currentUser.coins;
        document.getElementById('user-level').textContent = `Уровень ${currentUser.level}`;
        document.getElementById('user-avatar').textContent = currentUser.username[0].toUpperCase();
        
        // Применяем кастомизацию
        applyUserCustomization();
    }
}

function updateOnlineCount(count) {
    const element = document.getElementById('online-count');
    if (element) {
        element.textContent = `Онлайн: ${count}`;
    }
}

function applyUserCustomization() {
    if (!currentUser) return;
    
    // Применяем тему
    if (currentUser.inventory.includes('theme-dark')) {
        document.body.classList.add('dark-theme');
    }
    
    // Применяем аватар
    const avatar = document.getElementById('user-avatar');
    if (currentUser.inventory.includes('avatar-rainbow')) {
        avatar.style.background = 'conic-gradient(red, yellow, green, blue, purple, red)';
    } else if (currentUser.inventory.includes('avatar-gold')) {
        avatar.style.background = 'linear-gradient(135deg, #f39c12, #e67e22)';
    }
}

// Лобби
function createRoom() {
    const roomName = prompt('Название комнаты:') || `Комната ${currentUser.username}`;
    const maxPlayers = parseInt(prompt('Максимум игроков (4-16):') || '10');
    
    if (maxPlayers < 4 || maxPlayers > 16) {
        showNotification('Количество игроков должно быть от 4 до 16!', 'error');
        return;
    }

    socket.emit('create-room', {
        name: roomName,
        maxPlayers: maxPlayers,
        roles: ['mafia', 'don', 'sheriff', 'doctor', 'citizen', 'maniac', 'prostitute']
    });
}

function joinRoom() {
    const roomCode = prompt('Код комнаты:');
    if (roomCode) {
        socket.emit('join-room', roomCode.toUpperCase());
    }
}

function toggleReady() {
    if (currentRoom) {
        socket.emit('player-ready', currentRoom.code);
    }
}

function startGame() {
    if (currentRoom) {
        socket.emit('start-game', currentRoom.code);
    }
}

function updateLobbyUI() {
    if (!currentRoom) return;
    
    document.getElementById('room-code').textContent = currentRoom.code;
    document.getElementById('room-name').textContent = currentRoom.name;
    document.getElementById('player-count').textContent = `${currentRoom.players.length}/${currentRoom.maxPlayers}`;
    
    const container = document.getElementById('lobby-players');
    container.innerHTML = '';

    currentRoom.players.forEach(player => {
        const playerCard = document.createElement('div');
        playerCard.className = `player-card alive ${player.ready ? 'ready' : ''}`;
        
        playerCard.innerHTML = `
            <div class="player-avatar">${player.username[0].toUpperCase()}</div>
            <div><strong>${player.username}</strong></div>
            <div class="player-status">
                ${player.id === currentRoom.host ? '<span class="ready-indicator">👑 Хост</span>' : ''}
                ${player.ready ? '<span class="ready-indicator">✓ Готов</span>' : '<span>⏳ Не готов</span>'}
            </div>
        `;
        container.appendChild(playerCard);
    });

    // Показываем кнопку старта только хосту
    const startBtn = document.getElementById('start-game-btn');
    if (startBtn) {
        startBtn.style.display = (currentUser.id === currentRoom.host) ? 'block' : 'none';
    }
}

// Игра
function showRole() {
    if (!myRole) return;
    
    const roleData = getRoleData(myRole);
    const roleCard = document.getElementById('role-card');
    
    document.getElementById('role-icon').textContent = roleData.icon;
    document.getElementById('role-name').textContent = roleData.name;
    document.getElementById('role-description').textContent = roleData.description;
    
    roleCard.style.display = 'block';
    
    setTimeout(() => {
        roleCard.style.display = 'none';
    }, 6000);
}

function updateGameUI() {
    if (!currentRoom) return;
    
    const container = document.getElementById('game-players');
    container.innerHTML = '';

    currentRoom.players.forEach(player => {
        const playerCard = document.createElement('div');
        playerCard.className = `player-card ${player.alive ? 'alive' : 'dead'}`;
        playerCard.onclick = () => selectPlayer(player);
        
        playerCard.innerHTML = `
            <div class="player-avatar">${player.username[0].toUpperCase()}</div>
            <div><strong>${player.username}</strong></div>
            <div class="player-status">
                ${!player.alive ? '<span style="color: red;">💀 Мертв</span>' : '<span style="color: green;">💚 Жив</span>'}
            </div>
        `;
        container.appendChild(playerCard);
    });
    
    updatePhaseUI();
    updateTimerUI();
}

function updatePhaseUI() {
    if (!gameState) return;
    
    const indicator = document.getElementById('phase-indicator');
    indicator.className = 'phase-indicator';
    
    if (gameState.phase === 'day') {
        indicator.className += ' phase-day';
        indicator.textContent = `☀️ День ${gameState.day} - Обсуждение`;
    } else if (gameState.phase === 'voting') {
        indicator.className += ' phase-voting';
        indicator.textContent = '🗳️ Голосование';
        showVotingUI();
    } else if (gameState.phase === 'night') {
        indicator.className += ' phase-night';
        indicator.textContent = `🌙 Ночь ${gameState.day}`;
        showNightActionsUI();
    }
}

function updateTimerUI() {
    if (!gameState) return;
    
    const minutes = Math.floor(gameState.timer / 60);
    const seconds = gameState.timer % 60;
    document.getElementById('game-timer').textContent = 
        `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}

function selectPlayer(player) {
    if (!player.alive || player.id === currentUser.id) return;
    
    document.querySelectorAll('.player-card').forEach(card => {
        card.classList.remove('selected');
    });
    
    event.target.closest('.player-card').classList.add('selected');
    selectedPlayer = player;
}

function showVotingUI() {
    const votingArea = document.getElementById('voting-area');
    if (votingArea) {
        votingArea.style.display = 'block';
        
        const container = document.getElementById('vote-players');
        container.innerHTML = '';

        currentRoom.players.filter(p => p.alive && p.id !== currentUser.id).forEach(player => {
            const button = document.createElement('button');
            button.className = 'btn';
            button.textContent = player.username;
            button.onclick = () => {
                selectedPlayer = player;
                document.querySelectorAll('#vote-players .btn').forEach(b => b.classList.remove('btn-danger'));
                button.classList.add('btn-danger');
            };
            container.appendChild(button);
        });
    }
}

function submitVote() {
    if (!selectedPlayer) {
        showNotification('Выберите игрока для голосования!', 'error');
        return;
    }
    
    socket.emit('game-action', {
        roomCode: currentRoom.code,
        action: 'vote',
        target: selectedPlayer.id
    });
    
    showNotification('Голос отдан!', 'success');
    document.getElementById('vote-btn').disabled = true;
}

function showNightActionsUI() {
    const actionsContainer = document.getElementById('action-buttons');
    actionsContainer.innerHTML = '';
    
    if (!myRole || !hasNightAction(myRole)) {
        actionsContainer.innerHTML = '<p class="card" style="text-align: center;">😴 Спите спокойно... Ваша роль не действует ночью.</p>';
        return;
    }
    
    const actionButton = document.createElement('button');
    actionButton.className = 'btn btn-warning';
    actionButton.textContent = getNightActionText(myRole);
    actionButton.onclick = performNightAction;
    actionsContainer.appendChild(actionButton);
}

function performNightAction() {
    if (!selectedPlayer) {
        showNotification('Выберите цель!', 'error');
        return;
    }
    
    socket.emit('game-action', {
        roomCode: currentRoom.code,
        action: 'night-action',
        target: selectedPlayer.id,
        actionType: myRole
    });
    
    document.getElementById('action-buttons').innerHTML = '<p class="card" style="text-align: center;">✅ Действие выполнено. Ждите рассвета...</p>';
}

// Чат
function sendMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    
    if (!message) return;
    
    socket.emit('chat-message', {
        roomCode: currentRoom.code,
        message: message
    });
    
    input.value = '';
}

function addChatMessage(message) {
    const chatContainer = document.getElementById('game-chat');
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${message.type || ''}`;
    
    const time = new Date(message.timestamp || new Date()).toLocaleTimeString();
    messageDiv.innerHTML = `
        <strong>${message.user}:</strong> ${message.text}
        <small style="float: right; opacity: 0.7;">${time}</small>
    `;
    
    chatContainer.appendChild(messageDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

// Магазин
function buyItem(itemId, price) {
    socket.emit('buy-item', { itemId, price });
}

// Результаты игры
function showGameResults(data) {
    let winnerText = '';
    switch (data.winner) {
        case 'citizens':
            winnerText = '👥 Мирные жители победили!';
            break;
        case 'mafia':
            winnerText = '🔫 Мафия победила!';
            break;
        default:
            winnerText = `🏆 ${data.winner} победил!`;
    }
    
    showNotification(winnerText, 'success');
    
    setTimeout(() => {
        showScreen('main-menu');
        currentRoom = null;
        gameState = null;
        myRole = null;
    }, 5000);
}

// Утилиты
function getRoleData(roleKey) {
    const roles = {
        mafia: { name: 'Мафия', icon: '🔫', description: 'Убивайте мирных жителей по ночам' },
        don: { name: 'Дон мафии', icon: '👑', description: 'Главарь мафии с особыми способностями' },
        sheriff: { name: 'Шериф', icon: '👮', description: 'Проверяйте игроков на принадлежность к мафии' },
        doctor: { name: 'Доктор', icon: '👨‍⚕️', description: 'Лечите игроков от смерти' },
        citizen: { name: 'Мирный житель', icon: '👤', description: 'Найдите и исключите всех мафиози' },
        maniac: { name: 'Маньяк', icon: '🔪', description: 'Убивайте всех подряд' },
        prostitute: { name: 'Путана', icon: '💋', description: 'Блокируйте действия игроков' },
        lawyer: { name: 'Адвокат', icon: '👨‍💼', description: 'Защищайте игроков от исключения' }
    };
    return roles[roleKey] || { name: 'Неизвестная роль', icon: '❓', description: '' };
}

function getRoleName(roleKey) {
    return getRoleData(roleKey).name;
}

function hasNightAction(role) {
    const nightRoles = ['mafia', 'don', 'sheriff', 'doctor', 'maniac', 'prostitute'];
    return nightRoles.includes(role);
}

function getNightActionText(role) {
    const actions = {
        mafia: 'Выберите цель для убийства',
        don: 'Выберите цель для убийства',
        sheriff: 'Выберите игрока для проверки',
        doctor: 'Выберите игрока для лечения',
        maniac: 'Выберите цель для убийства',
        prostitute: 'Выберите игрока для блокировки'
    };
    return actions[role] || 'Выберите цель';
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 4000);
}

// Инициализация
window.onload = function() {
    createParticles();
    createStars();
    connectToServer();
    
    // Обработчики событий
    document.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const activeElement = document.activeElement;
            if (activeElement.id === 'chat-input') {
                sendMessage();
            } else if (activeElement.id === 'password') {
                login();
            } else if (activeElement.id === 'reg-email') {
                register();
            }
        }
    });
};

// Дополнительные функции
function leaveRoom() {
    if (currentRoom) {
        socket.emit('leave-room', currentRoom.code);
        currentRoom = null;
        showScreen('main-menu');
    }
}

function leaveGame() {
    if (currentRoom) {
        socket.emit('leave-game', currentRoom.code);
        currentRoom = null;
        gameState = null;
        myRole = null;
        document.body.classList.remove('dark-theme');
        document.getElementById('stars').style.opacity = '0';
        showScreen('main-menu');
    }
}

function quickMatch() {
    showNotification('Поиск игры...', 'info');
    // Попытка присоединиться к случайной комнате
    setTimeout(() => {
        // Если нет доступных комнат, создаем новую
        createRoom();
    }, 2000);
}

function saveSettings() {
    if (!currentUser) return;
    
    const settings = {
        sound: document.getElementById('sound-toggle').checked,
        animations: document.getElementById('animation-toggle').checked,
        notifications: document.getElementById('notification-toggle').checked,
        theme: document.getElementById('theme-select').value,
        language: document.getElementById('language-select').value
    };
    
    // Применяем настройки
    if (settings.theme === 'dark') {
        document.body.classList.add('dark-theme');
    } else if (settings.theme === 'light') {
        document.body.classList.remove('dark-theme');
    }
    
    showNotification('Настройки сохранены!', 'success');
}

// Загрузка рейтинга
function loadLeaderboard() {
    fetch('/api/leaderboard')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('leaderboard-list');
            container.innerHTML = '';
            
            data.forEach((player, index) => {
                const playerDiv = document.createElement('div');
                playerDiv.className = 'card';
                playerDiv.style.margin = '10px 0';
                playerDiv.style.padding = '15px';
                playerDiv.style.display = 'flex';
                playerDiv.style.justifyContent = 'space-between';
                playerDiv.style.alignItems = 'center';
                
                let medal = '';
                if (index === 0) medal = '🥇';
                else if (index === 1) medal = '🥈';
                else if (index === 2) medal = '🥉';
                else medal = `${index + 1}.`;
                
                playerDiv.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span style="font-size: 1.5rem; min-width: 40px;">${medal}</span>
                        <div>
                            <strong>${player.username}</strong>
                            <div style="font-size: 0.9rem; opacity: 0.7;">Уровень ${player.level}</div>
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div><strong>${player.gamesWon}</strong> побед</div>
                        <div style="font-size: 0.9rem; opacity: 0.7;">${player.winRate}% побед</div>
                    </div>
                `;
                
                container.appendChild(playerDiv);
            });
        })
        .catch(error => {
            console.error('Ошибка загрузки рейтинга:', error);
            document.getElementById('leaderboard-list').innerHTML = 
                '<div class="card" style="text-align: center; padding: 30px;">Ошибка загрузки рейтинга</div>';
        });
}

// Загрузка рейтинга при открытии экрана
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
    
    // Специальные действия для определенных экранов
    if (screenId === 'leaderboard') {
        loadLeaderboard();
    } else if (screenId === 'profile' && currentUser) {
        updateProfileStats();
    }
}

function updateProfileStats() {
    if (!currentUser) return;
    
    document.getElementById('profile-username').textContent = currentUser.username;
    document.getElementById('profile-level').textContent = `Уровень ${currentUser.level}`;
    document.getElementById('profile-coins').textContent = currentUser.coins;
    document.getElementById('games-played').textContent = currentUser.stats.gamesPlayed;
    document.getElementById('games-won').textContent = currentUser.stats.gamesWon;
    document.getElementById('total-coins').textContent = currentUser.stats.totalCoins;
    
    const winRate = currentUser.stats.gamesPlayed > 0 ? 
        Math.round((currentUser.stats.gamesWon / currentUser.stats.gamesPlayed) * 100) : 0;
    document.getElementById('win-rate').textContent = winRate + '%';
}

// Звуковые эффекты (заглушки)
function playSound(soundName) {
    // В будущем здесь можно добавить воспроизведение звуков
    console.log(`Играет звук: ${soundName}`);
}

// Управление анимациями
function toggleAnimations(enabled) {
    if (enabled) {
        document.body.classList.remove('no-animations');
    } else {
        document.body.classList.add('no-animations');
    }
}
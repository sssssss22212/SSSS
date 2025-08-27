const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(express.static('.'));
app.use(express.json());

// Файлы для хранения данных
const USERS_FILE = './data/users.json';
const ROOMS_FILE = './data/rooms.json';
const STATS_FILE = './data/stats.json';

// Структуры данных
let users = new Map();
let rooms = new Map();
let gameStats = {
    totalGames: 0,
    totalPlayers: 0,
    onlineUsers: 0
};

// Создание директории для данных
async function ensureDataDir() {
    try {
        await fs.mkdir('./data', { recursive: true });
    } catch (err) {
        console.log('Data directory already exists');
    }
}

// Загрузка данных
async function loadData() {
    try {
        await ensureDataDir();
        
        // Загрузка пользователей
        try {
            const usersData = await fs.readFile(USERS_FILE, 'utf8');
            const usersArray = JSON.parse(usersData);
            users = new Map(usersArray.map(user => [user.id, user]));
        } catch (err) {
            console.log('Creating new users file');
            await saveUsers();
        }

        // Загрузка комнат
        try {
            const roomsData = await fs.readFile(ROOMS_FILE, 'utf8');
            const roomsArray = JSON.parse(roomsData);
            rooms = new Map(roomsArray.map(room => [room.code, room]));
        } catch (err) {
            console.log('Creating new rooms file');
            await saveRooms();
        }

        // Загрузка статистики
        try {
            const statsData = await fs.readFile(STATS_FILE, 'utf8');
            gameStats = JSON.parse(statsData);
        } catch (err) {
            console.log('Creating new stats file');
            await saveStats();
        }
    } catch (err) {
        console.error('Error loading data:', err);
    }
}

// Сохранение данных
async function saveUsers() {
    try {
        const usersArray = Array.from(users.values());
        await fs.writeFile(USERS_FILE, JSON.stringify(usersArray, null, 2));
    } catch (err) {
        console.error('Error saving users:', err);
    }
}

async function saveRooms() {
    try {
        const roomsArray = Array.from(rooms.values());
        await fs.writeFile(ROOMS_FILE, JSON.stringify(roomsArray, null, 2));
    } catch (err) {
        console.error('Error saving rooms:', err);
    }
}

async function saveStats() {
    try {
        await fs.writeFile(STATS_FILE, JSON.stringify(gameStats, null, 2));
    } catch (err) {
        console.error('Error saving stats:', err);
    }
}

// Роли в игре (расширенные)
const roles = {
    mafia: { name: 'Мафия', icon: '🔫', team: 'mafia', nightAction: true },
    don: { name: 'Дон мафии', icon: '👑', team: 'mafia', nightAction: true },
    sheriff: { name: 'Шериф', icon: '👮', team: 'citizen', nightAction: true },
    doctor: { name: 'Доктор', icon: '👨‍⚕️', team: 'citizen', nightAction: true },
    citizen: { name: 'Мирный житель', icon: '👤', team: 'citizen', nightAction: false },
    maniac: { name: 'Маньяк', icon: '🔪', team: 'maniac', nightAction: true },
    prostitute: { name: 'Путана', icon: '💋', team: 'citizen', nightAction: true },
    lawyer: { name: 'Адвокат', icon: '👨‍💼', team: 'citizen', nightAction: false },
    kamikaze: { name: 'Камикадзе', icon: '💣', team: 'citizen', nightAction: false },
    lover: { name: 'Любовник', icon: '💕', team: 'lover', nightAction: false },
    witch: { name: 'Ведьма', icon: '🧙‍♀️', team: 'citizen', nightAction: true },
    werewolf: { name: 'Оборотень', icon: '🐺', team: 'werewolf', nightAction: true },
    ghost: { name: 'Призрак', icon: '👻', team: 'citizen', nightAction: true },
    angel: { name: 'Ангел', icon: '😇', team: 'citizen', nightAction: true }
};

// WebSocket подключения
const connectedUsers = new Map();

io.on('connection', (socket) => {
    console.log('Пользователь подключился:', socket.id);
    gameStats.onlineUsers++;
    
    // Регистрация пользователя
    socket.on('register', async (userData) => {
        try {
            const { username, password, email } = userData;
            
            // Проверка на существование пользователя
            const existingUser = Array.from(users.values()).find(u => u.username === username);
            if (existingUser) {
                socket.emit('register-error', 'Пользователь уже существует');
                return;
            }

            const newUser = {
                id: Date.now() + Math.random(),
                username,
                password,
                email,
                coins: 200,
                rank: 'Новичок',
                level: 1,
                experience: 0,
                stats: {
                    gamesPlayed: 0,
                    gamesWon: 0,
                    totalCoins: 200,
                    favoriteRole: 'citizen',
                    killCount: 0,
                    survivalRate: 0
                },
                inventory: ['avatar-blue', 'theme-light'],
                achievements: [],
                settings: {
                    sound: true,
                    animations: true,
                    notifications: true,
                    theme: 'light'
                },
                friends: [],
                blocked: [],
                lastLogin: new Date(),
                createdAt: new Date()
            };

            users.set(newUser.id, newUser);
            await saveUsers();
            
            socket.emit('register-success', 'Регистрация успешна');
        } catch (err) {
            socket.emit('register-error', 'Ошибка регистрации');
        }
    });

    // Авторизация пользователя
    socket.on('login', async (loginData) => {
        try {
            const { username, password } = loginData;
            const user = Array.from(users.values()).find(u => u.username === username && u.password === password);
            
            if (!user) {
                socket.emit('login-error', 'Неверные данные');
                return;
            }

            user.lastLogin = new Date();
            connectedUsers.set(socket.id, user);
            
            socket.emit('login-success', {
                user: user,
                onlineCount: gameStats.onlineUsers
            });
            
            // Обновляем статистику онлайн
            io.emit('online-update', gameStats.onlineUsers);
            
        } catch (err) {
            socket.emit('login-error', 'Ошибка входа');
        }
    });

    // Создание комнаты
    socket.on('create-room', (roomData) => {
        const user = connectedUsers.get(socket.id);
        if (!user) return;

        const roomCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        const newRoom = {
            code: roomCode,
            name: roomData.name || `Комната ${user.username}`,
            host: user.id,
            players: [{ ...user, socketId: socket.id, ready: false }],
            maxPlayers: roomData.maxPlayers || 10,
            gameState: 'lobby',
            settings: {
                dayTime: 300,
                nightTime: 120,
                votingTime: 60,
                roles: roomData.roles || ['mafia', 'don', 'sheriff', 'doctor', 'citizen'],
                customRoles: roomData.customRoles || false
            },
            createdAt: new Date(),
            gameData: null
        };

        rooms.set(roomCode, newRoom);
        socket.join(roomCode);
        
        socket.emit('room-created', newRoom);
        saveRooms();
    });

    // Присоединение к комнате
    socket.on('join-room', (roomCode) => {
        const user = connectedUsers.get(socket.id);
        const room = rooms.get(roomCode);
        
        if (!user || !room) {
            socket.emit('join-error', 'Комната не найдена');
            return;
        }

        if (room.players.length >= room.maxPlayers) {
            socket.emit('join-error', 'Комната заполнена');
            return;
        }

        if (room.gameState !== 'lobby') {
            socket.emit('join-error', 'Игра уже началась');
            return;
        }

        room.players.push({ ...user, socketId: socket.id, ready: false });
        socket.join(roomCode);
        
        socket.emit('room-joined', room);
        io.to(roomCode).emit('player-joined', { player: user, room });
        saveRooms();
    });

    // Готовность к игре
    socket.on('player-ready', (roomCode) => {
        const user = connectedUsers.get(socket.id);
        const room = rooms.get(roomCode);
        
        if (!user || !room) return;

        const player = room.players.find(p => p.id === user.id);
        if (player) {
            player.ready = !player.ready;
            io.to(roomCode).emit('player-ready-update', { playerId: user.id, ready: player.ready });
        }
    });

    // Начало игры
    socket.on('start-game', (roomCode) => {
        const user = connectedUsers.get(socket.id);
        const room = rooms.get(roomCode);
        
        if (!user || !room || room.host !== user.id) return;

        const readyPlayers = room.players.filter(p => p.ready);
        if (readyPlayers.length < 4) {
            socket.emit('game-error', 'Минимум 4 готовых игрока');
            return;
        }

        // Инициализация игры
        initializeGame(room);
        gameStats.totalGames++;
        saveStats();
        saveRooms();
    });

    // Игровые действия
    socket.on('game-action', (data) => {
        const user = connectedUsers.get(socket.id);
        const room = rooms.get(data.roomCode);
        
        if (!user || !room) return;

        handleGameAction(room, user, data);
    });

    // Чат
    socket.on('chat-message', (data) => {
        const user = connectedUsers.get(socket.id);
        const room = rooms.get(data.roomCode);
        
        if (!user || !room) return;

        const message = {
            id: Date.now(),
            user: user.username,
            text: data.message,
            timestamp: new Date(),
            type: data.type || 'public'
        };

        io.to(data.roomCode).emit('chat-message', message);
    });

    // Покупка в магазине
    socket.on('buy-item', async (data) => {
        const user = connectedUsers.get(socket.id);
        if (!user) return;

        const { itemId, price } = data;
        
        if (user.coins < price) {
            socket.emit('buy-error', 'Недостаточно монет');
            return;
        }

        if (user.inventory.includes(itemId)) {
            socket.emit('buy-error', 'Предмет уже куплен');
            return;
        }

        user.coins -= price;
        user.inventory.push(itemId);
        
        users.set(user.id, user);
        await saveUsers();
        
        socket.emit('buy-success', { user, item: itemId });
    });

    // Отключение
    socket.on('disconnect', () => {
        console.log('Пользователь отключился:', socket.id);
        gameStats.onlineUsers--;
        
        const user = connectedUsers.get(socket.id);
        if (user) {
            // Удаляем из всех комнат
            for (const [roomCode, room] of rooms) {
                room.players = room.players.filter(p => p.socketId !== socket.id);
                if (room.players.length === 0) {
                    rooms.delete(roomCode);
                } else {
                    io.to(roomCode).emit('player-left', { playerId: user.id, room });
                }
            }
            
            connectedUsers.delete(socket.id);
            saveRooms();
        }
        
        io.emit('online-update', gameStats.onlineUsers);
    });
});

// Инициализация игры
function initializeGame(room) {
    const players = room.players.filter(p => p.ready);
    
    // Распределение ролей
    const rolesList = distributeRoles(players.length, room.settings.roles);
    
    players.forEach((player, index) => {
        player.role = rolesList[index];
        player.alive = true;
        player.votes = 0;
        player.actions = [];
        player.protected = false;
        player.blocked = false;
    });

    room.gameState = 'playing';
    room.gameData = {
        phase: 'day',
        day: 1,
        timer: room.settings.dayTime,
        votes: new Map(),
        nightActions: [],
        deadPlayers: [],
        gameLog: []
    };

    // Отправляем игрокам их роли
    players.forEach(player => {
        const socket = io.sockets.sockets.get(player.socketId);
        if (socket) {
            socket.emit('game-started', {
                room,
                yourRole: player.role,
                players: players.map(p => ({ ...p, role: undefined })) // Скрываем роли других
            });
        }
    });

    // Запускаем игровой цикл
    startGameCycle(room);
}

// Распределение ролей
function distributeRoles(playerCount, availableRoles) {
    const rolesList = [];
    const mafiaCount = Math.max(1, Math.floor(playerCount / 3));
    
    // Добавляем мафию
    rolesList.push('don');
    for (let i = 1; i < mafiaCount; i++) {
        rolesList.push('mafia');
    }
    
    // Добавляем особые роли
    const specialRoles = availableRoles.filter(role => 
        role !== 'mafia' && role !== 'don' && role !== 'citizen'
    );
    
    const specialCount = Math.min(specialRoles.length, Math.floor(playerCount / 2));
    for (let i = 0; i < specialCount; i++) {
        rolesList.push(specialRoles[i]);
    }
    
    // Остальные - мирные жители
    while (rolesList.length < playerCount) {
        rolesList.push('citizen');
    }
    
    // Перемешиваем
    for (let i = rolesList.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [rolesList[i], rolesList[j]] = [rolesList[j], rolesList[i]];
    }
    
    return rolesList;
}

// Игровой цикл
function startGameCycle(room) {
    const gameInterval = setInterval(() => {
        if (!room.gameData || room.gameState !== 'playing') {
            clearInterval(gameInterval);
            return;
        }

        room.gameData.timer--;
        
        if (room.gameData.timer <= 0) {
            switchPhase(room);
        }
        
        // Отправляем обновление таймера
        io.to(room.code).emit('timer-update', {
            timer: room.gameData.timer,
            phase: room.gameData.phase
        });
        
        // Проверяем окончание игры
        if (checkGameEnd(room)) {
            clearInterval(gameInterval);
        }
        
    }, 1000);
}

// Смена фаз
function switchPhase(room) {
    const gameData = room.gameData;
    
    if (gameData.phase === 'day') {
        gameData.phase = 'voting';
        gameData.timer = room.settings.votingTime;
    } else if (gameData.phase === 'voting') {
        processVoting(room);
        gameData.phase = 'night';
        gameData.timer = room.settings.nightTime;
        gameData.votes.clear();
    } else if (gameData.phase === 'night') {
        processNightActions(room);
        gameData.phase = 'day';
        gameData.day++;
        gameData.timer = room.settings.dayTime;
        gameData.nightActions = [];
    }
    
    io.to(room.code).emit('phase-changed', {
        phase: gameData.phase,
        day: gameData.day,
        timer: gameData.timer
    });
}

// Обработка игровых действий
function handleGameAction(room, user, data) {
    const player = room.players.find(p => p.id === user.id);
    if (!player || !player.alive) return;

    switch (data.action) {
        case 'vote':
            if (room.gameData.phase === 'voting') {
                room.gameData.votes.set(user.id, data.target);
                io.to(room.code).emit('vote-cast', { voter: user.username, target: data.target });
            }
            break;
            
        case 'night-action':
            if (room.gameData.phase === 'night' && roles[player.role].nightAction) {
                room.gameData.nightActions.push({
                    player: user.id,
                    role: player.role,
                    target: data.target,
                    action: data.actionType || 'default'
                });
                
                const socket = io.sockets.sockets.get(player.socketId);
                if (socket) {
                    socket.emit('action-confirmed', 'Действие выполнено');
                }
            }
            break;
    }
}

// Обработка голосования
function processVoting(room) {
    const votes = new Map();
    
    for (const [voterId, targetId] of room.gameData.votes) {
        votes.set(targetId, (votes.get(targetId) || 0) + 1);
    }
    
    let maxVotes = 0;
    let eliminatedPlayer = null;
    
    for (const [playerId, voteCount] of votes) {
        if (voteCount > maxVotes) {
            maxVotes = voteCount;
            eliminatedPlayer = room.players.find(p => p.id === playerId);
        }
    }
    
    if (eliminatedPlayer && maxVotes > 0) {
        eliminatedPlayer.alive = false;
        room.gameData.deadPlayers.push(eliminatedPlayer);
        
        io.to(room.code).emit('player-eliminated', {
            player: eliminatedPlayer,
            votes: maxVotes,
            method: 'voting'
        });
    }
}

// Обработка ночных действий
function processNightActions(room) {
    const actions = room.gameData.nightActions;
    const results = [];
    
    // Группируем действия по типам
    const kills = actions.filter(a => ['mafia', 'don', 'maniac', 'werewolf'].includes(a.role));
    const heals = actions.filter(a => a.role === 'doctor');
    const checks = actions.filter(a => a.role === 'sheriff');
    const blocks = actions.filter(a => a.role === 'prostitute');
    
    // Обрабатываем лечение
    const healedPlayers = new Set();
    heals.forEach(heal => {
        healedPlayers.add(heal.target);
    });
    
    // Обрабатываем убийства
    kills.forEach(kill => {
        const target = room.players.find(p => p.id === kill.target);
        if (target && target.alive && !healedPlayers.has(kill.target)) {
            target.alive = false;
            room.gameData.deadPlayers.push(target);
            results.push(`💀 ${target.username} был убит`);
        }
    });
    
    // Обрабатываем проверки
    checks.forEach(check => {
        const target = room.players.find(p => p.id === check.target);
        const checker = room.players.find(p => p.id === check.player);
        
        if (target && checker) {
            const isMafia = ['mafia', 'don'].includes(target.role);
            const socket = io.sockets.sockets.get(checker.socketId);
            if (socket) {
                socket.emit('check-result', {
                    target: target.username,
                    result: isMafia ? 'mafia' : 'innocent'
                });
            }
        }
    });
    
    // Отправляем результаты ночи
    if (results.length > 0) {
        io.to(room.code).emit('night-results', results);
    }
}

// Проверка окончания игры
function checkGameEnd(room) {
    const alivePlayers = room.players.filter(p => p.alive);
    const aliveMafia = alivePlayers.filter(p => ['mafia', 'don'].includes(p.role));
    const aliveCitizens = alivePlayers.filter(p => !['mafia', 'don', 'maniac', 'werewolf'].includes(p.role));
    
    let winner = null;
    
    if (aliveMafia.length === 0) {
        winner = 'citizens';
    } else if (aliveMafia.length >= aliveCitizens.length) {
        winner = 'mafia';
    }
    
    if (winner) {
        endGame(room, winner);
        return true;
    }
    
    return false;
}

// Окончание игры
async function endGame(room, winner) {
    room.gameState = 'finished';
    
    // Начисляем награды и опыт
    for (const player of room.players) {
        const user = users.get(player.id);
        if (user) {
            user.stats.gamesPlayed++;
            
            const baseReward = 20;
            let reward = baseReward;
            
            // Бонус за победу
            const playerTeam = roles[player.role].team;
            if ((winner === 'citizens' && playerTeam === 'citizen') ||
                (winner === 'mafia' && playerTeam === 'mafia')) {
                user.stats.gamesWon++;
                reward += 30;
            }
            
            // Бонус за выживание
            if (player.alive) {
                reward += 10;
            }
            
            user.coins += reward;
            user.experience += reward;
            user.stats.totalCoins += reward;
            
            // Проверка повышения уровня
            const newLevel = Math.floor(user.experience / 100) + 1;
            if (newLevel > user.level) {
                user.level = newLevel;
                user.coins += newLevel * 10; // Бонус за уровень
            }
            
            users.set(user.id, user);
        }
    }
    
    await saveUsers();
    
    io.to(room.code).emit('game-ended', {
        winner,
        players: room.players,
        gameData: room.gameData
    });
    
    // Удаляем комнату через 30 секунд
    setTimeout(() => {
        rooms.delete(room.code);
        saveRooms();
    }, 30000);
}

// API маршруты
app.get('/api/stats', (req, res) => {
    res.json(gameStats);
});

app.get('/api/leaderboard', (req, res) => {
    const topPlayers = Array.from(users.values())
        .sort((a, b) => b.stats.gamesWon - a.stats.gamesWon)
        .slice(0, 10)
        .map(user => ({
            username: user.username,
            level: user.level,
            gamesWon: user.stats.gamesWon,
            gamesPlayed: user.stats.gamesPlayed,
            winRate: user.stats.gamesPlayed > 0 ? 
                Math.round((user.stats.gamesWon / user.stats.gamesPlayed) * 100) : 0
        }));
    
    res.json(topPlayers);
});

// Запуск сервера
const PORT = process.env.PORT || 3000;

loadData().then(() => {
    server.listen(PORT, () => {
        console.log(`🎮 Сервер мафии запущен на порту ${PORT}`);
        console.log(`📊 Загружено пользователей: ${users.size}`);
        console.log(`🏠 Активных комнат: ${rooms.size}`);
    });
});

// Автосохранение каждые 5 минут
setInterval(async () => {
    await saveUsers();
    await saveRooms();
    await saveStats();
    console.log('📁 Данные автоматически сохранены');
}, 5 * 60 * 1000);
/**
 * Умный автономный бот для Minecraft 1.21.8
 * Версия: 2.0.0
 * Расширенный функционал с обучением, строительством, добычей ресурсов, боем и стратегией
 */

const mineflayer = require('mineflayer');
const { pathfinder, Movements, goals } = require('mineflayer-pathfinder');
const { GoalNear, GoalBlock, GoalXZ, GoalY, GoalFollow, GoalInvert, GoalPlaceBlock } = goals;
const pvp = require('mineflayer-pvp').plugin;
const autoEat = require('mineflayer-auto-eat');
const armorManager = require('mineflayer-armor-manager');
const toolPlugin = require('mineflayer-tool').plugin;
const Vec3 = require('vec3');

// ================== КОНФИГУРАЦИЯ БОТА ==================
const BOT_CONFIG = {
    host: 'n1.netronyx.pro',
    port: 4007,
    username: 'SmartBot_' + Math.floor(Math.random() * 1000),
    version: '1.21.8',
    auth: 'offline',
    hideErrors: false,
    checkTimeoutInterval: 60000,
    logErrors: true
};

// ================== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ==================
let bot = null;
let mcData = null;
let defaultMove = null;
let guardPos = null;
let currentTask = null;
let learningData = {
    successfulMines: {},
    failedMines: {},
    combatVictories: {},
    combatDefeats: {},
    buildingPatterns: [],
    pathingHistory: [],
    resourceLocations: {},
    dangerZones: [],
    safeZones: [],
    toolEfficiency: {},
    craftingRecipes: {}
};

let botState = {
    isIdle: true,
    currentActivity: 'idle',
    health: 20,
    food: 20,
    inventory: {},
    position: null,
    following: null,
    building: false,
    mining: false,
    fighting: false,
    crafting: false,
    exploring: false,
    autoMode: true,
    owner: null
};

let commandQueue = [];
let knowledgeBase = {
    blocks: {},
    mobs: {},
    items: {},
    strategies: {}
};

// ================== СОЗДАНИЕ И ИНИЦИАЛИЗАЦИЯ БОТА ==================
function createBot() {
    console.log('🤖 Создание умного бота для Minecraft...');
    
    bot = mineflayer.createBot(BOT_CONFIG);
    
    // Загрузка плагинов
    bot.loadPlugin(pathfinder);
    bot.loadPlugin(pvp);
    bot.loadPlugin(autoEat);
    bot.loadPlugin(armorManager);
    bot.loadPlugin(toolPlugin);
    
    // Настройка авто-еды
    bot.autoEat.options = {
        priority: 'foodPoints',
        startAt: 14,
        bannedFood: ['rotten_flesh', 'spider_eye', 'poisonous_potato']
    };
    
    setupEventHandlers();
}

// ================== ОБРАБОТЧИКИ СОБЫТИЙ ==================
function setupEventHandlers() {
    bot.once('spawn', onSpawn);
    bot.on('chat', onChat);
    bot.on('whisper', onWhisper);
    bot.on('health', onHealth);
    bot.on('death', onDeath);
    bot.on('kicked', onKicked);
    bot.on('error', onError);
    bot.on('end', onEnd);
    bot.on('entityHurt', onEntityHurt);
    bot.on('playerCollect', onPlayerCollect);
    bot.on('physicsTick', onPhysicsTick);
    bot.on('goal_reached', onGoalReached);
}

function onSpawn() {
    console.log('✅ Бот успешно подключился к серверу!');
    console.log(`📍 Позиция: ${bot.entity.position}`);
    
    mcData = require('minecraft-data')(bot.version);
    defaultMove = new Movements(bot, mcData);
    defaultMove.canDig = true;
    defaultMove.allow1by1towers = true;
    defaultMove.allowFreeMotion = true;
    defaultMove.allowParkour = true;
    defaultMove.allowSprinting = true;
    
    bot.pathfinder.setMovements(defaultMove);
    
    botState.position = bot.entity.position;
    guardPos = bot.entity.position.clone();
    
    initializeKnowledgeBase();
    startAutonomousBehavior();
    startLearningSystem();
    
    bot.chat('Умный бот готов к работе! Используйте команды в чате.');
}

function onChat(username, message) {
    if (username === bot.username) return;
    
    const msg = message.toLowerCase().trim();
    botState.owner = username;
    
    console.log(`💬 [${username}]: ${message}`);
    
    processCommand(username, msg, message);
}

function onWhisper(username, message) {
    if (username === bot.username) return;
    
    const msg = message.toLowerCase().trim();
    console.log(`📨 Шепот от [${username}]: ${message}`);
    
    processCommand(username, msg, message);
}

function onHealth() {
    botState.health = bot.health;
    botState.food = bot.food;
    
    if (bot.health < 8 && !botState.fighting) {
        retreatToSafety();
    }
    
    if (bot.food < 6) {
        eatFood();
    }
}

function onDeath() {
    console.log('💀 Бот умер! Респавн...');
    botState.isIdle = true;
    currentTask = null;
    commandQueue = [];
    
    learningData.combatDefeats.death = (learningData.combatDefeats.death || 0) + 1;
    
    bot.chat('Я умер, но я учусь на своих ошибках!');
    
    setTimeout(() => {
        guardPos = bot.entity.position.clone();
        startAutonomousBehavior();
    }, 2000);
}

function onKicked(reason) {
    console.log(`⚠️ Бот был кикнут: ${reason}`);
}

function onError(err) {
    console.error('❌ Ошибка:', err.message);
}

function onEnd() {
    console.log('🔌 Соединение потеряно. Переподключение через 5 секунд...');
    setTimeout(createBot, 5000);
}

function onEntityHurt(entity) {
    if (entity === bot.entity) {
        const attacker = findNearbyHostileMobs()[0];
        if (attacker && botState.autoMode) {
            defendSelf(attacker);
        }
    }
}

function onPlayerCollect(collector, collected) {
    if (collector === bot.entity) {
        const item = collected.getDroppedItem();
        if (item) {
            console.log(`📦 Подобрал: ${item.name} x${item.count}`);
            updateInventoryKnowledge();
            
            // Автоматически экипируем броню и оружие
            setTimeout(() => {
                equipBestGear();
            }, 500);
        }
    }
}

function onPhysicsTick() {
    // Проверка опасности каждый тик
    if (botState.autoMode && bot.entity) {
        const dangers = checkForDangers();
        if (dangers.length > 0) {
            avoidDangers(dangers);
        }
        
        // Автоматическая защита
        if (!botState.fighting) {
            const hostiles = findNearbyHostileMobs();
            if (hostiles.length > 0 && botState.autoMode) {
                defendSelf(hostiles[0]);
            }
        }
    }
}

function onGoalReached(goal) {
    console.log('🎯 Цель достигнута!');
    if (currentTask) {
        continueCurrentTask();
    }
}

// ================== СИСТЕМА КОМАНД ==================
async function processCommand(username, msg, originalMsg) {
    const args = msg.split(' ');
    const command = args[0];
    
    // Команды движения
    if (command === 'иди' || command === 'go' || command === 'идти') {
        handleGoCommand(args, username);
    }
    else if (command === 'стой' || command === 'stop' || command === 'останься') {
        handleStopCommand(username);
    }
    else if (command === 'следуй' || command === 'follow' || command === 'иди за мной') {
        handleFollowCommand(username);
    }
    else if (command === 'ко' && args[1] === 'мне') {
        handleComeCommand(username);
    }
    
    // Команды добычи
    else if (command === 'копай' || command === 'mine' || command === 'добывай') {
        handleMineCommand(args, username, originalMsg);
    }
    else if (command === 'руби' || command === 'руда' || command === 'дерево') {
        handleTreeCommand(args, username);
    }
    else if (command === 'ломай' || command === 'break') {
        handleBreakCommand(args, username);
    }
    
    // Команды строительства
    else if (command === 'строй' || command === 'build' || command === 'построй') {
        handleBuildCommand(args, username, originalMsg);
    }
    else if (command === 'ставь' || command === 'place' || command === 'поставь') {
        handlePlaceCommand(args, username);
    }
    
    // Команды боя
    else if (command === 'атакуй' || command === 'attack' || command === 'убей' || command === 'бей') {
        handleAttackCommand(args, username);
    }
    else if (command === 'защищайся' || command === 'defend' || command === 'защита') {
        handleDefendCommand(username);
    }
    
    // Команды инвентаря
    else if (command === 'инвентарь' || command === 'inventory' || command === 'inv') {
        handleInventoryCommand(username);
    }
    else if (command === 'drop' || command === 'выброси' || command === 'скинь') {
        handleDropCommand(args, username);
    }
    else if (command === 'экипируй' || command === 'equip' || command === 'надень') {
        handleEquipCommand(username);
    }
    
    // Команды крафта
    else if (command === 'крафт' || command === 'craft' || command === 'скрафти') {
        handleCraftCommand(args, username, originalMsg);
    }
    
    // Команды еды
    else if (command === 'ешь' || command === 'eat' || command === 'поешь') {
        handleEatCommand(username);
    }
    
    // Информационные команды
    else if (command === 'статус' || command === 'status' || command === 'инфо') {
        handleStatusCommand(username);
    }
    else if (command === 'где' || command === 'where' || command === 'позиция') {
        handleWhereCommand(username);
    }
    else if (command === 'помощь' || command === 'help' || command === 'команды') {
        handleHelpCommand(username);
    }
    
    // Режимы работы
    else if (command === 'авто' || command === 'auto') {
        botState.autoMode = !botState.autoMode;
        bot.chat(`Автономный режим: ${botState.autoMode ? 'включен' : 'выключен'}`);
    }
    else if (command === 'охраняй' || command === 'guard') {
        handleGuardCommand(username);
    }
    else if (command === 'исследуй' || command === 'explore') {
        handleExploreCommand(username);
    }
    
    // Обучение
    else if (command === 'учись' || command === 'learn') {
        bot.chat('Я всегда учусь! Собрано данных: ' + Object.keys(learningData.successfulMines).length);
    }
    else if (command === 'статистика' || command === 'stats') {
        showLearningStats(username);
    }
}

// ================== ОБРАБОТЧИКИ КОМАНД ==================
function handleGoCommand(args, username) {
    if (args.length >= 2) {
        const target = args.slice(1).join(' ');
        
        // Проверяем, это координаты или игрок
        if (!isNaN(args[1])) {
            const x = parseFloat(args[1]);
            const y = args[2] ? parseFloat(args[2]) : bot.entity.position.y;
            const z = args[3] ? parseFloat(args[3]) : parseFloat(args[2]);
            
            goToPosition(x, y, z, username);
        } else {
            const player = bot.players[target];
            if (player && player.entity) {
                goToPlayer(target, username);
            } else {
                bot.chat(`Не могу найти игрока ${target}`);
            }
        }
    } else {
        bot.chat('Куда идти? Укажите координаты или имя игрока.');
    }
}

function handleStopCommand(username) {
    bot.pathfinder.setGoal(null);
    botState.isIdle = true;
    botState.following = null;
    currentTask = null;
    commandQueue = [];
    bot.chat('Остановился.');
}

function handleFollowCommand(username) {
    const player = bot.players[username];
    if (player && player.entity) {
        botState.following = username;
        followPlayer(username);
        bot.chat(`Следую за ${username}`);
    } else {
        bot.chat('Не вижу вас рядом!');
    }
}

function handleComeCommand(username) {
    const player = bot.players[username];
    if (player && player.entity) {
        goToPlayer(username, username);
        bot.chat('Иду к вам!');
    } else {
        bot.chat('Не могу найти вас!');
    }
}

async function handleMineCommand(args, username, originalMsg) {
    let blockType = args.slice(1).join(' ');
    
    // Распознаем русские названия блоков
    blockType = translateBlockName(blockType);
    
    if (!blockType) {
        bot.chat('Что добывать? Укажите тип блока (камень, железо, уголь, дерево и т.д.)');
        return;
    }
    
    bot.chat(`Начинаю добычу: ${blockType}`);
    botState.currentActivity = 'mining';
    botState.mining = true;
    
    await mineResource(blockType, 64, username);
}

async function handleTreeCommand(args, username) {
    bot.chat('Ищу дерево...');
    botState.currentActivity = 'mining';
    await mineResource('log', 32, username);
}

async function handleBreakCommand(args, username) {
    const blockType = args.slice(1).join(' ');
    const translated = translateBlockName(blockType);
    
    bot.chat(`Ломаю ${translated || blockType}...`);
    await breakNearbyBlock(translated || blockType, username);
}

async function handleBuildCommand(args, username, originalMsg) {
    const structure = args.slice(1).join(' ');
    
    bot.chat(`Начинаю строительство: ${structure}`);
    botState.currentActivity = 'building';
    botState.building = true;
    
    await buildStructure(structure, username);
}

async function handlePlaceCommand(args, username) {
    const blockType = args.slice(1).join(' ');
    const translated = translateBlockName(blockType);
    
    await placeBlockNearby(translated || blockType, username);
}

async function handleAttackCommand(args, username) {
    const target = args.slice(1).join(' ');
    
    if (target === 'мобы' || target === 'враги' || target === 'mob' || target === 'hostile') {
        attackNearbyHostiles(username);
    } else {
        const entity = findEntityByName(target);
        if (entity) {
            attackEntity(entity, username);
        } else {
            bot.chat(`Не могу найти цель: ${target}`);
        }
    }
}

function handleDefendCommand(username) {
    botState.autoMode = true;
    guardPos = bot.entity.position.clone();
    bot.chat('Режим защиты активирован! Охраняю эту позицию.');
    guardArea();
}

function handleInventoryCommand(username) {
    const items = bot.inventory.items();
    if (items.length === 0) {
        bot.chat('Инвентарь пуст.');
        return;
    }
    
    let inv = 'Инвентарь: ';
    const itemCounts = {};
    
    items.forEach(item => {
        itemCounts[item.name] = (itemCounts[item.name] || 0) + item.count;
    });
    
    const itemList = Object.entries(itemCounts)
        .map(([name, count]) => `${name} x${count}`)
        .slice(0, 10)
        .join(', ');
    
    bot.chat(inv + itemList);
}

async function handleDropCommand(args, username) {
    if (args.length === 1 || args[1] === 'все' || args[1] === 'all') {
        await dropAllItems(username);
    } else {
        const itemName = args.slice(1).join(' ');
        await dropItem(itemName, username);
    }
}

async function handleEquipCommand(username) {
    bot.chat('Экипирую лучшую броню и оружие...');
    await equipBestGear();
    bot.chat('Экипировка завершена!');
}

async function handleCraftCommand(args, username, originalMsg) {
    const itemName = args.slice(1).join(' ');
    const translated = translateItemName(itemName);
    
    bot.chat(`Пытаюсь скрафтить: ${translated || itemName}`);
    await craftItem(translated || itemName, 1, username);
}

async function handleEatCommand(username) {
    await eatFood();
}

function handleStatusCommand(username) {
    const status = `
Статус: ${botState.currentActivity}
Здоровье: ${bot.health}/20
Голод: ${bot.food}/20
Позиция: ${Math.floor(bot.entity.position.x)}, ${Math.floor(bot.entity.position.y)}, ${Math.floor(bot.entity.position.z)}
Предметов: ${bot.inventory.items().length}
Режим: ${botState.autoMode ? 'Авто' : 'Ручной'}
    `.trim();
    
    bot.chat(status);
}

function handleWhereCommand(username) {
    const pos = bot.entity.position;
    bot.chat(`Я на ${Math.floor(pos.x)}, ${Math.floor(pos.y)}, ${Math.floor(pos.z)}`);
}

function handleHelpCommand(username) {
    const commands = `
Команды: иди/стой/следуй/ко мне, копай/ломай/руби, строй/ставь, атакуй/защищайся, 
drop/экипируй/инвентарь, крафт/ешь, статус/где/помощь, авто/охраняй/исследуй
    `.trim();
    
    bot.chat(commands);
}

function handleGuardCommand(username) {
    guardPos = bot.entity.position.clone();
    botState.autoMode = true;
    bot.chat('Охраняю эту позицию!');
    guardArea();
}

function handleExploreCommand(username) {
    bot.chat('Начинаю исследование!');
    botState.currentActivity = 'exploring';
    botState.exploring = true;
    exploreArea();
}

// ================== СИСТЕМА ДВИЖЕНИЯ И НАВИГАЦИИ ==================
async function goToPosition(x, y, z, username) {
    try {
        botState.isIdle = false;
        const goal = new GoalBlock(x, y, z);
        bot.pathfinder.setGoal(goal);
        
        learningData.pathingHistory.push({
            from: bot.entity.position.clone(),
            to: new Vec3(x, y, z),
            timestamp: Date.now()
        });
        
        console.log(`🚶 Иду к позиции: ${x}, ${y}, ${z}`);
    } catch (err) {
        bot.chat('Не могу найти путь туда!');
        console.error(err);
    }
}

async function goToPlayer(playerName, username) {
    const player = bot.players[playerName];
    if (!player || !player.entity) {
        bot.chat(`Не вижу игрока ${playerName}`);
        return;
    }
    
    try {
        const goal = new GoalNear(player.entity.position.x, player.entity.position.y, player.entity.position.z, 2);
        bot.pathfinder.setGoal(goal);
    } catch (err) {
        bot.chat('Не могу найти путь к игроку!');
        console.error(err);
    }
}

function followPlayer(playerName) {
    const player = bot.players[playerName];
    if (!player || !player.entity) {
        bot.chat(`Потерял ${playerName} из виду!`);
        botState.following = null;
        return;
    }
    
    const goal = new GoalFollow(player.entity, 3);
    bot.pathfinder.setGoal(goal, true);
    
    // Продолжаем следовать
    setTimeout(() => {
        if (botState.following === playerName) {
            followPlayer(playerName);
        }
    }, 1000);
}

// ================== СИСТЕМА ДОБЫЧИ РЕСУРСОВ ==================
async function mineResource(blockType, count, username) {
    let mined = 0;
    const maxAttempts = 100;
    let attempts = 0;
    
    while (mined < count && attempts < maxAttempts) {
        attempts++;
        
        // Экипируем лучший инструмент
        await equipBestTool(blockType);
        
        // Ищем ближайший блок
        const block = findNearestBlock(blockType, 64);
        
        if (!block) {
            bot.chat(`Не могу найти ${blockType} поблизости. Исследую дальше...`);
            
            // Запоминаем, что здесь нет ресурса
            learningData.resourceLocations[blockType] = learningData.resourceLocations[blockType] || [];
            
            // Исследуем дальше
            const explorePos = findExplorationPoint();
            if (explorePos) {
                await goToPosition(explorePos.x, explorePos.y, explorePos.z, username);
                await sleep(2000);
                continue;
            } else {
                break;
            }
        }
        
        try {
            // Идем к блоку
            await bot.pathfinder.goto(new GoalBlock(block.position.x, block.position.y, block.position.z));
            
            // Копаем блок
            await bot.dig(block);
            mined++;
            
            console.log(`⛏️ Добыто ${blockType}: ${mined}/${count}`);
            
            // Обучение: успешная добыча
            learningData.successfulMines[blockType] = (learningData.successfulMines[blockType] || 0) + 1;
            
            // Запоминаем локацию ресурса
            if (!learningData.resourceLocations[blockType]) {
                learningData.resourceLocations[blockType] = [];
            }
            learningData.resourceLocations[blockType].push({
                position: block.position.clone(),
                timestamp: Date.now()
            });
            
            if (mined % 10 === 0) {
                bot.chat(`Добыто ${blockType}: ${mined}/${count}`);
            }
            
        } catch (err) {
            console.error('Ошибка добычи:', err.message);
            learningData.failedMines[blockType] = (learningData.failedMines[blockType] || 0) + 1;
            await sleep(500);
        }
        
        // Проверяем инвентарь
        if (bot.inventory.items().length >= 35) {
            bot.chat('Инвентарь почти полон!');
            await organizeInventory();
        }
        
        // Проверяем здоровье и голод
        if (bot.food < 10) {
            await eatFood();
        }
        
        if (bot.health < 10) {
            bot.chat('Мало здоровья! Нужно восстановиться.');
            break;
        }
    }
    
    botState.mining = false;
    bot.chat(`Добыча завершена! Добыто ${blockType}: ${mined} блоков.`);
}

function findNearestBlock(blockType, maxDistance = 64) {
    try {
        const mcData = require('minecraft-data')(bot.version);
        const blockId = mcData.blocksByName[blockType]?.id;
        
        if (!blockId) {
            // Пробуем найти по частичному совпадению
            const possibleBlock = Object.keys(mcData.blocksByName).find(name => 
                name.includes(blockType) || blockType.includes(name)
            );
            
            if (possibleBlock) {
                return bot.findBlock({
                    matching: mcData.blocksByName[possibleBlock].id,
                    maxDistance: maxDistance
                });
            }
            return null;
        }
        
        return bot.findBlock({
            matching: blockId,
            maxDistance: maxDistance
        });
    } catch (err) {
        console.error('Ошибка поиска блока:', err.message);
        return null;
    }
}

async function breakNearbyBlock(blockType, username) {
    const block = findNearestBlock(blockType, 32);
    
    if (!block) {
        bot.chat(`Не вижу ${blockType} рядом!`);
        return;
    }
    
    try {
        await equipBestTool(blockType);
        await bot.pathfinder.goto(new GoalBlock(block.position.x, block.position.y, block.position.z));
        await bot.dig(block);
        bot.chat(`Сломал ${blockType}!`);
    } catch (err) {
        bot.chat('Не смог сломать блок!');
        console.error(err);
    }
}

// ================== СИСТЕМА СТРОИТЕЛЬСТВА ==================
async function buildStructure(structureName, username) {
    const structures = {
        'дом': buildHouse,
        'house': buildHouse,
        'стена': buildWall,
        'wall': buildWall,
        'башня': buildTower,
        'tower': buildTower,
        'мост': buildBridge,
        'bridge': buildBridge,
        'укрытие': buildShelter,
        'shelter': buildShelter,
        'платформа': buildPlatform,
        'platform': buildPlatform
    };
    
    const buildFunction = structures[structureName.toLowerCase()];
    
    if (buildFunction) {
        await buildFunction(username);
    } else {
        bot.chat(`Не знаю как строить ${structureName}. Доступно: дом, стена, башня, мост, укрытие, платформа`);
    }
    
    botState.building = false;
}

async function buildHouse(username) {
    bot.chat('Строю дом! Это займет время...');
    
    const startPos = bot.entity.position.clone();
    const buildMaterial = findBuildingMaterial();
    
    if (!buildMaterial) {
        bot.chat('Нет материалов для строительства!');
        return;
    }
    
    try {
        // Фундамент 5x5
        for (let x = 0; x < 5; x++) {
            for (let z = 0; z < 5; z++) {
                const pos = startPos.offset(x, -1, z);
                await placeBlockAt(buildMaterial, pos);
            }
        }
        
        // Стены
        for (let y = 0; y < 3; y++) {
            // Передняя и задняя стены
            for (let x = 0; x < 5; x++) {
                await placeBlockAt(buildMaterial, startPos.offset(x, y, 0));
                await placeBlockAt(buildMaterial, startPos.offset(x, y, 4));
            }
            
            // Боковые стены
            for (let z = 1; z < 4; z++) {
                await placeBlockAt(buildMaterial, startPos.offset(0, y, z));
                await placeBlockAt(buildMaterial, startPos.offset(4, y, z));
            }
        }
        
        // Крыша
        for (let x = 0; x < 5; x++) {
            for (let z = 0; z < 5; z++) {
                await placeBlockAt(buildMaterial, startPos.offset(x, 3, z));
            }
        }
        
        // Дверь (убираем 2 блока)
        const doorPos1 = startPos.offset(2, 0, 0);
        const doorPos2 = startPos.offset(2, 1, 0);
        const block1 = bot.blockAt(doorPos1);
        const block2 = bot.blockAt(doorPos2);
        if (block1) await bot.dig(block1);
        if (block2) await bot.dig(block2);
        
        bot.chat('Дом построен!');
        
        // Запоминаем паттерн строительства
        learningData.buildingPatterns.push({
            type: 'house',
            position: startPos,
            material: buildMaterial,
            timestamp: Date.now()
        });
        
    } catch (err) {
        bot.chat('Ошибка при строительстве дома!');
        console.error(err);
    }
}

async function buildWall(username) {
    bot.chat('Строю стену!');
    
    const startPos = bot.entity.position.clone();
    const buildMaterial = findBuildingMaterial();
    
    if (!buildMaterial) {
        bot.chat('Нет материалов!');
        return;
    }
    
    try {
        for (let x = 0; x < 10; x++) {
            for (let y = 0; y < 3; y++) {
                await placeBlockAt(buildMaterial, startPos.offset(x, y, 0));
            }
        }
        
        bot.chat('Стена построена!');
    } catch (err) {
        bot.chat('Ошибка строительства!');
        console.error(err);
    }
}

async function buildTower(username) {
    bot.chat('Строю башню!');
    
    const startPos = bot.entity.position.clone();
    const buildMaterial = findBuildingMaterial();
    
    if (!buildMaterial) {
        bot.chat('Нет материалов!');
        return;
    }
    
    try {
        for (let y = 0; y < 10; y++) {
            for (let x = 0; x < 3; x++) {
                for (let z = 0; z < 3; z++) {
                    await placeBlockAt(buildMaterial, startPos.offset(x, y, z));
                }
            }
        }
        
        bot.chat('Башня построена!');
    } catch (err) {
        bot.chat('Ошибка строительства башни!');
        console.error(err);
    }
}

async function buildBridge(username) {
    bot.chat('Строю мост!');
    
    const startPos = bot.entity.position.clone();
    const buildMaterial = findBuildingMaterial();
    
    if (!buildMaterial) {
        bot.chat('Нет материалов!');
        return;
    }
    
    try {
        for (let x = 0; x < 15; x++) {
            await placeBlockAt(buildMaterial, startPos.offset(x, -1, 0));
            await placeBlockAt(buildMaterial, startPos.offset(x, -1, 2));
        }
        
        bot.chat('Мост построен!');
    } catch (err) {
        bot.chat('Ошибка строительства моста!');
        console.error(err);
    }
}

async function buildShelter(username) {
    bot.chat('Строю укрытие!');
    
    const startPos = bot.entity.position.clone();
    const buildMaterial = findBuildingMaterial();
    
    if (!buildMaterial) {
        bot.chat('Нет материалов!');
        return;
    }
    
    try {
        // Быстрое укрытие 3x3
        for (let x = 0; x < 3; x++) {
            for (let z = 0; z < 3; z++) {
                await placeBlockAt(buildMaterial, startPos.offset(x, 2, z));
            }
        }
        
        bot.chat('Укрытие готово!');
    } catch (err) {
        bot.chat('Ошибка строительства!');
        console.error(err);
    }
}

async function buildPlatform(username) {
    bot.chat('Строю платформу!');
    
    const startPos = bot.entity.position.clone();
    const buildMaterial = findBuildingMaterial();
    
    if (!buildMaterial) {
        bot.chat('Нет материалов!');
        return;
    }
    
    try {
        for (let x = -3; x <= 3; x++) {
            for (let z = -3; z <= 3; z++) {
                await placeBlockAt(buildMaterial, startPos.offset(x, 0, z));
            }
        }
        
        bot.chat('Платформа построена!');
    } catch (err) {
        bot.chat('Ошибка строительства!');
        console.error(err);
    }
}

async function placeBlockAt(blockType, position) {
    try {
        const item = bot.inventory.items().find(i => i.name === blockType);
        if (!item) return false;
        
        await bot.equip(item, 'hand');
        
        const referenceBlock = bot.blockAt(position.offset(0, -1, 0));
        if (referenceBlock && referenceBlock.name !== 'air') {
            await bot.placeBlock(referenceBlock, new Vec3(0, 1, 0));
            await sleep(100);
            return true;
        }
        
        return false;
    } catch (err) {
        console.error('Ошибка установки блока:', err.message);
        return false;
    }
}

async function placeBlockNearby(blockType, username) {
    const item = bot.inventory.items().find(i => i.name.includes(blockType));
    
    if (!item) {
        bot.chat(`У меня нет ${blockType}!`);
        return;
    }
    
    try {
        await bot.equip(item, 'hand');
        const referenceBlock = bot.blockAt(bot.entity.position.offset(0, -1, 0));
        
        if (referenceBlock) {
            await bot.placeBlock(referenceBlock, new Vec3(1, 0, 0));
            bot.chat(`Поставил ${blockType}!`);
        }
    } catch (err) {
        bot.chat('Не могу поставить блок!');
        console.error(err);
    }
}

function findBuildingMaterial() {
    const materials = ['dirt', 'cobblestone', 'stone', 'planks', 'wood', 'oak_planks', 'spruce_planks'];
    
    for (const mat of materials) {
        const item = bot.inventory.items().find(i => i.name.includes(mat));
        if (item) return item.name;
    }
    
    return null;
}

// ================== СИСТЕМА БОЯ ==================
async function defendSelf(target) {
    if (!target || !target.isValid) return;
    
    botState.fighting = true;
    botState.currentActivity = 'fighting';
    
    try {
        // Экипируем лучшее оружие
        await equipBestWeapon();
        
        // Экипируем щит в offhand если есть
        await equipShield();
        
        console.log(`⚔️ Атакую: ${target.name || target.username || 'враг'}`);
        
        bot.pvp.attack(target);
        
        // Стратегия боя с обучением
        const combatInterval = setInterval(async () => {
            if (!target.isValid || target.health <= 0 || bot.health <= 5) {
                bot.pvp.stop();
                clearInterval(combatInterval);
                botState.fighting = false;
                
                if (bot.health > 0 && (!target.isValid || target.health <= 0)) {
                    learningData.combatVictories[target.name] = (learningData.combatVictories[target.name] || 0) + 1;
                    bot.chat('Враг повержен!');
                } else if (bot.health <= 5) {
                    retreatToSafety();
                }
                
                return;
            }
            
            // Умная стратегия: отступаем если мало здоровья
            if (bot.health < 10 && bot.food > 10) {
                await eatFood();
            }
            
            // Прыгаем во время боя для критических ударов
            if (Math.random() > 0.7) {
                bot.setControlState('jump', true);
                setTimeout(() => bot.setControlState('jump', false), 100);
            }
            
        }, 500);
        
    } catch (err) {
        console.error('Ошибка в бою:', err.message);
        botState.fighting = false;
    }
}

async function attackEntity(entity, username) {
    if (!entity) {
        bot.chat('Цель не найдена!');
        return;
    }
    
    bot.chat(`Атакую ${entity.name || entity.username}!`);
    await defendSelf(entity);
}

async function attackNearbyHostiles(username) {
    const hostiles = findNearbyHostileMobs();
    
    if (hostiles.length === 0) {
        bot.chat('Нет враждебных мобов рядом.');
        return;
    }
    
    bot.chat(`Атакую ${hostiles.length} врагов!`);
    
    for (const mob of hostiles) {
        if (bot.health <= 5) {
            bot.chat('Мало здоровья! Отступаю!');
            retreatToSafety();
            break;
        }
        
        await defendSelf(mob);
        await sleep(1000);
    }
}

function findNearbyHostileMobs() {
    const hostileMobs = [
        'zombie', 'skeleton', 'spider', 'creeper', 'enderman',
        'witch', 'slime', 'phantom', 'drowned', 'husk',
        'stray', 'cave_spider', 'silverfish', 'blaze', 'ghast'
    ];
    
    const entities = Object.values(bot.entities).filter(entity => {
        if (!entity || !entity.position) return false;
        if (entity === bot.entity) return false;
        
        const dist = entity.position.distanceTo(bot.entity.position);
        if (dist > 16) return false;
        
        return hostileMobs.some(mob => entity.name && entity.name.toLowerCase().includes(mob));
    });
    
    return entities;
}

async function retreatToSafety() {
    bot.chat('Отступаю в безопасное место!');
    
    botState.currentActivity = 'retreating';
    bot.pvp.stop();
    
    // Ищем безопасное место
    const safePos = findSafeLocation();
    
    if (safePos) {
        await goToPosition(safePos.x, safePos.y, safePos.z, 'system');
        
        // Строим укрытие если есть материалы
        const buildMat = findBuildingMaterial();
        if (buildMat) {
            await buildShelter('system');
        }
        
        // Лечимся
        await eatFood();
    }
    
    botState.currentActivity = 'idle';
}

function findSafeLocation() {
    const currentPos = bot.entity.position;
    const hostiles = findNearbyHostileMobs();
    
    if (hostiles.length === 0) {
        return currentPos;
    }
    
    // Ищем позицию подальше от врагов
    let bestPos = currentPos.clone();
    let maxDist = 0;
    
    for (let x = -20; x <= 20; x += 5) {
        for (let z = -20; z <= 20; z += 5) {
            const testPos = currentPos.offset(x, 0, z);
            const minDistToHostile = Math.min(...hostiles.map(h => 
                h.position.distanceTo(testPos)
            ));
            
            if (minDistToHostile > maxDist) {
                maxDist = minDistToHostile;
                bestPos = testPos;
            }
        }
    }
    
    return bestPos;
}

// ================== СИСТЕМА ЭКИПИРОВКИ ==================
async function equipBestGear() {
    await equipBestArmor();
    await equipBestWeapon();
}

async function equipBestArmor() {
    const armorSlots = ['head', 'torso', 'legs', 'feet'];
    const armorPriority = ['diamond', 'iron', 'chainmail', 'golden', 'leather'];
    
    for (const slot of armorSlots) {
        for (const material of armorPriority) {
            const armor = bot.inventory.items().find(item => 
                item.name.includes(material) && item.name.includes(slot === 'torso' ? 'chestplate' : slot === 'feet' ? 'boots' : slot)
            );
            
            if (armor) {
                try {
                    await bot.equip(armor, slot);
                    console.log(`🛡️ Надел: ${armor.name}`);
                    break;
                } catch (err) {
                    console.error('Ошибка экипировки брони:', err.message);
                }
            }
        }
    }
}

async function equipBestWeapon() {
    const weaponPriority = ['netherite_sword', 'diamond_sword', 'iron_sword', 'stone_sword', 'wooden_sword', 'netherite_axe', 'diamond_axe', 'iron_axe'];
    
    for (const weaponName of weaponPriority) {
        const weapon = bot.inventory.items().find(item => item.name === weaponName);
        
        if (weapon) {
            try {
                await bot.equip(weapon, 'hand');
                console.log(`⚔️ Взял в руки: ${weapon.name}`);
                return true;
            } catch (err) {
                console.error('Ошибка экипировки оружия:', err.message);
            }
        }
    }
    
    return false;
}

async function equipBestTool(blockType) {
    const tools = {
        'stone': ['diamond_pickaxe', 'iron_pickaxe', 'stone_pickaxe', 'wooden_pickaxe'],
        'cobblestone': ['diamond_pickaxe', 'iron_pickaxe', 'stone_pickaxe', 'wooden_pickaxe'],
        'iron_ore': ['diamond_pickaxe', 'iron_pickaxe', 'stone_pickaxe'],
        'diamond_ore': ['diamond_pickaxe', 'iron_pickaxe'],
        'coal_ore': ['diamond_pickaxe', 'iron_pickaxe', 'stone_pickaxe', 'wooden_pickaxe'],
        'log': ['diamond_axe', 'iron_axe', 'stone_axe', 'wooden_axe'],
        'dirt': ['diamond_shovel', 'iron_shovel', 'stone_shovel', 'wooden_shovel'],
        'sand': ['diamond_shovel', 'iron_shovel', 'stone_shovel', 'wooden_shovel'],
        'gravel': ['diamond_shovel', 'iron_shovel', 'stone_shovel', 'wooden_shovel']
    };
    
    let toolList = tools[blockType] || tools['stone'];
    
    // Определяем инструмент по типу блока
    if (blockType.includes('ore') || blockType.includes('stone')) {
        toolList = tools['stone'];
    } else if (blockType.includes('log') || blockType.includes('wood')) {
        toolList = tools['log'];
    } else if (blockType.includes('dirt') || blockType.includes('sand') || blockType.includes('gravel')) {
        toolList = tools['dirt'];
    }
    
    for (const toolName of toolList) {
        const tool = bot.inventory.items().find(item => item.name === toolName);
        
        if (tool) {
            try {
                await bot.equip(tool, 'hand');
                console.log(`🔧 Использую: ${tool.name}`);
                
                // Обучение: запоминаем эффективность инструмента
                learningData.toolEfficiency[`${toolName}_${blockType}`] = 
                    (learningData.toolEfficiency[`${toolName}_${blockType}`] || 0) + 1;
                
                return true;
            } catch (err) {
                console.error('Ошибка экипировки инструмента:', err.message);
            }
        }
    }
    
    return false;
}

async function equipShield() {
    const shield = bot.inventory.items().find(item => item.name === 'shield');
    
    if (shield) {
        try {
            await bot.equip(shield, 'off-hand');
            console.log('🛡️ Взял щит');
        } catch (err) {
            // Щит не всегда можно экипировать
        }
    }
}

// ================== СИСТЕМА ИНВЕНТАРЯ ==================
async function dropAllItems(username) {
    const items = bot.inventory.items();
    
    if (items.length === 0) {
        bot.chat('Инвентарь уже пуст!');
        return;
    }
    
    bot.chat('Выбрасываю все предметы...');
    
    for (const item of items) {
        try {
            await bot.toss(item.type, null, item.count);
            await sleep(100);
        } catch (err) {
            console.error('Ошибка выброса предмета:', err.message);
        }
    }
    
    bot.chat('Все предметы выброшены!');
}

async function dropItem(itemName, username) {
    const item = bot.inventory.items().find(i => i.name.includes(itemName));
    
    if (!item) {
        bot.chat(`У меня нет ${itemName}!`);
        return;
    }
    
    try {
        await bot.toss(item.type, null, item.count);
        bot.chat(`Выбросил ${item.name} x${item.count}`);
    } catch (err) {
        bot.chat('Не могу выбросить предмет!');
        console.error(err);
    }
}

async function organizeInventory() {
    console.log('📦 Организую инвентарь...');
    
    // Сортируем предметы
    const items = bot.inventory.items();
    const itemGroups = {};
    
    items.forEach(item => {
        if (!itemGroups[item.name]) {
            itemGroups[item.name] = [];
        }
        itemGroups[item.name].push(item);
    });
    
    // Объединяем стаки
    for (const itemName in itemGroups) {
        const group = itemGroups[itemName];
        if (group.length > 1) {
            // Логика объединения стаков
            console.log(`Объединяю ${itemName}: ${group.length} стаков`);
        }
    }
}

function updateInventoryKnowledge() {
    const items = bot.inventory.items();
    botState.inventory = {};
    
    items.forEach(item => {
        botState.inventory[item.name] = (botState.inventory[item.name] || 0) + item.count;
    });
    
    knowledgeBase.items = botState.inventory;
}

// ================== СИСТЕМА КРАФТА ==================
async function craftItem(itemName, count, username) {
    try {
        const mcData = require('minecraft-data')(bot.version);
        const item = mcData.itemsByName[itemName];
        
        if (!item) {
            bot.chat(`Не знаю рецепт для ${itemName}`);
            return;
        }
        
        const recipe = bot.recipesFor(item.id)[0];
        
        if (!recipe) {
            bot.chat(`Нет рецепта для ${itemName}`);
            return;
        }
        
        // Ищем верстак
        const craftingTable = bot.findBlock({
            matching: mcData.blocksByName.crafting_table?.id,
            maxDistance: 32
        });
        
        if (!craftingTable && recipe.requiresTable) {
            bot.chat('Нужен верстак для крафта!');
            
            // Пытаемся скрафтить верстак если есть доски
            const planks = bot.inventory.items().find(i => i.name.includes('planks'));
            if (planks && planks.count >= 4) {
                await craftCraftingTable();
                await sleep(1000);
            } else {
                return;
            }
        }
        
        if (craftingTable && recipe.requiresTable) {
            await bot.pathfinder.goto(new GoalBlock(craftingTable.position.x, craftingTable.position.y, craftingTable.position.z));
        }
        
        await bot.craft(recipe, count, craftingTable);
        bot.chat(`Скрафтил ${itemName} x${count}!`);
        
        // Обучение
        learningData.craftingRecipes[itemName] = (learningData.craftingRecipes[itemName] || 0) + count;
        
    } catch (err) {
        bot.chat(`Не могу скрафтить ${itemName}!`);
        console.error(err);
    }
}

async function craftCraftingTable() {
    try {
        const mcData = require('minecraft-data')(bot.version);
        const craftingTableId = mcData.itemsByName.crafting_table?.id;
        const recipe = bot.recipesFor(craftingTableId)[0];
        
        if (recipe) {
            await bot.craft(recipe, 1, null);
            bot.chat('Скрафтил верстак!');
        }
    } catch (err) {
        console.error('Ошибка крафта верстака:', err);
    }
}

// ================== СИСТЕМА ПИТАНИЯ ==================
async function eatFood() {
    try {
        const foods = bot.inventory.items().filter(item => item.name.includes('food') || 
            item.name.includes('bread') || item.name.includes('meat') || 
            item.name.includes('apple') || item.name.includes('carrot') ||
            item.name.includes('potato') || item.name.includes('beef') ||
            item.name.includes('porkchop') || item.name.includes('chicken') ||
            item.name.includes('fish') || item.name.includes('salmon'));
        
        if (foods.length > 0) {
            await bot.equip(foods[0], 'hand');
            bot.consume();
            console.log(`🍖 Ем: ${foods[0].name}`);
            return true;
        }
        
        return false;
    } catch (err) {
        console.error('Ошибка при еде:', err.message);
        return false;
    }
}

// ================== СИСТЕМА АВТОНОМНОГО ПОВЕДЕНИЯ ==================
function startAutonomousBehavior() {
    // Автономное поведение каждые 5 секунд
    setInterval(() => {
        if (!botState.autoMode || !botState.isIdle) return;
        
        autonomousDecisionMaking();
    }, 5000);
}

function autonomousDecisionMaking() {
    // Умное принятие решений на основе обучения
    
    // Приоритет 1: Здоровье и голод
    if (bot.health < 15 && bot.food > 10) {
        if (findNearbyHostileMobs().length > 0) {
            retreatToSafety();
            return;
        }
    }
    
    if (bot.food < 8) {
        const hasFood = bot.inventory.items().some(i => 
            i.name.includes('food') || i.name.includes('meat') || i.name.includes('bread')
        );
        
        if (!hasFood) {
            // Ищем еду
            botState.currentActivity = 'searching_food';
            searchForFood();
            return;
        }
    }
    
    // Приоритет 2: Защита
    const hostiles = findNearbyHostileMobs();
    if (hostiles.length > 0 && bot.health > 10) {
        defendSelf(hostiles[0]);
        return;
    }
    
    // Приоритет 3: Сбор ресурсов
    if (Math.random() > 0.5) {
        const resources = ['log', 'stone', 'coal_ore', 'iron_ore'];
        const resource = resources[Math.floor(Math.random() * resources.length)];
        
        const block = findNearestBlock(resource, 32);
        if (block) {
            botState.isIdle = false;
            mineResource(resource, 10, 'auto').then(() => {
                botState.isIdle = true;
            });
        }
    }
}

async function searchForFood() {
    console.log('🔍 Ищу еду...');
    
    // Ищем животных
    const animals = Object.values(bot.entities).filter(entity => 
        entity && entity.name && 
        (entity.name.includes('cow') || entity.name.includes('pig') || 
         entity.name.includes('chicken') || entity.name.includes('sheep'))
    );
    
    if (animals.length > 0) {
        const target = animals[0];
        await equipBestWeapon();
        await defendSelf(target);
    } else {
        // Исследуем окрестности
        exploreArea();
    }
}

function guardArea() {
    if (!guardPos) guardPos = bot.entity.position.clone();
    
    const guardInterval = setInterval(() => {
        if (!botState.autoMode || botState.currentActivity !== 'idle') {
            clearInterval(guardInterval);
            return;
        }
        
        const dist = bot.entity.position.distanceTo(guardPos);
        
        if (dist > 8) {
            bot.pathfinder.setGoal(new GoalNear(guardPos.x, guardPos.y, guardPos.z, 2));
        }
        
        const hostiles = findNearbyHostileMobs();
        if (hostiles.length > 0) {
            defendSelf(hostiles[0]);
        }
        
    }, 2000);
}

function exploreArea() {
    botState.currentActivity = 'exploring';
    
    const explorePos = findExplorationPoint();
    
    if (explorePos) {
        goToPosition(explorePos.x, explorePos.y, explorePos.z, 'auto');
        
        setTimeout(() => {
            botState.currentActivity = 'idle';
        }, 10000);
    }
}

function findExplorationPoint() {
    const currentPos = bot.entity.position;
    const radius = 50;
    
    const x = currentPos.x + (Math.random() - 0.5) * radius * 2;
    const z = currentPos.z + (Math.random() - 0.5) * radius * 2;
    const y = currentPos.y;
    
    return new Vec3(Math.floor(x), Math.floor(y), Math.floor(z));
}

// ================== СИСТЕМА ОБУЧЕНИЯ ==================
function startLearningSystem() {
    // Система обучения анализирует данные каждые 30 секунд
    setInterval(() => {
        analyzeAndLearn();
    }, 30000);
}

function analyzeAndLearn() {
    console.log('🧠 Анализирую и учусь...');
    
    // Анализ успешности добычи
    const totalMines = Object.values(learningData.successfulMines).reduce((a, b) => a + b, 0);
    const totalFails = Object.values(learningData.failedMines).reduce((a, b) => a + b, 0);
    
    if (totalMines > 0) {
        const successRate = totalMines / (totalMines + totalFails);
        console.log(`⛏️ Успешность добычи: ${(successRate * 100).toFixed(1)}%`);
    }
    
    // Анализ боевой эффективности
    const totalVictories = Object.values(learningData.combatVictories).reduce((a, b) => a + b, 0);
    const totalDefeats = Object.values(learningData.combatDefeats).reduce((a, b) => a + b, 0);
    
    if (totalVictories > 0 || totalDefeats > 0) {
        const combatRate = totalVictories / (totalVictories + totalDefeats);
        console.log(`⚔️ Побед в бою: ${totalVictories}, Поражений: ${totalDefeats}, Процент побед: ${(combatRate * 100).toFixed(1)}%`);
    }
    
    // Оптимизация стратегий на основе данных
    optimizeStrategies();
}

function optimizeStrategies() {
    // Определяем лучшие инструменты
    let bestTools = {};
    for (const combo in learningData.toolEfficiency) {
        const [tool, block] = combo.split('_');
        if (!bestTools[block] || learningData.toolEfficiency[combo] > learningData.toolEfficiency[bestTools[block]]) {
            bestTools[block] = combo;
        }
    }
    
    knowledgeBase.strategies.bestTools = bestTools;
    
    // Определяем опасные зоны
    if (learningData.combatDefeats.death > 3) {
        const currentPos = bot.entity.position;
        if (!learningData.dangerZones.some(zone => zone.distanceTo(currentPos) < 10)) {
            learningData.dangerZones.push(currentPos.clone());
            console.log('⚠️ Запомнил опасную зону');
        }
    }
    
    // Определяем богатые ресурсами зоны
    for (const resource in learningData.resourceLocations) {
        const locations = learningData.resourceLocations[resource];
        if (locations.length > 10) {
            console.log(`💎 Найдена богатая зона ${resource}: ${locations.length} блоков`);
        }
    }
}

function showLearningStats(username) {
    const stats = `
=== СТАТИСТИКА ОБУЧЕНИЯ ===
Добыто блоков: ${Object.values(learningData.successfulMines).reduce((a, b) => a + b, 0)}
Побед в бою: ${Object.values(learningData.combatVictories).reduce((a, b) => a + b, 0)}
Построено структур: ${learningData.buildingPatterns.length}
Известных локаций ресурсов: ${Object.keys(learningData.resourceLocations).length}
Опасных зон: ${learningData.dangerZones.length}
Эффективность инструментов: ${Object.keys(learningData.toolEfficiency).length}
    `.trim();
    
    console.log(stats);
    bot.chat('Статистика в консоли!');
}

// ================== СИСТЕМА ОПРЕДЕЛЕНИЯ ОПАСНОСТИ ==================
function checkForDangers() {
    const dangers = [];
    
    // Проверка лавы
    const lava = bot.findBlock({
        matching: block => block && (block.name === 'lava' || block.name === 'flowing_lava'),
        maxDistance: 5
    });
    
    if (lava) {
        dangers.push({ type: 'lava', position: lava.position });
    }
    
    // Проверка падения
    const below = bot.blockAt(bot.entity.position.offset(0, -2, 0));
    if (!below || below.name === 'air') {
        const groundDist = findGroundDistance();
        if (groundDist > 5) {
            dangers.push({ type: 'fall', distance: groundDist });
        }
    }
    
    // Проверка воды (если не плаваем специально)
    const water = bot.blockAt(bot.entity.position);
    if (water && water.name === 'water' && botState.currentActivity !== 'swimming') {
        dangers.push({ type: 'water', position: water.position });
    }
    
    return dangers;
}

function avoidDangers(dangers) {
    for (const danger of dangers) {
        if (danger.type === 'lava') {
            // Отходим от лавы
            const safePos = findSafeLocationFromPoint(danger.position);
            if (safePos) {
                bot.pathfinder.setGoal(new GoalNear(safePos.x, safePos.y, safePos.z, 1));
            }
        } else if (danger.type === 'fall') {
            // Останавливаемся если впереди пропасть
            bot.clearControlStates();
            
            // Пытаемся поставить блок под собой
            const buildMat = findBuildingMaterial();
            if (buildMat) {
                placeBlockAt(buildMat, bot.entity.position.offset(0, -1, 0));
            }
        } else if (danger.type === 'water') {
            // Выплываем на поверхность
            bot.setControlState('jump', true);
        }
    }
}

function findGroundDistance() {
    let dist = 0;
    for (let i = 1; i <= 20; i++) {
        const block = bot.blockAt(bot.entity.position.offset(0, -i, 0));
        if (block && block.name !== 'air') {
            return i;
        }
        dist = i;
    }
    return dist;
}

function findSafeLocationFromPoint(dangerPos) {
    const currentPos = bot.entity.position;
    const direction = currentPos.minus(dangerPos).normalize();
    return currentPos.plus(direction.scaled(5));
}

// ================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==================
function translateBlockName(ruName) {
    const translations = {
        'камень': 'stone',
        'булыжник': 'cobblestone',
        'железо': 'iron_ore',
        'золото': 'gold_ore',
        'алмаз': 'diamond_ore',
        'алмазы': 'diamond_ore',
        'уголь': 'coal_ore',
        'дерево': 'log',
        'бревно': 'log',
        'земля': 'dirt',
        'песок': 'sand',
        'гравий': 'gravel',
        'изумруд': 'emerald_ore',
        'лазурит': 'lapis_ore',
        'редстоун': 'redstone_ore',
        'обсидиан': 'obsidian',
        'кварц': 'nether_quartz_ore',
        'незерит': 'ancient_debris'
    };
    
    return translations[ruName.toLowerCase()] || ruName;
}

function translateItemName(ruName) {
    const translations = {
        'верстак': 'crafting_table',
        'печь': 'furnace',
        'палка': 'stick',
        'доски': 'planks',
        'факел': 'torch',
        'кирка': 'pickaxe',
        'топор': 'axe',
        'лопата': 'shovel',
        'меч': 'sword',
        'броня': 'armor',
        'еда': 'food',
        'хлеб': 'bread'
    };
    
    return translations[ruName.toLowerCase()] || ruName;
}

function findEntityByName(name) {
    return Object.values(bot.entities).find(entity => 
        entity && entity.name && entity.name.toLowerCase().includes(name.toLowerCase())
    );
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function continueCurrentTask() {
    if (!currentTask) return;
    
    console.log(`Продолжаю задачу: ${currentTask.type}`);
    
    // Логика продолжения текущей задачи
}

function initializeKnowledgeBase() {
    console.log('📚 Инициализация базы знаний...');
    
    try {
        knowledgeBase.blocks = mcData.blocks;
        knowledgeBase.items = mcData.items;
        
        console.log(`Загружено блоков: ${Object.keys(mcData.blocks).length}`);
        console.log(`Загружено предметов: ${Object.keys(mcData.items).length}`);
    } catch (err) {
        console.error('Ошибка инициализации базы знаний:', err);
    }
}

// ================== ЗАПУСК БОТА ==================
console.log('🚀 Запуск умного бота для Minecraft 1.21.8...');
console.log(`📡 Сервер: ${BOT_CONFIG.host}:${BOT_CONFIG.port}`);
console.log('⚙️ Загрузка плагинов и систем...');

createBot();

// Обработка завершения процесса
process.on('SIGINT', () => {
    console.log('\n👋 Выключение бота...');
    
    if (bot) {
        bot.chat('Отключаюсь. До встречи!');
        bot.quit();
    }
    
    console.log('📊 Финальная статистика обучения:');
    console.log(learningData);
    
    process.exit(0);
});

// Экспорт для использования в других модулях
module.exports = {
    bot,
    botState,
    learningData,
    knowledgeBase
};

/*
  Mega Minecraft Bot (CommonJS)
  Features:
  - Connects to server, auto-reconnect
  - Russian/English chat command parser
  - Building a house (blueprint-based)
  - Mining/collecting resources with best tools
  - Pathfinding: follow, go, stop
  - PvP vs hostile mobs, armor/weapon auto-equip
  - Auto eat, hazard avoidance, swimming
  - Simple learning memory persisted to JSON

  Run:
    npm install
    npm run start:server
  or customize with env/args: --host --port --username --auth --password --version
*/

const fs = require('fs');
const path = require('path');
const mineflayer = require('mineflayer');
const { pathfinder, Movements, goals } = require('mineflayer-pathfinder');
const collectBlock = require('mineflayer-collectblock').plugin;
const autoeat = require('mineflayer-auto-eat');
const armorManager = require('mineflayer-armor-manager');
const pvp = require('mineflayer-pvp').plugin;
const toolPlugin = require('mineflayer-tool').plugin;
const { Vec3 } = require('vec3');
const { getHouseBlueprint, chooseBestBlock } = require('./blueprints.js');

// -------------------- Config --------------------
const argv = require('yargs/yargs')(process.argv.slice(2))
  .usage('Usage: $0 [options]')
  .option('host', { type: 'string', default: process.env.MC_HOST || 'n1.netronyx.pro' })
  .option('port', { type: 'number', default: Number(process.env.MC_PORT || 4007) })
  .option('version', { type: 'string', default: process.env.MC_VERSION || '1.21.1' })
  .option('username', { type: 'string', default: process.env.MC_USERNAME || ('Bot' + Math.floor(Math.random() * 1000)) })
  .option('auth', { type: 'string', default: process.env.MC_AUTH || 'offline' }) // 'microsoft' or 'offline'
  .option('password', { type: 'string', default: process.env.MC_PASSWORD || undefined })
  .option('owner', { type: 'string', default: process.env.MC_OWNER || undefined })
  .help()
  .argv;

const CONFIG = {
  host: argv.host,
  port: argv.port,
  version: argv.version,
  username: argv.username,
  auth: argv.auth,
  password: argv.password,
  owner: argv.owner // player name whose chat the bot obeys
};

const MEMORY_FILE = path.join(process.cwd(), 'bot_memory.json');

// -------------------- Utilities --------------------
function log(...args) {
  console.log('[BOT]', ...args);
}

function sanitizeText(text) {
  return (text || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function delay(ms) {
  return new Promise(res => setTimeout(res, ms));
}

function vecEquals(a, b) {
  return a && b && a.x === b.x && a.y === b.y && a.z === b.z;
}

// -------------------- Learning Memory --------------------
class LearningMemory {
  constructor(filePath) {
    this.filePath = filePath;
    this.state = {
      commandStats: {},
      strategyScore: {},
      synonyms: {}
    };
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        this.state = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      }
    } catch (e) {
      log('Memory load error:', e.message);
    }
  }

  save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.state, null, 2));
    } catch (e) {
      log('Memory save error:', e.message);
    }
  }

  recordCommand(commandKey, success) {
    const stats = this.state.commandStats[commandKey] || { success: 0, fail: 0 };
    if (success) stats.success++; else stats.fail++;
    this.state.commandStats[commandKey] = stats;
    this.save();
  }

  scoreStrategy(name, delta) {
    const cur = this.state.strategyScore[name] || 0;
    this.state.strategyScore[name] = cur + delta;
    this.save();
  }

  addSynonym(canonical, word) {
    const set = new Set(this.state.synonyms[canonical] || []);
    if (!set.has(word)) set.add(word);
    this.state.synonyms[canonical] = Array.from(set);
    this.save();
  }

  expandSynonyms(input) {
    const words = input.split(' ');
    const all = new Set(words);
    for (const [canon, list] of Object.entries(this.state.synonyms)) {
      for (const w of list) all.add(w);
    }
    return Array.from(all).join(' ');
  }
}

// -------------------- Task Queue --------------------
class TaskQueue {
  constructor() {
    this.current = null;
    this.queue = [];
  }

  get isBusy() { return !!this.current; }

  enqueue(name, fn) {
    this.queue.push({ name, fn });
  }

  async runNext(bot) {
    if (this.current || this.queue.length === 0) return;
    const task = this.queue.shift();
    this.current = task;
    log('Task start:', task.name);
    try {
      await task.fn(bot);
      log('Task complete:', task.name);
    } catch (e) {
      log('Task error:', task.name, e.message);
    } finally {
      this.current = null;
      // slight idle delay
      await delay(200);
      this.runNext(bot);
    }
  }

  cancelAll() {
    this.queue = [];
    if (this.current && this.current.cancel) this.current.cancel();
    this.current = null;
  }
}

// -------------------- Bot Controller --------------------
class BotController {
  constructor(config) {
    this.config = config;
    this.bot = null;
    this.movements = null;
    this.queue = new TaskQueue();
    this.memory = new LearningMemory(MEMORY_FILE);
    this.owner = config.owner;
    this.lastHealth = 20;
    this.followingOwner = false;
  }

  create() {
    const options = {
      host: this.config.host,
      port: this.config.port,
      version: this.config.version,
      username: this.config.username,
      auth: this.config.auth,
      password: this.config.password
    };
    const bot = mineflayer.createBot(options);

    // Plugins
    bot.loadPlugin(pathfinder);
    bot.loadPlugin(collectBlock);
    bot.loadPlugin(autoeat);
    bot.loadPlugin(armorManager);
    bot.loadPlugin(pvp);
    bot.loadPlugin(toolPlugin);

    this.bot = bot;

    // Events
    bot.once('login', () => {
      log('Logged in as', bot.username, '->', this.config.host + ':' + this.config.port);
    });

    bot.once('spawn', () => {
      log('Spawned at', bot.entity.position);
      this.setupMovements();
      this.setupAutoEat();
      this.watchHazards();
      this.autoequipBest();
    });

    bot.on('chat', (username, message) => this.onChat(username, message));

    bot.on('health', () => {
      if (bot.health < this.lastHealth) {
        log('Took damage, health:', bot.health);
        this.memory.scoreStrategy('avoidance', +0.1);
        // try to step back a bit
        this.evadeDanger();
      }
      this.lastHealth = bot.health;
    });

    bot.on('kicked', (reason) => {
      log('Kicked:', reason);
    });
    bot.on('error', (err) => {
      log('Error:', err.message);
    });
    bot.on('end', () => {
      log('Disconnected, retrying in 5s...');
      setTimeout(() => this.create(), 5000);
    });

    // Combat: auto attack nearby hostile mobs opportunistically
    bot.on('physicsTick', () => this.tickCombat());

    return bot;
  }

  setupMovements() {
    const bot = this.bot;
    const mcData = require('minecraft-data')(bot.version);
    const movements = new Movements(bot, mcData);
    movements.scafoldingBlocks = [
      mcData.blocksByName.oak_planks?.id,
      mcData.blocksByName.cobblestone?.id,
      mcData.blocksByName.dirt?.id,
      mcData.blocksByName.stone?.id
    ].filter(Boolean);
    movements.allow1by1towers = true;
    movements.canOpenDoors = true;
    movements.allowSprinting = true;
    movements.waterCost = 1.2; // ok to swim
    movements.lavaCost = 100; // avoid lava
    movements.digCost = 2.5;
    this.movements = movements;
    bot.pathfinder.setMovements(movements);
  }

  setupAutoEat() {
    const bot = this.bot;
    bot.autoEat.options = {
      priority: 'foodPoints',
      startAt: 14,
      bannedFood: []
    };
    bot.on('autoeat_started', () => log('AutoEat started'));
    bot.on('autoeat_stopped', () => log('AutoEat stopped'));
  }

  watchHazards() {
    const bot = this.bot;
    setInterval(() => {
      const below = bot.blockAt(bot.entity.position.offset(0, -1, 0));
      if (below && (below.name.includes('lava') || below.name.includes('magma'))) {
        this.evadeDanger();
      }
      // Avoid suffocation
      const headBlock = bot.blockAt(bot.entity.position.offset(0, 1, 0));
      if (headBlock && headBlock.boundingBox === 'block' && !headBlock.name.includes('water')) {
        bot.setControlState('jump', true);
        setTimeout(() => bot.setControlState('jump', false), 300);
      }
    }, 1000);
  }

  async evadeDanger() {
    const bot = this.bot;
    try {
      // Step backwards
      const yaw = bot.entity.yaw;
      const back = new Vec3(-Math.sin(yaw) * 3, 0, Math.cos(yaw) * 3);
      const target = bot.entity.position.plus(back);
      bot.pathfinder.setMovements(this.movements);
      bot.pathfinder.setGoal(new goals.GoalBlock(Math.floor(target.x), Math.floor(target.y), Math.floor(target.z)), true);
      setTimeout(() => bot.pathfinder.setGoal(null), 1000);
    } catch (e) { /* ignore */ }
  }

  // --------------- Equip logic ---------------
  async autoequipBest() {
    const bot = this.bot;
    try {
      // Armor
      await bot.armorManager.equipAll();
      // Weapon/tool
      const priorities = ['diamond_sword', 'netherite_sword', 'iron_sword', 'stone_sword', 'wooden_sword'];
      for (const name of priorities) {
        const item = bot.inventory.items().find(i => i.name === name);
        if (item) { await bot.equip(item, 'hand'); break; }
      }
    } catch (e) {}
  }

  // --------------- Chat commands ---------------
  isOwner(username) {
    if (!this.owner) return true; // if owner not set, accept all
    return username === this.owner;
  }

  onChat(username, message) {
    if (username === this.bot.username) return;
    const text = sanitizeText(message);

    // learn synonyms when user writes: synonym: canonical
    if (this.isOwner(username) && text.includes(':')) {
      const [a, b] = text.split(':').map(s => s.trim());
      if (a && b && a.length < 20 && b.length < 20) {
        this.memory.addSynonym(b, a);
        this.say(`Запомнил, что "${a}" = ${b}`);
        return;
      }
    }

    if (!this.isOwner(username)) return; // ignore others

    const expanded = this.memory.expandSynonyms(text);

    if (/^(стой|стоп|stop|stay)$/.test(expanded)) return this.cmdStop();
    if (/^(иди за мной|следуй|follow|иди сюда|ко мне)$/.test(expanded)) return this.cmdFollow(username);
    if (/^(отмена|cancel|сброс)$/.test(expanded)) return this.cmdCancel();
    if (/^(drop|скинь|выкинь все|скидывай)$/.test(expanded)) return this.cmdDropAll();

    if (/^(строй дом|построй дом|build house)$/.test(expanded)) return this.cmdBuildHouse();

    if (/^(ломай|копай|добывай|mine|collect) /.test(expanded)) {
      const res = expanded.replace(/^(ломай|копай|добывай|mine|collect)\s+/, '');
      return this.cmdMineResource(res);
    }

    if (/^(крафти|создай|craft) /.test(expanded)) {
      const item = expanded.replace(/^(крафти|создай|craft)\s+/, '');
      return this.cmdCraft(item);
    }

    if (/^(дерись|атакуй|бей|pvp|защищай)$/ .test(expanded)) return this.cmdGuard();

    if (/^(поднимись|tower|вверх)$/.test(expanded)) return this.cmdTower();

    if (/^(скаф|bridge|мост)$/.test(expanded)) return this.cmdBridge();

    if (/^иди (к|to) /.test(expanded)) {
      const coordsText = expanded.replace(/^иди (к|to)\s+/, '');
      return this.cmdGoto(coordsText);
    }
  }

  say(msg) {
    try { this.bot.chat(msg); } catch (_) { log('Say:', msg); }
  }

  // --------------- Commands implementation ---------------
  async cmdStop() {
    this.followingOwner = false;
    this.queue.cancelAll();
    this.bot.stopDigging();
    this.bot.pathfinder.setGoal(null);
    this.say('Остановился.');
  }

  async cmdCancel() { return this.cmdStop(); }

  async cmdFollow(username) {
    const bot = this.bot;
    const player = bot.players[username]?.entity;
    if (!player) { this.say('Не вижу тебя. Подойди ближе.'); return; }
    this.followingOwner = true;
    bot.pathfinder.setMovements(this.movements);
    const goal = new goals.GoalFollow(player, 2);
    bot.pathfinder.setGoal(goal, true);
    this.say('Иду за тобой.');
  }

  async cmdGoto(coordsText) {
    const nums = coordsText.split(/[,\s]+/).map(Number).filter(n => !Number.isNaN(n));
    if (nums.length < 2) { this.say('Нужны координаты X Z или X Y Z'); return; }
    const [x, yMaybe, zMaybe] = nums;
    const y = nums.length === 3 ? yMaybe : Math.floor(this.bot.entity.position.y);
    const z = nums.length === 3 ? zMaybe : yMaybe;
    this.queue.enqueue('goto', async (bot) => {
      bot.pathfinder.setMovements(this.movements);
      bot.pathfinder.setGoal(new goals.GoalBlock(Math.floor(x), Math.floor(y), Math.floor(z)));
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('timeout')), 120000);
        const done = () => { clearTimeout(timeout); bot.removeListener('goal_reached', done); resolve(); };
        bot.once('goal_reached', done);
      });
      this.say('Пришел.');
      this.memory.recordCommand('goto', true);
    });
    this.queue.runNext(this.bot);
  }

  async cmdDropAll() {
    this.queue.enqueue('dropAll', async (bot) => {
      for (const item of bot.inventory.items()) {
        try { await bot.tossStack(item); } catch (_) {}
        await delay(50);
      }
      this.say('Скинул все.');
      this.memory.recordCommand('drop', true);
    });
    this.queue.runNext(this.bot);
  }

  async cmdBuildHouse() {
    const blueprint = getHouseBlueprint({});
    this.queue.enqueue('buildHouse', async (bot) => {
      await this.buildFromBlueprint(blueprint);
      this.say('Дом готов (или почти).');
      this.memory.recordCommand('build_house', true);
    });
    this.queue.runNext(this.bot);
  }

  resourceAliases(res) {
    const text = sanitizeText(res);
    const map = new Map([
      ['камень', 'stone'],
      ['stone', 'stone'],
      ['железо', 'iron_ore'],
      ['iron', 'iron_ore'],
      ['уголь', 'coal_ore'],
      ['coal', 'coal_ore'],
      ['алмаз', 'diamond_ore'],
      ['алмазы', 'diamond_ore'],
      ['diamond', 'diamond_ore'],
      ['золото', 'gold_ore'],
      ['gold', 'gold_ore'],
      ['медь', 'copper_ore'],
      ['copper', 'copper_ore'],
      ['песок', 'sand'],
      ['sand', 'sand'],
      ['земля', 'dirt'],
      ['дерево', 'oak_log'],
      ['деревья', 'oak_log'],
      ['wood', 'oak_log'],
      ['бревно', 'oak_log'],
      ['бревна', 'oak_log']
    ]);
    return map.get(text) || text;
  }

  async cmdMineResource(res) {
    const targetName = this.resourceAliases(res);
    this.queue.enqueue('mine:' + targetName, async (bot) => {
      const mcData = require('minecraft-data')(bot.version);
      const blockId = mcData.blocksByName[targetName]?.id;
      if (!blockId) { this.say('Не знаю блок: ' + targetName); this.memory.recordCommand('mine', false); return; }

      const blocks = bot.findBlocks({ matching: blockId, maxDistance: 64, count: 64 });
      if (!blocks || blocks.length === 0) { this.say('Не нашел блоки рядом: ' + targetName); this.memory.recordCommand('mine', false); return; }

      // Equip best tool for this block
      try {
        const sampleBlock = bot.blockAt(blocks[0]);
        await bot.tool.equipForBlock(sampleBlock);
      } catch (e) {}

      // Collect them
      for (const pos of blocks.slice(0, 24)) {
        const block = bot.blockAt(pos);
        if (!block) continue;
        try {
          await bot.collectBlock.collect(block, { ignoreNoPath: true, count: 1 });
        } catch (e) {
          // ignore unreachable
        }
      }
      this.say('Готово: ' + targetName);
      this.memory.recordCommand('mine', true);
      await this.autoequipBest();
    });
    this.queue.runNext(this.bot);
  }

  async cmdCraft(itemText) {
    const bot = this.bot;
    const mcData = require('minecraft-data')(bot.version);
    const name = sanitizeText(itemText).replace(/\s+/g, '_');
    this.queue.enqueue('craft:' + name, async (bot) => {
      const item = mcData.itemsByName[name];
      if (!item) { this.say('Не знаю предмет: ' + name); this.memory.recordCommand('craft', false); return; }
      let table = null;
      const tableBlock = bot.findBlock({ matching: mcData.blocksByName.crafting_table.id, maxDistance: 32 });
      if (tableBlock) table = tableBlock;
      const recipe = bot.recipesFor(item.id, null, 1, table)[0];
      if (!recipe) { this.say('Нет рецепта рядом.'); this.memory.recordCommand('craft', false); return; }
      try {
        await bot.craft(recipe, 1, table);
        this.say('Скрафтил: ' + name);
        this.memory.recordCommand('craft', true);
      } catch (e) {
        this.say('Не получилось: ' + e.message);
        this.memory.recordCommand('craft', false);
      }
    });
    this.queue.runNext(this.bot);
  }

  async cmdGuard() {
    this.queue.enqueue('guard', async () => {
      // Just increase aggression score; actual fight handled in tick
      this.memory.scoreStrategy('aggression', +0.2);
      this.say('Буду защищать.');
    });
    this.queue.runNext(this.bot);
  }

  async cmdTower() {
    const bot = this.bot;
    this.queue.enqueue('tower', async () => {
      const mcData = require('minecraft-data')(bot.version);
      const blockItem = chooseBestBlock(bot, ['cobblestone', 'dirt', 'stone', 'oak_planks']);
      if (!blockItem) { this.say('Нет блоков для башни.'); return; }
      await bot.equip(blockItem, 'hand');
      for (let i = 0; i < 5; i++) {
        const under = bot.blockAt(bot.entity.position.offset(0, -1, 0));
        if (!under) break;
        try {
          await bot.placeBlock(under, new Vec3(0, 1, 0));
          bot.setControlState('jump', true);
          await delay(250);
          bot.setControlState('jump', false);
          await delay(150);
        } catch (_) { break; }
      }
      this.say('Поднялся.');
    });
    this.queue.runNext(this.bot);
  }

  async cmdBridge() {
    const bot = this.bot;
    this.queue.enqueue('bridge', async () => {
      const blockItem = chooseBestBlock(bot, ['cobblestone', 'dirt', 'stone', 'oak_planks']);
      if (!blockItem) { this.say('Нет блоков для моста.'); return; }
      await bot.equip(blockItem, 'hand');
      const yaw = bot.entity.yaw;
      for (let i = 0; i < 8; i++) {
        const forward = new Vec3(-Math.sin(yaw), 0, Math.cos(yaw));
        const pos = bot.entity.position.plus(forward.scaled(1.0));
        const below = bot.blockAt(pos.offset(0, -1, 0));
        if (!below || below.name === 'air' || below.boundingBox === 'empty') {
          const under = bot.blockAt(bot.entity.position.offset(0, -1, 0));
          if (!under) break;
          try { await bot.placeBlock(under, forward); } catch (_) { break; }
        }
        bot.setControlState('forward', true);
        await delay(350);
        bot.setControlState('forward', false);
      }
      this.say('Построил мост.');
    });
    this.queue.runNext(this.bot);
  }

  // --------------- Building system ---------------
  async buildFromBlueprint(blueprint) {
    const bot = this.bot;
    const origin = bot.entity.position.floored();
    const mcData = require('minecraft-data')(bot.version);

    // Prepare - clear space: break blocks intersecting walls/floor/roof (but avoid chests etc.)
    const candidates = blueprint.blocks.map(b => origin.offset(b.x, b.y, b.z));
    for (const pos of candidates) {
      const block = bot.blockAt(pos);
      if (!block) continue;
      const keep = (block.name.includes('chest') || block.name.includes('furnace') || block.name.includes('crafting'));
      if (!keep && block.name !== 'air' && block.hardness > 0) {
        try {
          await bot.tool.equipForBlock(block);
        } catch (_) {}
        try {
          await bot.dig(block, true);
        } catch (_) {}
      }
    }

    // Place blocks
    for (const b of blueprint.blocks) {
      if (b.use === 'air') continue; // door hole
      const targetPos = origin.offset(b.x, b.y, b.z);
      const existing = bot.blockAt(targetPos);
      if (existing && existing.name !== 'air' && existing.boundingBox === 'block') continue;

      let item = null;
      if (b.use === 'glass') item = chooseBestBlock(bot, blueprint.use.glass);
      else if (b.use === 'door') item = chooseBestBlock(bot, blueprint.use.door);
      else if (b.use === 'roof') item = chooseBestBlock(bot, blueprint.use.roof);
      else if (b.use === 'torch') item = chooseBestBlock(bot, blueprint.use.torch);
      else if (b.use === 'floor') item = chooseBestBlock(bot, blueprint.use.floor);
      else item = chooseBestBlock(bot, blueprint.use.wall);

      if (!item) { this.say(`Нет материалов для ${b.use}. Пропускаю.`); continue; }
      try { await bot.equip(item, 'hand'); } catch (_) {}

      // Determine support block to place against
      const neighbors = [
        new Vec3(0, -1, 0), new Vec3(1, 0, 0), new Vec3(-1, 0, 0), new Vec3(0, 0, 1), new Vec3(0, 0, -1)
      ];
      let placed = false;
      for (const dir of neighbors) {
        const placeAgainst = bot.blockAt(targetPos.plus(dir));
        if (placeAgainst && placeAgainst.name !== 'air' && placeAgainst.boundingBox !== 'empty') {
          try {
            await bot.placeBlock(placeAgainst, dir.negate());
            placed = true;
            break;
          } catch (_) { /* try other face */ }
        }
      }

      // If no neighbor, try to scaffold from below
      if (!placed) {
        const under = bot.blockAt(targetPos.offset(0, -1, 0));
        if (under && under.name !== 'air') {
          try { await bot.placeBlock(under, new Vec3(0, 1, 0)); placed = true; } catch (_) {}
        }
      }

      await delay(75);
    }

    // Place door after walls to ensure correctness
    const doorRel = blueprint.blocks.find(b => b.use === 'door');
    if (doorRel) {
      const pos = origin.offset(doorRel.x, doorRel.y, doorRel.z);
      const doorItem = chooseBestBlock(bot, blueprint.use.door);
      if (doorItem) {
        try { await bot.equip(doorItem, 'hand'); } catch (_) {}
        const against = bot.blockAt(pos.offset(0, -1, 0));
        if (against) {
          try { await bot.placeBlock(against, new Vec3(0, 1, 0)); } catch (_) {}
        }
      }
    }

    // Torch inside
    const torchRel = blueprint.blocks.find(b => b.use === 'torch');
    if (torchRel) {
      const pos = origin.offset(torchRel.x, torchRel.y, torchRel.z);
      const torchItem = chooseBestBlock(bot, blueprint.use.torch);
      if (torchItem) {
        try { await bot.equip(torchItem, 'hand'); } catch (_) {}
        const floor = bot.blockAt(pos.offset(0, -1, 0));
        if (floor) {
          try { await bot.placeBlock(floor, new Vec3(0, 1, 0)); } catch (_) {}
        }
      }
    }
  }

  // --------------- Combat tick ---------------
  tickCombat() {
    const bot = this.bot;
    const nearby = Object.values(bot.entities).filter(e => e.type === 'mob');
    const hostiles = nearby.filter(e => {
      const name = (e.name || '').toLowerCase();
      return ['zombie', 'skeleton', 'spider', 'creeper', 'drowned', 'husk', 'pillager', 'witch'].some(h => name.includes(h));
    });
    const target = hostiles.sort((a, b) => a.position.distanceTo(bot.entity.position) - b.position.distanceTo(bot.entity.position))[0];
    if (target && bot.entity.position.distanceTo(target.position) < 4) {
      try {
        bot.pvp.attack(target);
      } catch (_) {}
    }
  }
}

// -------------------- Bootstrap --------------------
const controller = new BotController(CONFIG);
controller.create();

module.exports = controller;

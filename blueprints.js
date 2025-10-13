// House and structure blueprints and helpers (CommonJS)

/**
 * A small starter house blueprint generator.
 * Produces relative block placements from (0,0,0) origin at ground level.
 * The builder will choose materials from inventory if available.
 */
function getHouseBlueprint(options = {}) {
  const size = options.size || { width: 7, length: 9, height: 5 };
  const doorSide = options.doorSide || 'south'; // 'north'|'south'|'east'|'west'
  const use = {
    wall: options.wall || ['oak_planks', 'spruce_planks', 'cobblestone'],
    floor: options.floor || ['oak_planks', 'spruce_planks', 'cobblestone'],
    roof: options.roof || ['oak_planks', 'spruce_planks', 'cobblestone'],
    glass: options.glass || ['glass_pane', 'glass'],
    door: options.door || ['oak_door', 'spruce_door'],
    torch: options.torch || ['torch']
  };

  const blocks = [];
  const half = {
    w: Math.floor(size.width / 2),
    l: Math.floor(size.length / 2)
  };

  // Floor
  for (let x = -half.w; x <= half.w; x++) {
    for (let z = -half.l; z <= half.l; z++) {
      blocks.push({ x, y: 0, z, use: 'floor' });
    }
  }

  // Walls and corners
  for (let y = 1; y <= size.height; y++) {
    for (let x = -half.w; x <= half.w; x++) {
      blocks.push({ x, y, z: -half.l, use: 'wall' });
      blocks.push({ x, y, z: half.l, use: 'wall' });
    }
    for (let z = -half.l; z <= half.l; z++) {
      blocks.push({ x: -half.w, y, z, use: 'wall' });
      blocks.push({ x: half.w, y, z, use: 'wall' });
    }
  }

  // Windows (cut-outs handled by builder placing glass instead of wall)
  const windowY = 2;
  for (let x = -half.w + 1; x <= half.w - 1; x += 2) {
    blocks.push({ x, y: windowY, z: -half.l, use: 'glass' });
    blocks.push({ x, y: windowY, z: half.l, use: 'glass' });
  }
  for (let z = -half.l + 1; z <= half.l - 1; z += 2) {
    blocks.push({ x: -half.w, y: windowY, z, use: 'glass' });
    blocks.push({ x: half.w, y: windowY, z, use: 'glass' });
  }

  // Door opening
  const door = { x: 0, y: 1, z: doorSide === 'south' ? half.l : doorSide === 'north' ? -half.l : 0 };
  if (doorSide === 'east') door.x = half.w;
  if (doorSide === 'west') door.x = -half.w;
  blocks.push({ x: door.x, y: 1, z: door.z, use: 'door' });
  blocks.push({ x: door.x, y: 2, z: door.z, use: 'air' });

  // Roof (simple flat)
  const roofY = size.height + 1;
  for (let x = -half.w - 1; x <= half.w + 1; x++) {
    for (let z = -half.l - 1; z <= half.l + 1; z++) {
      blocks.push({ x, y: roofY, z, use: 'roof' });
    }
  }

  // Torches inside
  blocks.push({ x: 0, y: 2, z: 0, use: 'torch' });

  return { size, use, blocks };
}

function chooseBestBlock(bot, useList) {
  for (const name of useList) {
    const item = bot.inventory.items().find(i => i.name === name);
    if (item) return item;
  }
  return null;
}

module.exports = {
  getHouseBlueprint,
  chooseBestBlock
};

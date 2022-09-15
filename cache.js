const MAX_CACHE_SIZE = 100;

const transformArrayBufferIntoStr = (str) => {
  if (
    !str ||
    str.length === 0 ||
    (!isArrayBuffer(str) && typeof str !== "string")
  ) {
    return;
  }

  let newStr = str;

  // Trim leading `0x` if present
  if (newStr.slice(0, 2) === "0x") {
    newStr = newStr.slice(2);
  } else if (isArrayBuffer(newStr)) {
    newStr = Buffer.from(newStr).toString("hex");
  }

  return newStr;
};

const generateDefKey = (data, to) => {
  if (!data || !to) {
    return;
  }

  const dataStr = transformArrayBufferIntoStr(data);
  const toStr = transformArrayBufferIntoStr(to);

  if (!dataStr || !toStr) {
    return;
  }

  return `${toStr}${dataStr.slice(0, 8)}`;
};

const getCachedDef = (tx, cache) => {
  return cache.get(generateDefKey(tx.data, tx.to));
};

const saveDefToCache = (tx, cache, def) => {
  if (!tx.data || tx.data.length === 0) {
    return;
  }

  const key = generateDefKey(tx.data, tx.to);
  if (!key) {
    return;
  }

  if (cache.size >= MAX_CACHE_SIZE) {
    cache.delete(cache.keys().next().value);
  }
  cache.set(key, def);
};

const serializeCache = (cache) => {
  return JSON.stringify([...cache]);
};

const deserializeCache = (cache) => {
  return new Map(JSON.parse(cache));
};

const isArrayBuffer = (value) => {
  return (
    value &&
    value.buffer instanceof ArrayBuffer &&
    value.byteLength !== undefined
  );
};

module.exports = {
  generateDefKey,
  getCachedDef,
  saveDefToCache,
  serializeCache,
  deserializeCache,
};

// =============================================================================
// TENKORD v3 — clean rewrite
// True P2P chat (Trystero/Nostr + WebRTC). No central server.
// Multi-device = join own room; all online same-account devices mesh-sync.
// Schema-versioned messages + IDB so future updates never brick history.
// =============================================================================

const APP_VERSION = "3.1.0";
const PROTOCOL_VERSION = 1;
const IDB_VERSION = 4;
const CHUNK_SIZE = 16 * 1024;
const MAX_INLINE_MEDIA = 4 * 1024 * 1024;
const LARGE_FILE_SKIP = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Crypto helpers (ECDSA P-256 identity + AES-GCM identity bundles)
// ---------------------------------------------------------------------------
function abb64(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
function b64ab(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u.buffer;
}
function rndBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
function uuid() {
  return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36);
}

const CRYPTO = {
  privateKey: null,
  publicKey: null,
  pubKeyRaw: null,
  fingerprint: null,

  async init() {
    const raw = localStorage.getItem("tk_kp");
    if (raw) {
      try {
        const { priv, pub } = JSON.parse(raw);
        this.privateKey = await crypto.subtle.importKey("pkcs8", b64ab(priv), { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
        this.publicKey = await crypto.subtle.importKey("spki", b64ab(pub), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
        this.pubKeyRaw = pub;
        this.fingerprint = await this._fp(pub);
        return;
      } catch (_) {
        localStorage.removeItem("tk_kp");
      }
    }
    await this._generate();
  },

  async _generate() {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const priv = abb64(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
    const pub = abb64(await crypto.subtle.exportKey("spki", kp.publicKey));
    localStorage.setItem("tk_kp", JSON.stringify({ priv, pub }));
    this.privateKey = kp.privateKey;
    this.publicKey = kp.publicKey;
    this.pubKeyRaw = pub;
    this.fingerprint = await this._fp(pub);
  },

  async sign(msg) {
    return abb64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.privateKey, new TextEncoder().encode(String(msg))));
  },

  async verify(msg, sig, pubRaw) {
    try {
      const key = await crypto.subtle.importKey("spki", b64ab(pubRaw), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64ab(sig), new TextEncoder().encode(String(msg)));
    } catch (_) { return false; }
  },

  async _fp(pubRaw) {
    const dig = await crypto.subtle.digest("SHA-256", b64ab(pubRaw));
    return Array.from(new Uint8Array(dig)).slice(0, 8).map(b => b.toString(16).padStart(2, "0")).join("");
  },

  async exportBundle(passphrase, meta = {}) {
    const salt = rndBytes(16);
    const iv = rndBytes(12);
    const key = await this._deriveKey(passphrase, salt);
    const privBuf = await crypto.subtle.exportKey("pkcs8", this.privateKey);
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const privU8 = new Uint8Array(privBuf);
    const packed = new Uint8Array(4 + privU8.length + metaBytes.length);
    new DataView(packed.buffer).setUint32(0, privU8.length, false);
    packed.set(privU8, 4);
    packed.set(metaBytes, 4 + privU8.length);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, packed);
    return JSON.stringify({
      v: 1,
      pub: this.pubKeyRaw,
      salt: abb64(salt),
      iv: abb64(iv),
      data: abb64(ct)
    });
  },

  async importBundle(jsonStr, passphrase) {
    const bundle = JSON.parse(jsonStr);
    if (bundle.v !== 1) throw new Error("Unknown identity bundle version");
    const salt = b64ab(bundle.salt);
    const iv = b64ab(bundle.iv);
    const key = await this._deriveKey(passphrase, salt);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64ab(bundle.data));
    const keyLen = new DataView(pt).getUint32(0, false);
    const privBuf = pt.slice(4, 4 + keyLen);
    const meta = JSON.parse(new TextDecoder().decode(pt.slice(4 + keyLen)) || "{}");
    const privKey = await crypto.subtle.importKey("pkcs8", privBuf, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const pubKey = await crypto.subtle.importKey("spki", b64ab(bundle.pub), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const privExp = abb64(await crypto.subtle.exportKey("pkcs8", privKey));
    localStorage.setItem("tk_kp", JSON.stringify({ priv: privExp, pub: bundle.pub }));
    this.privateKey = privKey;
    this.publicKey = pubKey;
    this.pubKeyRaw = bundle.pub;
    this.fingerprint = await this._fp(bundle.pub);
    return meta;
  },

  async _deriveKey(pass, salt) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
};

// ---------------------------------------------------------------------------
// IndexedDB (versioned)
// ---------------------------------------------------------------------------
let DB = null;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("tenkord", IDB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains("messages")) {
        const s = db.createObjectStore("messages", { keyPath: "id" });
        s.createIndex("chat", "chatId");
        s.createIndex("ts", "ts");
      }
      if (!db.objectStoreNames.contains("files")) {
        db.createObjectStore("files", { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains("favorites")) {
        db.createObjectStore("favorites", { keyPath: "id" });
      }
      // future: meta store for schema markers
    };
    req.onsuccess = (e) => { DB = e.target.result; resolve(DB); };
    req.onerror = (e) => reject(e);
  });
}

function dbPut(store, obj) {
  return new Promise((res, rej) => {
    const tx = DB.transaction(store, "readwrite");
    tx.objectStore(store).put(obj);
    tx.oncomplete = () => res();
    tx.onerror = (e) => rej(e);
  });
}
function dbGet(store, key) {
  return new Promise((res, rej) => {
    const tx = DB.transaction(store);
    const r = tx.objectStore(store).get(key);
    r.onsuccess = () => res(r.result);
    r.onerror = (e) => rej(e);
  });
}
function dbGetAll(store, indexName, key) {
  return new Promise((res, rej) => {
    const tx = DB.transaction(store);
    const src = indexName ? tx.objectStore(store).index(indexName) : tx.objectStore(store);
    const r = key !== undefined ? src.getAll(key) : src.getAll();
    r.onsuccess = () => res(r.result || []);
    r.onerror = (e) => rej(e);
  });
}
function dbDel(store, key) {
  return new Promise((res, rej) => {
    const tx = DB.transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => res();
    tx.onerror = (e) => rej(e);
  });
}

// ---------------------------------------------------------------------------
// Local storage helpers + canonical IDs
// ---------------------------------------------------------------------------
function lsGet(k, def = "") { return localStorage.getItem(k) ?? def; }
function lsGetJ(k, def) {
  try { return JSON.parse(localStorage.getItem(k)) || def; } catch (_) { return def; }
}
function saveFriendsAndQueue() {
  localStorage.setItem("tk_friends", JSON.stringify(S.friends));
  localStorage.setItem("tk_queue", JSON.stringify(S.queue));
}

function fpFromPeerId(id) {
  if (!id) return null;
  const m = String(id).match(/^tk-([a-f0-9]{16})/i);
  return m ? m[1].toLowerCase() : null;
}
function canonicalId(id) {
  if (!id) return id;
  const fp = fpFromPeerId(id);
  return fp ? "tk-" + fp : id;
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
const S = {
  myId: null,
  myFingerprint: null,
  myName: lsGet("tk_name", ""),
  myStatus: lsGet("tk_status", ""),
  myAvatar: lsGet("tk_avatar", ""),
  deviceId: lsGet("tk_device_id", "") || (() => {
    const id = uuid();
    localStorage.setItem("tk_device_id", id);
    return id;
  })(),

  conns: {},          // connKey -> { send, open }
  _peerMap: {},       // trysteroPeerId -> { roomId, send, open, connKey? }
  _rooms: {},         // roomId -> room

  friends: lsGetJ("tk_friends", {}),
  queue: lsGetJ("tk_queue", {}),
  linkedDevices: {},  // "self:<deviceId>" -> { sameAccount, deviceId, online, name, lastSeen }

  view: "home",
  activeChat: null,
  fhTab: "all",
  typingTimers: {},
  rtimers: {},
  backoff: {},

  qrStream: null,
  qrScannedId: null,
  ctxTarget: null,
  msgCtxTarget: null,
  mobView: "home",
  peerReady: false,
  signalingOk: false,
  replyTo: null,
  editMsg: null,

  fileSyncOn: lsGet("tk_filesync", "1") === "1",
  largeFileSkip: lsGet("tk_largeskip", "1") === "1",
  fileTransfers: {},  // fileId -> transfer state
  pendingIdentityImport: null,
  identityPassMode: null
};

const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
  { urls: "stun:stun.cloudflare.com:3478" },
  { urls: "turn:openrelay.metered.ca:80", username: "openrelayproject", credential: "openrelayproject" },
  { urls: "turn:openrelay.metered.ca:443", username: "openrelayproject", credential: "openrelayproject" },
  { urls: "turn:openrelay.metered.ca:443?transport=tcp", username: "openrelayproject", credential: "openrelayproject" }
];

// ---------------------------------------------------------------------------
// Networking (Trystero 0.25+)
// ---------------------------------------------------------------------------
async function initPeer() {
  await CRYPTO.init();
  S.myFingerprint = CRYPTO.fingerprint;
  S.myId = "tk-" + CRYPTO.fingerprint;
  S._peerMap = {};
  S._rooms = {};

  setSig("warn", "connecting");
  updateTopBar();

  try {
    const mod = await import("https://esm.run/trystero@0.25.4");
    window.trystero = { joinRoom: mod.joinRoom };
  } catch (e) {
    console.error("[NET] trystero load failed", e);
    setSig("err", "offline");
    return;
  }

  _joinOwnRoom();
}

function _trysteroConfig() {
  return {
    appId: "tenkord-v3",
    relayUrls: [
      "wss://relay.damus.io",
      "wss://relay.primal.net",
      "wss://nos.lol",
      "wss://relay.nostr.band",
      "wss://nostr.fmt.wiz.biz"
    ],
    rtcConfig: { iceServers: ICE_SERVERS }
  };
}

function setSig(cls, text) {
  const dot = document.getElementById("sig-dot");
  const lbl = document.getElementById("sig-lbl");
  if (dot) dot.className = "sdot-sm " + cls;
  if (lbl) lbl.textContent = text;
}

function _joinOwnRoom() {
  _joinRoom(S.myId, false);
  S.peerReady = true;
  S.signalingOk = true;
  setSig("ok", "connected");
  updateTopBar();
  reconnectAll();
}

function _joinRoom(roomId, initiator) {
  if (S._rooms[roomId]) return S._rooms[roomId];

  const room = trystero.joinRoom(_trysteroConfig(), roomId);
  S._rooms[roomId] = room;

  const [sendData, getData] = room.makeAction("tk");
  room._send = sendData;

  room.onPeerJoin(async (peerId) => {
    console.log("[NET] peer joined", roomId, peerId);
    S._peerMap[peerId] = {
      roomId,
      send: (msg) => sendData(msg, peerId),
      open: true
    };
    // Immediate handshake
    const ts = Date.now().toString();
    const sig = await CRYPTO.sign(S.myId + ts);
    S._peerMap[peerId].send({
      type: "handshake",
      v: PROTOCOL_VERSION,
      id: S.myId,
      name: S.myName,
      avatar: S.myAvatar,
      status: S.myStatus,
      pubKey: CRYPTO.pubKeyRaw,
      ts,
      sig,
      deviceId: S.deviceId,
      appVersion: APP_VERSION
    });
  });

  room.onPeerLeave((peerId) => {
    const entry = S._peerMap[peerId];
    if (entry?.connKey) _connLost(entry.connKey);
    delete S._peerMap[peerId];
    console.log("[NET] peer left", roomId, peerId);
  });

  getData(async (data, peerId) => {
    const entry = S._peerMap[peerId];
    if (!entry) return;

    if (data.type === "handshake") {
      let ok = false;
      try {
        const fp = "tk-" + (await CRYPTO._fp(data.pubKey));
        ok = fp === data.id && await CRYPTO.verify(data.id + data.ts, data.sig, data.pubKey);
      } catch (_) {}
      if (!ok) {
        console.warn("[NET] handshake failed", peerId);
        entry.open = false;
        return;
      }

      const isSelf = data.id === S.myId;
      const connKey = isSelf ? ("self:" + data.deviceId) : data.id;
      entry.connKey = connKey;
      S.conns[connKey] = { send: entry.send, open: true };
      S.backoff[connKey] = 2000;
      setLoader(false);

      if (isSelf) {
        S.linkedDevices[connKey] = {
          sameAccount: true,
          deviceId: data.deviceId,
          online: true,
          name: data.name || data.deviceId.slice(-6),
          lastSeen: Date.now(),
          appVersion: data.appVersion
        };
        renderDeviceList();
        const ss = document.getElementById("sync-status");
        if (ss) {
          ss.textContent = "SYNCING";
          ss.className = "sync-badge syncing";
          ss.style.display = "";
        }
        setTimeout(() => syncWithOwnDevice(connKey), 600);
      } else {
        if (S.friends[connKey]) {
          Object.assign(S.friends[connKey], {
            name: data.name,
            avatar: data.avatar,
            status: data.status,
            pubKey: data.pubKey,
            verified: true,
            online: true,
            pending: false
          });
        } else {
          S.friends[connKey] = {
            name: data.name || connKey.slice(-8),
            avatar: data.avatar || "",
            status: data.status || "",
            pubKey: data.pubKey,
            verified: true,
            online: true,
            pending: true,
            unread: 0
          };
          toast("👋 Friend request from " + (data.name || connKey.slice(-8)));
        }
        saveFriendsAndQueue();
        renderFriendPanel();
        renderFriendsHome();
        renderMembers();
        processQueue(connKey);
        setTimeout(() => requestSync(connKey), 500);
      }
      return;
    }

    // Only process after verified handshake
    if (!entry.connKey || !S.conns[entry.connKey]?.open) return;
    handleData(entry.connKey, data);
  });

  if (initiator) {
    room._offlineTimer = setTimeout(() => {
      const any = Object.values(S._peerMap).some(e => e.roomId === roomId && e.connKey);
      if (!any) console.log("[NET] no peer in room", roomId);
    }, 30000);
  }
  return room;
}

function connectTo(peerId, silent = false) {
  peerId = canonicalId(peerId);
  if (!peerId || peerId === S.myId || S.conns[peerId]?.open) return;
  if (!silent) setLoader(true, "Connecting to " + (S.friends[peerId]?.name || peerId.slice(-8)) + "...");
  _joinRoom(peerId, true);
  schedRec(peerId, 25000);
}

function reconnectAll() {
  Object.keys(S.friends).forEach(id => {
    if (!S.conns[id]?.open && !S.friends[id]?.pending) {
      schedRec(id, 400 + Math.random() * 1200);
    }
  });
  // Re-announce in own room so sibling devices can find us
  if (!S._rooms[S.myId]) _joinOwnRoom();
}

function schedRec(id, delay) {
  if (S.rtimers[id]) return;
  const d = delay ?? Math.min(1.6 * (S.backoff[id] || 4000), 90000);
  S.backoff[id] = d;
  S.rtimers[id] = setTimeout(() => {
    delete S.rtimers[id];
    if (!S.conns[id]?.open && S.friends[id] && !S.friends[id].pending) {
      connectTo(id, true);
    }
  }, d);
}

function _connLost(connKey) {
  if (S.conns[connKey]) S.conns[connKey].open = false;
  delete S.conns[connKey];
  if (S.friends[connKey]) {
    S.friends[connKey].online = false;
    saveFriendsAndQueue();
    renderFriendPanel();
    renderFriendsHome();
    renderMembers();
  }
  if (S.linkedDevices[connKey]) {
    S.linkedDevices[connKey].online = false;
    renderDeviceList();
  }
  if (S.friends[connKey] && !S.friends[connKey].pending) schedRec(connKey);
  renderQueue();
}

function send(conn, msg) {
  try {
    if (conn?.open && conn.send) conn.send(msg);
  } catch (_) {}
}

function broadcastToLinked(msg) {
  Object.entries(S.linkedDevices).forEach(([key, info]) => {
    if (info.sameAccount && S.conns[key]?.open) send(S.conns[key], msg);
  });
}

function setLoader(show, text) {
  const el = document.getElementById("fullscreen-loader");
  if (text) document.getElementById("loader-status").textContent = text;
  el.classList.toggle("hidden", !show);
  if (show) {
    clearTimeout(setLoader._t);
    setLoader._t = setTimeout(() => el.classList.add("hidden"), 12000);
  }
}

// ---------------------------------------------------------------------------
// Queue (offline messages)
// ---------------------------------------------------------------------------
function addToQueue(peerId, packet) {
  S.queue[peerId] = S.queue[peerId] || [];
  S.queue[peerId].push(packet);
  localStorage.setItem("tk_queue", JSON.stringify(S.queue));
  renderQueue();
}

function renderQueue() {
  const el = document.getElementById("chat-queue-area");
  if (!el) return;
  if (S.activeChat && S.queue[S.activeChat.id]?.length) {
    const n = S.queue[S.activeChat.id].length;
    el.innerHTML = `<div class="queue-warning"><span>🕒 ${n} message${n > 1 ? "s" : ""} queued (offline)</span><span class="queue-cancel" onclick="clearQueue('${S.activeChat.id}')">Cancel all</span></div>`;
  } else {
    el.innerHTML = "";
  }
}

async function cleanupMessageFile(msg) {
  if (!msg) return;
  const fileId = msg.fileId || ((msg.mediaUrl || msg.fileName) ? msg.id : null);
  if (fileId) await dbDel("files", fileId);
}

async function removeQueuedMessage(packet) {
  if (!packet?.msgId || packet.type !== "dm") return;
  const msg = await dbGet("messages", packet.msgId);
  if (msg?.self) {
    await cleanupMessageFile(msg);
    await dbDel("messages", packet.msgId);
  }
}

async function clearQueue(peerId) {
  const q = S.queue[peerId] || [];
  delete S.queue[peerId];
  localStorage.setItem("tk_queue", JSON.stringify(S.queue));
  for (const m of q) await removeQueuedMessage(m);
  renderQueue();
  if (S.activeChat?.id === peerId) renderMessages();
}

async function processQueue(peerId) {
  const c = S.conns[peerId];
  if (!c?.open || !S.queue[peerId]) return;
  const q = S.queue[peerId];
  delete S.queue[peerId];
  localStorage.setItem("tk_queue", JSON.stringify(S.queue));
  renderQueue();
  q.forEach(m => send(c, m));
}

// ---------------------------------------------------------------------------
// Cross-device + friend sync
// ---------------------------------------------------------------------------
function isSameAccount(peerId) {
  return S.linkedDevices[peerId]?.sameAccount === true;
}

async function requestSync(peerId) {
  if (peerId === S.myId || peerId.startsWith("self:")) return;
  const msgs = await dbGetAll("messages", "chat", peerId);
  const ids = msgs.map(m => m.id);
  send(S.conns[peerId], { type: "sync-request", v: PROTOCOL_VERSION, knownIds: ids, deviceId: S.deviceId });
}

async function syncWithOwnDevice(peerId) {
  const all = await dbGetAll("messages");
  const ids = all.map(m => m.id);
  send(S.conns[peerId], {
    type: "device-sync-request",
    v: PROTOCOL_VERSION,
    knownIds: ids,
    deviceId: S.deviceId,
    friends: S.friends
  });
}

// The rest of the file continues with handleSyncRequest, file transfer, UI, boot, etc. (exact prefix of the full rewrite)

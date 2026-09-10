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

  const action = room.makeAction("tk");
  room._action = action;

  room.onPeerJoin = async (peerId) => {
    console.log("[NET] peer joined", roomId, peerId);
    S._peerMap[peerId] = {
      roomId,
      send: (msg) => action.send(msg, { target: peerId }),
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
  };

  room.onPeerLeave = (peerId) => {
    const entry = S._peerMap[peerId];
    if (entry?.connKey) _connLost(entry.connKey);
    delete S._peerMap[peerId];
    console.log("[NET] peer left", roomId, peerId);
  };

  action.onMessage = async (data, { peerId }) => {
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
  };

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

async function handleSyncRequest(from, data) {
  const msgs = await dbGetAll("messages", "chat", from);
  const missing = msgs.filter(m => !data.knownIds.includes(m.id));
  if (missing.length) {
    // chunk large responses
    for (let i = 0; i < missing.length; i += 40) {
      send(S.conns[from], { type: "sync-response", v: PROTOCOL_VERSION, messages: missing.slice(i, i + 40) });
    }
  }
}

async function handleSyncResponse(from, data) {
  let count = 0;
  for (const m of data.messages || []) {
    const existing = await dbGet("messages", m.id);
    if (!existing) {
      await dbPut("messages", m);
      count++;
    }
  }
  if (count > 0) {
    toast(`Synced ${count} messages`);
    if (S.activeChat?.id === from) renderMessages();
  }
}

async function handleDeviceSyncRequest(from, data) {
  // Merge their friends (don't overwrite richer local data)
  if (data.friends) {
    for (const [id, f] of Object.entries(data.friends)) {
      if (!S.friends[id]) {
        S.friends[id] = { ...f, online: false, pending: f.pending || false };
      } else {
        // keep local name/avatar if set, but adopt pubKey if missing
        if (!S.friends[id].pubKey && f.pubKey) S.friends[id].pubKey = f.pubKey;
      }
    }
    saveFriendsAndQueue();
    renderFriendPanel();
    renderFriendsHome();
  }

  const all = await dbGetAll("messages");
  const missing = all.filter(m => !data.knownIds.includes(m.id));
  send(S.conns[from], { type: "device-sync-friends", v: PROTOCOL_VERSION, friends: S.friends });
  if (missing.length) {
    for (let i = 0; i < missing.length; i += 40) {
      send(S.conns[from], {
        type: "device-sync-response",
        v: PROTOCOL_VERSION,
        messages: missing.slice(i, i + 40),
        total: missing.length,
        offset: i
      });
    }
  } else {
    // still notify synced
    send(S.conns[from], { type: "device-sync-response", v: PROTOCOL_VERSION, messages: [], total: 0, offset: 0 });
  }
}

async function handleDeviceSyncResponse(from, data) {
  let count = 0;
  for (const m of data.messages || []) {
    const existing = await dbGet("messages", m.id);
    if (!existing) {
      await dbPut("messages", m);
      count++;
    } else if ((m.editedAt || 0) > (existing.editedAt || 0) || (m.deleted && !existing.deleted)) {
      await dbPut("messages", { ...existing, ...m });
      count++;
    }
  }
  const ss = document.getElementById("sync-status");
  if (ss) {
    ss.textContent = "SYNCED";
    ss.className = "sync-badge synced";
    ss.style.display = "";
    setTimeout(() => { ss.style.display = "none"; }, 2800);
  }
  if (count > 0) {
    if (S.activeChat) renderMessages();
    renderFriendPanel();
  }
}

function requestHistoryFromFriend() {
  const raw = document.getElementById("import-hist-peer")?.value.trim();
  if (!raw) return toast("Enter a peer ID");
  const peerId = canonicalId(raw);
  if (!S.conns[peerId]?.open) return toast("Not connected to that peer");
  send(S.conns[peerId], { type: "history-request", v: PROTOCOL_VERSION, requesterId: S.myId });
  toast("History requested...");
}

async function handleHistoryRequest(from) {
  // Send a signed snapshot of messages that involve the requester
  const all = await dbGetAll("messages");
  const relevant = all.filter(m => m.chatId === from || m.authorId === from);
  const payload = JSON.stringify(relevant);
  const sig = await CRYPTO.sign(payload);
  send(S.conns[from], {
    type: "history-response",
    v: PROTOCOL_VERSION,
    messages: relevant,
    sig,
    pubKey: CRYPTO.pubKeyRaw
  });
}

async function handleHistoryResponse(from, data) {
  const verified = await CRYPTO.verify(JSON.stringify(data.messages), data.sig, data.pubKey);
  if (!verified) return toast("History verification failed");
  let count = 0;
  for (const m of data.messages || []) {
    const existing = await dbGet("messages", m.id);
    if (!existing) {
      await dbPut("messages", m);
      count++;
    }
  }
  toast(`Imported ${count} messages from friend`);
  if (S.activeChat) renderMessages();
}

// ---------------------------------------------------------------------------
// Incoming data router
// ---------------------------------------------------------------------------
async function handleData(from, n) {
  switch (n.type) {
    case "dm": {
      const verified = n.sig ? await CRYPTO.verify((n.text || "") + n.ts, n.sig, S.friends[from]?.pubKey || n.pubKey) : false;
      const msg = {
        id: n.msgId,
        chatId: from,
        author: n.author,
        avatar: n.avatar,
        text: n.text || "",
        ts: n.ts,
        self: false,
        verified,
        replyTo: n.replyTo || null,
        fileId: n.fileId || null,
        fileName: n.fileName || null,
        fileSize: n.fileSize || null,
        fileType: n.fileType || null,
        mediaUrl: n.mediaUrl || null,
        deleted: false
      };
      const existing = await dbGet("messages", msg.id);
      if (!existing) await dbPut("messages", msg);
      const f = S.friends[from];
      if (f) {
        f.lastMsg = n.text || n.fileName || "📎 File";
        f.unread = (f.unread || 0) + 1;
        f.online = true;
      }
      saveFriendsAndQueue();
      if (S.activeChat?.id === from) {
        appendMsg(msg);
        scrollBottom();
      } else {
        renderFriendPanel();
        renderFriendsHome();
      }
      if (n.fileId && !n.mediaUrl) initiateFileReceive(from, n);
      break;
    }
    case "edit-msg": {
      const msg = await dbGet("messages", n.msgId);
      if (!msg) break;
      msg.edits = msg.edits || [];
      msg.edits.push({ text: msg.text, ts: msg.ts });
      msg.text = n.newText;
      msg.editedAt = n.editTs;
      await dbPut("messages", msg);
      if (S.activeChat?.id === from) rerenderMsg(msg);
      break;
    }
    case "delete-msg": {
      const msg = await dbGet("messages", n.msgId);
      if (!msg) break;
      await cleanupMessageFile(msg);
      msg.deleted = true;
      msg.text = "[Message deleted]";
      msg.mediaUrl = null;
      msg.fileId = null;
      await dbPut("messages", msg);
      if (S.activeChat?.id === from) rerenderMsg(msg);
      break;
    }
    case "typing": {
      if (S.activeChat?.id === from) {
        const bar = document.getElementById("typing-bar");
        if (bar) {
          bar.textContent = (S.friends[from]?.name || "Friend") + " is typing…";
          clearTimeout(S.typingTimers[from]);
          S.typingTimers[from] = setTimeout(() => { bar.textContent = ""; }, 2500);
        }
      }
      break;
    }
    case "sync-request": handleSyncRequest(from, n); break;
    case "sync-response": handleSyncResponse(from, n); break;
    case "device-sync-request": handleDeviceSyncRequest(from, n); break;
    case "device-sync-response": handleDeviceSyncResponse(from, n); break;
    case "device-sync-friends": {
      if (n.friends) {
        for (const [id, f] of Object.entries(n.friends)) {
          if (!S.friends[id]) S.friends[id] = { ...f, online: false };
        }
        saveFriendsAndQueue();
        renderFriendPanel();
        renderFriendsHome();
      }
      break;
    }
    case "history-request": handleHistoryRequest(from); break;
    case "history-response": handleHistoryResponse(from, n); break;
    case "file-offer": handleFileOffer(from, n); break;
    case "file-accept": handleFileAccept(from, n); break;
    case "file-chunk": handleFileChunk(from, n); break;
    case "file-done": handleFileDone(from, n); break;
    case "file-request-pull": handleFilePull(from, n); break;
    case "profile-update": {
      if (S.friends[from]) {
        Object.assign(S.friends[from], { name: n.name, avatar: n.avatar, status: n.status });
        saveFriendsAndQueue();
        renderFriendPanel();
        renderFriendsHome();
        renderMembers();
      }
      break;
    }
    default:
      console.log("[NET] unknown type", n.type);
  }
}

// ---------------------------------------------------------------------------
// Messaging (send / edit / delete)
// ---------------------------------------------------------------------------
async function sendMsg() {
  const inp = document.getElementById("msg-input");
  const text = inp.value.trim();
  if (!text || !S.activeChat) return;
  if (inp.dataset.editId) {
    sendEdit(inp.dataset.editId, text);
    return;
  }
  inp.value = "";
  resizeTA(inp);

  const id = uuid();
  const ts = Date.now();
  const chatId = S.activeChat.id;
  const sig = await CRYPTO.sign(text + ts);
  const replyTo = S.replyTo ? { id: S.replyTo.id, author: S.replyTo.author, text: (S.replyTo.text || "").slice(0, 80) } : null;

  const msg = {
    id, chatId, author: S.myName, avatar: S.myAvatar, text, ts,
    self: true, verified: true, replyTo, deleted: false
  };
  const packet = {
    type: "dm", v: PROTOCOL_VERSION, msgId: id, author: S.myName, avatar: S.myAvatar,
    text, ts, sig, replyTo
  };

  await dbPut("messages", msg);
  const f = S.friends[chatId];
  if (f) { f.lastMsg = text; f.unread = 0; }
  saveFriendsAndQueue();
  appendMsg(msg);
  scrollBottom();
  renderFriendPanel();

  const conn = S.conns[chatId];
  if (conn?.open) send(conn, packet);
  else { addToQueue(chatId, packet); toast("Friend offline — queued"); }

  // Fan-out to every online linked device
  broadcastToLinked({ type: "device-sync-response", v: PROTOCOL_VERSION, messages: [msg], total: 1, offset: 0 });
  clearReply();
}

async function sendEdit(msgId, newText) {
  if (!newText) return;
  const msg = await dbGet("messages", msgId);
  if (!msg || !msg.self) return;
  const editTs = Date.now();
  const sig = await CRYPTO.sign(newText + msgId + editTs);
  msg.edits = msg.edits || [];
  msg.edits.push({ text: msg.text, ts: msg.ts });
  msg.text = newText;
  msg.editedAt = editTs;
  await dbPut("messages", msg);
  rerenderMsg(msg);

  const chatId = msg.chatId;
  const packet = { type: "edit-msg", v: PROTOCOL_VERSION, msgId, newText, author: S.myName, editTs, sig };
  const conn = S.conns[chatId];
  if (conn?.open) send(conn, packet);
  else addToQueue(chatId, packet);

  broadcastToLinked({ type: "device-sync-response", v: PROTOCOL_VERSION, messages: [msg], total: 1, offset: 0 });
  clearEdit();
}

async function deleteMsg(msgId) {
  if (!confirm("Delete this message for everyone?")) return;
  const msg = await dbGet("messages", msgId);
  if (!msg || !msg.self) return;
  const ts = Date.now();
  const sig = await CRYPTO.sign("delete" + msgId + ts);
  await cleanupMessageFile(msg);
  msg.deleted = true;
  msg.text = "[Message deleted]";
  msg.mediaUrl = null;
  msg.fileId = null;
  await dbPut("messages", msg);
  rerenderMsg(msg);

  const chatId = msg.chatId;
  const packet = { type: "delete-msg", v: PROTOCOL_VERSION, msgId, author: S.myName, ts, sig };
  const conn = S.conns[chatId];
  if (conn?.open) send(conn, packet);
  else addToQueue(chatId, packet);

  broadcastToLinked({ type: "device-sync-response", v: PROTOCOL_VERSION, messages: [msg], total: 1, offset: 0 });
}

function setReply(msg) {
  S.replyTo = msg;
  const area = document.getElementById("reply-bar-area");
  if (area) {
    area.innerHTML = `<div class="reply-bar"><span>↩️ Replying to ${msg.author || "msg"}: ${(msg.text || "").slice(0, 60)}</span><button onclick="clearReply()">✕</button></div>`;
  }
}
function clearReply() {
  S.replyTo = null;
  const area = document.getElementById("reply-bar-area");
  if (area) area.innerHTML = "";
}
function clearEdit() {
  S.editMsg = null;
  const inp = document.getElementById("msg-input");
  if (inp) { delete inp.dataset.editId; inp.placeholder = "Message..."; }
  const area = document.getElementById("edit-bar-area");
  if (area) area.innerHTML = "";
}

function sendTyping() {
  if (!S.activeChat) return;
  const conn = S.conns[S.activeChat.id];
  if (conn?.open) send(conn, { type: "typing", v: PROTOCOL_VERSION });
}

// ---------------------------------------------------------------------------
// File transfer (robust offer / accept / chunk / done)
// ---------------------------------------------------------------------------
function fileIcon(type) {
  if (!type) return "📎";
  if (type.startsWith("image/")) return "🖼️";
  if (type.startsWith("video/")) return "🎬";
  if (type.startsWith("audio/")) return "🎵";
  if (type.includes("pdf")) return "📄";
  if (type.includes("zip") || type.includes("compressed")) return "🗜️";
  return "📎";
}
function formatBytes(b) {
  if (b < 1024) return b + "B";
  if (b < 1048576) return (b / 1024).toFixed(1) + "KB";
  return (b / 1048576).toFixed(1) + "MB";
}

async function handleFileUpload(event) {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file || !S.activeChat) return;
  const isMedia = file.type.startsWith("image/") || file.type.startsWith("video/") || file.type.startsWith("audio/");
  const id = uuid();
  const chatId = S.activeChat.id;

  if (isMedia && file.size < MAX_INLINE_MEDIA) {
    const reader = new FileReader();
    reader.onload = async (e) => {
      const mediaUrl = e.target.result;
      const ts = Date.now();
      const sig = await CRYPTO.sign("" + ts);
      const msg = {
        id, chatId, author: S.myName, avatar: S.myAvatar, text: "", ts,
        self: true, verified: true, replyTo: null,
        fileName: file.name, fileType: file.type, fileSize: file.size, mediaUrl
      };
      const packet = {
        type: "dm", v: PROTOCOL_VERSION, msgId: id, author: S.myName, avatar: S.myAvatar,
        text: "", ts, sig, fileName: file.name, fileType: file.type, fileSize: file.size, mediaUrl
      };
      await dbPut("messages", msg);
      await dbPut("files", { id, name: file.name, type: file.type, size: file.size, data: mediaUrl, ts });
      saveFriendsAndQueue();
      appendMsg(msg);
      scrollBottom();
      const conn = S.conns[chatId];
      if (conn?.open) send(conn, packet);
      else addToQueue(chatId, packet);
      if (S.fileSyncOn && (!S.largeFileSkip || file.size <= LARGE_FILE_SKIP)) {
        broadcastToLinked({ type: "device-sync-response", v: PROTOCOL_VERSION, messages: [msg], total: 1, offset: 0 });
      }
    };
    reader.readAsDataURL(file);
  } else {
    await sendFileTransfer(file, id, chatId);
  }
}

async function sendFileTransfer(file, id, chatId) {
  const reader = new FileReader();
  reader.onload = async (e) => {
    const data = e.target.result; // ArrayBuffer
    await dbPut("files", { id, name: file.name, type: file.type, size: file.size, data, ts: Date.now() });
    const ts = Date.now();
    const sig = await CRYPTO.sign("" + ts);
    const msg = {
      id, chatId, author: S.myName, avatar: S.myAvatar, text: "", ts,
      self: true, verified: true, replyTo: null,
      fileId: id, fileName: file.name, fileType: file.type, fileSize: file.size, mediaUrl: null
    };
    const packet = {
      type: "dm", v: PROTOCOL_VERSION, msgId: id, author: S.myName, avatar: S.myAvatar,
      text: "", ts, sig, fileId: id, fileName: file.name, fileType: file.type, fileSize: file.size, mediaUrl: null
    };
    await dbPut("messages", msg);
    saveFriendsAndQueue();
    appendMsg(msg);
    scrollBottom();

    const conn = S.conns[chatId];
    if (conn?.open) {
      send(conn, packet);
      // Offer the file so the other side can pull
      setTimeout(() => startFileSend(id, chatId), 300);
    } else {
      addToQueue(chatId, packet);
    }

    if (S.fileSyncOn && (!S.largeFileSkip || file.size <= LARGE_FILE_SKIP)) {
      broadcastToLinked({ type: "device-sync-response", v: PROTOCOL_VERSION, messages: [msg], total: 1, offset: 0 });
    }
  };
  reader.readAsArrayBuffer(file);
}

async function startFileSend(fileId, peerId) {
  const conn = S.conns[peerId];
  if (!conn?.open) return;
  const f = await dbGet("files", fileId);
  if (!f) return;

  let buf = f.data;
  if (typeof buf === "string") {
    // data URL → ArrayBuffer
    const i = buf.indexOf(",");
    buf = b64ab(buf.slice(i + 1));
  }
  const total = buf.byteLength || buf.length;
  const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;

  send(conn, {
    type: "file-offer",
    v: PROTOCOL_VERSION,
    fileId,
    fileName: f.name,
    fileType: f.type,
    fileSize: total
  });

  // Wait for accept (or just stream after short delay for compatibility)
  S.fileTransfers[fileId] = S.fileTransfers[fileId] || {};
  S.fileTransfers[fileId].sending = true;

  let offset = 0;
  let idx = 0;
  function sendNext() {
    if (!S.conns[peerId]?.open) return;
    if (offset >= total) {
      send(conn, { type: "file-done", v: PROTOCOL_VERSION, fileId });
      return;
    }
    const end = Math.min(offset + CHUNK_SIZE, total);
    const chunk = u8.slice(offset, end);
    send(conn, {
      type: "file-chunk",
      v: PROTOCOL_VERSION,
      fileId,
      idx,
      data: abb64(chunk)
    });
    offset = end;
    idx++;
    setTimeout(sendNext, 8);
  }
  setTimeout(sendNext, 250);
}

function handleFileOffer(from, n) {
  // Auto-accept for now (could show UI later)
  S.fileTransfers[n.fileId] = {
    from,
    name: n.fileName,
    type: n.fileType,
    size: n.fileSize,
    chunks: [],
    received: 0,
    expected: Math.ceil(n.fileSize / CHUNK_SIZE)
  };
  send(S.conns[from], { type: "file-accept", v: PROTOCOL_VERSION, fileId: n.fileId });
}

function handleFileAccept(from, n) {
  // Already streaming in startFileSend; nothing extra needed
}

function handleFileChunk(from, n) {
  let ft = S.fileTransfers[n.fileId];
  if (!ft) {
    // late start
    ft = S.fileTransfers[n.fileId] = { from, name: "file", type: "", size: 0, chunks: [], received: 0 };
  }
  if (n.data) {
    ft.chunks[n.idx] = n.data;
    ft.received++;
  }
  const pct = ft.size ? Math.min(100, Math.round((ft.received * CHUNK_SIZE / ft.size) * 100)) : 50;
  const fill = document.getElementById("fill-" + n.fileId);
  const txt = document.getElementById("ftext-" + n.fileId);
  const prog = document.getElementById("fprog-" + n.fileId);
  if (prog) prog.style.display = "";
  if (fill) fill.style.width = pct + "%";
  if (txt) txt.textContent = pct + "% — " + formatBytes(ft.received * CHUNK_SIZE) + "/" + formatBytes(ft.size);
}

async function handleFileDone(from, n) {
  await assembleFile(n.fileId);
}

async function handleFilePull(from, n) {
  // Peer is asking us to re-send a file we have
  const f = await dbGet("files", n.fileId);
  if (f) startFileSend(n.fileId, from);
}

async function assembleFile(fileId) {
  const ft = S.fileTransfers[fileId];
  if (!ft) return;
  const parts = [];
  for (let i = 0; i < ft.chunks.length; i++) {
    if (ft.chunks[i]) parts.push(new Uint8Array(b64ab(ft.chunks[i])));
  }
  const total = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  parts.forEach(p => { buf.set(p, off); off += p.length; });

  const blob = new Blob([buf], { type: ft.type || "application/octet-stream" });
  let dataUrlOrBlobUrl = URL.createObjectURL(blob);

  if (ft.type && ft.type.startsWith("image/") && total < MAX_INLINE_MEDIA) {
    const reader = new FileReader();
    reader.onload = async (e) => {
      await dbPut("files", { id: fileId, name: ft.name, type: ft.type, size: total, data: e.target.result, ts: Date.now() });
      const msg = await dbGet("messages", fileId);
      if (msg) {
        msg.mediaUrl = e.target.result;
        await dbPut("messages", msg);
        if (S.activeChat?.id === ft.from) renderMessages();
      }
    };
    reader.readAsDataURL(blob);
  } else {
    await dbPut("files", { id: fileId, name: ft.name, type: ft.type, size: total, data: dataUrlOrBlobUrl, ts: Date.now() });
    const msg = await dbGet("messages", fileId);
    if (msg) {
      // keep mediaUrl null for large files; download button uses files store
      if (S.activeChat?.id === ft.from) renderMessages();
    }
  }

  const prog = document.getElementById("fprog-" + fileId);
  if (prog) prog.style.display = "none";
  toast("File received: " + (ft.name || fileId.slice(0, 8)));
  delete S.fileTransfers[fileId];
}

async function initiateFileReceive(peerId, msgData) {
  const conn = S.conns[peerId];
  if (conn?.open) {
    send(conn, { type: "file-request-pull", v: PROTOCOL_VERSION, fileId: msgData.fileId });
  }
}

async function downloadFile(fileId) {
  const f = await dbGet("files", fileId);
  if (!f) return toast("File not available");
  let url = f.data;
  if (typeof url === "string" && url.startsWith("data:")) {
    const arr = b64ab(url.slice(url.indexOf(",") + 1));
    const blob = new Blob([arr], { type: f.type });
    url = URL.createObjectURL(blob);
  }
  const a = document.createElement("a");
  a.href = url;
  a.download = f.name || "file";
  a.click();
}

// ---------------------------------------------------------------------------
// Favorites & GIFs (kept simple)
// ---------------------------------------------------------------------------
const GIF_KEY = "LIVDSRZULELA";

async function toggleFavorite(event, msgId) {
  event.stopPropagation();
  const msg = await dbGet("messages", msgId);
  if (!msg) return;
  const existing = await dbGet("favorites", msgId);
  if (existing) {
    await dbDel("favorites", msgId);
    toast("Removed from favorites");
    event.target.classList.remove("active");
  } else {
    await dbPut("favorites", {
      id: msgId,
      src: msg.mediaUrl || "",
      fileName: msg.fileName || "",
      fileType: msg.fileType || "",
      ts: Date.now()
    });
    toast("⭐ Added to favorites!");
    event.target.classList.add("active");
  }
}

async function openFavoritesPanel() {
  const favs = await dbGetAll("favorites");
  const grid = document.getElementById("fav-grid");
  const empty = document.getElementById("fav-empty");
  if (!favs.length) {
    grid.innerHTML = "";
    empty.style.display = "";
    openModal("favorites-modal");
    return;
  }
  empty.style.display = "none";
  grid.innerHTML = favs.map(f =>
    `<div class="fav-item"><img src="${f.src}" loading="lazy" onclick="sendFavorite('${f.id}')" title="Click to send"><button class="fav-remove" onclick="removeFavorite(event,'${f.id}')">❌</button></div>`
  ).join("");
  openModal("favorites-modal");
}

async function removeFavorite(e, id) {
  e.stopPropagation();
  await dbDel("favorites", id);
  openFavoritesPanel();
}

async function sendFavorite(id) {
  if (!S.activeChat) return;
  const f = await dbGet("favorites", id);
  if (!f) return;
  closeModal("favorites-modal");
  const msgId = uuid();
  const ts = Date.now();
  const chatId = S.activeChat.id;
  const sig = await CRYPTO.sign("" + ts);
  const msg = {
    id: msgId, chatId, author: S.myName, avatar: S.myAvatar, text: "", ts,
    self: true, verified: true, replyTo: null,
    fileName: f.fileName, fileType: f.fileType, mediaUrl: f.src
  };
  const packet = {
    type: "dm", v: PROTOCOL_VERSION, msgId, author: S.myName, avatar: S.myAvatar,
    text: "", ts, sig, fileName: f.fileName, fileType: f.fileType, mediaUrl: f.src
  };
  await dbPut("messages", msg);
  saveFriendsAndQueue();
  appendMsg(msg);
  scrollBottom();
  const conn = S.conns[chatId];
  if (conn?.open) send(conn, packet);
  else addToQueue(chatId, packet);
}

function toggleGifPicker(event) {
  event?.stopPropagation();
  if (!ensureActiveChatForAttachment()) return;
  const p = document.getElementById("gif-picker");
  closeAttachMenu();
  p.classList.toggle("open");
  if (p.classList.contains("open")) loadTrendingGifs();
}
function closeGifPicker() {
  document.getElementById("gif-picker")?.classList.remove("open");
}
function gifTab(tab, el) {
  document.querySelectorAll(".gif-picker-tab").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  if (tab === "favorites") loadFavGifs();
  else loadTrendingGifs();
}
async function loadTrendingGifs() {
  const grid = document.getElementById("gif-grid");
  grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">Loading...</div>';
  try {
    const r = await fetch(`https://tenor.googleapis.com/v2/featured?key=${GIF_KEY}&limit=20&media_filter=gif`);
    const j = await r.json();
    renderGifs(j.results || []);
  } catch (_) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">Could not load GIFs</div>';
  }
}
async function loadFavGifs() {
  const favs = await dbGetAll("favorites");
  const grid = document.getElementById("gif-grid");
  if (!favs.length) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">No favorites yet</div>';
    return;
  }
  grid.innerHTML = favs.map(f =>
    `<div class="gif-item" onclick="sendGif('${f.src}','${(f.fileName || "gif").replace(/'/g, "")}')"><img src="${f.src}" loading="lazy"></div>`
  ).join("");
}
function renderGifs(results) {
  const grid = document.getElementById("gif-grid");
  grid.innerHTML = results.map(g => {
    const url = g.media_formats?.gif?.url || g.media_formats?.tinygif?.url || "";
    return `<div class="gif-item" onclick="sendGif('${url}','gif')"><img src="${url}" loading="lazy"></div>`;
  }).join("");
}
async function sendGif(url, name) {
  if (!S.activeChat) return;
  closeGifPicker();
  const msgId = uuid();
  const ts = Date.now();
  const chatId = S.activeChat.id;
  const sig = await CRYPTO.sign("" + ts);
  const msg = {
    id: msgId, chatId, author: S.myName, avatar: S.myAvatar, text: "", ts,
    self: true, verified: true, replyTo: null,
    fileName: name, fileType: "image/gif", mediaUrl: url
  };
  const packet = {
    type: "dm", v: PROTOCOL_VERSION, msgId, author: S.myName, avatar: S.myAvatar,
    text: "", ts, sig, fileName: name, fileType: "image/gif", mediaUrl: url
  };
  await dbPut("messages", msg);
  saveFriendsAndQueue();
  appendMsg(msg);
  scrollBottom();
  const conn = S.conns[chatId];
  if (conn?.open) send(conn, packet);
  else addToQueue(chatId, packet);
}
function searchGifs(q) {
  clearTimeout(window._gifDebounce);
  window._gifDebounce = setTimeout(async () => {
    if (!q.trim()) return loadTrendingGifs();
    const grid = document.getElementById("gif-grid");
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">Searching...</div>';
    try {
      const r = await fetch(`https://tenor.googleapis.com/v2/search?key=${GIF_KEY}&q=${encodeURIComponent(q)}&limit=20&media_filter=gif`);
      const j = await r.json();
      renderGifs(j.results || []);
    } catch (_) {
      grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">Search failed</div>';
    }
  }, 400);
}

// ---------------------------------------------------------------------------
// UI rendering (friends, messages, members, devices)
// ---------------------------------------------------------------------------
function toast(msg) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("show"), 2800);
}

function updateTopBar() {
  const name = document.getElementById("ub-name");
  const idel = document.getElementById("ub-id");
  if (name) name.textContent = S.myName || "Set your name…";
  if (idel) idel.textContent = S.myId || "connecting...";
  const av = document.getElementById("ub-av");
  if (av) {
    if (S.myAvatar && (S.myAvatar.startsWith("data:") || S.myAvatar.startsWith("http"))) {
      av.innerHTML = `<img src="${S.myAvatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover"><span class="sdot online"></span>`;
    } else if (S.myAvatar) {
      av.innerHTML = S.myAvatar + '<span class="sdot online"></span>';
    }
  }
  const pp = document.getElementById("pp-id");
  const share = document.getElementById("pp-share-id");
  if (pp) pp.textContent = S.myId || "";
  if (share) share.textContent = S.myId || "";
  const linkTxt = document.getElementById("my-link-txt");
  if (linkTxt) linkTxt.textContent = S.myId ? `tenkord://peer/${S.myId}` : "loading...";
}

function renderFriendPanel() {
  const panel = document.getElementById("friend-list-panel");
  if (!panel) return;
  const entries = Object.entries(S.friends);
  if (!entries.length) {
    panel.innerHTML = '<div style="padding:20px;color:var(--muted);font-size:12px;text-align:center">No friends yet.<br>Tap ➕ to add someone.</div>';
    return;
  }
  panel.innerHTML = entries.map(([id, f]) => {
    const unread = f.unread ? `<span class="unread-badge">${f.unread}</span>` : "";
    const online = f.online ? "online" : "offline";
    const av = f.avatar && (f.avatar.startsWith("data:") || f.avatar.startsWith("http"))
      ? `<img src="${f.avatar}">` : (f.avatar || "👤");
    return `<div class="friend-item" onclick="openChat('${id}')" oncontextmenu="showCtx(event,'${id}')">
      <div class="av">${av}<span class="sdot ${online}"></span></div>
      <div class="fi-info"><div class="fi-name">${esc(f.name || id.slice(-8))}${unread}</div>
      <div class="fi-last">${esc(f.lastMsg || "")}</div></div></div>`;
  }).join("");
}

function renderFriendsHome() {
  const body = document.getElementById("fh-body");
  if (!body) return;
  let list = Object.entries(S.friends);
  if (S.fhTab === "online") list = list.filter(([, f]) => f.online);
  if (S.fhTab === "pending") list = list.filter(([, f]) => f.pending);
  if (!list.length) {
    body.innerHTML = '<div style="padding:40px;text-align:center;color:var(--muted);font-size:13px">Nothing here yet</div>';
    return;
  }
  body.innerHTML = list.map(([id, f]) => {
    const av = f.avatar && (f.avatar.startsWith("data:") || f.avatar.startsWith("http"))
      ? `<img src="${f.avatar}">` : (f.avatar || "👤");
    return `<div class="friend-row" onclick="openChat('${id}')">
      <div class="av">${av}<span class="sdot ${f.online ? "online" : "offline"}"></span></div>
      <div class="fr-info"><div class="fr-name">${esc(f.name || id.slice(-8))}</div>
      <div class="fr-status">${esc(f.status || (f.online ? "Online" : "Offline"))}</div></div>
      ${f.pending ? '<button class="btn btn-sm" onclick="event.stopPropagation();acceptFriend(\'' + id + '\')">Accept</button>' : ""}
    </div>`;
  }).join("");
}

function setFhTab(tab, el) {
  S.fhTab = tab;
  document.querySelectorAll(".fh-tab").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  renderFriendsHome();
}

function renderMembers() {
  const on = document.getElementById("mp-on");
  const off = document.getElementById("mp-off");
  if (!on || !off) return;
  const online = [], offline = [];
  Object.entries(S.friends).forEach(([id, f]) => {
    (f.online ? online : offline).push({ id, f });
  });
  // also show self
  online.unshift({ id: S.myId, f: { name: S.myName + " (you)", avatar: S.myAvatar, online: true } });
  on.innerHTML = online.map(({ id, f }) => memberRow(id, f)).join("") || '<div class="mp-empty">Nobody online</div>';
  off.innerHTML = offline.map(({ id, f }) => memberRow(id, f)).join("") || '<div class="mp-empty">—</div>';
}

function memberRow(id, f) {
  const av = f.avatar && (f.avatar.startsWith("data:") || f.avatar.startsWith("http"))
    ? `<img src="${f.avatar}">` : (f.avatar || "👤");
  return `<div class="mp-item" onclick="openFriendProfile('${id}')"><div class="av sm">${av}<span class="sdot ${f.online ? "online" : "offline"}"></span></div><span>${esc(f.name || id.slice(-8))}</span></div>`;
}

function renderDeviceList() {
  const area = document.getElementById("device-list-area");
  if (!area) return;
  const devices = Object.entries(S.linkedDevices);
  if (!devices.length) {
    area.innerHTML = '<div style="font-size:11px;color:var(--muted);font-family:var(--font-mono)">No other devices linked yet. Export your identity JSON and import it on another device.</div>';
    return;
  }
  area.innerHTML = devices.map(([key, d]) =>
    `<div class="device-row"><span class="sdot ${d.online ? "online" : "offline"}"></span>
     <span>${esc(d.name || d.deviceId.slice(-6))} ${d.online ? "(online)" : "(offline)"}</span>
     <span style="font-size:10px;color:var(--muted)">${d.appVersion || ""}</span></div>`
  ).join("");
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s || "";
  return d.innerHTML;
}

async function renderMessages() {
  const el = document.getElementById("messages");
  if (!el || !S.activeChat) return;
  const msgs = await dbGetAll("messages", "chat", S.activeChat.id);
  msgs.sort((a, b) => a.ts - b.ts);
  el.innerHTML = msgs.map(m => msgHtml(m)).join("");
  scrollBottom();
}

function msgHtml(m) {
  if (m.deleted) {
    return `<div class="msg ${m.self ? "self" : ""} deleted" data-id="${m.id}"><div class="msg-body">[Message deleted]</div></div>`;
  }
  let body = "";
  if (m.mediaUrl) {
    if ((m.fileType || "").startsWith("image/") || (m.fileType || "").includes("gif")) {
      body = `<img class="msg-media" src="${m.mediaUrl}" onclick="openLightbox('${m.mediaUrl}')" loading="lazy">`;
    } else if ((m.fileType || "").startsWith("video/")) {
      body = `<video class="msg-media" src="${m.mediaUrl}" controls></video>`;
    } else {
      body = `<a class="msg-file" href="${m.mediaUrl}" download="${esc(m.fileName || "file")}">${fileIcon(m.fileType)} ${esc(m.fileName || "File")}</a>`;
    }
  } else if (m.fileId) {
    body = `<div class="msg-file-pending" id="fprog-${m.fileId}">
      <div>${fileIcon(m.fileType)} ${esc(m.fileName || "File")} (${formatBytes(m.fileSize || 0)})</div>
      <div class="prog-bar"><div class="prog-fill" id="fill-${m.fileId}" style="width:0%"></div></div>
      <div class="prog-text" id="ftext-${m.fileId}">waiting…</div>
      <button class="btn btn-sm" onclick="downloadFile('${m.fileId}')">Download</button>
    </div>`;
  }
  if (m.text) body += `<div class="msg-text">${esc(m.text)}</div>`;
  const reply = m.replyTo ? `<div class="msg-reply">↩️ ${esc(m.replyTo.author)}: ${esc(m.replyTo.text || "")}</div>` : "";
  const edited = m.editedAt ? ' <span class="edited">(edited)</span>' : "";
  return `<div class="msg ${m.self ? "self" : ""}" data-id="${m.id}" oncontextmenu="showMsgCtx(event,'${m.id}')">
    ${!m.self ? `<div class="msg-author">${esc(m.author || "")}</div>` : ""}
    ${reply}${body}
    <div class="msg-meta">${new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}${edited}
    ${m.mediaUrl ? `<button class="fav-btn" onclick="toggleFavorite(event,'${m.id}')">⭐</button>` : ""}
    </div></div>`;
}

function appendMsg(m) {
  const el = document.getElementById("messages");
  if (!el) return;
  el.insertAdjacentHTML("beforeend", msgHtml(m));
}
function rerenderMsg(m) {
  const el = document.querySelector(`.msg[data-id="${m.id}"]`);
  if (el) el.outerHTML = msgHtml(m);
}
function scrollBottom() {
  const el = document.getElementById("messages");
  if (el) el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------------------
// Chat open / navigation
// ---------------------------------------------------------------------------
async function openChat(id) {
  id = canonicalId(id);
  S.activeChat = { id, name: S.friends[id]?.name || id.slice(-8) };
  S.view = "chat";
  document.getElementById("friends-home").style.display = "none";
  document.getElementById("chat-view").style.display = "flex";
  document.getElementById("hdr-name").textContent = S.activeChat.name;
  document.getElementById("hdr-sub").textContent = S.friends[id]?.online ? "Online" : "Offline";
  if (S.friends[id]) S.friends[id].unread = 0;
  saveFriendsAndQueue();
  renderFriendPanel();
  await renderMessages();
  if (window.innerWidth <= 620) {
    document.getElementById("left-panel")?.classList.remove("open");
  }
  connectTo(id, true);
}

function closeActiveChat() {
  S.activeChat = null;
  document.getElementById("chat-view").style.display = "none";
}

function showFriendsHome() {
  document.getElementById("friends-home").style.display = "flex";
  document.getElementById("chat-view").style.display = "none";
  S.view = "home";
  renderFriendsHome();
}
function hideFriendsHome() {
  document.getElementById("friends-home").style.display = "none";
}

function goBack() {
  if (window.innerWidth > 620) openLP();
  if (S.view === "home") showFriendsHome();
  else hideFriendsHome();
  closeActiveChat();
}

function openLP() { document.getElementById("left-panel")?.classList.add("open"); }
function closeLP() { document.getElementById("left-panel")?.classList.remove("open"); }

function openMembersPanel() {
  if (window.innerWidth <= 620) {
    renderMobMembers();
    document.getElementById("mob-members-sheet")?.classList.add("open");
    document.getElementById("sheet-backdrop")?.classList.add("open");
  } else {
    const e = document.getElementById("members-panel");
    e.style.display = e.style.display === "flex" ? "none" : "flex";
  }
}

function renderMobMembers() {
  const body = document.getElementById("mob-members-body");
  if (!body) return;
  const online = Object.entries(S.friends).filter(([, f]) => f.online);
  body.innerHTML = online.map(([id, f]) => memberRow(id, f)).join("") || '<div style="padding:20px;color:var(--muted)">Nobody else online</div>';
}

function mobNav(tab) {
  if (tab === "home") {
    switchView("home");
    setMobTab("home");
  }
}
function setMobTab(tab) {
  document.querySelectorAll(".mob-nav-item").forEach(e => e.classList.remove("active"));
  if (tab === "home") document.getElementById("mob-tab-home")?.classList.add("active");
}
function switchView(v) {
  S.view = v;
  if (v === "home") {
    showFriendsHome();
    closeActiveChat();
  }
}

function openActionSheet() {
  document.getElementById("mob-action-sheet")?.classList.add("open");
  document.getElementById("sheet-backdrop")?.classList.add("open");
}
function closeActionSheet() {
  document.getElementById("mob-action-sheet")?.classList.remove("open");
  document.getElementById("sheet-backdrop")?.classList.remove("open");
}
function closeAllSheets() {
  document.getElementById("mob-members-sheet")?.classList.remove("open");
  document.getElementById("mob-action-sheet")?.classList.remove("open");
  document.getElementById("sheet-backdrop")?.classList.remove("open");
}

// ---------------------------------------------------------------------------
// Profile / identity / QR
// ---------------------------------------------------------------------------
const EMOJIS = ["🌙","🌊","🔥","⚡","🎯","🦊","🐸","🤖","👾","🎮","🎵","💎","🚀","🌙","⭐","🦁","🎲","🧠","⚔️","🔮","👽","💡","🔧","🎨"];

function buildEmojiStrip() {
  const el = document.getElementById("av-emoji-strip");
  if (!el) return;
  el.innerHTML = EMOJIS.map(e =>
    `<div class="av-eo${S.myAvatar === e ? " sel" : ""}" onclick="pickEmoji('${e}')">${e}</div>`
  ).join("");
}
function pickEmoji(t) {
  S.myAvatar = t;
  localStorage.setItem("tk_avatar", t);
  document.querySelectorAll(".av-eo").forEach(e => e.classList.toggle("sel", e.textContent === t));
  refreshAvPreview();
  updateTopBar();
}
function refreshAvPreview() {
  const e = document.getElementById("av-preview");
  if (!e) return;
  if (S.myAvatar && (S.myAvatar.startsWith("data:") || S.myAvatar.startsWith("http"))) {
    e.innerHTML = `<img src="${S.myAvatar}">`;
  } else {
    e.innerHTML = `<span class="av-up-icon">📷</span><span class="av-up-lbl">Upload photo</span>`;
  }
}
function handleAvUpload(e) {
  const f = e.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = (ev) => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = 128; c.height = 128;
      const ctx = c.getContext("2d");
      const n = Math.min(img.width, img.height);
      const a = (img.width - n) / 2;
      const b = (img.height - n) / 2;
      ctx.drawImage(img, a, b, n, n, 0, 0, 128, 128);
      S.myAvatar = c.toDataURL("image/jpeg", 0.85);
      localStorage.setItem("tk_avatar", S.myAvatar);
      refreshAvPreview();
      updateTopBar();
    };
    img.src = ev.target.result;
  };
  r.readAsDataURL(f);
}

async function saveProfile() {
  S.myName = document.getElementById("p-name")?.value.trim() || S.myName;
  S.myStatus = document.getElementById("p-status")?.value.trim() || "";
  localStorage.setItem("tk_name", S.myName);
  localStorage.setItem("tk_status", S.myStatus);
  updateTopBar();
  // broadcast profile to friends + linked devices
  const ts = Date.now().toString();
  const sig = await CRYPTO.sign(S.myId + ts);
  const msg = {
    type: "profile-update", v: PROTOCOL_VERSION,
    name: S.myName, avatar: S.myAvatar, status: S.myStatus, ts, sig
  };
  Object.values(S.conns).forEach(c => send(c, msg));
  // also re-handshake style for discovery
  toast("Profile saved");
  closeModal("profile-modal");
  renderQR();
}

function renderQR() {
  const cont = document.getElementById("qr-cont");
  if (!cont || !S.myId || typeof QRCode === "undefined") return;
  cont.innerHTML = "";
  new QRCode(cont, {
    text: "tenkord://peer/" + S.myId,
    width: 160,
    height: 160,
    colorDark: "#f5c400",
    colorLight: "#0a0a0a"
  });
}

function copyMyId() {
  if (!S.myId) return;
  navigator.clipboard.writeText(S.myId).then(() => toast("Peer ID copied"));
}
function copyMyInviteLink() {
  if (!S.myId) return;
  navigator.clipboard.writeText("tenkord://peer/" + S.myId).then(() => toast("Invite link copied"));
}
function copyToClip(t) {
  navigator.clipboard.writeText(t).then(() => toast("Copied"));
}

function openModal(id) {
  document.getElementById(id)?.classList.add("open");
  if (id === "profile-modal") {
    document.getElementById("p-name").value = S.myName;
    document.getElementById("p-status").value = S.myStatus;
    buildEmojiStrip();
    refreshAvPreview();
    updateTopBar();
    renderQR();
    renderDeviceList();
    document.getElementById("toggle-file-sync")?.classList.toggle("on", S.fileSyncOn);
    document.getElementById("toggle-large-skip")?.classList.toggle("on", S.largeFileSkip);
  }
}
function closeModal(id) {
  document.getElementById(id)?.classList.remove("open");
}
function switchTab(el, modalId) {
  const modal = document.getElementById(modalId);
  modal.querySelectorAll(".mtab").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  modal.querySelectorAll(".tpane").forEach(p => p.classList.remove("active"));
  document.getElementById("tab-" + el.dataset.tab)?.classList.add("active");
}

// Identity import / export
function openIdentityPassModal(mode) {
  S.identityPassMode = mode;
  document.getElementById("identity-pass-title").textContent = mode === "export" ? "Export Identity" : "Import Identity";
  document.getElementById("identity-pass-help").textContent = mode === "export"
    ? "Choose a passphrase to encrypt your identity bundle. You will need it to import on another device."
    : "Enter the passphrase used when this identity was exported.";
  document.getElementById("identity-pass-input").value = "";
  openModal("identity-pass-modal");
  setTimeout(() => document.getElementById("identity-pass-input")?.focus(), 100);
}
function closeIdentityPassModal() {
  closeModal("identity-pass-modal");
  S.identityPassMode = null;
}
function openIdentityExportModal() { openIdentityPassModal("export"); }
function triggerIdentityImportFile() { document.getElementById("identity-import-file")?.click(); }

function handleIdentityImportFile(event) {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    S.pendingIdentityImport = e.target.result;
    openIdentityPassModal("import");
  };
  reader.readAsText(file);
}

async function confirmIdentityPass() {
  const pass = document.getElementById("identity-pass-input")?.value;
  if (!pass) return toast("Enter a passphrase");
  if (S.identityPassMode === "export") await exportIdentity(pass);
  else await importIdentity(pass);
}

async function exportIdentity(pass) {
  try {
    const bundle = await CRYPTO.exportBundle(pass, {
      name: S.myName,
      status: S.myStatus,
      avatar: S.myAvatar,
      deviceId: S.deviceId
    });
    const blob = new Blob([bundle], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "tenkord-identity.json";
    a.click();
    URL.revokeObjectURL(a.href);
    closeIdentityPassModal();
    toast("Identity exported!");
  } catch (e) {
    toast("Export failed: " + e.message);
  }
}

async function importIdentity(pass) {
  if (!S.pendingIdentityImport) return toast("Choose an identity JSON file first");
  if (!confirm("Replace identity on this device? Current local key will be overwritten.")) return;
  try {
    const meta = await CRYPTO.importBundle(S.pendingIdentityImport, pass);
    if (meta.name) { S.myName = meta.name; localStorage.setItem("tk_name", meta.name); }
    if (meta.status) { S.myStatus = meta.status; localStorage.setItem("tk_status", meta.status); }
    if (meta.avatar) { S.myAvatar = meta.avatar; localStorage.setItem("tk_avatar", meta.avatar); }
    S.pendingIdentityImport = null;
    closeIdentityPassModal();
    toast("Identity imported — reloading…");
    setTimeout(() => location.reload(), 600);
  } catch (e) {
    toast("Import failed (wrong passphrase or corrupt file)");
  }
}

function toggleFileSyncSetting(el) {
  S.fileSyncOn = !S.fileSyncOn;
  el.classList.toggle("on", S.fileSyncOn);
  localStorage.setItem("tk_filesync", S.fileSyncOn ? "1" : "0");
}
function toggleLargeSkip(el) {
  S.largeFileSkip = !S.largeFileSkip;
  el.classList.toggle("on", S.largeFileSkip);
  localStorage.setItem("tk_largeskip", S.largeFileSkip ? "1" : "0");
}

// ---------------------------------------------------------------------------
// Add friend / QR / links
// ---------------------------------------------------------------------------
function addFriendById() {
  const raw = document.getElementById("af-id-input")?.value.trim();
  const nick = document.getElementById("af-nick")?.value.trim();
  if (!raw) return toast("Enter a Peer ID");
  const id = canonicalId(raw);
  if (id === S.myId) return toast("That's you");
  S.friends[id] = S.friends[id] || {
    name: nick || id.slice(-8),
    avatar: "",
    status: "",
    online: false,
    pending: false,
    unread: 0
  };
  if (nick) S.friends[id].name = nick;
  saveFriendsAndQueue();
  renderFriendPanel();
  renderFriendsHome();
  connectTo(id);
  closeModal("add-friend-modal");
  toast("Connecting…");
}

function joinByLink() {
  const raw = document.getElementById("af-link-input")?.value.trim();
  if (!raw) return;
  const id = parsePeerLink(raw);
  if (!id) return toast("Invalid link");
  document.getElementById("af-id-input").value = id;
  addFriendById();
}

function parsePeerLink(str) {
  if (!str) return null;
  const m = str.match(/(?:tenkord:\/\/peer\/|tk-)([a-f0-9]{16})/i);
  if (m) return "tk-" + m[1].toLowerCase();
  if (/^tk-[a-f0-9]{16}$/i.test(str.trim())) return str.trim().toLowerCase();
  return null;
}

async function startQRScan() {
  const area = document.getElementById("qr-scan-area");
  const video = document.getElementById("qr-video");
  area.style.display = "block";
  try {
    S.qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
    video.srcObject = S.qrStream;
    if ("BarcodeDetector" in window) {
      const det = new BarcodeDetector({ formats: ["qr_code"] });
      const loop = async () => {
        if (!S.qrStream) return;
        try {
          const codes = await det.detect(video);
          if (codes.length) {
            const id = parsePeerLink(codes[0].rawValue);
            if (id) {
              S.qrScannedId = id;
              document.getElementById("qr-scanned-display").textContent = id;
              document.getElementById("qr-result").style.display = "block";
              stopQRScan();
              return;
            }
          }
        } catch (_) {}
        setTimeout(loop, 500);
      };
      video.onloadeddata = loop;
    } else {
      toast("QR scanning not supported in this browser");
    }
  } catch (_) {
    toast("Camera denied");
    area.style.display = "none";
  }
}
function stopQRScan() {
  if (S.qrStream) {
    S.qrStream.getTracks().forEach(t => t.stop());
    S.qrStream = null;
  }
}
function connectScannedQR() {
  if (!S.qrScannedId) return;
  S.friends[S.qrScannedId] = S.friends[S.qrScannedId] || {
    name: S.qrScannedId.slice(-8), avatar: "", status: "", online: false, pending: false, unread: 0
  };
  saveFriendsAndQueue();
  connectTo(S.qrScannedId);
  setLoader(false);
  closeModal("add-friend-modal");
}

function acceptFriend(id) {
  if (S.friends[id]) {
    S.friends[id].pending = false;
    saveFriendsAndQueue();
    renderFriendsHome();
    renderFriendPanel();
    connectTo(id);
  }
}

// ---------------------------------------------------------------------------
// Context menus, lightbox, helpers
// ---------------------------------------------------------------------------
function showCtx(e, id) {
  e.preventDefault();
  S.ctxTarget = id;
  const menu = document.getElementById("ctx-menu");
  menu.style.left = e.clientX + "px";
  menu.style.top = e.clientY + "px";
  menu.classList.add("open");
  document.getElementById("ctx-profile").onclick = () => { openFriendProfile(id); menu.classList.remove("open"); };
  document.getElementById("ctx-dm").onclick = () => { openChat(id); menu.classList.remove("open"); };
  document.getElementById("ctx-copy-id").onclick = () => { copyToClip(id); menu.classList.remove("open"); };
  document.getElementById("ctx-remove").onclick = () => {
    if (confirm("Remove friend?")) {
      delete S.friends[id];
      saveFriendsAndQueue();
      renderFriendPanel();
      renderFriendsHome();
    }
    menu.classList.remove("open");
  };
}
function showMsgCtx(e, msgId) {
  e.preventDefault();
  S.msgCtxTarget = msgId;
  const menu = document.getElementById("msg-ctx-menu");
  menu.style.left = e.clientX + "px";
  menu.style.top = e.clientY + "px";
  menu.classList.add("open");
  document.getElementById("mctx-reply").onclick = async () => {
    const m = await dbGet("messages", msgId);
    if (m) setReply(m);
    menu.classList.remove("open");
  };
  document.getElementById("mctx-edit").onclick = async () => {
    const m = await dbGet("messages", msgId);
    if (m && m.self) {
      const inp = document.getElementById("msg-input");
      inp.value = m.text;
      inp.dataset.editId = msgId;
      inp.placeholder = "Edit message…";
      document.getElementById("edit-bar-area").innerHTML = `<div class="edit-bar">Editing message <button onclick="clearEdit()">✕</button></div>`;
      inp.focus();
    }
    menu.classList.remove("open");
  };
  document.getElementById("mctx-delete").onclick = () => {
    deleteMsg(msgId);
    menu.classList.remove("open");
  };
}
document.addEventListener("click", () => {
  document.getElementById("ctx-menu")?.classList.remove("open");
  document.getElementById("msg-ctx-menu")?.classList.remove("open");
  closeAttachMenu();
});

function openFriendProfile(id) {
  const f = id === S.myId
    ? { name: S.myName, status: S.myStatus, avatar: S.myAvatar }
    : S.friends[id];
  if (!f) return;
  document.getElementById("fp-name").textContent = f.name || id.slice(-8);
  document.getElementById("fp-status").textContent = f.status || "";
  document.getElementById("fp-id").textContent = id;
  const av = document.getElementById("fp-av");
  if (f.avatar && (f.avatar.startsWith("data:") || f.avatar.startsWith("http"))) {
    av.innerHTML = `<img src="${f.avatar}">`;
  } else {
    av.textContent = f.avatar || "👤";
  }
  document.getElementById("fp-dm-btn").onclick = () => { closeModal("fp-modal"); openChat(id); };
  openModal("fp-modal");
}

function openLightbox(src) {
  const lb = document.getElementById("media-lightbox");
  document.getElementById("lightbox-content").innerHTML = `<img src="${src}">`;
  lb.classList.add("open");
}
function closeLightbox() {
  document.getElementById("media-lightbox")?.classList.remove("open");
}

function toggleAttachMenu() {
  if (!ensureActiveChatForAttachment()) return;
  document.getElementById("attach-menu")?.classList.toggle("open");
}
function closeAttachMenu() {
  document.getElementById("attach-menu")?.classList.remove("open");
}
function triggerFileInput(id) {
  closeAttachMenu();
  document.getElementById(id)?.click();
}
function ensureActiveChatForAttachment() {
  if (!S.activeChat) {
    toast("Open a chat first");
    return false;
  }
  return true;
}
function openAttachmentFavorites() {
  closeAttachMenu();
  openFavoritesPanel();
}

function resizeTA(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 120) + "px";
}
function handleKey(e) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMsg();
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function boot() {
  setLoader(true, "Starting Tenkord…");
  try {
    await openDB();
    await initPeer();
    updateTopBar();
    renderFriendPanel();
    renderFriendsHome();
    renderMembers();
    buildEmojiStrip();
    // hide loader after a short moment if still showing
    setTimeout(() => setLoader(false), 1500);
  } catch (e) {
    console.error("Boot failed", e);
    setSig("err", "error");
    setLoader(false);
    toast("Failed to start: " + e.message);
  }
}

// Expose everything the HTML onclick handlers need
Object.assign(window, {
  openModal, closeModal, switchTab, saveProfile, addFriendById, joinByLink,
  startQRScan, connectScannedQR, copyMyId, copyMyInviteLink, copyToClip,
  sendMsg, handleKey, resizeTA, sendTyping, setFhTab, openChat, goBack,
  openMembersPanel, openActionSheet, closeActionSheet, closeAllSheets, mobNav,
  handleFileUpload, toggleAttachMenu, triggerFileInput, toggleGifPicker, closeGifPicker,
  gifTab, searchGifs, sendGif, openFavoritesPanel, openAttachmentFavorites,
  toggleFavorite, removeFavorite, sendFavorite, downloadFile,
  openIdentityExportModal, triggerIdentityImportFile, handleIdentityImportFile,
  confirmIdentityPass, closeIdentityPassModal, toggleFileSyncSetting, toggleLargeSkip,
  requestHistoryFromFriend, pickEmoji, handleAvUpload, clearQueue, clearReply, clearEdit,
  openFriendProfile, openLightbox, closeLightbox, acceptFriend, showCtx, showMsgCtx,
  setReply, deleteMsg
});

document.addEventListener("DOMContentLoaded", boot);

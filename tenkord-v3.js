// === TENKORD V3 CORE ===
function abb64(e){var t=new Uint8Array(e);let n="";for(let e=0;e<t.length;e++)n+=String.fromCharCode(t[e]);return btoa(n)}
function b64ab(e){var t=atob(e),n=new Uint8Array(t.length);for(let e=0;e<t.length;e++)n[e]=t.charCodeAt(e);return n.buffer}
function rnd16(){return crypto.getRandomValues(new Uint8Array(16))}
function rnd12(){return crypto.getRandomValues(new Uint8Array(12))}
function uuid(){return crypto.randomUUID?crypto.randomUUID():Math.random().toString(36).slice(2)+Date.now().toString(36)}

let CRYPTO={privateKey:null,publicKey:null,pubKeyRaw:null,fingerprint:null,
async init(){var e=localStorage.getItem("tk_kp");if(e)try{var{priv:t,pub:n}=JSON.parse(e);return this.privateKey=await crypto.subtle.importKey("pkcs8",b64ab(t),{name:"ECDSA",namedCurve:"P-256"},!0,["sign"]),this.publicKey=await crypto.subtle.importKey("spki",b64ab(n),{name:"ECDSA",namedCurve:"P-256"},!0,["verify"]),this.pubKeyRaw=n,void(this.fingerprint=await this._fp(n))}catch(e){localStorage.removeItem("tk_kp")}await this._generate()},
async _generate(){var e=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},!0,["sign","verify"]),t=abb64(await crypto.subtle.exportKey("pkcs8",e.privateKey)),n=abb64(await crypto.subtle.exportKey("spki",e.publicKey));localStorage.setItem("tk_kp",JSON.stringify({priv:t,pub:n})),this.privateKey=e.privateKey,this.publicKey=e.publicKey,this.pubKeyRaw=n,this.fingerprint=await this._fp(n)},
async sign(e){return abb64(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},this.privateKey,new TextEncoder().encode(String(e))))},
async verify(e,t,n){try{var a=await crypto.subtle.importKey("spki",b64ab(n),{name:"ECDSA",namedCurve:"P-256"},!1,["verify"]);return await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},a,b64ab(t),new TextEncoder().encode(String(e)))}catch(e){return!1}},
async _fp(e){e=await crypto.subtle.digest("SHA-256",b64ab(e));return Array.from(new Uint8Array(e)).slice(0,8).map(e=>e.toString(16).padStart(2,"0")).join("")},
async exportBundle(e,t){var n=rnd16(),a=rnd12(),e2=await this._deriveKey(e,n),r=await crypto.subtle.exportKey("pkcs8",this.privateKey),t2=JSON.stringify(t||{}),t3=new TextEncoder().encode(t2),r2=new Uint8Array(r),s=new Uint8Array(4+r2.length+t3.length);new DataView(s.buffer).setUint32(0,r2.length,!1);s.set(r2,4);s.set(t3,4+r2.length);var ct=await crypto.subtle.encrypt({name:"AES-GCM",iv:a},e2,s);return JSON.stringify({v:1,pub:this.pubKeyRaw,salt:abb64(n),iv:abb64(a),data:abb64(ct)})},
async importBundle(e,t){e=JSON.parse(e);if(1!==e.v)throw new Error("Unknown bundle version");var n=b64ab(e.salt),a=b64ab(e.iv),dk=await this._deriveKey(t,n),pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:a},dk,b64ab(e.data)),kl=new DataView(pt).getUint32(0,!1),kb=pt.slice(4,4+kl),md=new TextDecoder().decode(pt.slice(4+kl)),meta=JSON.parse(md||"{}"),pk=await crypto.subtle.importKey("pkcs8",kb,{name:"ECDSA",namedCurve:"P-256"},!0,["sign"]),pub=await crypto.subtle.importKey("spki",b64ab(e.pub),{name:"ECDSA",namedCurve:"P-256"},!0,["verify"]),pe=abb64(await crypto.subtle.exportKey("pkcs8",pk));return localStorage.setItem("tk_kp",JSON.stringify({priv:pe,pub:e.pub})),this.privateKey=pk,this.publicKey=pub,this.pubKeyRaw=e.pub,this.fingerprint=await this._fp(e.pub),meta},
async _deriveKey(e,t){var k=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),"PBKDF2",!1,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t,iterations:2e5,hash:"SHA-256"},k,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])}
};

// === IndexedDB ===
let DB=null;
function openDB(){return new Promise((res,rej)=>{let r=indexedDB.open("tenkord",3);r.onupgradeneeded=e=>{let db=e.target.result;if(!db.objectStoreNames.contains("messages")){let ms=db.createObjectStore("messages",{keyPath:"id"});ms.createIndex("chat","chatId");ms.createIndex("ts","ts")}if(!db.objectStoreNames.contains("files"))db.createObjectStore("files",{keyPath:"id"});if(!db.objectStoreNames.contains("favorites"))db.createObjectStore("favorites",{keyPath:"id"})};r.onsuccess=e=>{DB=e.target.result;res(DB)};r.onerror=e=>rej(e)})}

function dbPut(store,obj){return new Promise((res,rej)=>{let tx=DB.transaction(store,"readwrite");tx.objectStore(store).put(obj);tx.oncomplete=()=>res();tx.onerror=e=>rej(e)})}
function dbGet(store,key){return new Promise((res,rej)=>{let tx=DB.transaction(store);let r=tx.objectStore(store).get(key);r.onsuccess=()=>res(r.result);r.onerror=e=>rej(e)})}
function dbGetAll(store,indexName,key){return new Promise((res,rej)=>{let tx=DB.transaction(store);let src=indexName?tx.objectStore(store).index(indexName):tx.objectStore(store);let r=key?src.getAll(key):src.getAll();r.onsuccess=()=>res(r.result);r.onerror=e=>rej(e)})}
function dbDel(store,key){return new Promise((res,rej)=>{let tx=DB.transaction(store,"readwrite");tx.objectStore(store).delete(key);tx.oncomplete=()=>res();tx.onerror=e=>rej(e)})}

// === State ===
function lsGet(e,t){return localStorage.getItem(e)||t}
function lsGetJ(e,t){try{return JSON.parse(localStorage.getItem(e))||t}catch(e){return t}}
function save(){localStorage.setItem("tk_friends",JSON.stringify(S.friends));localStorage.setItem("tk_queue",JSON.stringify(S.queue))}

// Canonical friend key: "tk-<fingerprint>" derived from any peer ID format
function canonicalId(peerId){
  if(!peerId)return peerId;
  let fp=fpFromPeerId(peerId);
  return fp?"tk-"+fp:peerId;
}

let S={myId:null,myFingerprint:null,myName:lsGet("tk_name",""),myStatus:lsGet("tk_status",""),myAvatar:lsGet("tk_avatar",""),
peer:null,conns:{},rtimers:{},backoff:{},
friends:lsGetJ("tk_friends",{}),queue:lsGetJ("tk_queue",{}),
view:"home",activeChat:null,fhTab:"all",typingTimers:{},
qrStream:null,qrScannedId:null,ctxTarget:null,msgCtxTarget:null,mobView:"home",
peerReady:!1,signalingOk:!1,
replyTo:null,editMsg:null,
deviceId:lsGet("tk_device_id","")||(() =>{let id=uuid();localStorage.setItem("tk_device_id",id);return id})(),
linkedDevices:{},fileSyncOn:lsGet("tk_filesync","1")==="1",largeFileSkip:lsGet("tk_largeskip","1")==="1",
fileTransfers:{},pendingIdentityImport:null,identityPassMode:null
};
let gifDebounce=null;

let ICE_SERVERS=[{urls:"stun:stun.l.google.com:19302"},{urls:"stun:stun1.l.google.com:19302"},{urls:"stun:stun2.l.google.com:19302"},{urls:"stun:stun3.l.google.com:19302"},{urls:"stun:openrelay.metered.ca:80"},{urls:"turn:openrelay.metered.ca:80",username:"openrelayproject",credential:"openrelayproject"},{urls:"turn:openrelay.metered.ca:443",username:"openrelayproject",credential:"openrelayproject"},{urls:"turn:openrelay.metered.ca:443?transport=tcp",username:"openrelayproject",credential:"openrelayproject"}];

// === Networking ===
const PEER_SERVERS=[
  {host:"0.peerjs.com",port:443,path:"/",secure:true,key:"peerjs"},
  {host:"peer.peerjs.com",port:443,path:"/",secure:true,key:"peerjs"},
  {host:"peerjs.fly.dev",port:443,path:"/",secure:true,key:"peerjs"},
];
async function initPeer(){await CRYPTO.init();S.myFingerprint=CRYPTO.fingerprint;S.myId="tk-"+CRYPTO.fingerprint+"-"+S.deviceId.slice(0,8);document.getElementById("sig-dot").className="sdot-sm warn";document.getElementById("sig-lbl").textContent="connecting";updateTopBar();await loadScript("https://cdnjs.cloudflare.com/ajax/libs/peerjs/1.5.2/peerjs.min.js");_startPeer(0)}
function _startPeer(serverIdx=0){if(S.peer){try{S.peer.destroy()}catch(e){}S.peer=null}
let srv=PEER_SERVERS[serverIdx%PEER_SERVERS.length];
console.log("[NET] trying signaling server",srv.host);
S.peer=new Peer(S.myId,{...srv,config:{iceServers:ICE_SERVERS},debug:0});
S.peer.on("open",e=>{S.peerReady=!0;S.signalingOk=!0;document.getElementById("sig-dot").className="sdot-sm ok";document.getElementById("sig-lbl").textContent="connected";updateTopBar();reconnectAll()});
S.peer.on("connection",e=>handleIncomingConn(e));
S.peer.on("disconnected",()=>{S.peerReady=!1;document.getElementById("sig-dot").className="sdot-sm warn";document.getElementById("sig-lbl").textContent="reconnecting";setTimeout(()=>{if(S.peer&&!S.peer.destroyed)try{S.peer.reconnect()}catch(e){_startPeer(serverIdx)}else _startPeer(serverIdx)},3e3)});
S.peer.on("error",e=>{console.warn("[NET]",e.type,e.message);if(e.type==="unavailable-id"){setTimeout(()=>_startPeer(serverIdx+1),1e3)}else if(["network","server-error","socket-error","webrtc"].includes(e.type)){document.getElementById("sig-dot").className="sdot-sm warn";document.getElementById("sig-lbl").textContent="retrying...";let next=serverIdx+1;let delay=next%PEER_SERVERS.length===0?8e3:2e3;setTimeout(()=>_startPeer(next),delay)}else if(e.type==="peer-unavailable"){let m=e.message?.match(/Could not connect to peer ([^\s]+)/);if(m){let rawId=m[1];schedRec(canonicalId(rawId)||rawId,15e3,rawId)}}})}
function loadScript(a){return new Promise((e,t)=>{if(document.querySelector(`script[src="${a}"]`))return e();let n=document.createElement("script");n.src=a;n.onload=e;n.onerror=t;document.head.appendChild(n)})}
function connectTo(t,silent=!1){
  // t is the canonical friend key; use stored peerId if available for actual network connect
  let netId=S.friends[t]?.peerId||t;
  if(S.peer&&t&&t!==S.myId&&!S.conns[t]?.open)
    if(S.peerReady)try{if(!silent)setLoader(!0,"Connecting to "+(S.friends[t]?.name||t.slice(-8))+"...");setupConn(S.peer.connect(netId,{reliable:!0,metadata:{from:S.myId,name:S.myName}}))}catch(e){setLoader(!1);schedRec(t,5e3)}
    else schedRec(t,3e3)
}
function reconnectAll(){Object.keys(S.friends).forEach(e=>{if(!S.conns[e]?.open&&!S.friends[e].pending)schedRec(e,500+1e3*Math.random())})}
function schedRec(e,t,rawPeerId){if(!S.rtimers[e]){t=t??Math.min(1.5*(S.backoff[e]||2e3),12e4);S.backoff[e]=t;// store raw peer ID so connectTo can use it
if(rawPeerId&&S.friends[e])S.friends[e].peerId=rawPeerId;
S.rtimers[e]=setTimeout(()=>{delete S.rtimers[e];if(!S.conns[e]?.open&&S.friends[e]&&!S.friends[e].pending)connectTo(e,!0)},t)}}
function handleIncomingConn(e){
  let cid=canonicalId(e.peer);
  if(S.conns[cid]?.open){if(S.myId<e.peer)return void e.close();try{S.conns[cid].close()}catch(x){}}
  setupConn(e)
}

function setupConn(n){n.on("open",async()=>{setLoader(!1);
let isSelf=fpFromPeerId(n.peer)===S.myFingerprint;
let connKey=isSelf?n.peer:canonicalId(n.peer);
S.conns[connKey]=n;S.backoff[connKey]=2e3;
let ts=Date.now().toString(),sig=await CRYPTO.sign(S.myId+ts);
send(n,{type:"handshake",id:S.myId,name:S.myName,avatar:S.myAvatar,status:S.myStatus,pubKey:CRYPTO.pubKeyRaw,ts,sig,deviceId:S.deviceId});
if(S.friends[connKey]){S.friends[connKey].online=!0;save();renderFriendPanel();renderFriendsHome();renderMembers()}
processQueue(connKey);setTimeout(()=>isSelf?syncWithOwnDevice(connKey):requestSync(connKey),600)});
n.on("data",e=>{
  let isSelf=fpFromPeerId(n.peer)===S.myFingerprint;
  let connKey=isSelf?n.peer:canonicalId(n.peer);
  handleData(connKey,e)
});
n.on("close",()=>{
  let isSelf=fpFromPeerId(n.peer)===S.myFingerprint;
  let connKey=isSelf?n.peer:canonicalId(n.peer);
  _connLost(connKey,n.peer)
});
n.on("error",e=>{console.warn("[NET] conn error",n.peer,e);
  let isSelf=fpFromPeerId(n.peer)===S.myFingerprint;
  let connKey=isSelf?n.peer:canonicalId(n.peer);
  _connLost(connKey,n.peer);setLoader(!1)})}

function _connLost(connKey,rawPeerId){delete S.conns[connKey];if(S.friends[connKey]){S.friends[connKey].online=!1;save();renderFriendPanel();renderFriendsHome();renderMembers()}if(S.linkedDevices[connKey])S.linkedDevices[connKey].online=!1;if(S.friends[connKey]&&!S.friends[connKey].pending)schedRec(connKey,undefined,rawPeerId);renderQueue()}
function send(e,t){try{if(e&&e.open)e.send(t)}catch(x){}}
function broadcast(n,skip){Object.entries(S.conns).forEach(([e,t])=>{if(e!==skip)send(t,n)})}
function setLoader(e,t){var n=document.getElementById("fullscreen-loader");if(t)document.getElementById("loader-status").textContent=t;n.classList.toggle("hidden",!e);if(e){clearTimeout(setLoader._t);setLoader._t=setTimeout(()=>n.classList.add("hidden"),10000)}}

// === Queue ===
function addToQueue(e,t){S.queue[e]=S.queue[e]||[];S.queue[e].push(t);localStorage.setItem("tk_queue",JSON.stringify(S.queue));renderQueue()}
function renderQueue(){let el=document.getElementById("chat-queue-area");if(!el)return;if(S.activeChat&&S.queue[S.activeChat.id]?.length){let n=S.queue[S.activeChat.id].length;el.innerHTML=`<div class="queue-warning"><span>🕒 ${n} message${n>1?"s":""} queued (offline)</span><span class="queue-cancel" onclick="clearQueue('${S.activeChat.id}')">Cancel all</span></div>`}else el.innerHTML=""}
async function cleanupMessageFile(msg){
  if(!msg)return;
  let fileId=msg.fileId||((msg.mediaUrl||msg.fileName||msg.fileType)?msg.id:null);
  if(fileId)await dbDel("files",fileId);
}
async function removeQueuedMessage(packet){
  if(!packet?.msgId||packet.type!=="dm")return;
  let msg=await dbGet("messages",packet.msgId);
  if(msg?.self){await cleanupMessageFile(msg);await dbDel("messages",packet.msgId)}
}
async function clearQueue(e){let q=S.queue[e]||[];delete S.queue[e];localStorage.setItem("tk_queue",JSON.stringify(S.queue));for(let m of q)await removeQueuedMessage(m);renderQueue();if(S.activeChat?.id===e)renderMessages()}
async function processQueue(t){let c=S.conns[t];if(c?.open&&S.queue[t]){let q=S.queue[t];delete S.queue[t];localStorage.setItem("tk_queue",JSON.stringify(S.queue));renderQueue();q.forEach(m=>send(c,m))}}

// === Cross-device sync ===
function isSameAccount(peerId){return S.linkedDevices[peerId]?.sameAccount===!0}
// Sync with a friend: exchange messages for that specific chat
async function requestSync(peerId){
  // Only do friend-sync for non-own-account peers
  if(fpFromPeerId(peerId)===S.myFingerprint)return;
  let msgs=await dbGetAll("messages","chat",peerId);
  let ids=msgs.map(m=>m.id);
  send(S.conns[peerId],{type:"sync-request",knownIds:ids,deviceId:S.deviceId})
}

// Sync with own device: exchange ALL messages
async function syncWithOwnDevice(peerId){
  let allMsgs=await dbGetAll("messages");
  let ids=allMsgs.map(m=>m.id);
  send(S.conns[peerId],{type:"device-sync-request",knownIds:ids,deviceId:S.deviceId})
}

async function handleSyncRequest(from,data){
  let msgs=await dbGetAll("messages","chat",from);
  let missing=msgs.filter(m=>!data.knownIds.includes(m.id));
  if(missing.length)send(S.conns[from],{type:"sync-response",messages:missing})
}
async function handleSyncResponse(from,data){
  let count=0;
  for(let m of data.messages){let existing=await dbGet("messages",m.id);if(!existing){await dbPut("messages",m);count++}}
  if(count>0){toast(`Synced ${count} messages`);if(S.activeChat?.id===from)renderMessages()}
}
async function handleDeviceSyncRequest(from,data){
  let allMsgs=await dbGetAll("messages");
  let missing=allMsgs.filter(m=>!data.knownIds.includes(m.id));
  // Send friend list so new device can reconnect to everyone
  send(S.conns[from],{type:"device-sync-friends",friends:S.friends});
  if(missing.length){
    for(let i=0;i<missing.length;i+=50){
      send(S.conns[from],{type:"device-sync-response",messages:missing.slice(i,i+50),total:missing.length,offset:i})
    }
  }
}
async function handleDeviceSyncResponse(from,data){let count=0;for(let m of data.messages){let existing=await dbGet("messages",m.id);if(!existing){await dbPut("messages",m);count++}}if(count>0){let ss=document.getElementById("sync-status");if(ss){ss.textContent="SYNCED";ss.className="sync-badge synced";ss.style.display="";setTimeout(()=>ss.style.display="none",3000)}if(S.activeChat)renderMessages();renderFriendPanel()}}
async function relayPendingForAccount(friendId){if(!S.conns[friendId]?.open)return;Object.entries(S.linkedDevices).forEach(([devPeer,info])=>{if(info.sameAccount&&S.conns[devPeer]?.open){send(S.conns[devPeer],{type:"relay-check",friendId})}})}
function requestHistoryFromFriend(){let raw=document.getElementById("import-hist-peer")?.value.trim();if(!raw)return toast("Enter a peer ID");let peerId=canonicalId(raw)||raw;if(!S.conns[peerId]?.open)return toast("Not connected to that peer");send(S.conns[peerId],{type:"history-request",requesterId:S.myId});toast("History requested...")}
async function handleHistoryRequest(from){if(!S.friends[from])return;let msgs=await dbGetAll("messages","chat",from);let bundle=JSON.stringify(msgs);let sig=await CRYPTO.sign(bundle);send(S.conns[from],{type:"history-response",messages:msgs,sig,pubKey:CRYPTO.pubKeyRaw})}
async function handleHistoryResponse(from,data){let verified=await CRYPTO.verify(JSON.stringify(data.messages),data.sig,data.pubKey);if(!verified)return toast("History verification failed!");let count=0;for(let m of data.messages){let existing=await dbGet("messages",m.id);if(!existing){await dbPut("messages",m);count++}}toast(`Imported ${count} messages from friend`);if(S.activeChat)renderMessages()}
async function broadcastProfile(){let ts=Date.now().toString(),sig=await CRYPTO.sign(S.myId+ts);let msg={type:"handshake",id:S.myId,name:S.myName,avatar:S.myAvatar,status:S.myStatus,pubKey:CRYPTO.pubKeyRaw,ts,sig,deviceId:S.deviceId};Object.values(S.conns).forEach(c=>send(c,msg))}

// === MESSAGE HANDLING ===
async function handleData(t,n){
  switch(n.type){
    case "handshake":{
      let ok=false;
      try{let fp="tk-"+(await CRYPTO._fp(n.pubKey));let idFp=canonicalId(n.id);ok=fp===idFp&&await CRYPTO.verify(n.id+n.ts,n.sig,n.pubKey)}catch(e){}
      if(!ok){S.conns[t]?.close();break}
      let sameAccount=fpFromPeerId(t)===S.myFingerprint;
      if(sameAccount){
        S.linkedDevices[t]={sameAccount:true,deviceId:n.deviceId,online:true,name:n.name||t.slice(-8)};
        renderDeviceList();
        let ss=document.getElementById("sync-status");
        if(ss){ss.textContent="SYNCING";ss.className="sync-badge syncing";ss.style.display=""}
        setTimeout(()=>syncWithOwnDevice(t),700);
      }
      if(!sameAccount){
        if(S.friends[t])Object.assign(S.friends[t],{name:n.name,avatar:n.avatar,status:n.status,pubKey:n.pubKey,verified:true,online:true,peerId:t});
        else{S.friends[t]={name:n.name||t.slice(-8),avatar:n.avatar||"",status:n.status||"",pubKey:n.pubKey,verified:true,online:true,pending:true,unread:0};toast("👋 Friend request from "+(n.name||t.slice(-8)))}
      }
      save();renderFriendPanel();renderFriendsHome();renderMembers();break;
    }
    case "dm":{
      let f=S.friends[t];
      let verified=false;
      if(f?.pubKey)verified=await CRYPTO.verify(n.text+n.ts,n.sig,f.pubKey);
      let existing=await dbGet("messages",n.msgId);
      if(existing)break;
      let msg={id:n.msgId,chatId:t,author:n.author,avatar:n.avatar,text:n.text,ts:n.ts,self:false,verified,replyTo:n.replyTo||null,fileId:n.fileId||null,fileName:n.fileName||null,fileSize:n.fileSize||null,fileType:n.fileType||null,mediaUrl:n.mediaUrl||null};
      await dbPut("messages",msg);
      if(f){f.lastMsg=n.text||n.fileName||"📎 File";f.unread=(f.unread||0)+1}
      save();
      if(S.activeChat?.type==="dm"&&S.activeChat?.id===t){appendMsg(msg);scrollBottom();if(f){f.unread=0;save()}}
      renderFriendPanel();renderFriendsHome();updateMobBadge();
      if(n.fileId&&!n.mediaUrl)initiateFileReceive(t,n);
      break;
    }
    case "edit-msg":{
      let msg=await dbGet("messages",n.msgId);
      if(!msg)break;
      let f=S.friends[t];
      if(!f?.pubKey)break;
      let verified=await CRYPTO.verify(n.newText+n.msgId+n.editTs,n.sig,f.pubKey);
      if(!verified)break;
      msg.edits=msg.edits||[];
      msg.edits.push({text:msg.text,ts:msg.ts});
      msg.text=n.newText;msg.editedAt=n.editTs;
      await dbPut("messages",msg);
      if(S.activeChat?.id===t)rerenderMsg(msg);
      break;
    }
    case "delete-msg":{
      let msg=await dbGet("messages",n.msgId);
      if(!msg)break;
      let f=S.friends[t];
      if(!f?.pubKey)break;
      let verified=await CRYPTO.verify("delete"+n.msgId+n.ts,n.sig,f.pubKey);
      if(!verified)break;
      await cleanupMessageFile(msg);
      msg.deleted=true;msg.text="[Message deleted]";msg.mediaUrl=null;msg.fileId=null;
      await dbPut("messages",msg);
      if(S.activeChat?.id===t)rerenderMsg(msg);
      break;
    }
    case "typing":
      if(S.activeChat?.type==="dm"&&S.activeChat?.id===t)showTyping(n.name);break;
    case "accept-friend":{
      let f=S.friends[t];
      if(f?.pending){f.pending=false;save();renderFriendPanel();renderFriendsHome();toast(f.name+" is now your friend")}break;
    }
    case "sync-request": handleSyncRequest(t,n);break;
    case "sync-response": handleSyncResponse(t,n);break;
    case "device-sync-friends": {
      // Merge friend list from sibling device; don't overwrite existing richer data
      let changed=false;
      Object.entries(n.friends||{}).forEach(([id,f])=>{
        if(!S.friends[id]){S.friends[id]={...f,online:false};changed=true}
      });
      if(changed){save();renderFriendPanel();renderFriendsHome();renderMembers();reconnectAll()}
      break;
    }
    case "device-sync-request": handleDeviceSyncRequest(t,n);break;
    case "device-sync-response": handleDeviceSyncResponse(t,n);break;
    case "history-request": handleHistoryRequest(t);break;
    case "history-response": handleHistoryResponse(t,n);break;
    case "file-chunk": handleFileChunk(t,n);break;
    case "file-request": handleFileRequest(t,n);break;
    case "relay-check": {
      if(S.queue[n.friendId]?.length) send(S.conns[t], {type:"relay-queue", friendId: n.friendId, messages: S.queue[n.friendId]});
      break;
    }
    case "relay-queue": {
      n.messages.forEach(m => addToQueue(n.friendId, m));
      break;
    }
  }
}

async function relayQueuedForDevice(friendId){
  Object.entries(S.linkedDevices).forEach(([devPeer,info])=>{
    if(info.sameAccount&&S.conns[devPeer]?.open)
      send(S.conns[devPeer],{type:"relay-check",friendId});
  });
}

async function sendMsg(){
  let inp=document.getElementById("msg-input"),text=inp.value.trim();
  if(!text||!S.activeChat)return;
  if(inp.dataset.editId){sendEdit(inp.dataset.editId,text);return}
  inp.value="";resizeTA(inp);
  let id=uuid(),ts=Date.now(),chatId=S.activeChat.id;
  let sig=await CRYPTO.sign(text+ts);
  let replyTo=S.replyTo?{id:S.replyTo.id,author:S.replyTo.author,text:(S.replyTo.text||"").slice(0,80)}:null;
  let msg={id,chatId,author:S.myName,avatar:S.myAvatar,text,ts,self:true,verified:true,replyTo};
  let packet={type:"dm",msgId:id,author:S.myName,avatar:S.myAvatar,text,ts,sig,replyTo};
  await dbPut("messages",msg);
  let f=S.friends[chatId];if(f){f.lastMsg=text;f.unread=0}
  save();appendMsg(msg);scrollBottom();renderFriendPanel();
  let conn=S.conns[chatId];
  if(conn?.open)send(conn,packet);
  else{addToQueue(chatId,packet);toast("Friend offline — queued")}
  Object.entries(S.linkedDevices).forEach(([d,i])=>{if(i.sameAccount&&S.conns[d]?.open)send(S.conns[d],{type:"device-sync-response",messages:[msg],total:1,offset:0})});
  clearReply();
}

async function sendEdit(msgId,newText){
  if(!newText)return;
  let msg=await dbGet("messages",msgId);
  if(!msg||!msg.self)return;
  let editTs=Date.now(),sig=await CRYPTO.sign(newText+msgId+editTs);
  msg.edits=msg.edits||[];
  msg.edits.push({text:msg.text,ts:msg.ts});
  msg.text=newText;msg.editedAt=editTs;
  await dbPut("messages",msg);rerenderMsg(msg);
  let chatId=msg.chatId,packet={type:"edit-msg",msgId,newText,author:S.myName,editTs,sig};
  let conn=S.conns[chatId];
  if(conn?.open)send(conn,packet);else addToQueue(chatId,packet);
  Object.entries(S.linkedDevices).forEach(([d,i])=>{if(i.sameAccount&&S.conns[d]?.open)send(S.conns[d],{type:"device-sync-response",messages:[msg],total:1,offset:0})});
  clearEdit();
}

async function deleteMsg(msgId){
  if(!confirm("Delete this message for everyone?"))return;
  let msg=await dbGet("messages",msgId);
  if(!msg||!msg.self)return;
  let ts=Date.now(),sig=await CRYPTO.sign("delete"+msgId+ts);
  await cleanupMessageFile(msg);
  msg.deleted=true;msg.text="[Message deleted]";msg.mediaUrl=null;msg.fileId=null;
  await dbPut("messages",msg);rerenderMsg(msg);
  let chatId=msg.chatId,packet={type:"delete-msg",msgId,author:S.myName,ts,sig};
  let conn=S.conns[chatId];
  if(conn?.open)send(conn,packet);else addToQueue(chatId,packet);
  Object.entries(S.linkedDevices).forEach(([d,i])=>{if(i.sameAccount&&S.conns[d]?.open)send(S.conns[d],{type:"device-sync-response",messages:[msg],total:1,offset:0})});
}

function setReply(msg){
  S.replyTo=msg;clearEdit();
  document.getElementById("reply-bar-area").innerHTML=`<div class="reply-bar"><span style="color:var(--y)">↩️ Reply to <b>${esc(msg.author)}</b></span><span class="reply-bar-text">${esc((msg.text||"File").slice(0,60))}</span><button class="reply-bar-close" onclick="clearReply()">❌</button></div>`;
  document.getElementById("msg-input").focus();
}
function clearReply(){S.replyTo=null;document.getElementById("reply-bar-area").innerHTML=""}

function startEdit(msgId){
  dbGet("messages",msgId).then(msg=>{
    if(!msg||!msg.self)return;
    S.editMsg=msg;clearReply();
    let inp=document.getElementById("msg-input");
    inp.value=msg.text;resizeTA(inp);inp.focus();inp.dataset.editId=msgId;
    document.getElementById("edit-bar-area").innerHTML=`<div class="edit-bar">📝 Editing message<button class="edit-bar-close" onclick="clearEdit()">❌</button></div>`;
  });
}
function clearEdit(){S.editMsg=null;document.getElementById("edit-bar-area").innerHTML="";let inp=document.getElementById("msg-input");delete inp.dataset.editId}

function handleKey(e){
  if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();
    let inp=document.getElementById("msg-input");
    if(inp.dataset.editId)sendEdit(inp.dataset.editId,inp.value.trim());
    else sendMsg();
  }
}
function resizeTA(e){e.style.height="auto";e.style.height=Math.min(e.scrollHeight,120)+"px"}
let tyDebounce;
function sendTyping(){
  if(!S.activeChat||S.activeChat.type!=="dm")return;
  clearTimeout(tyDebounce);
  let c=S.conns[S.activeChat.id];
  if(c?.open)send(c,{type:"typing",name:S.myName});
  tyDebounce=setTimeout(()=>{},3e3);
}
function showTyping(e){let t=document.getElementById("typing-bar");t.innerHTML=`<div class="tdots"><span></span><span></span><span></span></div><span>${esc(e)} is typing</span>`;clearTimeout(S.typingTimers[e]);S.typingTimers[e]=setTimeout(()=>t.innerHTML="",4e3)}
function addFriendById(){
  let raw=document.getElementById("af-id-input").value.trim(),t=document.getElementById("af-nick").value.trim();
  if(!raw)return toast("Enter a Peer ID");
  let e=canonicalId(raw)||raw; // normalize to tk-<fp>
  if(e===canonicalId(S.myId))return toast("That is your own ID!");
  if(S.friends[e]){if(t)S.friends[e].name=t;S.friends[e].peerId=raw}
  else S.friends[e]={name:t||raw.slice(-8),avatar:"",status:"",online:false,pending:false,unread:0,peerId:raw};
  save();connectTo(e);renderFriendPanel();renderFriendsHome();closeModal("add-friend-modal");toast("Connecting...");
}
function acceptFriend(e){let f=S.friends[e];if(!f)return;f.pending=false;save();let c=S.conns[e];if(c?.open)send(c,{type:"accept-friend"});else connectTo(e);renderFriendPanel();renderFriendsHome();toast("Accepted "+f.name)}
function declineFriend(e){delete S.friends[e];S.conns[e]?.close();save();renderFriendPanel();renderFriendsHome()}
function removeFriend(e){delete S.friends[e];S.conns[e]?.close();clearTimeout(S.rtimers[e]);delete S.rtimers[e];save();renderFriendPanel();renderFriendsHome();renderMembers();toast("Friend removed")}
function joinByLink(){let e=parsePeerLink(document.getElementById("af-link-input").value.trim());if(e){document.getElementById("af-id-input").value=e;addFriendById()}else toast("Invalid link")}

// UI helpers
function esc(e){return String(e||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
function fmt(e){let t=esc(e);return t.replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>").replace(/\*(.+?)\*/g,"<em>$1</em>").replace(/`(.+?)`/g,"<code>$1</code>").replace(/@(\w+)/g,'<span class="mention">@$1</span>').replace(/\n/g,"<br>")}
function avI(e){return e?(e.startsWith("data:")||e.startsWith("http")?`<img src="${e}" style="width:100%;height:100%;object-fit:cover">`:e):"👤"}
function avH(e,t=30,n){return `<div class="av" style="width:${t}px;height:${t}px;font-size:${Math.round(.46*t)}px;flex-shrink:0">${avI(e?.avatar)}${n?`<span class="sdot ${n}"></span>`:""}</div>`}
function toast(e){let t=document.getElementById("toast");t.textContent=e;t.classList.add("show");clearTimeout(toast._t);toast._t=setTimeout(()=>t.classList.remove("show"),2500)}
function copyToClip(t){navigator.clipboard.writeText(t).then(()=>toast("Copied!")).catch(()=>{let e=document.createElement("textarea");e.value=t;document.body.appendChild(e);e.select();document.execCommand("copy");document.body.removeChild(e);toast("Copied!")})}
function copyMyId(){S.myId&&copyToClip(S.myId)}
function copyMyInviteLink(){S.myId&&copyToClip(buildPeerLink(S.myId))}
function buildPeerLink(e){try{let u=new URL(window.location.href);u.searchParams.set("join",e);u.hash="";return u.toString()}catch(x){return window.location.href.split("?")[0]+"?join="+e}}
function parsePeerLink(e){if(!e)return null;let m=e.match(/join=(tk-[a-zA-Z0-9]+)/);if(m)return m[1];let t=e.match(/tenkord:\/\/peer\/([a-zA-Z0-9_-]+)/);if(t)return t[1];let i=e.match(/(tk-[a-zA-Z0-9]+)/);return i?i[1]:null}
function scrollBottom(){let e=document.getElementById("messages");e.scrollTop=e.scrollHeight}
function updateTopBar(){}function updateConnCount(){}function updateNodeCount(){}
function updateUBs(){["ub-av","ub-av2"].forEach(e=>{let d=document.getElementById(e);if(d)d.innerHTML=avI(S.myAvatar)+'<span class="sdot online"></span>'});document.getElementById("ub-name").textContent=S.myName||"Set your name";document.getElementById("ub-id").textContent=S.myStatus||"online"}
function updateMobBadge(){let e=Object.values(S.friends).reduce((e,t)=>e+(t.unread||0),0),t=document.getElementById("mob-unread-badge");if(t){t.style.display=e>0?"":"none";t.textContent=e>9?"9+":e}}

// Rendering
function renderFriendPanel(){
  let e=document.getElementById("friend-list-panel"),t=Object.entries(S.friends).filter(([,e])=>e.pending),n=Object.entries(S.friends).filter(([,e])=>!e.pending),a=n.filter(([,e])=>e.online),r=n.filter(([,e])=>!e.online);
  let s="";
  if(t.length){s+=`<div class="f-section">Pending (${t.length})</div>`;t.forEach(([e,t])=>{s+=`<div class="f-row" data-ch="${e}">${avH(t,28)}<div class="fri"><div class="fn">${esc(t.name)}</div><div class="fs">wants to connect</div></div><div class="fba" style="display:flex"><button class="btn btn-sm" onclick="acceptFriend('${e}');event.stopPropagation()">✅</button><button class="btn btn-sm btn-outline" onclick="declineFriend('${e}');event.stopPropagation()">❌</button></div></div>`})}
  if(a.length){s+=`<div class="f-section">Online — ${a.length}</div>`;a.forEach(([e,t])=>s+=fRowH(e,t))}
  if(r.length){s+=`<div class="f-section">Offline — ${r.length}</div>`;r.forEach(([e,t])=>s+=fRowH(e,t))}
  if(!n.length&&!t.length)s='<div style="padding:14px 10px;font-size:11px;color:var(--muted);font-family:var(--font-mono)">No friends yet.<br>Tap ➕ to add someone.</div>';
  e.innerHTML=s;
  e.querySelectorAll(".f-row[data-ch]").forEach(e=>{let t=e.dataset.ch;e.onclick=()=>openChat("dm",t,null,S.friends[t]?.name||t);e.oncontextmenu=e=>{e.preventDefault();showCtxMenu(e,t)}});
}
function fRowH(e,t){let n=t.online?"online":"offline",a=t.unread?`<div class="unread-badge">${t.unread}</div>`:"",r=t.status?esc(t.status):"No status",s=t.verified?'<span style="color:var(--y3);font-size:9px;margin-left:4px">✅</span>':"";
  return `<div class="f-row" data-ch="${e}">${avH(t,30,n)}<div class="fri"><div class="fn">${esc(t.name)}${s}</div><div class="fs">${r}</div></div>${a}<button class="icon-btn" onclick="event.stopPropagation();showCtxMenu(event,'${e}')" style="min-width:26px;min-height:26px;margin-left:4px;display:flex">⋮</button></div>`}
function renderFriendsHome(){
  let e=document.getElementById("fh-body"),t=Object.entries(S.friends);let n=t;
  if(S.fhTab==="online")n=t.filter(([,e])=>e.online&&!e.pending);
  else if(S.fhTab==="pending")n=t.filter(([,e])=>e.pending);
  else n=t.filter(([,e])=>!e.pending);
  if(!n.length){let m={all:"No friends yet.",online:"No friends online.",pending:"No pending requests."};e.innerHTML=`<div class="fh-empty"><span class="ei">${S.fhTab==="pending"?"📩":"👥"}</span>${m[S.fhTab]}<br><br><button class="btn" onclick="openModal('add-friend-modal')">Add Friend</button></div>`;return}
  e.innerHTML=n.map(([e,t])=>{if(t.pending)return `<div class="fh-card" style="cursor:default">${avH(t,42)}<div class="fhci"><div class="fhcn">${esc(t.name)}</div><div class="fhcs">Incoming friend request</div></div><div class="fhca"><button class="btn btn-sm" onclick="acceptFriend('${e}')">Accept</button><button class="btn btn-sm btn-outline" onclick="declineFriend('${e}')">Decline</button></div></div>`;
    let n=t.online?"online":"offline",a=t.online?t.status||"Online":"Offline",r=esc(t.name).replace(/'/g,"\\'");
    return `<div class="fh-card" onclick="openChat('dm','${e}',null,'${r}')">${avH(t,42,n)}<div class="fhci"><div class="fhcn">${esc(t.name)}${t.verified?'<span style="color:var(--y3);font-size:9px;margin-left:5px">✅</span>':""}</div><div class="fhcs">${a}</div></div><div class="fhca"><button class="btn btn-sm" onclick="event.stopPropagation();openChat('dm','${e}',null,'${r}')">Message</button><button class="icon-btn" onclick="event.stopPropagation();showCtxMenu(event,'${e}')">⋮</button></div></div>`}).join("");
}
function setFhTab(e,t){S.fhTab=e;document.querySelectorAll(".fh-tab").forEach(e=>e.classList.remove("active"));t.classList.add("active");renderFriendsHome()}
function renderMembers(){
  let o=document.getElementById("mp-on"),i=document.getElementById("mp-off");
  if(!o||!i)return;
  o.innerHTML="";i.innerHTML="";
  let t=document.createElement("div");t.className="mp-item";
  t.innerHTML=`<div class="av" style="width:26px;height:26px;font-size:11px">${avI(S.myAvatar)}<span class="sdot online"></span></div><div class="mp-info"><div class="mp-name">${esc(S.myName||"You")} <span style="font-size:9px;color:var(--y3)">(you)</span></div><div class="mp-status">${esc(S.myStatus||"online")}</div></div>`;
  o.appendChild(t);
  Object.entries(S.friends).filter(([,e])=>!e.pending).forEach(([e,t])=>{let n=!!S.conns[e]?.open,s=document.createElement("div");s.className="mp-item";s.onclick=()=>openChat("dm",e,null,t.name);s.innerHTML=`<div class="av" style="width:26px;height:26px;font-size:11px">${avI(t.avatar)}<span class="sdot ${n?"online":"offline"}"></span></div><div class="mp-info"><div class="mp-name">${esc(t.name)}</div><div class="mp-status">${esc(t.status||(n?"online":"offline"))}</div></div>`;(n?o:i).appendChild(s)});
}
function renderMobMembers(){
  let e=document.getElementById("mob-members-body");let s=`<div class="mp-item">${avH({avatar:S.myAvatar},30,"online")}<div class="mp-info"><div class="mp-name">${esc(S.myName||"You")} <span style="font-size:9px;color:var(--y3)">(you)</span></div><div class="mp-status">${esc(S.myStatus||"online")}</div></div></div>`;
  Object.entries(S.friends).filter(([,e])=>!e.pending).forEach(([e,t])=>{let n=!!S.conns[e]?.open;s+=`<div class="mp-item" onclick="openChat('dm','${e}',null,'${esc(t.name).replace(/'/g,"\\'")}');closeAllSheets()">${avH({avatar:t.avatar},30,n?"online":"offline")}<div class="mp-info"><div class="mp-name">${esc(t.name)}</div><div class="mp-status">${esc(t.status||(n?"online":"offline"))}</div></div></div>`});
  e.innerHTML=s;
}
function renderDeviceList(){
  let el=document.getElementById("device-list-area");if(!el)return;
  let html='<div style="font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px">Your Devices</div>';
  html+=`<div class="device-card"><span class="dev-icon">💻</span><div class="dev-info"><div class="dev-name">${esc(S.myName||"This device")}</div><div class="dev-status">${S.deviceId.slice(0,16)}... (this device)</div></div><div class="device-dot on"></div></div>`;
  Object.entries(S.linkedDevices).forEach(([id,d])=>{html+=`<div class="device-card"><span class="dev-icon">📱</span><div class="dev-info"><div class="dev-name">${esc(d.name||"Linked device")}</div><div class="dev-status">${id.slice(-12)}</div></div><div class="device-dot ${d.online?"on":"off"}"></div></div>`});
  el.innerHTML=html;
}

// Message rendering
async function renderMessages(){
  let n=document.getElementById("messages");
  n.innerHTML="";
  if(!S.activeChat)return;
  let msgs=await dbGetAll("messages","chat",S.activeChat.id);
  msgs.sort((a,b)=>a.ts-b.ts);
  if(!msgs.length){n.innerHTML='<div class="sys-msg">Start of conversation</div>';return}
  let lastAuthor=null,lastTs=0;
  msgs.forEach(m=>{appendMsg(m,lastAuthor===m.author&&m.ts-lastTs<3e5);lastAuthor=m.author;lastTs=m.ts});
  scrollBottom();
}

function mediaHtml(msg){
  let h="";
  if(msg.mediaUrl){
    let type=msg.fileType||"";
    let isVideo=type.startsWith("video/")||/\.(mp4|webm|ogg|mov)$/i.test(msg.fileName||"");
    let isGif=/\.gif$/i.test(msg.fileName||"")||type==="image/gif";
    if(isVideo)h=`<div class="msg-media"><video src="${msg.mediaUrl}" controls playsinline style="max-width:100%;max-height:300px;border-radius:8px;background:#000"></video><button class="msg-media-fav" onclick="toggleFavorite(event,'${msg.id}')" title="Favorite">⭐</button></div>`;
    else h=`<div class="msg-media"><img src="${msg.mediaUrl}" loading="lazy" onclick="openLightbox(this.src)" alt="${esc(msg.fileName||"image")}"><button class="msg-media-fav" id="fav-btn-${msg.id}" onclick="toggleFavorite(event,'${msg.id}')" title="Favorite">⭐</button></div>`;
    dbGet("favorites",msg.id).then(f=>{if(f){let b=document.getElementById("fav-btn-"+msg.id);if(b){b.classList.add("active");b.title="Unfavorite"}}});
  }else if(msg.fileId&&!msg.deleted){
    let icon=fileIcon(msg.fileType||"");
    let size=msg.fileSize?formatBytes(msg.fileSize):"";
    h=`<div class="msg-file" onclick="downloadFile('${msg.fileId}')"><div class="msg-file-icon">${icon}</div><div class="msg-file-info"><div class="msg-file-name">${esc(msg.fileName||"File")}</div><div class="msg-file-size">${size}</div></div><div class="msg-file-dl">📥</div></div><div id="fprog-${msg.id}" class="file-progress" style="display:none"><div class="file-progress-bar"><div class="file-progress-fill" id="fill-${msg.id}"></div></div><div class="file-progress-text" id="ftext-${msg.id}"></div></div>`;
  }
  return h;
}
function replyHtml(replyTo){
  if(!replyTo)return "";
  return `<div class="msg-reply-quote" onclick="scrollToMsg('${replyTo.id}')"><span class="msg-reply-author">${esc(replyTo.author)}</span><span class="msg-reply-text">${esc(replyTo.text||"📎 Attachment")}</span></div>`;
}
function appendMsg(msg,compact){
  let a=document.getElementById("messages");
  if(!compact&&!msg.replyTo){let last=a.lastElementChild;compact=last&&last.dataset&&last.dataset.author===msg.author&&msg.ts-(parseInt(last.dataset.ts)||0)<3e5}
  let el=document.createElement("div");
  el.dataset.author=msg.author;el.dataset.ts=msg.ts;el.dataset.msgid=msg.id;
  let editBadge=msg.editedAt?`<span class="msg-edited" onclick="showEditHistory('${msg.id}')" title="Click to see edit history">(edited)</span>`:"";
  let delClass=msg.deleted?"msg-deleted":"";
  let actHtml=`<div class="msg-actions">${msg.self&&!msg.deleted?`<button class="msg-act-btn" onclick="startEdit('${msg.id}')" title="Edit">📝</button>`:""}${!msg.deleted?`<button class="msg-act-btn" onclick="setReply({id:'${msg.id}',author:'${esc(msg.author).replace(/'/g,"\\'")}',text:'${esc((msg.text||"").slice(0,80)).replace(/'/g,"\\'")}'})" title="Reply">↩️</button>`:""}${msg.self&&!msg.deleted?`<button class="msg-act-btn danger" onclick="deleteMsg('${msg.id}')" title="Delete">🗑️</button>`:""}</div>`;
  let media=mediaHtml(msg);
  let reply=replyHtml(msg.replyTo);
  if(compact&&!msg.replyTo){
    el.className="msg-cont";
    el.innerHTML=`${actHtml}<div class="msg-text ${delClass}">${msg.deleted?"<em>[Message deleted]</em>":fmt(msg.text)}${editBadge}</div>${media}`;
  }else{
    el.className="msg-group";
    let time=new Date(msg.ts);let ts=time.getHours().toString().padStart(2,"0")+":"+time.getMinutes().toString().padStart(2,"0");
    let ver=msg.verified===true?'<span class="msg-ver" style="color:var(--y3)">✅</span>':msg.verified===false?'<span class="msg-ver" style="color:var(--danger)">❌</span>':"";
    el.innerHTML=`${actHtml}<div class="av" style="width:36px;height:36px;font-size:16px;cursor:pointer" onclick="showFriendProfile('${msg.self?"self":S.activeChat?.id}')">${avI(msg.avatar)}</div><div class="msg-body"><div class="msg-meta"><span class="msg-author ${msg.self?"self":"peer"}">${esc(msg.author)}</span><span class="msg-time">${ts}</span>${ver}</div>${reply}<div class="msg-text ${delClass}">${msg.deleted?"<em>[Message deleted]</em>":fmt(msg.text)}${editBadge}</div>${media}</div>`;
  }
  a.appendChild(el);
}
function rerenderMsg(msg){let el=document.querySelector(`[data-msgid="${msg.id}"]`);if(!el){renderMessages();return}renderMessages()}
function scrollToMsg(id){let el=document.querySelector(`[data-msgid="${id}"]`);if(el){el.scrollIntoView({behavior:"smooth",block:"center"});el.style.background="rgba(245,196,0,.08)";setTimeout(()=>el.style.background="",1500)}}
async function showEditHistory(msgId){
  let msg=await dbGet("messages",msgId);if(!msg||!msg.edits?.length)return;
  let body=document.getElementById("edit-history-body");
  body.innerHTML=msg.edits.map((e,i)=>`<div class="edit-entry"><div class="edit-entry-time">${new Date(e.ts).toLocaleString()} — Version ${i+1}</div><div>${esc(e.text)}</div></div>`).join("")+`<div class="edit-entry"><div class="edit-entry-time">Current</div><div>${esc(msg.text)}</div></div>`;
  openModal("edit-history-modal");
}

function ensureActiveChatForAttachment(){
  if(S.activeChat)return true;
  toast("Open a chat first to send attachments");
  return false;
}
function toggleAttachMenu(event){
  event?.stopPropagation();
  if(!ensureActiveChatForAttachment())return;
  closeGifPicker();
  document.getElementById("attach-menu")?.classList.toggle("open");
}
function closeAttachMenu(){document.getElementById("attach-menu")?.classList.remove("open")}
function triggerFileInput(inputId){
  if(!ensureActiveChatForAttachment())return;
  closeAttachMenu();
  closeGifPicker();
  document.getElementById(inputId)?.click();
}
function openAttachmentFavorites(){
  if(!ensureActiveChatForAttachment())return;
  closeAttachMenu();
  closeGifPicker();
  openFavoritesPanel();
}
function openGifPicker(){
  if(!ensureActiveChatForAttachment())return;
  closeAttachMenu();
  let p=document.getElementById("gif-picker");
  p.classList.add("open");
  loadTrendingGifs();
}

// File transfer
const CHUNK=16384;
function fileIcon(type){if(!type)return "📎";if(type.startsWith("image/"))return "🖼️";if(type.startsWith("video/"))return "🎬";if(type.startsWith("audio/"))return "🎵";if(type.includes("pdf"))return "📄";if(type.includes("zip")||type.includes("compressed"))return "🗜️";return "📎"}
function formatBytes(b){if(b<1024)return b+"B";if(b<1048576)return (b/1024).toFixed(1)+"KB";return (b/1048576).toFixed(1)+"MB"}
async function handleFileUpload(event){
  let file=event.target.files[0];event.target.value="";
  if(!file||!S.activeChat)return;
  let isMedia=file.type.startsWith("image/")||file.type.startsWith("video/")||file.type.startsWith("audio/");
  let id=uuid(),chatId=S.activeChat.id;
  if(isMedia&&file.size<4*1024*1024){
    let reader=new FileReader();
    reader.onload=async e=>{
      let mediaUrl=e.target.result;
      let ts=Date.now(),text="",sig=await CRYPTO.sign(text+ts);
      let msg={id,chatId,author:S.myName,avatar:S.myAvatar,text:"",ts,self:true,verified:true,replyTo:null,fileName:file.name,fileType:file.type,fileSize:file.size,mediaUrl};
      let packet={type:"dm",msgId:id,author:S.myName,avatar:S.myAvatar,text:"",ts,sig,fileName:file.name,fileType:file.type,fileSize:file.size,mediaUrl};
      await dbPut("messages",msg);await dbPut("files",{id,name:file.name,type:file.type,size:file.size,data:mediaUrl,ts});
      save();appendMsg(msg);scrollBottom();
      let conn=S.conns[chatId];if(conn?.open)send(conn,packet);else addToQueue(chatId,packet);
      Object.entries(S.linkedDevices).forEach(([d,i])=>{if(i.sameAccount&&S.conns[d]?.open)send(S.conns[d],{type:"device-sync-response",messages:[msg],total:1,offset:0})});
    };reader.readAsDataURL(file);
  }else sendFileTransfer(file,id,chatId);
}
async function sendFileTransfer(file,id,chatId){
  let reader=new FileReader();
  reader.onload=async e=>{
    let data=e.target.result;
    await dbPut("files",{id,name:file.name,type:file.type,size:file.size,data,ts:Date.now()});
    let ts=Date.now(),sig=await CRYPTO.sign(""+ts);
    let msg={id,chatId,author:S.myName,avatar:S.myAvatar,text:"",ts,self:true,verified:true,replyTo:null,fileId:id,fileName:file.name,fileType:file.type,fileSize:file.size,mediaUrl:null};
    let packet={type:"dm",msgId:id,author:S.myName,avatar:S.myAvatar,text:"",ts,sig,fileId:id,fileName:file.name,fileType:file.type,fileSize:file.size,mediaUrl:null};
    await dbPut("messages",msg);save();appendMsg(msg);scrollBottom();
    let conn=S.conns[chatId];if(conn?.open){send(conn,packet);setTimeout(()=>startFileSend(id,chatId),500)}else addToQueue(chatId,packet);
    Object.entries(S.linkedDevices).forEach(([d,i])=>{if(i.sameAccount&&S.conns[d]?.open){if(!S.largeFileSkip||file.size<=10*1024*1024)send(S.conns[d],{type:"device-sync-response",messages:[msg],total:1,offset:0})}});
  };reader.readAsArrayBuffer(file);
}
async function startFileSend(fileId,peerId){
  let conn=S.conns[peerId];if(!conn?.open)return;
  let f=await dbGet("files",fileId);if(!f)return;
  let buf=typeof f.data==="string"?_b64ToAb(f.data):f.data;
  let total=buf.byteLength,offset=0,idx=0;
  send(conn,{type:"file-request",fileId,fileName:f.name,fileType:f.type,fileSize:total});
  function sendChunk(){
    if(offset>=total){send(conn,{type:"file-chunk",fileId,done:true});return}
    let chunk=buf.slice(offset,offset+CHUNK);send(conn,{type:"file-chunk",fileId,idx,data:abb64(chunk)});
    offset+=CHUNK;idx++;setTimeout(sendChunk,10);
  }setTimeout(sendChunk,200);
}
function _b64ToAb(str){let i=str.indexOf(",");let b=str.slice(i+1);return b64ab(b)}
function handleFileRequest(from,n){S.fileTransfers[n.fileId]={from,name:n.fileName,type:n.fileType,size:n.fileSize,chunks:[],received:0}}
function handleFileChunk(from,n){
  let ft=S.fileTransfers[n.fileId];if(!ft)return;
  if(n.done){assembleFile(n.fileId);return}
  ft.chunks[n.idx]=n.data;ft.received++;
  let pct=ft.size?Math.min(100,Math.round(ft.received*CHUNK/ft.size*100)):50;
  let fill=document.getElementById("fill-"+n.fileId),txt=document.getElementById("ftext-"+n.fileId),prog=document.getElementById("fprog-"+n.fileId);
  if(prog)prog.style.display="";if(fill)fill.style.width=pct+"%";if(txt)txt.textContent=pct+"% — "+formatBytes(ft.received*CHUNK)+"/"+formatBytes(ft.size);
}
async function assembleFile(fileId){
  let ft=S.fileTransfers[fileId];if(!ft)return;
  let parts=ft.chunks.map(c=>new Uint8Array(b64ab(c)));
  let total=parts.reduce((s,p)=>s+p.length,0),buf=new Uint8Array(total),off=0;
  parts.forEach(p=>{buf.set(p,off);off+=p.length});
  let blob=new Blob([buf],{type:ft.type}),url=URL.createObjectURL(blob);
  if(ft.type.startsWith("image/")&&buf.length<4*1024*1024){
    let reader=new FileReader();
    reader.onload=async e=>{
      await dbPut("files",{id:fileId,name:ft.name,type:ft.type,size:buf.length,data:e.target.result,ts:Date.now()});
      let msg=await dbGet("messages",fileId);if(msg){msg.mediaUrl=e.target.result;await dbPut("messages",msg);if(S.activeChat?.id===ft.from)renderMessages()}
    };reader.readAsDataURL(blob);
  }else await dbPut("files",{id:fileId,name:ft.name,type:ft.type,size:buf.length,data:url,ts:Date.now()});
  let prog=document.getElementById("fprog-"+fileId);if(prog)prog.style.display="none";
  toast("File received: "+ft.name);delete S.fileTransfers[fileId];
}
async function downloadFile(fileId){
  let f=await dbGet("files",fileId);if(!f)return toast("File not available");
  let url=f.data;if(url.startsWith("data:")){let arr=_b64ToAb(url),blob=new Blob([arr],{type:f.type});url=URL.createObjectURL(blob)}
  let a=document.createElement("a");a.href=url;a.download=f.name||"file";a.click();
}
async function initiateFileReceive(peerId,msgData){let conn=S.conns[peerId];if(conn?.open)send(conn,{type:"file-request-pull",fileId:msgData.fileId})}

// Favorites & GIFs
async function toggleFavorite(event,msgId){
  event.stopPropagation();let msg=await dbGet("messages",msgId);if(!msg)return;
  let existing=await dbGet("favorites",msgId);
  if(existing){await dbDel("favorites",msgId);toast("Removed from favorites");event.target.classList.remove("active")}
  else{await dbPut("favorites",{id:msgId,src:msg.mediaUrl||"",fileName:msg.fileName||"",fileType:msg.fileType||"",ts:Date.now()});toast("⭐ Added to favorites!");event.target.classList.add("active")}
}
async function openFavoritesPanel(){
  let favs=await dbGetAll("favorites"),grid=document.getElementById("fav-grid"),empty=document.getElementById("fav-empty");
  if(!favs.length){grid.innerHTML="";empty.style.display="";openModal("favorites-modal");return}
  empty.style.display="none";grid.innerHTML=favs.map(f=>`<div class="fav-item"><img src="${f.src}" loading="lazy" onclick="sendFavorite('${f.id}')" title="Click to send"><button class="fav-remove" onclick="removeFavorite(event,'${f.id}')">❌</button></div>`).join("");
  openModal("favorites-modal");
}
async function removeFavorite(e,id){e.stopPropagation();await dbDel("favorites",id);openFavoritesPanel()}
async function sendFavorite(id){
  if(!S.activeChat)return;let f=await dbGet("favorites",id);if(!f)return;closeModal("favorites-modal");
  let msgId=uuid(),ts=Date.now(),chatId=S.activeChat.id,sig=await CRYPTO.sign(""+ts);
  let msg={id:msgId,chatId,author:S.myName,avatar:S.myAvatar,text:"",ts,self:true,verified:true,replyTo:null,fileName:f.fileName,fileType:f.fileType,mediaUrl:f.src};
  let packet={type:"dm",msgId,author:S.myName,avatar:S.myAvatar,text:"",ts,sig,fileName:f.fileName,fileType:f.fileType,mediaUrl:f.src};
  await dbPut("messages",msg);save();appendMsg(msg);scrollBottom();
  let conn=S.conns[chatId];if(conn?.open)send(conn,packet);else addToQueue(chatId,packet);
}

const GIF_KEY="LIVDSRZULELA";
function toggleGifPicker(event){event?.stopPropagation();if(!ensureActiveChatForAttachment())return;let p=document.getElementById("gif-picker");closeAttachMenu();p.classList.toggle("open");if(p.classList.contains("open"))loadTrendingGifs()}
function closeGifPicker(){document.getElementById("gif-picker").classList.remove("open")}
function gifTab(tab,el){document.querySelectorAll(".gif-picker-tab").forEach(t=>t.classList.remove("active"));el.classList.add("active");if(tab==="favorites")loadFavGifs();else loadTrendingGifs()}
async function loadTrendingGifs(){
  let grid=document.getElementById("gif-grid");grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">Loading...</div>';
  try{let r=await fetch(`https://tenor.googleapis.com/v2/featured?key=${GIF_KEY}&limit=20&media_filter=gif`);let j=await r.json();renderGifs(j.results||[])}catch(e){grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">Could not load GIFs</div>'}
}
function searchGifs(q){clearTimeout(gifDebounce);if(!q){loadTrendingGifs();return}gifDebounce=setTimeout(async()=>{try{let r=await fetch(`https://tenor.googleapis.com/v2/search?key=${GIF_KEY}&q=${encodeURIComponent(q)}&limit=20&media_filter=gif`);let j=await r.json();renderGifs(j.results||[])}catch(e){}},400)}
function renderGifs(results){
  let grid=document.getElementById("gif-grid");if(!results.length){grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">No GIFs found</div>';return}
  grid.innerHTML=results.map(r=>{let url=r.media_formats?.gif?.url||r.media_formats?.tinygif?.url||"";let p=r.media_formats?.tinygif?.url||url;return `<div class="gif-item"><img src="${p}" loading="lazy" onclick="sendGif('${url}','${esc(r.title||"gif")}')"><button class="gif-fav-btn" onclick="favGif(event,'${url}','${esc(r.title||"gif")}')">⭐</button></div>`}).join("");
}
async function loadFavGifs(){
  let favs=await dbGetAll("favorites"),gifs=favs.filter(f=>f.fileType==="image/gif"||/\.gif$/i.test(f.fileName||"")),grid=document.getElementById("gif-grid");
  if(!gifs.length){grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--muted);font-size:11px;padding:20px">No favorite GIFs yet</div>';return}
  grid.innerHTML=gifs.map(f=>`<div class="gif-item"><img src="${f.src}" loading="lazy" onclick="sendGif('${f.src}','${esc(f.fileName||"gif")}')"><button class="gif-fav-btn active" onclick="removeFavorite(event,'${f.id}');loadFavGifs()">❌</button></div>`).join("");
}
async function favGif(e,url,name){e.stopPropagation();let id=uuid();await dbPut("favorites",{id,src:url,fileName:name+".gif",fileType:"image/gif",ts:Date.now()});toast("⭐ Saved to favorites");e.target.classList.add("active")}
async function sendGif(url,name){
  if(!S.activeChat)return;closeGifPicker();
  let id=uuid(),ts=Date.now(),chatId=S.activeChat.id,sig=await CRYPTO.sign(""+ts);
  let msg={id,chatId,author:S.myName,avatar:S.myAvatar,text:"",ts,self:true,verified:true,replyTo:null,fileName:name,fileType:"image/gif",mediaUrl:url};
  let packet={type:"dm",msgId:id,author:S.myName,avatar:S.myAvatar,text:"",ts,sig,fileName:name,fileType:"image/gif",mediaUrl:url};
  await dbPut("messages",msg);save();appendMsg(msg);scrollBottom();
  let conn=S.conns[chatId];if(conn?.open)send(conn,packet);else addToQueue(chatId,packet);
}

// Nav, Profile, Modals
function openModal(e){
  document.getElementById(e).classList.add("open");
  if(e==="profile-modal"){document.getElementById("p-name").value=S.myName;document.getElementById("p-status").value=S.myStatus;document.getElementById("pp-id").textContent=S.myId||"connecting...";refreshAvPreview();buildEmojiStrip();genQR();renderDeviceList()}
  if(e==="add-friend-modal")document.getElementById("my-link-txt").textContent=S.myId?buildPeerLink(S.myId):"...";
}
function closeModal(e){document.getElementById(e).classList.remove("open");if(e==="add-friend-modal")stopQRScan()}
function switchTab(e,t){e.closest(".modal").querySelectorAll(".mtab").forEach(e=>e.classList.remove("active"));e.classList.add("active");e.closest(".modal").querySelectorAll(".tpane").forEach(e=>e.classList.remove("active"));document.getElementById("tab-"+e.dataset.tab)?.classList.add("active")}
function showCtxMenu(e,t){S.ctxTarget=t;let m=document.getElementById("ctx-menu"),x=e.clientX||0,y=e.clientY||0;m.classList.add("open");m.style.left=Math.min(x,window.innerWidth-180)+"px";m.style.top=Math.min(y,window.innerHeight-180)+"px"}
function switchView(t){S.view=t;let n="home"===t;document.getElementById("home-panel").style.display=n?"flex":"none";closeActiveChat();(n?showFriendsHome:hideFriendsHome)();openLP();setMobTab(n?"home":null)}
function closeActiveChat(){S.activeChat=null;document.getElementById("chat-hdr").style.display="none";document.getElementById("chat-view").style.display="none";clearReply();clearEdit()}
function showFriendsHome(){document.getElementById("friends-home").style.display="flex";document.getElementById("chat-view").style.display="none"}
function hideFriendsHome(){document.getElementById("friends-home").style.display="none"}
function openChat(e,t,n,a){
  S.activeChat={type:e,id:t,chId:n};closeLP();hideFriendsHome();document.getElementById("chat-hdr").style.display="flex";document.getElementById("chat-view").style.display="flex";
  document.getElementById("hdr-name").textContent=a;document.getElementById("hdr-sub").textContent=S.friends[t]?.status||"Direct Message";
  if(e==="dm"&&S.friends[t]){S.friends[t].unread=0;save();renderFriendPanel();renderFriendsHome();updateMobBadge()}
  renderMessages();renderQueue();document.querySelectorAll(".f-row").forEach(e=>e.classList.remove("active"));
  document.querySelector(`[data-ch="${t}"]`)?.classList.add("active");document.getElementById("msg-input").focus();setTimeout(()=>requestSync(t),300);
}
function goBack(){if(window.innerWidth>620)openLP();("home"===S.view?showFriendsHome:hideFriendsHome)();closeActiveChat()}
function openLP(){document.getElementById("left-panel").classList.add("open")}
function closeLP(){document.getElementById("left-panel").classList.remove("open")}
function openMembersPanel(){if(window.innerWidth<=620){renderMobMembers();document.getElementById("mob-members-sheet").classList.add("open");document.getElementById("sheet-backdrop").classList.add("open")}else{let e=document.getElementById("members-panel");e.style.display="flex"===e.style.display?"none":"flex"}}
function mobNav(e){if(e==="home"){switchView("home");setMobTab("home")}}
function setMobTab(e){document.querySelectorAll(".mob-nav-item").forEach(e=>e.classList.remove("active"));if(e==="home")document.getElementById("mob-tab-home")?.classList.add("active")}
function openActionSheet(){document.getElementById("mob-action-sheet").classList.add("open");document.getElementById("sheet-backdrop").classList.add("open")}
function closeActionSheet(){document.getElementById("mob-action-sheet").classList.remove("open");document.getElementById("sheet-backdrop").classList.remove("open")}
function closeAllSheets(){document.getElementById("mob-members-sheet").classList.remove("open");document.getElementById("mob-action-sheet").classList.remove("open");document.getElementById("sheet-backdrop").classList.remove("open")}

let EMOJIS=["🌑","🌊","🔥","⚡","🎯","🦊","🐉","🤖","👾","🎮","🎵","💎","🚀","🌙","⭐","🦁","🎲","🧠","⚔️","🔮","🛸","💡","🔧","🎨"];
function buildEmojiStrip(){document.getElementById("av-emoji-strip").innerHTML=EMOJIS.map(e=>`<div class="av-eo${S.myAvatar===e?" sel":""}" onclick="pickEmoji('${e}')">${e}</div>`).join("")}
function pickEmoji(t){S.myAvatar=t;localStorage.setItem("tk_avatar",t);document.querySelectorAll(".av-eo").forEach(e=>e.classList.toggle("sel",e.textContent===t));refreshAvPreview();updateUBs()}
function refreshAvPreview(){let e=document.getElementById("av-preview");S.myAvatar&&(S.myAvatar.startsWith("data:")||S.myAvatar.startsWith("http"))?e.innerHTML=`<img src="${S.myAvatar}">`:e.innerHTML=`<span class="av-up-icon">📷</span><span class="av-up-lbl">Upload photo</span>`}
function handleAvUpload(e){let f=e.target.files[0];if(!f)return;let r=new FileReader();r.onload=e=>{let s=new Image();s.onload=()=>{let c=document.createElement("canvas");c.width=128;c.height=128;let ctx=c.getContext("2d"),n=Math.min(s.width,s.height),a=(s.width-n)/2,b=(s.height-n)/2;ctx.drawImage(s,a,b,n,n,0,0,128,128);S.myAvatar=c.toDataURL("image/jpeg",.6);localStorage.setItem("tk_avatar",S.myAvatar);refreshAvPreview();updateUBs()};s.src=e.target.result};r.readAsDataURL(f)}
function saveProfile(){let e=document.getElementById("p-name").value.trim();if(!e)return toast("Enter your name");S.myName=e;S.myStatus=document.getElementById("p-status").value.trim();localStorage.setItem("tk_name",S.myName);localStorage.setItem("tk_status",S.myStatus);updateUBs();save();broadcastProfile();closeModal("profile-modal");toast("Profile saved")}
function showFriendProfile(e){if(e==="self")return openModal("profile-modal");let t=S.friends[e];if(!t)return;document.getElementById("fp-title").textContent=t.name;document.getElementById("fp-name").textContent=t.name;document.getElementById("fp-status").textContent=t.status||(t.online?"Online":"Offline");document.getElementById("fp-id").textContent=e;document.getElementById("fp-av").innerHTML=avI(t.avatar);document.getElementById("fp-ver").innerHTML=t.verified?'<span style="color:var(--online)">✅ Identity verified</span>':'<span style="color:var(--muted)">Not yet verified</span>';openModal("fp-modal")}
function genQR(){if(S.myId){let e=document.getElementById("qr-cont");e.innerHTML="";try{new QRCode(e,{text:buildPeerLink(S.myId),width:130,height:130,colorDark:"#F5C400",colorLight:"#111111"})}catch(e){}}}
async function startQRScan(){let t=document.getElementById("qr-scan-area"),r=document.getElementById("qr-video");t.style.display="block";try{S.qrStream=await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}});r.srcObject=S.qrStream;if("BarcodeDetector"in window){let n=new BarcodeDetector({formats:["qr_code"]}),a=async()=>{if(S.qrStream){try{let e=await n.detect(r);if(e.length){let t=parsePeerLink(e[0].rawValue);if(t){S.qrScannedId=t;document.getElementById("qr-scanned-display").textContent=t;document.getElementById("qr-result").style.display="block";stopQRScan();return}}}catch(e){}setTimeout(a,500)}};r.onloadeddata=a}else toast("QR scanning not supported")}catch(e){toast("Camera denied");t.style.display="none"}}
function stopQRScan(){if(S.qrStream){S.qrStream.getTracks().forEach(e=>e.stop());S.qrStream=null}}
function connectScannedQR(){if(S.qrScannedId){S.friends[S.qrScannedId]=S.friends[S.qrScannedId]||{name:S.qrScannedId.slice(-8),avatar:"",status:"",online:false,pending:false,unread:0};save();connectTo(S.qrScannedId);setLoader(false)}}
function openIdentityPassModal(mode){
  S.identityPassMode=mode;
  let title=document.getElementById("identity-pass-title"),help=document.getElementById("identity-pass-help"),btn=document.getElementById("identity-pass-confirm"),inp=document.getElementById("identity-pass-input");
  title.textContent=mode==="export"?"Export Identity":"Import Identity";
  help.textContent=mode==="export"?"Choose a passphrase to encrypt your exported JSON identity bundle.":"Enter the passphrase used when this JSON identity bundle was exported.";
  btn.textContent=mode==="export"?"Export JSON":"Import Identity";
  inp.value="";inp.autocomplete=mode==="export"?"new-password":"current-password";
  openModal("identity-pass-modal");setTimeout(()=>inp.focus(),80);
}
function closeIdentityPassModal(){closeModal("identity-pass-modal");S.identityPassMode=null}
function openIdentityExportModal(){openIdentityPassModal("export")}
function triggerIdentityImportFile(){document.getElementById("identity-import-file")?.click()}
function handleIdentityImportFile(event){
  let file=event.target.files[0];event.target.value="";
  if(!file)return;
  let reader=new FileReader();
  reader.onload=e=>{S.pendingIdentityImport=e.target.result;openIdentityPassModal("import")};
  reader.onerror=()=>toast("Could not read identity file");
  reader.readAsText(file);
}
async function confirmIdentityPass(){
  let pass=document.getElementById("identity-pass-input")?.value||"";
  if(!pass||pass.length<6)return toast("Passphrase must be 6+ chars");
  if(S.identityPassMode==="export")return exportIdentity(pass);
  if(S.identityPassMode==="import")return importIdentity(pass);
}
async function exportIdentity(pass){try{let t=await CRYPTO.exportBundle(pass,{name:S.myName,status:S.myStatus,avatar:S.myAvatar}),n=new Blob([t],{type:"application/json"}),a=URL.createObjectURL(n),r=document.createElement("a");r.href=a;r.download=`tenkord-identity.json`;r.click();URL.revokeObjectURL(a);closeIdentityPassModal();toast("Identity exported!")}catch(e){toast("Export failed: "+e.message)}}
async function importIdentity(pass){let e=S.pendingIdentityImport;if(!e||!pass)return toast("Choose an identity JSON file first");if(!confirm("Replace identity?"))return;try{await CRYPTO.importBundle(e,pass);S.pendingIdentityImport=null;closeIdentityPassModal();location.reload()}catch(e){toast("Import failed")}}
function toggleFileSyncSetting(el){S.fileSyncOn=!S.fileSyncOn;el.classList.toggle("on",S.fileSyncOn);localStorage.setItem("tk_filesync",S.fileSyncOn?"1":"0")}
function toggleLargeSkip(el){S.largeFileSkip=!S.largeFileSkip;el.classList.toggle("on",S.largeFileSkip);localStorage.setItem("tk_largeskip",S.largeFileSkip?"1":"0")}

(async()=>{
  await openDB();await initPeer();updateUBs();renderFriendPanel();renderFriendsHome();renderMembers();updateMobBadge();
  if(!S.myName)setTimeout(()=>openModal("profile-modal"),900);
  save();setTimeout(()=>setLoader(false),3000);
  document.querySelectorAll(".overlay").forEach(t=>{t.addEventListener("click",e=>{if(e.target===t)closeModal(t.id)})});
  document.getElementById("ctx-profile").onclick=()=>S.ctxTarget&&showFriendProfile(S.ctxTarget);
  document.getElementById("ctx-dm").onclick=()=>S.ctxTarget&&S.friends[S.ctxTarget]&&openChat("dm",S.ctxTarget,null,S.friends[S.ctxTarget].name);
  document.getElementById("ctx-copy-id").onclick=()=>S.ctxTarget&&copyToClip(S.ctxTarget);
  document.getElementById("ctx-remove").onclick=()=>S.ctxTarget&&removeFriend(S.ctxTarget);
  let join=new URLSearchParams(location.search).get("join");if(join)setTimeout(()=>{document.getElementById("af-id-input").value=join;addFriendById()},1500);
  document.addEventListener("click",e=>{if(!e.target.closest(".attach-btn")&&!e.target.closest(".attach-menu"))document.getElementById("attach-menu").classList.remove("open");if(!e.target.closest(".gif-picker")&&!e.target.closest(".attach-btn")&&!e.target.closest(".attach-menu"))document.getElementById("gif-picker").classList.remove("open");if(!e.target.closest(".ctx-menu"))document.getElementById("ctx-menu").classList.remove("open")});
})();

import { DurableObject } from "cloudflare:workers";

const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 12;
const MAX_BODY_BYTES = 8192;
const MAX_SIGNAL_BYTES = 8192;
const ROOM_LIFETIME_MS = 24 * 60 * 60 * 1000;
const ROOM_TOUCH_INTERVAL_MS = 60 * 60 * 1000;
const IP_PREFIX = "10.77.0.";
const MAX_KICK_RECORDS = 64;
const PENDING_PEER_TTL_MS = 150000;
const MAX_ADMISSION_RTT_MS = 500;
const MIN_ADMISSION_ROUND_TRIPS = 3;
const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400"
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...CORS_HEADERS,
      ...headers
    }
  });
}

function text(value, status = 200) {
  return new Response(value, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...CORS_HEADERS
    }
  });
}

function withCors(response) {
  if (response.status === 101) return response;
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

async function readJson(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > MAX_BODY_BYTES) {
    throw new Error("Request body is too large.");
  }

  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) {
    throw new Error("Request body is too large.");
  }
  if (!raw) return {};
  const value = JSON.parse(raw);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("A JSON object is required.");
  }
  return value;
}

function cleanString(value, maxLength, fallback = "") {
  if (typeof value !== "string") return fallback;
  return value.trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, maxLength);
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomToken() {
  return toBase64Url(randomBytes(32));
}

function randomCode() {
  const bytes = randomBytes(CODE_LENGTH);
  let code = "";
  for (const byte of bytes) {
    code += CODE_ALPHABET[byte % CODE_ALPHABET.length];
  }
  return code;
}

function randomSalt() {
  return toBase64Url(randomBytes(16));
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  let diff = left.length ^ right.length;
  const count = Math.max(left.length, right.length);
  for (let i = 0; i < count; i++) {
    diff |= (left.charCodeAt(i % Math.max(left.length, 1)) || 0) ^
      (right.charCodeAt(i % Math.max(right.length, 1)) || 0);
  }
  return diff === 0;
}

function validCode(code) {
  return typeof code === "string" && /^(?:[A-Z2-9]{8}|[A-Z2-9]{12})$/.test(code);
}

function roomStub(env, code) {
  const id = env.ROOMS.idFromName(code);
  return env.ROOMS.get(id);
}

function socketUrl(requestUrl, code, peerId, token) {
  const url = new URL(requestUrl);
  url.protocol = url.protocol === "http:" ? "ws:" : "wss:";
  url.pathname = `/api/rooms/${code}/ws`;
  url.search = new URLSearchParams({ peer: peerId, token }).toString();
  return url.toString();
}

function publicRoom(room) {
  const host = room.peers.find(peer => peer.ip === `${IP_PREFIX}1`);
  return {
    roomCode: room.code,
    roomName: room.name,
    maxPeers: room.maxPeers,
    hostPeerId: host ? host.id : "",
    createdAt: room.createdAt,
    peers: room.peers.map(peer => ({
      id: peer.id,
      name: peer.name,
      ip: peer.ip,
      online: Boolean(peer.online)
    }))
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    if (request.method === "GET" && url.pathname === "/") {
      return text("Network signaling server is running.");
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        ok: true,
        service: "Network",
        role: "signaling",
        transport: "direct-udp-ice",
        packetRelay: false
      });
    }

    if (request.method === "POST" && url.pathname === "/api/rooms") {
      try {
        const body = await readJson(request);
        const roomName = cleanString(body.roomName, 32, "Network room") || "Network room";
        const peerName = cleanString(body.peerName, 24, "Host") || "Host";
        const password = cleanString(body.password, 64, "");
        const maxPeers = Number(body.maxPeers ?? 7);
        if (!Number.isInteger(maxPeers) || maxPeers < 2 || maxPeers > 7) {
          return json({ ok: false, error: "maxPeers must be between 2 and 7." }, 400);
        }

        const peerId = crypto.randomUUID();
        const token = randomToken();
        const tokenHash = await sha256(token);
        const passwordSalt = password ? randomSalt() : null;
        const passwordHash = password ? await sha256(`${passwordSalt}:${password}`) : null;

        for (let attempt = 0; attempt < 5; attempt++) {
          const code = randomCode();
          const stub = roomStub(env, code);
          const response = await stub.fetch("https://room.internal/_init", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              code,
              roomName,
              maxPeers,
              passwordSalt,
              passwordHash,
              host: {
                id: peerId,
                name: peerName,
                ip: `${IP_PREFIX}1`,
                tokenHash,
                joinedAt: Date.now()
              }
            })
          });
          const result = await response.json();
          if (response.status === 409) continue;
          if (!response.ok) return json(result, response.status);

          return json({
            ok: true,
            ...result,
            peer: { id: peerId, name: peerName, ip: `${IP_PREFIX}1`, token },
            webSocketUrl: socketUrl(request.url, code, peerId, token)
          }, 201);
        }
        return json({ ok: false, error: "Could not allocate a room. Try again." }, 503);
      } catch (error) {
        return json({ ok: false, error: error instanceof SyntaxError ? "Invalid JSON." : error.message }, 400);
      }
    }

    const joinMatch = url.pathname.match(/^\/api\/rooms\/((?:[A-Z2-9]{8}|[A-Z2-9]{12}))\/join$/);
    if (request.method === "POST" && joinMatch) {
      try {
        const code = joinMatch[1];
        const body = await readJson(request);
        const peerName = cleanString(body.peerName, 24, "Player") || "Player";
        const password = cleanString(body.password, 64, "");
        const peerId = crypto.randomUUID();
        const token = randomToken();
        const tokenHash = await sha256(token);
        const stub = roomStub(env, code);
        const response = await stub.fetch("https://room.internal/_join", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "cf-connecting-ip": request.headers.get("cf-connecting-ip") || "unknown"
          },
          body: JSON.stringify({ peerId, peerName, password, tokenHash })
        });
        const result = await response.json();
        if (!response.ok) return json(result, response.status);
        return json({
          ok: true,
          ...result,
          peer: { id: peerId, name: peerName, ip: result.peer.ip, token },
          webSocketUrl: socketUrl(request.url, code, peerId, token)
        }, 200);
      } catch (error) {
        return json({ ok: false, error: error instanceof SyntaxError ? "Invalid JSON." : error.message }, 400);
      }
    }

    const wsMatch = url.pathname.match(/^\/api\/rooms\/((?:[A-Z2-9]{8}|[A-Z2-9]{12}))\/ws$/);
    if (wsMatch && request.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const stub = roomStub(env, wsMatch[1]);
      const internalUrl = new URL(request.url);
      internalUrl.hostname = "room.internal";
      internalUrl.pathname = "/_ws";
      return stub.fetch(new Request(internalUrl.toString(), request));
    }

    const statusMatch = url.pathname.match(/^\/api\/rooms\/((?:[A-Z2-9]{8}|[A-Z2-9]{12}))$/);
    if (request.method === "GET" && statusMatch) {
      const stub = roomStub(env, statusMatch[1]);
      const response = await stub.fetch("https://room.internal/_status");
      return withCors(response);
    }

    const leaveMatch = url.pathname.match(/^\/api\/rooms\/((?:[A-Z2-9]{8}|[A-Z2-9]{12}))\/leave$/);
    if (request.method === "POST" && leaveMatch) {
      try {
        const body = await readJson(request);
        const stub = roomStub(env, leaveMatch[1]);
        const response = await stub.fetch("https://room.internal/_leave", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
        });
        return withCors(response);
      } catch (error) {
        return json({ ok: false, error: error instanceof SyntaxError ? "Invalid JSON." : error.message }, 400);
      }
    }

    const kickMatch = url.pathname.match(/^\/api\/rooms\/((?:[A-Z2-9]{8}|[A-Z2-9]{12}))\/kick$/);
    if (request.method === "POST" && kickMatch) {
      try {
        const body = await readJson(request);
        const stub = roomStub(env, kickMatch[1]);
        const response = await stub.fetch("https://room.internal/_kick", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
        });
        return withCors(response);
      } catch (error) {
        return json({ ok: false, error: error instanceof SyntaxError ? "Invalid JSON." : error.message }, 400);
      }
    }

    return json({ ok: false, error: "Not found." }, 404);
  }
};

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  ensureRoomCollections(room) {
    if (!Array.isArray(room.peers)) room.peers = [];
    if (!Array.isArray(room.pendingPeers)) room.pendingPeers = [];
    if (!Array.isArray(room.kickedPeers)) room.kickedPeers = [];
  }

  async scheduleRoomAlarm(room) {
    const deadlines = [];
    if (Number.isFinite(room.expiresAt)) deadlines.push(room.expiresAt);
    for (const peer of room.pendingPeers || []) {
      if (Number.isFinite(peer.expiresAt)) deadlines.push(peer.expiresAt);
    }
    if (deadlines.length) await this.ctx.storage.setAlarm(Math.min(...deadlines));
  }

  async prunePending(room) {
    this.ensureRoomCollections(room);
    const now = Date.now();
    const expired = room.pendingPeers.filter(peer => !peer.expiresAt || peer.expiresAt <= now);
    if (!expired.length) return false;
    const expiredIds = new Set(expired.map(peer => peer.id));
    room.pendingPeers = room.pendingPeers.filter(peer => !expiredIds.has(peer.id));
    await this.saveRoom(room);
    for (const peer of expired) {
      for (const socket of this.ctx.getWebSockets(peer.id)) {
        try { socket.send(JSON.stringify({ type: "admission-failed", reason: "Direct UDP connection was not established." })); } catch (_) { }
        try { socket.close(4002, "Direct UDP connection timed out"); } catch (_) { }
      }
      this.sendPendingToHost({ type: "peer-pending-left", peerId: peer.id }, room);
    }
    await this.scheduleRoomAlarm(room);
    return true;
  }

  async getRoom() {
    return await this.ctx.storage.get("room");
  }

  async saveRoom(room) {
    await this.ctx.storage.put("room", room);
  }

  async touchRoom(room) {
    const now = Date.now();
    if (now - (room.lastActivity || 0) >= ROOM_TOUCH_INTERVAL_MS) {
      room.lastActivity = now;
      room.expiresAt = now + ROOM_LIFETIME_MS;
      await this.saveRoom(room);
      await this.scheduleRoomAlarm(room);
    }
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/_init") {
      const body = await request.json();
      if (await this.getRoom()) {
        return json({ ok: false, error: "Room code already exists." }, 409);
      }
      const now = Date.now();
      const room = {
        code: body.code,
        name: body.roomName,
        maxPeers: body.maxPeers,
        passwordSalt: body.passwordSalt,
        passwordHash: body.passwordHash,
        createdAt: now,
        lastActivity: now,
        expiresAt: now + ROOM_LIFETIME_MS,
        closed: false,
        kickedPeers: [],
        pendingPeers: [],
        peers: [{
          ...body.host,
          online: false,
          connectionId: null
        }]
      };
      await this.saveRoom(room);
      await this.ctx.storage.setAlarm(room.expiresAt);
      return json({ ok: true, ...publicRoom(room) }, 201);
    }

    if (request.method === "POST" && url.pathname === "/_join") {
      const body = await request.json();
      const room = await this.getRoom();
      if (!room || room.closed) return json({ ok: false, error: "Room not found or closed." }, 404);
      this.ensureRoomCollections(room);
      await this.prunePending(room);
      const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
      const rateKey = `join-fail:${await sha256(clientIp)}`;
      const now = Date.now();
      const rate = await this.ctx.storage.get(rateKey) || { count: 0, startedAt: now };
      if (now - rate.startedAt > 10 * 60 * 1000) {
        rate.count = 0;
        rate.startedAt = now;
      }
      if (rate.count >= 10) {
        return json({ ok: false, error: "Too many attempts. Try again later." }, 429);
      }
      if (room.passwordHash) {
        const suppliedHash = await sha256(`${room.passwordSalt}:${body.password || ""}`);
        if (!constantTimeEqual(suppliedHash, room.passwordHash)) {
          rate.count++;
          await this.ctx.storage.put(rateKey, rate);
          return json({ ok: false, error: "Incorrect room password." }, 403);
        }
      }
      const peerName = cleanString(body.peerName, 24, "Player") || "Player";
      const allReserved = room.peers.concat(room.pendingPeers);
      const duplicateName = allReserved.some(peer => peer.name.toLowerCase() === peerName.toLowerCase());
      if (duplicateName) {
        return json({ ok: false, error: "That player name is already in this room." }, 409);
      }
      if (room.peers.length + room.pendingPeers.length >= room.maxPeers) {
        return json({ ok: false, error: "Room is full." }, 409);
      }
      const usedSlots = new Set(allReserved.map(peer => Number(peer.ip.split(".").pop())));
      let slot = 2;
      while (slot <= 7 && usedSlots.has(slot)) slot++;
      if (slot > 7) return json({ ok: false, error: "No virtual IP addresses are available." }, 409);
      const peer = {
        id: body.peerId,
        name: peerName,
        ip: `${IP_PREFIX}${slot}`,
        tokenHash: body.tokenHash,
        joinedAt: now,
        online: false,
        connectionId: null,
        expiresAt: now + PENDING_PEER_TTL_MS,
        readyFromGuest: false,
        readyFromHost: false,
        readyHostId: null
      };
      room.pendingPeers.push(peer);
      room.lastActivity = now;
      room.expiresAt = now + ROOM_LIFETIME_MS;
      await this.saveRoom(room);
      await this.scheduleRoomAlarm(room);
      return json({
        ok: true,
        ...publicRoom(room),
        pending: true,
        peer: { id: peer.id, name: peer.name, ip: peer.ip }
      });
    }

    if (request.method === "GET" && url.pathname === "/_status") {
      const room = await this.getRoom();
      if (!room || room.closed) return json({ ok: false, error: "Room not found or closed." }, 404);
      await this.prunePending(room);
      return json({ ok: true, ...publicRoom(room) });
    }

    if (request.method === "POST" && url.pathname === "/_leave") {
      const body = await request.json();
      const room = await this.getRoom();
      if (!room || room.closed) return json({ ok: false, error: "Room not found or closed." }, 404);
      const activePeer = room.peers.find(item => item.id === body.peerId);
      const pendingPeer = room.pendingPeers.find(item => item.id === body.peerId);
      const peer = activePeer || pendingPeer;
      if (!peer || !constantTimeEqual(await sha256(body.token || ""), peer.tokenHash)) {
        return json({ ok: false, error: "Invalid peer credentials." }, 403);
      }
      if (pendingPeer) {
        room.pendingPeers = room.pendingPeers.filter(item => item.id !== pendingPeer.id);
        await this.saveRoom(room);
        this.sendPendingToHost({ type: "peer-pending-left", peerId: pendingPeer.id }, room);
        for (const ws of this.ctx.getWebSockets(pendingPeer.id)) {
          try { ws.close(4004, "Join cancelled"); } catch (_) { }
        }
        await this.scheduleRoomAlarm(room);
        return json({ ok: true, roomClosed: false, pendingCancelled: true });
      }
      if (peer.ip === `${IP_PREFIX}1`) {
        room.closed = true;
        await this.saveRoom(room);
        for (const ws of this.ctx.getWebSockets()) {
          try { ws.close(1000, "Room closed by host"); } catch (_) { }
        }
        await this.ctx.storage.setAlarm(Date.now() + 60 * 1000);
        return json({ ok: true, roomClosed: true });
      }
      room.peers = room.peers.filter(item => item.id !== peer.id);
      await this.saveRoom(room);
      this.broadcast({ type: "peer-left", peerId: peer.id });
      return json({ ok: true, roomClosed: false });
    }

    if (request.method === "POST" && url.pathname === "/_kick") {
      const body = await request.json();
      const room = await this.getRoom();
      if (!room || room.closed) {
        return json({ ok: false, error: "Room not found or closed." }, 404);
      }

      const host = room.peers.find(item => item.id === body.peerId);
      const suppliedTokenHash = await sha256(body.token || "");
      if (!host || !constantTimeEqual(suppliedTokenHash, host.tokenHash)) {
        return json({ ok: false, error: "Invalid host credentials." }, 403);
      }
      if (host.ip !== `${IP_PREFIX}1`) {
        return json({ ok: false, error: "Only the room host can kick players." }, 403);
      }

      const targetId = cleanString(body.targetPeerId, 64, "");
      const target = room.peers.find(item => item.id === targetId);
      if (!target || target.id === host.id) {
        return json({ ok: false, error: "The selected player is no longer in this room." }, 404);
      }

      const hostName = cleanString(host.name, 24, "Host") || "Host";
      if (!Array.isArray(room.kickedPeers)) room.kickedPeers = [];
      room.kickedPeers = room.kickedPeers.filter(item => item.id !== target.id);
      room.kickedPeers.push({
        id: target.id,
        tokenHash: target.tokenHash,
        name: target.name,
        hostName,
        kickedAt: Date.now()
      });
      while (room.kickedPeers.length > MAX_KICK_RECORDS) room.kickedPeers.shift();

      room.peers = room.peers.filter(item => item.id !== target.id);
      room.lastActivity = Date.now();
      room.expiresAt = room.lastActivity + ROOM_LIFETIME_MS;
      await this.saveRoom(room);
      await this.ctx.storage.setAlarm(room.expiresAt);

      const kickNotice = JSON.stringify({ type: "kicked", hostName });
      for (const socket of this.ctx.getWebSockets(target.id)) {
        try { socket.send(kickNotice); } catch (_) { }
        try { socket.close(4003, "Kicked by " + hostName); } catch (_) { }
      }
      this.broadcast({ type: "peer-left", peerId: target.id }, target.id);
      return json({
        ok: true,
        kicked: true,
        targetName: target.name,
        wasOnline: Boolean(target.online)
      });
    }

    if (request.method === "GET" && url.pathname === "/_ws") {
      return this.openWebSocket(request, url);
    }

    return json({ ok: false, error: "Not found." }, 404);
  }

  async openWebSocket(request, url) {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return json({ ok: false, error: "WebSocket upgrade required." }, 426);
    }

    const room = await this.getRoom();
    if (!room || room.closed) return json({ ok: false, error: "Room not found or closed." }, 404);
    this.ensureRoomCollections(room);
    await this.prunePending(room);
    const peerId = url.searchParams.get("peer") || "";
    const token = url.searchParams.get("token") || "";
    const tokenHash = await sha256(token);
    let peer = room.peers.find(item => item.id === peerId);
    let pending = false;
    if (!peer) {
      peer = room.pendingPeers.find(item => item.id === peerId);
      pending = Boolean(peer);
    }
    if (!peer || !constantTimeEqual(tokenHash, peer.tokenHash)) {
      const kicked = (room.kickedPeers || []).find(item =>
        item.id === peerId && constantTimeEqual(tokenHash, item.tokenHash)
      );
      if (kicked) {
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        const connectionId = crypto.randomUUID();
        this.ctx.acceptWebSocket(server, [peerId]);
        server.serializeAttachment({ peerId, connectionId, kicked: true });
        const hostName = cleanString(kicked.hostName, 24, "the room host") || "the room host";
        try { server.send(JSON.stringify({ type: "kicked", hostName })); } catch (_) { }
        try { server.close(4003, "Kicked by " + hostName); } catch (_) { }
        return new Response(null, { status: 101, webSocket: client });
      }
      return json({ ok: false, error: "Invalid peer credentials." }, 403);
    }

    const oldSockets = this.ctx.getWebSockets(peerId);
    for (const oldSocket of oldSockets) {
      try { oldSocket.close(4001, "Reconnected"); } catch (_) { }
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const connectionId = crypto.randomUUID();

    peer.online = true;
    peer.connectionId = connectionId;
    if (pending) peer.expiresAt = Date.now() + PENDING_PEER_TTL_MS;
    room.lastActivity = Date.now();
    room.expiresAt = room.lastActivity + ROOM_LIFETIME_MS;
    await this.saveRoom(room);
    this.ctx.acceptWebSocket(server, [peerId]);
    server.serializeAttachment({ peerId, connectionId });
    server.send(JSON.stringify({
      type: "welcome",
      admitted: !pending,
      hostPeerId: (room.peers.find(item => item.ip === `${IP_PREFIX}1`) || {}).id || "",
      room: {
        roomCode: room.code,
        roomName: room.name,
        maxPeers: room.maxPeers
      },
      self: { id: peer.id, name: peer.name, ip: peer.ip },
      peers: room.peers.filter(item => item.id !== peer.id && (!pending || item.ip === `${IP_PREFIX}1`)).map(item => ({
        id: item.id,
        name: item.name,
        ip: item.ip,
        online: Boolean(item.online)
      }))
    }));

    if (pending) {
      this.sendPendingToHost({
        type: "peer-pending",
        peer: { id: peer.id, name: peer.name, ip: peer.ip, online: true }
      }, room);
    } else {
      this.broadcastToAdmitted({
        type: "peer-online",
        peer: { id: peer.id, name: peer.name, ip: peer.ip }
      }, room, peer.id);
      // Restore pending ICE participants to a reconnecting admitted member.
      if (peer.ip === `${IP_PREFIX}1`) {
        for (const waiting of room.pendingPeers) {
          if (!waiting.online) continue;
          this.sendToPeer(peer.id, {
            type: "peer-pending",
            peer: { id: waiting.id, name: waiting.name, ip: waiting.ip, online: true }
          });
        }
      }
    }

    await this.scheduleRoomAlarm(room);
    return new Response(null, { status: 101, webSocket: client });
  }

  sendToPeer(peerId, payload) {
    const message = JSON.stringify(payload);
    let sent = false;
    for (const socket of this.ctx.getWebSockets(peerId)) {
      try {
        socket.send(message);
        sent = true;
      } catch (_) { }
    }
    return sent;
  }

  broadcast(payload, exceptPeerId = null) {
    const message = JSON.stringify(payload);
    for (const socket of this.ctx.getWebSockets()) {
      try {
        const attachment = socket.deserializeAttachment();
        if (!attachment || attachment.peerId === exceptPeerId) continue;
        socket.send(message);
      } catch (_) { }
    }
  }

  broadcastToAdmitted(payload, room, exceptPeerId = null) {
    for (const peer of room.peers || []) {
      if (peer.id === exceptPeerId || !peer.online) continue;
      this.sendToPeer(peer.id, payload);
    }
  }

  sendPendingToHost(payload, room) {
    const host = (room.peers || []).find(peer => peer.ip === `${IP_PREFIX}1` && peer.online);
    if (host) this.sendToPeer(host.id, payload);
  }

  async webSocketMessage(socket, message) {
    const attachment = socket.deserializeAttachment();
    if (!attachment || typeof message !== "string" || message.length > MAX_SIGNAL_BYTES) {
      try { socket.send(JSON.stringify({ type: "error", error: "Invalid message." })); } catch (_) { }
      return;
    }
    let packet;
    try {
      packet = JSON.parse(message);
    } catch (_) {
      try { socket.send(JSON.stringify({ type: "error", error: "Invalid JSON." })); } catch (_) { }
      return;
    }
    if (!packet || typeof packet !== "object" || Array.isArray(packet)) return;

    const room = await this.getRoom();
    if (!room || room.closed) return;
    this.ensureRoomCollections(room);
    const senderActive = room.peers.find(peer => peer.id === attachment.peerId);
    const senderPending = room.pendingPeers.find(peer => peer.id === attachment.peerId);
    const sender = senderActive || senderPending;
    if (!sender || sender.connectionId !== attachment.connectionId) return;

    if (packet.type === "ping") {
      if (senderPending) senderPending.expiresAt = Date.now() + PENDING_PEER_TTL_MS;
      await this.touchRoom(room);
      await this.saveRoom(room);
      try { socket.send(JSON.stringify({ type: "pong", time: Date.now() })); } catch (_) { }
      return;
    }

    if (packet.type === "udp-ready") {
      const targetId = cleanString(packet.to, 64, "");
      const targetActive = room.peers.find(peer => peer.id === targetId);
      const targetPending = room.pendingPeers.find(peer => peer.id === targetId);
      const samples = Number(packet.samples);
      const maxRttMs = Number(packet.maxRttMs);
      if (!targetId || targetId === sender.id || (!targetActive && !targetPending) ||
          !Number.isInteger(samples) || samples < MIN_ADMISSION_ROUND_TRIPS || samples > 20 ||
          !Number.isFinite(maxRttMs) || maxRttMs < 0 || maxRttMs > MAX_ADMISSION_RTT_MS) {
        try { socket.send(JSON.stringify({ type: "error", error: "UDP admission proof is invalid." })); } catch (_) { }
        return;
      }

      const host = room.peers.find(peer => peer.ip === `${IP_PREFIX}1`);
      if (senderPending && targetActive && host && targetActive.id === host.id && targetActive.online) {
        sender.readyFromGuest = true;
        sender.readyHostId = host.id;
        sender.expiresAt = Date.now() + PENDING_PEER_TTL_MS;
      } else if (senderActive && senderActive.ip === `${IP_PREFIX}1` && targetPending &&
                 host && senderActive.id === host.id && targetPending.online) {
        targetPending.readyFromHost = true;
        targetPending.readyHostId = host.id;
        targetPending.expiresAt = Date.now() + PENDING_PEER_TTL_MS;
      } else {
        try { socket.send(JSON.stringify({ type: "error", error: "Only a direct UDP path to the online room host can admit a pending player." })); } catch (_) { }
        return;
      }

      const pendingTarget = senderPending ? sender : targetPending;
      if (pendingTarget && pendingTarget.readyFromGuest && pendingTarget.readyFromHost &&
          pendingTarget.readyHostId && host && pendingTarget.readyHostId === host.id && host.online) {
        const admitted = {
          id: pendingTarget.id,
          name: pendingTarget.name,
          ip: pendingTarget.ip,
          tokenHash: pendingTarget.tokenHash,
          joinedAt: pendingTarget.joinedAt,
          online: true,
          connectionId: pendingTarget.connectionId
        };
        room.pendingPeers = room.pendingPeers.filter(peer => peer.id !== pendingTarget.id);
        if (!room.peers.some(peer => peer.id === admitted.id)) room.peers.push(admitted);
        room.lastActivity = Date.now();
        room.expiresAt = room.lastActivity + ROOM_LIFETIME_MS;
        await this.saveRoom(room);
        const peerPayload = { id: admitted.id, name: admitted.name, ip: admitted.ip, online: true };
        this.sendToPeer(admitted.id, {
          type: "room-admitted",
          hostPeerId: host.id,
          peer: peerPayload,
          peers: room.peers.filter(peer => peer.id !== admitted.id).map(peer => ({
            id: peer.id, name: peer.name, ip: peer.ip, online: Boolean(peer.online)
          }))
        });
        this.broadcastToAdmitted({ type: "peer-online", peer: peerPayload }, room, admitted.id);
        await this.scheduleRoomAlarm(room);
      } else {
        await this.saveRoom(room);
        await this.scheduleRoomAlarm(room);
        try { socket.send(JSON.stringify({ type: "udp-ready-waiting", to: targetId })); } catch (_) { }
      }
      return;
    }

    if (packet.type !== "signal") {
      try { socket.send(JSON.stringify({ type: "error", error: "Unsupported message type." })); } catch (_) { }
      return;
    }

    const targetId = cleanString(packet.to, 64, "");
    const targetActive = room.peers.find(peer => peer.id === targetId);
    const targetPending = room.pendingPeers.find(peer => peer.id === targetId);
    const target = targetActive || targetPending;
    const host = room.peers.find(peer => peer.ip === `${IP_PREFIX}1`);
    const touchesPending = Boolean(senderPending || targetPending);
    const pendingSignalAllowed = !touchesPending || (host && (
      (senderPending && targetActive && targetActive.id === host.id) ||
      (senderActive && senderActive.id === host.id && targetPending)
    ));
    const kind = cleanString(packet.kind, 32, "");
    if (!target || target.id === sender.id || !pendingSignalAllowed) {
      try { socket.send(JSON.stringify({ type: "error", error: "Invalid or unauthorized signal destination." })); } catch (_) { }
      return;
    }
    if (!/^[a-z0-9._-]{1,32}$/i.test(kind)) {
      try { socket.send(JSON.stringify({ type: "error", error: "Invalid signal kind." })); } catch (_) { }
      return;
    }
    let dataText;
    try { dataText = JSON.stringify(packet.data); } catch (_) { dataText = ""; }
    if (!dataText || new TextEncoder().encode(dataText).length > MAX_SIGNAL_BYTES) {
      try { socket.send(JSON.stringify({ type: "error", error: "Signal data is too large or invalid." })); } catch (_) { }
      return;
    }
    const delivered = this.sendToPeer(target.id, {
      type: "signal",
      from: sender.id,
      kind,
      data: packet.data
    });
    if (!delivered) {
      try { socket.send(JSON.stringify({ type: "error", code: "PEER_OFFLINE", error: "Peer is offline." })); } catch (_) { }
    }
    if (senderPending) sender.expiresAt = Date.now() + PENDING_PEER_TTL_MS;
    if (target.expiresAt && room.pendingPeers.some(peer => peer.id === target.id)) target.expiresAt = Date.now() + PENDING_PEER_TTL_MS;
    await this.touchRoom(room);
    await this.saveRoom(room);
    await this.scheduleRoomAlarm(room);
  }

  async onSocketClosed(socket) {
    const attachment = socket.deserializeAttachment();
    if (!attachment) return;
    const room = await this.getRoom();
    if (!room) return;
    this.ensureRoomCollections(room);
    const pending = room.pendingPeers.find(item => item.id === attachment.peerId);
    if (pending && pending.connectionId === attachment.connectionId) {
      // Keep a pending reservation briefly after a signaling interruption so the
      // same client can reconnect and continue ICE/UDP hole punching. It is still
      // excluded from room.peers and from every admitted-player roster.
      pending.online = false;
      pending.connectionId = null;
      pending.expiresAt = Date.now() + PENDING_PEER_TTL_MS;
      await this.saveRoom(room);
      this.sendPendingToHost({ type: "peer-pending-left", peerId: pending.id }, room);
      await this.scheduleRoomAlarm(room);
      return;
    }
    const peer = room.peers.find(item => item.id === attachment.peerId);
    if (!peer || peer.connectionId !== attachment.connectionId) return;

    peer.online = false;
    peer.connectionId = null;
    room.lastActivity = Date.now();
    room.expiresAt = room.lastActivity + ROOM_LIFETIME_MS;
    await this.saveRoom(room);
    await this.scheduleRoomAlarm(room);
    this.broadcastToAdmitted({ type: "peer-offline", peerId: peer.id }, room);
  }

  async webSocketClose(socket, code, reason, wasClean) {
    await this.onSocketClosed(socket);
  }

  async webSocketError(socket, error) {
    await this.onSocketClosed(socket);
  }

  async alarm() {
    let room = await this.getRoom();
    if (!room) return;
    this.ensureRoomCollections(room);
    await this.prunePending(room);
    room = await this.getRoom();
    if (!room) return;
    if (room.closed || (room.expiresAt && room.expiresAt <= Date.now())) {
      for (const socket of this.ctx.getWebSockets()) {
        try { socket.close(1000, "Room expired"); } catch (_) { }
      }
      await this.ctx.storage.deleteAll();
      return;
    }
    await this.scheduleRoomAlarm(room);
  }
}

// Notible Teams (prototype): share one project with a few people through the
// Notible Teams server. Everything leaves this machine encrypted with a key
// the server never sees. Design and threat model:
// docs/superpowers/specs/2026-09-29-notible-teams-prototype-design.md
//
// The decisions (what to send, what to accept, conflicts) are pure functions,
// exported for self-check.mjs. The Teams class only moves bytes.

// ponytail: the server address is a constant, not config. A plugin update is
// cheap, and this is the only server there is.
export const SERVER = "https://notible.szymonjankiewicz.com";
const INVITE_PREFIX = "NT1";
const MAX_ITEM_CHARS = 1_400_000;   // server refuses above 1.5 MB
const MAX_BATCH_CHARS = 750_000;    // server refuses a PUT above 900 KB
const MAX_BATCH_ITEMS = 100;
const POLL_MS = 60_000;
const AFTER_CHANGE_MS = 10_000;

const LIMITS = { title: 4_000, content: 20_000_000, props: 4_000_000, inflated: 64 * 1024 * 1024 };
const MAX_TIMESTAMP = Date.UTC(2200, 0, 1);
const CLOCK_SKEW = 24 * 60 * 60 * 1000;

const enc = new TextEncoder();
const dec = new TextDecoder();

// ----------------------------------------------------------------- encoding

export function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function base64ToBytes(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

const toUrl = (b64) => b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromUrl = (text) => text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);

/** `NT1.<spaceId>.<inviteToken>.<key>`: everything a friend needs to join. */
export function inviteCode(spaceId, token, keyBytes) {
  return [INVITE_PREFIX, spaceId, token, toUrl(bytesToBase64(keyBytes))].join(".");
}

export function parseInviteCode(text) {
  const parts = String(text ?? "").trim().split(".");
  if (parts.length !== 4 || parts[0] !== INVITE_PREFIX || !parts[1] || !parts[2]) {
    throw new Error("This is not a Notible Teams invite code.");
  }
  let key;
  try { key = base64ToBytes(fromUrl(parts[3])); } catch { key = null; }
  if (!key || key.length !== 32) throw new Error("The invite code is incomplete. Copy the whole code again.");
  return { spaceId: parts[1], token: parts[2], key };
}

// ------------------------------------------------------------------- crypto

async function gzip(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function gunzip(bytes, limit = LIMITS.inflated) {
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) throw new Error("Item expands past the size limit.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.length; }
  return out;
}

const keyFrom = (bytes) => crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);

/**
 * AES-256-GCM with the item's place as additional data (`spaceId|itemKey`):
 * the server cannot move a ciphertext to another item or space undetected.
 * It can still serve an older version of the same item — accepted for the
 * prototype (a member's next edit replaces it).
 */
export async function seal(keyBytes, payload, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = await gzip(enc.encode(JSON.stringify(payload)));
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(aad) }, await keyFrom(keyBytes), body));
  const out = new Uint8Array(12 + sealed.length);
  out.set(iv, 0);
  out.set(sealed, 12);
  return out;
}

export async function unseal(keyBytes, bytes, aad) {
  if (bytes.length <= 12) throw new Error("Item is too short to be valid.");
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: enc.encode(aad) }, await keyFrom(keyBytes), bytes.slice(12)));
  } catch {
    throw new Error("Item was not written with this space's key (or was moved).");
  }
  return JSON.parse(dec.decode(await gunzip(plain)), (key, value) =>
    (key === "__proto__" || key === "constructor" || key === "prototype") ? undefined : value);
}

// ---------------------------------------------------------------- the model

export const objectKey = (id) => `o:${id}`;
export const relationKey = (r) => `r:${r.from_id}:${r.to_id}:${r.kind}`;
const RELATION_KEY = /^r:([^:]+):([^:]+):([^:]+)$/;

/** cyrb53. Not security: a collision only hides one change until the next edit. */
function hash53(text) {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

// Automations keeps a per-device run log in a project's props; counted as
// content, every member's own check would look like an edit (Sync Simple 0.5.x
// learnt this the hard way).
function userProps(props) {
  if (typeof props !== "string" || !props.includes("_automationLog")) return props;
  try {
    const { _automationLog, ...rest } = JSON.parse(props);
    return JSON.stringify(rest);
  } catch {
    return props;
  }
}

/** What a person would call the object's content: everything but the clock. */
export function objectHash(o) {
  return hash53(JSON.stringify([o.type, o.title, o.content, userProps(o.props), o.archived_at ?? null, o.trashed_at ?? null]));
}

const DELETED = "deleted";
const PRESENT = "present";

export function objectPayload(o) {
  return {
    id: o.id, type: o.type, title: o.title, content: o.content, props: o.props,
    created_at: o.created_at, updated_at: o.updated_at,
    archived_at: o.archived_at ?? null, trashed_at: o.trashed_at ?? null,
  };
}

/**
 * The shared set: the root and every object whose `in` chain reaches it, and
 * the relations between two of those. Walked from the root down, so an
 * object filed in two places is shared if either place is.
 */
export function sharedSet(snapshot, rootId) {
  const objects = new Map((snapshot.objects ?? []).map((o) => [o.id, o]));
  const ids = new Set();
  if (objects.has(rootId)) {
    const children = new Map();
    for (const r of snapshot.relations ?? []) {
      if (r.kind !== "in") continue;
      if (!children.has(r.to_id)) children.set(r.to_id, []);
      children.get(r.to_id).push(r.from_id);
    }
    const queue = [rootId];
    while (queue.length) {
      const id = queue.pop();
      if (ids.has(id) || !objects.has(id)) continue;
      ids.add(id);
      for (const child of children.get(id) ?? []) queue.push(child);
    }
  }
  const relations = new Map();
  for (const r of snapshot.relations ?? []) {
    if (ids.has(r.from_id) && ids.has(r.to_id)) relations.set(relationKey(r), r);
  }
  return { ids, objects, relations };
}

/**
 * What this device has to send: everything in the shared set that differs
 * from the version it last agreed on with the server (`known`), and a
 * deletion for anything it once shared that is gone. Objects that merely
 * left the set (moved out of the project) are not deleted for anyone.
 */
export function planOutgoing(snapshot, rootId, known) {
  const shared = sharedSet(snapshot, rootId);
  const out = [];
  for (const id of shared.ids) {
    const object = shared.objects.get(id);
    const key = objectKey(id);
    const hash = objectHash(object);
    if (known[key]?.hash !== hash) out.push({ key, baseSeq: known[key]?.seq ?? 0, hash, payload: objectPayload(object) });
  }
  for (const [key, r] of shared.relations) {
    if (known[key]?.hash !== PRESENT) {
      out.push({ key, baseSeq: known[key]?.seq ?? 0, hash: PRESENT, payload: { from_id: r.from_id, to_id: r.to_id, kind: r.kind, created_at: r.created_at } });
    }
  }
  const now = Date.now();
  for (const [key, entry] of Object.entries(known)) {
    if (entry.hash === DELETED) continue;
    if (key.startsWith("o:")) {
      const id = key.slice(2);
      if (!shared.objects.has(id)) out.push({ key, baseSeq: entry.seq, hash: DELETED, payload: { deleted: true, deleted_at: now } });
    } else if (key.startsWith("r:") && !shared.relations.has(key)) {
      out.push({ key, baseSeq: entry.seq, hash: DELETED, payload: { deleted: true, deleted_at: now } });
    }
  }
  return out;
}

const isString = (v) => typeof v === "string";
const isTimestamp = (v) => Number.isInteger(v) && v >= 0 && v <= MAX_TIMESTAMP && v <= Date.now() + CLOCK_SKEW;
const isNullableTimestamp = (v) => v === null || v === undefined || isTimestamp(v);

function objectProblem(o, types) {
  if (!o || typeof o !== "object") return "not an object";
  if (!isString(o.id) || !o.id) return "missing id";
  if (!isString(o.type) || !o.type) return "missing type";
  if (!isString(o.title) || o.title.length > LIMITS.title) return "bad title";
  if (!isString(o.content) || o.content.length > LIMITS.content) return "bad content";
  if (!isString(o.props) || o.props.length > LIMITS.props) return "bad props";
  if (!isTimestamp(o.created_at) || !isTimestamp(o.updated_at)) return "bad timestamps";
  if (!isNullableTimestamp(o.archived_at) || !isNullableTimestamp(o.trashed_at)) return "bad archive/trash marker";
  if (types.size && !types.has(o.type)) return "unknown-type";
  return null;
}

/**
 * Decide what to do with items pulled from the server.
 *
 * Rules, in order of importance:
 * - Nothing received may touch an object that exists here OUTSIDE the shared
 *   project (or the project's root, for a deletion). A member cannot reach
 *   a private note by learning its id from a link.
 * - The server's version wins (Core applies newest-wins, so the applied copy
 *   gets a later `updated_at`). If this device changed the object too since
 *   it last agreed with the server, its version is kept as a conflict copy
 *   next to it.
 * - An edit beats a deletion, both ways: an object deleted on one side and
 *   edited on the other comes back.
 * - What cannot be applied yet (unknown type, the note open in the editor, a
 *   relation to an object not here yet) waits in `pending`; nothing is lost
 *   by moving the cursor.
 *
 * `items` are `{key, seq, payload}` (decrypted). Returns the apply request
 * parts plus the new `known` entries (hashes of objects are recomputed from a
 * fresh export by the caller after applying).
 */
export function planIncoming(items, ctx) {
  const { snapshot, rootId, known, openId = null, types = new Set(), now = Date.now(), copyLabel = "", newId = () => crypto.randomUUID() } = ctx;
  const shared = sharedSet(snapshot, rootId);
  const local = shared.objects; // every local object, shared or not
  const outside = (id) => local.has(id) && !shared.ids.has(id);
  const tombstoneOf = new Map((snapshot.tombstones ?? []).map((t) => [t.object_id, t.deleted_at]));
  const plan = { objects: [], relations: [], tombstones: [], relationTombstones: [], known: {}, pending: [], rejected: [], conflicts: 0, received: 0 };

  // Objects first, so a relation can tell whether its ends will exist.
  const arriving = new Set();
  const kept = new Set(); // deleted there, edited here: stays, links included
  const relationItems = [];
  for (const item of items) {
    const { key, seq, payload } = item;
    if (key.startsWith("r:")) { relationItems.push(item); continue; }
    if (!key.startsWith("o:") || !payload || typeof payload !== "object") { plan.rejected.push(`${key}: unreadable`); continue; }
    const id = key.slice(2);
    const mine = local.get(id);

    if (payload.deleted) {
      if (!mine) { plan.known[key] = { seq, hash: DELETED }; continue; }
      if (outside(id) || id === rootId) { plan.rejected.push(`${key}: deletion outside the shared project refused`); continue; }
      if (known[key] && objectHash(mine) !== known[key].hash) {
        // Edited here, deleted there: keep it. Recording the deletion as
        // known makes the next push send this version back up.
        plan.known[key] = { seq, hash: DELETED };
        kept.add(id);
        continue;
      }
      plan.tombstones.push({ object_id: id, deleted_at: Math.max(now, mine.updated_at) });
      plan.known[key] = { seq, hash: DELETED };
      plan.received += 1;
      continue;
    }

    if (payload.id !== id) { plan.rejected.push(`${key}: id does not match`); continue; }
    const problem = objectProblem(payload, types);
    if (problem === "unknown-type") { plan.pending.push(item); continue; }
    if (problem) { plan.rejected.push(`${key}: ${problem}`); continue; }
    if (outside(id)) { plan.rejected.push(`${key}: object outside the shared project refused`); continue; }
    if (id === openId) { plan.pending.push(item); continue; }

    const incomingHash = objectHash(payload);
    if (mine) {
      const mineHash = objectHash(mine);
      if (mineHash === incomingHash) { plan.known[key] = { seq, hash: incomingHash }; continue; }
      // CONFLICT-COPY-ROOT: never copy the shared root itself. A copy of the
      // project is a second project (same automations, linked folders,
      // favorite) filed INSIDE the original, which the Workspace view listed
      // as a stray project (Hive #1, 03.10). The server's version wins as usual.
      if (id !== rootId && (!known[key] || mineHash !== known[key].hash)) {
        plan.conflicts += 1;
        const copyId = newId();
        plan.objects.push({
          ...objectPayload(mine), id: copyId, title: `${mine.title} (conflict copy${copyLabel ? `, ${copyLabel}` : ""})`,
          created_at: now, updated_at: now,
        });
        const parent = (snapshot.relations ?? []).find((r) => r.kind === "in" && r.from_id === id && shared.ids.has(r.to_id))?.to_id ?? rootId;
        plan.relations.push({ from_id: copyId, to_id: parent, kind: "in", created_at: now });
        arriving.add(copyId);
      }
    }
    const floor = Math.max(mine ? mine.updated_at + 1 : 0, tombstoneOf.has(id) ? tombstoneOf.get(id) + 1 : 0);
    plan.objects.push({ ...payload, updated_at: Math.max(payload.updated_at, floor), parent_id: undefined });
    plan.known[key] = { seq, hash: incomingHash };
    arriving.add(id);
    plan.received += 1;
  }

  const willExist = (id) => shared.ids.has(id) || arriving.has(id);
  for (const item of relationItems) {
    const { key, seq, payload } = item;
    const match = RELATION_KEY.exec(key);
    if (!match || !payload || typeof payload !== "object") { plan.rejected.push(`${key}: unreadable`); continue; }
    const [, from, to, kind] = match;
    if (outside(from) || outside(to)) { plan.rejected.push(`${key}: link to an object outside the shared project refused`); continue; }
    if (payload.deleted) {
      // The deletion of an object takes its links with it; if that object
      // is being kept, so are its links (the next push sends them back).
      if (kept.has(from) || kept.has(to)) { plan.known[key] = { seq, hash: DELETED }; continue; }
      if (local.has(from) && local.has(to)) {
        plan.relationTombstones.push({ from_id: from, to_id: to, kind, deleted_at: now });
        plan.received += 1;
      }
      plan.known[key] = { seq, hash: DELETED };
      continue;
    }
    if (payload.from_id !== from || payload.to_id !== to || payload.kind !== kind || !isTimestamp(payload.created_at)) {
      plan.rejected.push(`${key}: does not match its key`);
      continue;
    }
    if (!willExist(from) || !willExist(to)) { plan.pending.push(item); continue; }
    plan.relations.push({ from_id: from, to_id: to, kind, created_at: payload.created_at });
    plan.known[key] = { seq, hash: PRESENT };
    plan.received += 1;
  }
  return plan;
}

/** Newest seq per key: pending items and fresh ones, merged. */
export function latestPerKey(items) {
  const byKey = new Map();
  for (const item of items) if (!byKey.has(item.key) || byKey.get(item.key).seq < item.seq) byKey.set(item.key, item);
  return [...byKey.values()].sort((a, b) => a.seq - b.seq);
}

/** Split outgoing items into PUT-sized batches. */
export function batches(items) {
  const out = [];
  let current = [];
  let size = 0;
  for (const item of items) {
    const length = item.ciphertext.length + item.key.length + 40;
    if (current.length && (current.length >= MAX_BATCH_ITEMS || size + length > MAX_BATCH_CHARS)) {
      out.push(current);
      current = [];
      size = 0;
    }
    current.push(item);
    size += length;
  }
  if (current.length) out.push(current);
  return out;
}

const MEDIA_REFERENCE = /media\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(?:png|jpg|jpeg|gif|webp|svg|bmp))/g;

export function mediaNamesOf(objects) {
  const names = new Set();
  for (const o of objects) {
    for (const text of [o?.content, o?.props]) {
      if (typeof text === "string") for (const match of text.matchAll(MEDIA_REFERENCE)) names.add(match[1]);
    }
  }
  return [...names];
}

// ------------------------------------------------------------------- server

export class Teams {
  constructor(context) {
    this.context = context;
    this.listeners = new Set();
    this.status = { state: "idle", text: "", notes: [] };
    this.running = false;
    this.applying = false;
    this.openObjectId = null;
    this.me = null; // last /v1/me
  }

  session() { return this.context.storage.get("session"); }
  user() { return this.context.storage.get("user"); }
  signedIn() { return Boolean(this.session()); }
  spaceState(id) { return this.context.storage.get(`space:${id}`); }
  saveSpace(id, state) { this.context.storage.set(`space:${id}`, state); }

  onStatus(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  setStatus(state, text, notes = []) {
    this.status = { state, text, notes };
    for (const listener of this.listeners) listener(this.status);
  }

  async api(method, path, body, raw = false) {
    const response = await fetch(`${SERVER}${path}`, {
      method,
      headers: {
        ...(this.session() ? { Authorization: `Bearer ${this.session()}` } : {}),
        ...(raw ? {} : { "Content-Type": "application/json" }),
      },
      body: raw ? body : body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 401 && path !== "/v1/session") {
      this.context.storage.delete("session");
      throw new Error("Your Teams session ended. Sign in again.");
    }
    if (raw && response.ok) return new Uint8Array(await response.arrayBuffer());
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.error || `Teams server answered ${response.status}.`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  async signIn() {
    let grant;
    try {
      grant = await this.context.oauth.google.signIn("google.identity");
    } catch (error) {
      if (/unknown sign-in provider/i.test(String(error?.message ?? error))) {
        throw new Error("Notible Teams needs Notible 0.91.2 or newer.");
      }
      throw error;
    }
    if (!grant?.idToken) throw new Error("Notible Teams needs Notible 0.91.2 or newer.");
    const { session, user } = await this.api("POST", "/v1/session", { idToken: grant.idToken });
    this.context.storage.set("session", session);
    this.context.storage.set("user", user);
    await this.refresh();
  }

  async signOut() {
    try { await this.api("DELETE", "/v1/session"); } catch { /* signing out locally is what matters */ }
    this.context.storage.delete("session");
    this.context.storage.delete("user");
    this.me = null;
  }

  async refresh() {
    this.me = await this.api("GET", "/v1/me");
    return this.me;
  }

  async share(rootId) {
    const space = await this.api("POST", "/v1/spaces", { rootId });
    const key = crypto.getRandomValues(new Uint8Array(32));
    this.saveSpace(space.id, { key: bytesToBase64(key), rootId, cursor: 0, known: {}, pending: [], sentMedia: [] });
    await this.refresh();
    return space.id;
  }

  async invite(spaceId) {
    const state = this.spaceState(spaceId);
    if (!state) throw new Error("This device has no key for the space.");
    const { token } = await this.api("POST", `/v1/spaces/${spaceId}/invites`);
    return inviteCode(spaceId, token, base64ToBytes(state.key));
  }

  async join(code) {
    const parsed = parseInviteCode(code);
    const { spaceId } = await this.api("POST", "/v1/invites/redeem", { token: parsed.token });
    if (spaceId !== parsed.spaceId) throw new Error("The invite code does not match its space.");
    const me = await this.refresh();
    const space = me.spaces.find((s) => s.id === spaceId);
    if (!this.spaceState(spaceId)) {
      this.saveSpace(spaceId, { key: bytesToBase64(parsed.key), rootId: space.rootId, cursor: 0, known: {}, pending: [], sentMedia: [] });
    }
    return spaceId;
  }

  async removeMember(spaceId, userId) {
    await this.api("DELETE", `/v1/spaces/${spaceId}/members/${encodeURIComponent(userId)}`);
    if (userId === this.user()?.id) this.context.storage.delete(`space:${spaceId}`);
    await this.refresh();
  }

  async deleteSpace(spaceId) {
    await this.api("DELETE", `/v1/spaces/${spaceId}`);
    this.context.storage.delete(`space:${spaceId}`);
    await this.refresh();
  }

  // ---------------------------------------------------------------- sync

  async run() {
    if (this.running || !this.signedIn()) return null;
    this.running = true;
    const notes = [];
    const totals = { received: 0, sent: 0, conflicts: 0, images: 0 };
    try {
      this.setStatus("busy", "Synchronising…");
      const me = await this.refresh();
      const member = new Set(me.spaces.map((s) => s.id));
      // Spaces this device has a key for but is no longer in: forget the
      // key, keep the notes.
      for (const key of this.context.storage.keys()) {
        const id = key.startsWith("space:") ? key.slice(6) : null;
        if (id && !member.has(id)) {
          this.context.storage.delete(key);
          notes.push("You are no longer in one of your shared projects; its notes stay on this computer.");
        }
      }
      const types = new Set((await this.context.data.types.list()).map((t) => t.name));
      for (const space of me.spaces) {
        const state = this.spaceState(space.id);
        if (!state) continue; // a member on another device: needs a code here
        try {
          const result = await this.runSpace(space, state, types, notes);
          for (const k of Object.keys(totals)) totals[k] += result[k];
        } catch (error) {
          notes.push(`${this.spaceTitle(space)}: ${error.message}`);
        }
      }
      this.context.storage.set("lastSync", Date.now());
      const parts = [
        totals.received ? `${totals.received} change${totals.received === 1 ? "" : "s"} received` : null,
        totals.sent ? `${totals.sent} sent` : null,
        totals.conflicts ? `${totals.conflicts} conflict cop${totals.conflicts === 1 ? "y" : "ies"} made` : null,
        totals.images ? `${totals.images} image${totals.images === 1 ? "" : "s"}` : null,
      ].filter(Boolean);
      this.setStatus(notes.length && !parts.length ? "error" : "ok", parts.join(" · ") || (notes.length ? "Some items could not be synchronised" : "Up to date"), notes);
      return totals;
    } catch (error) {
      this.setStatus("error", error.message || String(error), notes);
      return null;
    } finally {
      this.running = false;
    }
  }

  spaceTitle(space) {
    return this.titles?.get(space.rootId) || "Shared project";
  }

  async runSpace(space, state, types, notes) {
    const key = base64ToBytes(state.key);
    const aad = (itemKey) => `${space.id}|${itemKey}`;
    const out = { received: 0, sent: 0, conflicts: 0, images: 0 };

    // 1. Pull every page first, apply once.
    let cursor = state.cursor;
    const fresh = [];
    for (;;) {
      const page = await this.api("GET", `/v1/spaces/${space.id}/items?since=${cursor}`);
      for (const item of page.items) {
        try {
          fresh.push({ key: item.key, seq: item.seq, payload: await unseal(key, base64ToBytes(item.ciphertext), aad(item.key)) });
        } catch (error) {
          notes.push(`${item.key}: ${error.message}`);
        }
        cursor = Math.max(cursor, item.seq);
      }
      if (!page.more) break;
    }
    const incoming = latestPerKey([...(state.pending ?? []), ...fresh]);
    if (incoming.length) {
      const snapshot = await this.context.data.sync.export();
      const plan = planIncoming(incoming, {
        snapshot, rootId: space.rootId, known: state.known, openId: this.openObjectId, types,
        copyLabel: this.user()?.name || this.user()?.email || "",
      });
      notes.push(...plan.rejected);
      if (plan.objects.length || plan.relations.length || plan.tombstones.length || plan.relationTombstones.length) {
        this.applying = true;
        try {
          await this.context.data.sync.apply({
            cursor: snapshot.cursor,
            objects: plan.objects,
            relations: plan.relations,
            tombstones: plan.tombstones,
            relation_tombstones: plan.relationTombstones,
          });
        } finally {
          this.applying = false;
        }
      }
      // Hashes of what Core actually stored, so its own normalisation never
      // looks like a local edit and bounces back.
      const after = new Map((await this.context.data.sync.export()).objects.map((o) => [o.id, o]));
      for (const [itemKey, entry] of Object.entries(plan.known)) {
        const stored = itemKey.startsWith("o:") && entry.hash !== DELETED ? after.get(itemKey.slice(2)) : null;
        state.known[itemKey] = stored ? { seq: entry.seq, hash: objectHash(stored) } : entry;
      }
      state.pending = plan.pending;
      out.received += plan.received;
      out.conflicts += plan.conflicts;
    }
    state.cursor = cursor;
    this.saveSpace(space.id, state);

    // 2. Push what changed here.
    const snapshot = await this.context.data.sync.export();
    this.titles = new Map(snapshot.objects.map((o) => [o.id, o.title]));
    const outgoing = [];
    for (const item of planOutgoing(snapshot, space.rootId, state.known)) {
      const ciphertext = bytesToBase64(await seal(key, item.payload, aad(item.key)));
      if (ciphertext.length > MAX_ITEM_CHARS) {
        notes.push(`“${item.payload.title ?? item.key}” is too large to share.`);
        continue;
      }
      outgoing.push({ ...item, ciphertext });
    }
    for (const batch of batches(outgoing)) {
      const { results } = await this.api("PUT", `/v1/spaces/${space.id}/items`, {
        items: batch.map(({ key: itemKey, baseSeq, ciphertext }) => ({ key: itemKey, baseSeq, ciphertext })),
      });
      results.forEach((result, index) => {
        // A conflict needs no handling here: the next pull brings the newer
        // version and planIncoming keeps this one as a conflict copy.
        if (result.conflict) return;
        state.known[batch[index].key] = { seq: result.seq, hash: batch[index].hash };
        out.sent += 1;
      });
      this.saveSpace(space.id, state);
    }

    // 3. Pictures the shared notes refer to.
    out.images += await this.syncMedia(space, state, key, snapshot, notes);
    this.saveSpace(space.id, state);
    return out;
  }

  async syncMedia(space, state, key, snapshot, notes) {
    const shared = sharedSet(snapshot, space.rootId);
    const wanted = mediaNamesOf([...shared.ids].map((id) => shared.objects.get(id)));
    if (!wanted.length) return 0;
    const aad = (name) => `${space.id}|media/${name}`;
    let moved = 0;
    let missing = [];
    try { missing = await this.context.data.sync.media.missing(wanted); } catch (error) { notes.push(`images: ${error.message}`); return 0; }
    for (const name of missing) {
      try {
        const base64 = await unseal(key, await this.api("GET", `/v1/spaces/${space.id}/media/${name}`, undefined, true), aad(name));
        await this.context.data.sync.media.write(name, base64);
        moved += 1;
      } catch (error) {
        if (error.status !== 404) notes.push(`${name}: ${error.message}`); // 404: not sent yet
      }
    }
    const sent = new Set(state.sentMedia ?? []);
    for (const name of wanted.filter((n) => !missing.includes(n) && !sent.has(n))) {
      try {
        const base64 = await this.context.data.sync.media.read(name);
        await this.api("PUT", `/v1/spaces/${space.id}/media/${name}`, await seal(key, base64, aad(name)), true);
        sent.add(name);
        moved += 1;
      } catch (error) {
        notes.push(`Images not sent: ${error.message}`);
        break;
      }
    }
    state.sentMedia = [...sent];
    return moved;
  }
}

// ----------------------------------------------------------------------- UI

const styles = `
.nteams { display: grid; gap: 20px; max-width: 100%; color: var(--notible-text); }
.nteams-lead { margin: 0; max-width: 64ch; color: var(--notible-muted); font-size: 13px; line-height: 1.55; }
.nteams-now { display: grid; gap: 14px; padding-bottom: 20px; border-bottom: 1px solid var(--notible-border); }
.nteams-summary { display: flex; align-items: center; gap: 9px; color: var(--notible-muted); font-size: 13px; font-weight: 600; }
.nteams-summary__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--notible-border); }
.nteams-summary[data-state="ok"] { color: var(--notible-success); }
.nteams-summary[data-state="busy"] { color: var(--notible-accent); }
.nteams-summary[data-state="error"] { color: var(--notible-danger); }
.nteams-summary[data-state="ok"] .nteams-summary__dot { background: var(--notible-success); }
.nteams-summary[data-state="busy"] .nteams-summary__dot { background: var(--notible-accent); }
.nteams-summary[data-state="error"] .nteams-summary__dot { background: var(--notible-danger); }
.nteams-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.nteams .status { max-width: 90ch; margin: 0; color: var(--notible-muted); font-size: 12px; line-height: 1.5; }
.nteams .status:empty { display: none; }
.nteams .status[data-state="error"] { color: var(--notible-danger); }
.nteams-details > summary { width: fit-content; cursor: pointer; color: var(--notible-faint); font-size: 12px; }
.nteams-details ul { display: grid; gap: 4px; max-height: 240px; margin: 8px 0 0; padding-left: 18px; overflow: auto; color: var(--notible-muted); font-size: 12px; }
.nteams-rows { display: grid; }
.nteams-step { padding: 14px 0; border-top: 1px solid var(--notible-border-subtle, var(--notible-border)); }
.nteams-step:first-child { border-top: 0; padding-top: 0; }
.nteams-step[open] { padding-bottom: 20px; }
.nteams-step > summary { display: flex; align-items: center; gap: 10px; list-style: none; cursor: pointer; }
.nteams-step > summary::-webkit-details-marker { display: none; }
.nteams-step > summary::after { content: "\\25B8"; margin-left: 2px; color: var(--notible-faint); font-size: 11px; }
.nteams-step[open] > summary::after { content: "\\25BE"; }
.nteams-step__body { display: grid; gap: 14px; padding-top: 14px; }
.nteams h4 { margin: 0; font-size: 13px; font-weight: 600; }
.nteams-badge { margin-left: auto; color: var(--notible-muted); font-size: 12px; }
.nteams p { max-width: 70ch; margin: 0; color: var(--notible-muted); font-size: 12px; line-height: 1.55; }
.nteams-hint { color: var(--notible-faint) !important; font-size: 11px !important; }
.nteams-warning { color: var(--notible-danger) !important; }
.nteams button { min-height: 32px; padding: 6px 12px; border: 1px solid var(--notible-border); border-radius: 7px; background: transparent; color: var(--notible-text); font: inherit; font-size: 12px; cursor: pointer; }
.nteams button:hover:not(:disabled) { border-color: var(--notible-accent); background: var(--notible-hover); }
.nteams button:focus-visible, .nteams input:focus-visible, .nteams select:focus-visible, .nteams summary:focus-visible { outline: 2px solid var(--notible-accent); outline-offset: 2px; }
.nteams button:disabled { cursor: not-allowed; opacity: .46; }
.nteams .nteams-primary { border-color: var(--notible-accent); background: var(--notible-accent); color: var(--notible-on-accent); font-weight: 600; }
.nteams .nteams-primary:hover:not(:disabled) { border-color: var(--notible-accent-hover); background: var(--notible-accent-hover); }
.nteams .nteams-danger { color: var(--notible-danger); }
.nteams .nteams-danger:hover:not(:disabled) { border-color: var(--notible-danger); background: var(--notible-danger-surface); }
.nteams input, .nteams select { box-sizing: border-box; height: 32px; min-width: 0; padding: 6px 9px; border: 1px solid var(--notible-border); border-radius: 7px; background: var(--notible-surface); color: var(--notible-text); font: inherit; font-size: 12px; }
.nteams-code { width: min(100%, 520px); font-family: ui-monospace, Consolas, monospace; }
.nteams-people { display: grid; gap: 6px; margin: 0; padding: 0; list-style: none; font-size: 12px; }
.nteams-people li { display: flex; align-items: center; gap: 10px; }
.nteams-people button { min-height: 26px; padding: 2px 8px; }
`;

function element(tag, properties = {}, children = []) {
  const node = Object.assign(document.createElement(tag), properties);
  for (const child of children) if (child) node.append(child);
  return node;
}

function when(timestamp) {
  const date = new Date(timestamp);
  return date.toDateString() === new Date().toDateString()
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/** A button that asks "again?" instead of opening a dialog. */
function confirmButton(label, confirmLabel, action, className = "nteams-danger") {
  const button = element("button", { type: "button", className, textContent: label });
  let armed = false;
  button.onclick = async () => {
    if (!armed) {
      armed = true;
      button.textContent = confirmLabel;
      setTimeout(() => { armed = false; button.textContent = label; }, 4000);
      return;
    }
    button.disabled = true;
    try { await action(); } finally { button.disabled = false; }
  };
  return button;
}

function mountPanel(teams, container) {
  const root = element("div", { className: "nteams" });
  root.append(element("style", { textContent: styles }));
  root.append(element("p", {
    className: "nteams-lead",
    textContent: "Share a project with a few people. It is encrypted on this computer before it goes to the Notible Teams server, which cannot read it. Test version.",
  }));

  const summaryText = element("span", {});
  const summary = element("div", { className: "nteams-summary" }, [element("span", { className: "nteams-summary__dot" }), summaryText]);
  const status = element("p", { className: "status" });
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const detailsLabel = element("summary", {});
  const detailsList = element("ul", {});
  const details = element("details", { className: "nteams-details" }, [detailsLabel, detailsList]);
  const nowRow = element("div", { className: "nteams-row" });
  root.append(element("section", { className: "nteams-now" }, [summary, nowRow, status, details]));
  const rows = element("div", { className: "nteams-rows" });
  root.append(rows);

  const say = (state, text) => { status.dataset.state = state; status.textContent = text; };
  const act = async (fn, busyText) => {
    if (busyText) say("busy", busyText);
    try { await fn(); } catch (error) { say("error", error.message || String(error)); return false; }
    return true;
  };

  const now = element("button", { type: "button", className: "nteams-primary", textContent: "Synchronise now" });
  now.onclick = async () => { now.disabled = true; await teams.run(); now.disabled = false; render(); };
  const signIn = element("button", { type: "button", className: "nteams-primary", textContent: "Sign in with Google" });
  signIn.onclick = async () => {
    signIn.disabled = true;
    if (await act(() => teams.signIn(), "Finish signing in in your browser, then come back here.")) {
      say("idle", "");
      render();
      teams.run().then(render);
    }
    signIn.disabled = false;
  };

  const paint = ({ state, text, notes = [] }) => {
    const on = teams.signedIn();
    const last = teams.context.storage.get("lastSync");
    summary.dataset.state = on ? state : "idle";
    summaryText.textContent = !on ? "Not signed in"
      : state === "busy" ? "Synchronising…"
        : state === "error" ? "Needs attention"
          : last ? `Synced · ${when(last)}` : "Signed in";
    now.disabled = state === "busy";
    if (on && (state === "ok" || state === "error")) say(state, text);
    details.hidden = !notes.length;
    detailsLabel.textContent = `Details (${notes.length})`;
    detailsList.replaceChildren(...notes.map((note) => element("li", { textContent: note })));
  };

  const openRows = new Set();
  const row = (id, title, badge) => {
    const node = element("details", { className: "nteams-step", open: openRows.has(id) });
    node.addEventListener("toggle", () => { node.open ? openRows.add(id) : openRows.delete(id); });
    const body = element("div", { className: "nteams-step__body" });
    node.append(element("summary", {}, [element("h4", { textContent: title }), element("span", { className: "nteams-badge", textContent: badge })]), body);
    rows.append(node);
    return body;
  };

  const render = async () => {
    rows.replaceChildren();
    if (!teams.signedIn()) {
      nowRow.replaceChildren(signIn);
      paint(teams.status);
      return;
    }
    nowRow.replaceChildren(now);
    if (!teams.me) await act(() => teams.refresh());
    const me = teams.me;
    const user = teams.user() ?? {};
    const snapshot = await teams.context.data.sync.export().catch(() => ({ objects: [] }));
    const titles = new Map(snapshot.objects.map((o) => [o.id, o.title]));

    for (const space of me?.spaces ?? []) {
      const state = teams.spaceState(space.id);
      const owner = space.ownerId === user.id;
      const title = titles.get(space.rootId) || "Shared project (arrives with the first sync)";
      const body = row(`space:${space.id}`, title, `${space.members.length} ${space.members.length === 1 ? "person" : "people"}`);
      body.append(element("ul", { className: "nteams-people" }, space.members.map((m) => element("li", {}, [
        element("span", { textContent: `${m.name || m.email}${m.name ? ` · ${m.email}` : ""}${m.id === space.ownerId ? " · owner" : ""}${m.id === user.id ? " · you" : ""}` }),
        owner && m.id !== user.id
          ? confirmButton("Remove", "Click again to remove", () => act(async () => { await teams.removeMember(space.id, m.id); render(); }))
          : null,
      ]))));
      if (!state) {
        body.append(element("p", { textContent: "You are in this project on another computer. To open it here, ask a member for an invite code and paste it under “Join with a code”." }));
        continue;
      }
      const code = element("input", { className: "nteams-code", readOnly: true, placeholder: "Invite code appears here" });
      const make = element("button", { type: "button", textContent: "Create invite code" });
      make.onclick = () => act(async () => {
        code.value = await teams.invite(space.id);
        code.select();
        await navigator.clipboard?.writeText(code.value).catch(() => {});
        say("idle", "Invite code copied. Send it privately: it opens the project, once, within 24 hours.");
      });
      body.append(
        element("div", { className: "nteams-row" }, [make, code]),
        element("p", { className: "nteams-hint", textContent: "Removing someone stops their access to the server. What their computer already has stays there." }),
        element("div", { className: "nteams-row" }, [
          owner
            ? confirmButton("Delete from the server", "Click again: delete for everyone", () => act(async () => { await teams.deleteSpace(space.id); render(); }))
            : confirmButton("Leave", "Click again to leave", () => act(async () => { await teams.removeMember(space.id, user.id); render(); })),
        ]),
        element("p", { className: "nteams-hint", textContent: owner ? "Deleting removes the server copy for everyone. The notes stay in each person's Notible." : "Leaving keeps the notes on this computer; they just stop updating." }),
      );
    }

    // Share a project.
    const sharedRoots = new Set((me?.spaces ?? []).map((s) => s.rootId));
    const projects = snapshot.objects.filter((o) => o.type === "project" && !o.trashed_at && !sharedRoots.has(o.id));
    const shareBody = row("share", "Share a project", projects.length ? "" : "No projects yet");
    if (projects.length) {
      const select = element("select", {}, projects.map((p) => element("option", { value: p.id, textContent: p.title || "Untitled" })));
      const share = element("button", { type: "button", className: "nteams-primary", textContent: "Share" });
      share.onclick = () => act(async () => {
        await teams.share(select.value);
        await teams.run();
        openRows.add("share");
        render();
      }, "Sharing…");
      shareBody.append(
        element("div", { className: "nteams-row" }, [select, share]),
        element("p", { textContent: "The project and everything filed under it is shared. Then create an invite code for each person." }),
      );
    } else {
      shareBody.append(element("p", { textContent: "Create a project first; everything filed under it can be shared." }));
    }

    // Join.
    const joinBody = row("join", "Join with a code", "");
    const input = element("input", { className: "nteams-code", placeholder: "NT1.…" });
    const join = element("button", { type: "button", textContent: "Join" });
    join.onclick = () => act(async () => {
      await teams.join(input.value);
      input.value = "";
      await teams.run();
      render();
    }, "Joining…");
    joinBody.append(element("div", { className: "nteams-row" }, [input, join]));

    // Account.
    const accountBody = row("account", "Account", user.email ?? "");
    const out = element("button", { type: "button", className: "nteams-danger", textContent: "Sign out" });
    out.onclick = () => act(async () => { await teams.signOut(); render(); });
    accountBody.append(
      element("p", { className: "nteams-warning", textContent: "Do not install plugins from other authors on a computer that is in a team: any installed plugin can read what this one can." }),
      element("div", { className: "nteams-row" }, [out]),
    );
    paint(teams.status);
  };

  const stop = teams.onStatus(paint);
  render();
  container.append(root);
  return { dispose: () => { stop(); root.remove(); } };
}

// ------------------------------------------------------------------- plugin

export default {
  manifest: {
    id: "notible.teams",
    name: "Notible Teams",
    version: "0.1.2",
    apiVersion: "1.21",
    description: "Test version: share a project with a few people through the Notible Teams server. It is encrypted on your computer before it leaves.",
    author: "Notible",
    permissions: ["data.sync", "data.read", "workspace.ui", "network"],
  },

  onload(context) {
    const teams = new Teams(context);
    this._teams = teams;
    this._disposables = [];
    this._disposables.push(context.events.on("object.opened", (payload) => {
      teams.openObjectId = payload?.type === "table" ? null : payload?.id ?? null;
    }));
    this._disposables.push(context.settings.register({
      id: "teams",
      title: "Teams",
      mount: ({ container }) => mountPanel(teams, container),
    }));
    this._disposables.push(context.commands.register({
      id: "now",
      name: "Teams: synchronise now",
      description: "Send and receive changes to shared projects.",
      execute: () => teams.run(),
    }));
    // ponytail: polling, not a live connection. The app's CSP has no wss:
    // yet, and a minute is fine for a test with friends.
    this._timer = setInterval(() => { teams.run(); }, POLL_MS);
    this._startTimer = setTimeout(() => { teams.run(); }, 8_000);
    this._disposables.push(context.events.on("workspace.changed", () => {
      if (teams.applying) return;
      clearTimeout(this._changeTimer);
      this._changeTimer = setTimeout(() => { teams.run(); }, AFTER_CHANGE_MS);
    }));
  },

  onunload() {
    clearInterval(this._timer);
    clearTimeout(this._startTimer);
    clearTimeout(this._changeTimer);
    for (const disposable of this._disposables ?? []) disposable.dispose?.();
    this._disposables = [];
    this._teams = null;
  },
};

// Unit checks for the pure parts of Notible Teams. `node self-check.mjs`
// The end-to-end run (two people, the real server code) lives in
// services/notible-teams/e2e-check.mjs in the Notible monorepo.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import plugin, {
  inviteCode, parseInviteCode, seal, unseal, sharedSet, planOutgoing, planIncoming,
  objectHash, latestPerKey, batches, mediaNamesOf, objectKey,
} from "./main.js";

const manifest = JSON.parse(readFileSync(new URL("./plugin.json", import.meta.url), "utf8"));
for (const field of ["id", "name", "version", "apiVersion"]) assert.equal(plugin.manifest[field], manifest[field], `manifest ${field}`);
assert.deepEqual(plugin.manifest.permissions, manifest.permissions);

// --- invite codes
const key = crypto.getRandomValues(new Uint8Array(32));
const code = inviteCode("space-1", "tok_EN-123", key);
const parsed = parseInviteCode(`  ${code}\n`);
assert.equal(parsed.spaceId, "space-1");
assert.equal(parsed.token, "tok_EN-123");
assert.deepEqual([...parsed.key], [...key]);
for (const bad of ["", "NT2.a.b.c", "NT1.a.b", code.slice(0, -4)]) assert.throws(() => parseInviteCode(bad), undefined, bad);

// --- crypto: the place is part of the seal
const sealed = await seal(key, { hello: "świat" }, "s|o:1");
assert.deepEqual(await unseal(key, sealed, "s|o:1"), { hello: "świat" });
await assert.rejects(unseal(key, sealed, "s|o:2"), /this space's key/, "moved ciphertext is refused");
await assert.rejects(unseal(crypto.getRandomValues(new Uint8Array(32)), sealed, "s|o:1"), /this space's key/);

// --- a small workspace
const T = Date.now() - 100_000;
const obj = (id, extra = {}) => ({ id, type: "note", title: id, content: `text ${id}`, props: "{}", created_at: T, updated_at: T, archived_at: null, trashed_at: null, ...extra });
const rel = (from_id, to_id, kind = "in") => ({ from_id, to_id, kind, created_at: T });
const workspace = () => ({
  deviceId: "d", cursor: 0,
  objects: [obj("P", { type: "project" }), obj("F"), obj("N"), obj("X"), obj("private")],
  relations: [rel("F", "P"), rel("N", "F"), rel("N", "private", "mentions"), rel("X", "private")],
  tombstones: [], relationTombstones: [],
});

const shared = sharedSet(workspace(), "P");
assert.deepEqual([...shared.ids].sort(), ["F", "N", "P"]);
assert.deepEqual([...shared.relations.keys()].sort(), ["r:F:P:in", "r:N:F:in"], "links to private objects are not shared");
assert.equal(sharedSet(workspace(), "missing").ids.size, 0);

// --- outgoing
let ws = workspace();
let out = planOutgoing(ws, "P", {});
assert.deepEqual(out.map((i) => i.key).sort(), ["o:F", "o:N", "o:P", "r:F:P:in", "r:N:F:in"]);
assert.ok(out.every((i) => i.baseSeq === 0));
const known = Object.fromEntries(out.map((i, n) => [i.key, { seq: n + 1, hash: i.hash }]));
assert.equal(planOutgoing(ws, "P", known).length, 0, "nothing changed, nothing sent");
ws.objects.find((o) => o.id === "N").content = "edited";
out = planOutgoing(ws, "P", known);
assert.deepEqual(out.map((i) => [i.key, i.baseSeq]), [["o:N", known["o:N"].seq]]);
// Automations' own run log is not an edit.
ws = workspace();
ws.objects.find((o) => o.id === "P").props = JSON.stringify({ _automationLog: [1, 2] });
assert.equal(planOutgoing(ws, "P", known).length, 0);
// Deleted here: a deletion goes up. Moved out: only the link goes.
ws = workspace();
ws.objects = ws.objects.filter((o) => o.id !== "N");
ws.relations = ws.relations.filter((r) => r.from_id !== "N");
out = planOutgoing(ws, "P", known);
assert.deepEqual(out.map((i) => [i.key, i.payload.deleted]).sort(), [["o:N", true], ["r:N:F:in", true]]);
ws = workspace();
ws.relations = ws.relations.filter((r) => !(r.from_id === "N" && r.to_id === "F")).concat(rel("N", "private"));
out = planOutgoing(ws, "P", known);
assert.deepEqual(out.map((i) => [i.key, i.payload.deleted]), [["r:N:F:in", true]], "moving a note out deletes it for nobody");

// --- incoming
const item = (key, seq, payload) => ({ key, seq, payload });
const ctx = (extra = {}) => ({ snapshot: workspace(), rootId: "P", known, types: new Set(["note", "project"]), newId: () => "copy-1", now: Date.now(), ...extra });

// A new member: everything is new.
let plan = planIncoming([
  item("o:P", 1, obj("P", { type: "project" })), item("o:F", 2, obj("F")), item("r:F:P:in", 3, rel("F", "P")),
], { ...ctx(), snapshot: { objects: [], relations: [] }, known: {} });
assert.equal(plan.objects.length, 2);
assert.equal(plan.relations.length, 1);
assert.deepEqual(Object.keys(plan.known).sort(), ["o:F", "o:P", "r:F:P:in"]);

// Their edit, mine untouched: applied, newer than mine so Core takes it.
plan = planIncoming([item("o:N", 9, obj("N", { content: "theirs", updated_at: T - 50 }))], ctx());
assert.equal(plan.objects.length, 1);
assert.equal(plan.objects[0].content, "theirs");
assert.ok(plan.objects[0].updated_at > T, "server version wins even with an older clock");
assert.equal(plan.conflicts, 0);

// Both edited: theirs applied, mine kept as a copy in the same folder.
let snap = workspace();
snap.objects.find((o) => o.id === "N").content = "mine";
plan = planIncoming([item("o:N", 9, obj("N", { content: "theirs" }))], ctx({ snapshot: snap, copyLabel: "Ann" }));
assert.equal(plan.conflicts, 1);
const copy = plan.objects.find((o) => o.id === "copy-1");
assert.equal(copy.content, "mine");
assert.match(copy.title, /conflict copy, Ann/);
assert.deepEqual(plan.relations, [{ from_id: "copy-1", to_id: "F", kind: "in", created_at: plan.relations[0].created_at }]);

// Same content arriving: nothing to apply.
plan = planIncoming([item("o:N", 9, obj("N"))], ctx());
assert.equal(plan.objects.length, 0);
assert.equal(plan.known["o:N"].seq, 9);

// Attacks from a member: private objects are out of reach.
plan = planIncoming([
  item("o:private", 5, obj("private", { content: "overwritten" })),
  item("o:private", 6, { deleted: true }),
  item("r:private:P:in", 7, rel("private", "P")),
  item("o:P", 8, { deleted: true }),
  item("o:N", 9, obj("private")),
  item("r:N:X:in", 10, rel("N", "X")),
], ctx());
assert.equal(plan.objects.length + plan.relations.length + plan.tombstones.length, 0);
assert.equal(plan.rejected.length, 6, plan.rejected.join("\n"));
assert.equal(latestPerKey([item("o:a", 1, 1), item("o:a", 3, 3), item("o:b", 2, 2)]).map((i) => i.seq).join(), "2,3");

// Deleted there, untouched here: deleted. Edited here: kept, and re-sent.
plan = planIncoming([item("o:N", 12, { deleted: true })], ctx());
assert.deepEqual(plan.tombstones.map((t) => t.object_id), ["N"]);
snap = workspace();
snap.objects.find((o) => o.id === "N").content = "mine";
plan = planIncoming([item("o:N", 12, { deleted: true })], ctx({ snapshot: snap }));
assert.equal(plan.tombstones.length, 0, "an edit beats a deletion");
const reSend = planOutgoing(snap, "P", { ...known, ...plan.known });
assert.deepEqual(reSend.map((i) => [i.key, i.baseSeq]), [["o:N", 12]]);
// ...and it stays in its folder: the deletion's link removals are not applied.
plan = planIncoming([item("o:N", 12, { deleted: true }), item("r:N:F:in", 13, { deleted: true })], ctx({ snapshot: snap }));
assert.equal(plan.relationTombstones.length, 0, "a kept object keeps its links");
assert.deepEqual(planOutgoing(snap, "P", { ...known, ...plan.known }).map((i) => [i.key, i.baseSeq]).sort(), [["o:N", 12], ["r:N:F:in", 13]]);

// Deleted here, edited there: it comes back over the local tombstone.
snap = workspace();
snap.objects = snap.objects.filter((o) => o.id !== "N");
snap.tombstones = [{ object_id: "N", deleted_at: Date.now() - 10 }];
plan = planIncoming([item("o:N", 13, obj("N", { content: "theirs" }))], ctx({ snapshot: snap }));
assert.ok(plan.objects[0].updated_at > snap.tombstones[0].deleted_at);

// Waiting, not lost: unknown type, the open note, a link whose end is missing.
plan = planIncoming([
  item("o:T", 20, obj("T", { type: "table" })),
  item("o:N", 21, obj("N", { content: "theirs" })),
  item("r:Q:F:in", 22, rel("Q", "F")),
], ctx({ openId: "N" }));
assert.deepEqual(plan.pending.map((i) => i.key), ["o:T", "o:N", "r:Q:F:in"]);
assert.equal(Object.keys(plan.known).length, 0);

// A relation arriving with its object in the same pull.
plan = planIncoming([item("o:Q", 23, obj("Q")), item("r:Q:F:in", 24, rel("Q", "F"))], ctx());
assert.equal(plan.relations.length, 1);

// --- plumbing
const big = { key: "o:x", ciphertext: "x".repeat(400_000) };
assert.equal(batches([big, big, big]).length, 3, "two 400 KB items do not fit one 750 KB batch");
assert.equal(batches(Array.from({ length: 250 }, (_, i) => ({ key: `o:${i}`, ciphertext: "c" }))).length, 3);
assert.deepEqual(mediaNamesOf([{ content: "![](media/0f8fad5b-d9cb-469f-a165-70867728950e.png)", props: "" }]), ["0f8fad5b-d9cb-469f-a165-70867728950e.png"]);
assert.equal(objectKey("a"), "o:a");
assert.notEqual(objectHash(obj("a")), objectHash(obj("a", { trashed_at: T })), "trash is a change");

console.log("Notible Teams self-check passed.");

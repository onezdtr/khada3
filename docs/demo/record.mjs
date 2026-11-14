// Films the demo dashboard (gen.py, port 8054) through a headless Brave/Chrome started with --remote-debugging-port=9333.
// node docs/demo/record.mjs <frames dir>          then gif.sh turns the frames into docs/demo.gif
// node docs/demo/record.mjs <frames dir> --shot   one full-page screenshot, to check the layout
import { mkdirSync, writeFileSync } from "node:fs";

const [dossier, mode] = process.argv.slice(2);
mkdirSync(dossier, { recursive: true });
const cible = await (await fetch("http://127.0.0.1:9333/json/new?about:blank", { method: "PUT" })).json();
const ws = new WebSocket(cible.webSocketDebuggerUrl);
await new Promise((ok) => ws.addEventListener("open", ok));
let id = 0;
const attente = new Map(), images = [];
ws.addEventListener("message", (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && attente.has(msg.id)) { attente.get(msg.id)(msg.result); attente.delete(msg.id); }
  if (msg.method === "Page.screencastFrame") {
    images.push([msg.params.metadata.timestamp, msg.params.data]);
    envoyer("Page.screencastFrameAck", { sessionId: msg.params.sessionId });
  }
});
const envoyer = (method, params = {}) => new Promise((ok) => { attente.set(++id, ok); ws.send(JSON.stringify({ id, method, params })); });
const pause = (ms) => new Promise((ok) => setTimeout(ok, ms));
const js = async (code) => (await envoyer("Runtime.evaluate", { expression: code, awaitPromise: true, returnByValue: true })).result.value;

await envoyer("Emulation.setDeviceMetricsOverride", { width: 960, height: 667, deviceScaleFactor: 1, mobile: false });
await envoyer("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
await envoyer("Page.navigate", { url: "http://127.0.0.1:8054/?jeton=demojeton" });
await pause(2500);

if (mode === "--shot") {
  const h = await js("document.documentElement.scrollHeight");
  await envoyer("Emulation.setDeviceMetricsOverride", { width: 960, height: h, deviceScaleFactor: 1, mobile: false });
  await pause(500);
  writeFileSync(`${dossier}/page.png`, Buffer.from((await envoyer("Page.captureScreenshot")).data, "base64"));
  process.exit(0);
}

// centre d'un élément trouvé par une expression JS, après l'avoir fait défiler à l'écran
async function centre(expr) {
  return js(`(async () => { const e = ${expr}; e.scrollIntoView({ behavior: "instant", block: "center" });
    await new Promise((r) => setTimeout(r, 700)); const b = e.getBoundingClientRect(); return [b.x + b.width / 2, b.y + b.height / 2]; })()`);
}
async function survoler(expr) {
  const [x, y] = await centre(expr);
  await envoyer("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
}
async function cliquer(expr) {
  const [x, y] = await centre(expr);
  await envoyer("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
  await pause(250);
  for (const type of ["mousePressed", "mouseReleased"]) await envoyer("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
}
async function taper(texte) {
  for (const c of texte) { await envoyer("Input.insertText", { text: c }); await pause(45); }
}
const bouton = (texte, dans = "document") => `[...${dans}.querySelectorAll("button")].find((b) => b.textContent.trim().startsWith(${JSON.stringify(texte)}))`;

await envoyer("Page.startScreencast", { format: "png", everyNthFrame: 1 });
await pause(2500);  // le radar et ses échos
await survoler(`[...document.querySelectorAll("#heures .heure")].find((b) => b.ariaLabel.startsWith("03:"))`);  // le pic de la TV à 3 h
await pause(2500);
await cliquer(bouton("Living room TV", 'document.getElementById("appareils")'));
await pause(1800);
await cliquer(`document.getElementById("question")`);
await taper("What was the TV doing at 3 am?");
await envoyer("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
await js(`new Promise((ok) => { const t = Date.now(); (function f() { const r = document.getElementById("reponse").textContent;
  r && !r.endsWith("…") || Date.now() - t > 25000 ? ok() : setTimeout(f, 300); })(); })`);
await pause(4000);
await cliquer(bouton("block", 'document.getElementById("propositions")'));
await pause(1800);
await survoler(`document.getElementById("hors")`);
await pause(2500);
await cliquer(`document.getElementById("regle")`);
await taper("youtube.com 22-7 Living room TV");
await cliquer(bouton("add", 'document.getElementById("form-regle")'));
await pause(2200);
await js(`window.scrollTo({ top: 0, behavior: "instant" })`);
await pause(900);
await cliquer(`document.getElementById("pause")`);
await pause(2500);
await envoyer("Page.stopScreencast");

let fin = images.at(-1)[0] + 1, ffconcat = "ffconcat version 1.0\n";
images.forEach(([t, data], k) => {
  writeFileSync(`${dossier}/${String(k).padStart(4, "0")}.png`, Buffer.from(data, "base64"));
  ffconcat += `file ${String(k).padStart(4, "0")}.png\nduration ${((images[k + 1]?.[0] ?? fin) - t).toFixed(3)}\n`;
});
writeFileSync(`${dossier}/liste.txt`, ffconcat + `file ${String(images.length - 1).padStart(4, "0")}.png\n`);
console.log(`${images.length} frames over ${(fin - 1 - images[0][0]).toFixed(1)} s`);
process.exit(0);

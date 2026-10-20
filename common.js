// Public items live in this repo (served by GitHub Pages); personal ones in a private repo
// that is only reachable with the GitHub token, which the admin password unlocks.
const REPOS = { pub: "uzzinT/class_uz", me: "uzzinT/class_uz_private" };
const $ = id => document.getElementById(id);
const TINTS = ["#FFD9E2", "#FFEDB8", "#CDEFDD", "#D3E6FF", "#E5DAFF", "#FFDCC8"];
const tint = i => TINTS[i % TINTS.length];

// Only allow http(s) links so a bad entry can't run script via "javascript:" URLs.
function safeUrl(u) {
  try { return ["http:", "https:"].includes(new URL(u, location.href).protocol) ? u : ""; }
  catch { return ""; }
}

const normalize = d => ({ categories: d.categories || [], items: d.items || [] });

const bytesToB64 = bytes => { let bin = ""; bytes.forEach(b => bin += String.fromCharCode(b)); return btoa(bin); };
const b64ToBytes = b64 => Uint8Array.from(atob(b64.replace(/\n/g, "")), c => c.charCodeAt(0));
// GitHub's contents API speaks base64; go through bytes so Korean text survives.
const toB64 = text => bytesToB64(new TextEncoder().encode(text));
const fromB64 = b64 => new TextDecoder().decode(b64ToBytes(b64));
console.assert(fromB64(toB64("우리 반 🌱")) === "우리 반 🌱", "base64 roundtrip");

// Token lives only for this tab session; the password unlocks it again next time.
function store(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch {} }
function load(k) { try { return sessionStorage.getItem(k) || ""; } catch { return ""; } }

// auth.json is public, so the token in it is AES-GCM encrypted with a key stretched from the password.
const ITER = 600000;
async function passwordKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptToken(tok, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await passwordKey(pw, salt, ITER), new TextEncoder().encode(tok));
  return { iter: ITER, salt: bytesToB64(salt), iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(data)) };
}
async function decryptToken(auth, pw) { // throws on a wrong password
  const key = await passwordKey(pw, b64ToBytes(auth.salt), auth.iter);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(auth.iv) }, key, b64ToBytes(auth.data)));
}

// Returns the token, or throws Error("wrong") for a bad password.
async function unlock(pw) {
  const auth = await fetch("auth.json", { cache: "no-cache" }).then(r => r.json());
  try { return await decryptToken(auth, pw); }
  catch { throw new Error("wrong"); }
}

// raw=true downloads the file itself as a Blob (works up to 100MB, unlike the JSON form's 1MB).
async function gh(repo, path, opts = {}, raw = false) {
  const res = await fetch("https://api.github.com/repos/" + repo + "/contents/" + path + (raw ? "?t=" + Date.now() : ""), {
    ...opts,
    headers: { Authorization: "Bearer " + load("gh_token"), Accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json" },
  });
  if (!res.ok) throw Object.assign(new Error(res.status + " " + (await res.text())), { status: res.status });
  return raw ? res.blob() : res.json();
}

function saveBlob(blob, name) {
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}

const ext = name => (name.match(/\.([^.]+)$/)?.[1] || "").toLowerCase();

// Monkey button (Fluent 3D, MIT) next to each password box toggles showing the text.
function monkeyEyes() {
  document.querySelectorAll("input[type=password]").forEach(input => {
    const box = Object.assign(document.createElement("div"), { className: "pwbox" });
    const eye = Object.assign(document.createElement("button"), { type: "button", ariaLabel: "비밀번호 보기" });
    const face = Object.assign(document.createElement("img"), { src: "img/monkey-hide.png", alt: "" });
    eye.append(face);
    eye.setAttribute("aria-pressed", "false");
    eye.onclick = () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      face.src = show ? "img/monkey-see.png" : "img/monkey-hide.png";
      eye.setAttribute("aria-pressed", show);
    };
    input.replaceWith(box);
    box.append(input, eye);
  });
}

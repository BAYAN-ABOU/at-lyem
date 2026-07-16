/*
  auth.js — نظام تسجيل دخول / تسجيل بدون سيرفر (Static Site)
  ------------------------------------------------------------
  - يقرأ المستخدمين الأصليين من users.json (نفس الحسابات القديمة وكلمات مرورها المشفّرة bcrypt).
  - أي حساب جديد يسجّله المستخدم يتم حفظه محليًا بالمتصفح (localStorage) لأنه ما في سيرفر يخزّن الداتا بشكل دائم.
  - الجلسة (session) نفسها محفوظة بـ localStorage بدل PHP $_SESSION.
*/

const USERS_STORAGE_KEY = "site_users_extra"; // حسابات جديدة انسجلت من المتصفح
const SESSION_KEY = "site_session_user";

// يجلب المستخدمين الأصليين من users.json ثم يدمجهم مع أي حسابات جديدة محفوظة محليًا
async function loadAllUsers() {
  let baseUsers = {};
  try {
    const res = await fetch("users.json");
    if (res.ok) baseUsers = await res.json();
  } catch (e) {
    console.warn("تعذّر تحميل users.json:", e);
  }

  let extraUsers = {};
  try {
    extraUsers = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY) || "{}");
  } catch (e) {
    extraUsers = {};
  }

  return { ...baseUsers, ...extraUsers };
}

function saveExtraUser(username, hashedPassword) {
  let extraUsers = {};
  try {
    extraUsers = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY) || "{}");
  } catch (e) {
    extraUsers = {};
  }
  extraUsers[username] = hashedPassword;
  localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(extraUsers));
}

function setSession(username) {
  localStorage.setItem(SESSION_KEY, username);
}

function getSession() {
  return localStorage.getItem(SESSION_KEY);
}

function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

// يستخدم في كل صفحة محمية (كانت تتطلب session_start + isset($_SESSION['user']) بـ PHP)
function requireLogin() {
  if (!getSession()) {
    window.location.href = "login.html";
  }
}

// منطق تسجيل الدخول (يقابل login.php)
async function handleLogin(username, password) {
  const users = await loadAllUsers();
  if (!username || !password) {
    return { ok: false, error: "اسم المستخدم وكلمة المرور مطلوبان." };
  }
  const hash = users[username];
  if (!hash) {
    return { ok: false, error: "اسم المستخدم أو كلمة المرور غير صحيحة." };
  }
  const valid = dcodeIO.bcrypt.compareSync(password, hash);
  if (!valid) {
    return { ok: false, error: "اسم المستخدم أو كلمة المرور غير صحيحة." };
  }
  setSession(username);
  return { ok: true };
}

// منطق التسجيل (يقابل register.php)
async function handleRegister(username, password, passwordConfirm) {
  if (!username) return { ok: false, error: "اسم المستخدم مطلوب." };
  if (!password) return { ok: false, error: "كلمة المرور مطلوبة." };
  if (password !== passwordConfirm) return { ok: false, error: "كلمتا المرور غير متطابقتين." };

  const users = await loadAllUsers();
  if (users[username]) {
    return { ok: false, error: "اسم المستخدم هذا مستخدم بالفعل." };
  }

  const hash = dcodeIO.bcrypt.hashSync(password, 10);
  saveExtraUser(username, hash);
  setSession(username);
  return { ok: true };
}

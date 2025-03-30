// login.js

document.addEventListener('DOMContentLoaded', function () {
  const form = document.querySelector('form');
  const resultBox = document.getElementById('result');
  const logoutBtn = document.getElementById('logoutBtn');

  async function verifyToken(token) {
    try {
      const res = await fetch('/protected', {
        method: 'GET',
        headers: { 'Authorization': token }
      });
      const text = await res.text();
      if (!res.ok) throw new Error(text);
      resultBox.innerHTML = '🔐 ' + text;
    } catch (err) {
      resultBox.innerHTML = '⚠️ 驗證失敗：' + err.message;
      localStorage.removeItem('jwt_token');
    }
  }

  // Auto-verify on load if token exists
  const savedToken = localStorage.getItem('jwt_token');
  if (savedToken) {
    resultBox.innerHTML = '🔄 已發現登入資料，驗證中...';
    verifyToken(savedToken);
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
      const loginRes = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const loginData = await loginRes.json();
      if (!loginRes.ok) throw new Error(loginData.error || '登入失敗');

      const token = loginData.token;
      localStorage.setItem('jwt_token', token);
      resultBox.innerHTML = '✅ 登入成功，正在驗證身份...';
      verifyToken(token);
    } catch (err) {
      resultBox.innerHTML = '❌ 錯誤：' + err.message;
    }
  });

  logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('jwt_token');
    resultBox.innerHTML = '👋 已登出';
  });
});

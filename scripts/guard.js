(function guardAccess() {
  // ========== 配置 ==========
  var HOME_URLS = [
    'https://smartoriginbiomed.aivibeinvestment.com/'
  ];
  var HOME_URL = HOME_URLS[0];

  var VIP_USER_TYPE  = 'vip';
  var VVIP_USER_TYPE = 'vvip';
  var SESSION_KEY    = 'qgr_trendbm_ok';
  var FROM_KEY       = 'qgr_trendbm_from';
  var TOKEN_KEY      = 'qgr_trendbm_jwt_token';
  var SESSION_MAX_MS = 8 * 60 * 60 * 1000;   // 会话 8 小时

  function deny(reason) {
    console.warn('[TrendBM] Access denied:', reason);
    try {
      document.documentElement.innerHTML =
          '<head><meta charset="UTF-8"><title>访问被拒绝</title></head>'
        + '<body style="margin:0;background:#050510;color:#EF4444;'
        + 'font-family:\'Courier New\',monospace;height:100vh;'
        + 'display:flex;flex-direction:column;justify-content:center;'
        + 'align-items:center;gap:12px;letter-spacing:1px;">'
        + '<div style="font-size:42px;">⛔</div>'
        + '<div style="font-size:16px;">访问被拒绝</div>'
        + '<div style="color:#666;font-size:13px;">' + reason + '</div>'
        + '<div style="color:#555;font-size:12px;margin-top:20px;">3 秒后返回首页...</div>'
        + '</body>';
    } catch (e) {}
    try { window.stop(); } catch (e) {}
    setTimeout(function () { window.location.replace(HOME_URL); }, 3000);
  }

  function parseJwtPayload(token) {
    var parts = token.split('.');
    if (parts.length !== 3) throw new Error('Token 格式非法');
    return JSON.parse(
      decodeURIComponent(
        atob(parts[1]).split('').map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
      )
    );
  }

  // ---------- 1. 读取 URL 参数 ----------
  var params   = new URLSearchParams(location.search);
  var urlToken = params.get('token');
  var ts       = params.get('ts');
  var from     = params.get('from');

  // ---------- 2. 处理 token（主站跨域带来）----------
  if (urlToken) {
    try {
      var tmpPayload = parseJwtPayload(urlToken);
      if (!tmpPayload.exp || Date.now() > tmpPayload.exp) {
        return deny('携带的 Token 已过期');
      }
      localStorage.setItem(TOKEN_KEY, urlToken);
      console.log('[TrendBM] Token 已从 URL 写入 localStorage');
    } catch (e) {
      return deny('URL 携带的 Token 无效');
    }
  }

  var token = localStorage.getItem(TOKEN_KEY);
  if (!token) return deny('未检测到登录凭证，请从主站进入');

  var payload;
  try {
    payload = parseJwtPayload(token);
  } catch (e) {
    localStorage.removeItem(TOKEN_KEY);
    return deny('Token 解析失败');
  }

  // 过期校验
  if (!payload.exp || Date.now() > payload.exp) {
    localStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(FROM_KEY);
    return deny('登录已过期，请重新登录');
  }

  // VIP 校验
  var username = payload.user || '';
  var isAdmin  = (username === 'admin');
  var isVVIP   = (username.indexOf(VVIP_USER_TYPE) === 0);
  var isVIP    = (username.indexOf(VIP_USER_TYPE)  === 0);
  if (!isAdmin && !isVVIP && !isVIP) {
    return deny('当前账号无 VIP 权限');
  }

  // ---------- 3. 入场券 / 会话校验 ----------
  var sessionOk = false;
  try {
    var sess = sessionStorage.getItem(SESSION_KEY);
    if (sess) {
      var age = Date.now() - parseInt(sess, 10);
      if (!isNaN(age) && age < SESSION_MAX_MS) {
        sessionOk = true;
      } else {
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(FROM_KEY);
      }
    }
  } catch (e) {}

  if (!sessionOk) {
    // 没有有效会话 → 必须带 60 秒内的 ts
    if (!ts) return deny('缺少入场券，请从主站进入');
    var ticketAge = Date.now() - parseInt(ts, 10);
    if (isNaN(ticketAge) || ticketAge > 60 * 1000) {
      return deny('入场券已过期（超过 60 秒）');
    }
    try {
      sessionStorage.setItem(SESSION_KEY, String(Date.now()));
    } catch (e) {}
  }

  // ---------- 4. 写入 from ----------
  if (from) {
    try {
      sessionStorage.setItem(FROM_KEY, from);
    } catch (e) {}
  }

  // ---------- 5. 抹掉敏感参数（token + ts + from）----------
  try {
    var proxyParam = params.get('proxy');
    var keepSearch = (proxyParam === '0' || proxyParam === '1') ? '?proxy=' + proxyParam : '';
    history.replaceState({}, '', location.pathname + keepSearch);
  } catch (e) {}

  // ---------- 6. 挂载用户信息 ----------
  var fromValue = null;
  try {
    fromValue = sessionStorage.getItem(FROM_KEY);
  } catch (e) {}

  window.__TRADE_AGENT_USER__ = {
    username:  username,
    level:     isAdmin ? 'admin' : (isVVIP ? 'vvip' : 'vip'),
    grantedAt: Date.now(),
    from:      fromValue
  };

  console.log('[TrendBM] Access granted:', window.__TRADE_AGENT_USER__);
})();

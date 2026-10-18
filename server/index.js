// ============================================================
// tCloudPhone — Backend API (Express + ADB + JWT)
// Chạy: npm start  →  http://localhost:3000
// ============================================================
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-CHANGE-ME-in-production';

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ============================================================
// IN-MEMORY STORAGE
// ⚠️ Production: thay bằng PostgreSQL / MongoDB
// ============================================================
const users = new Map();   // email -> { name, email, hash, createdAt }
const devices = new Map(); // id    -> { id, ip, name, model, android, res, status, battery, ownerEmail }

// ============================================================
// HELPERS
// ============================================================
function adb(ip, cmd, timeout = 15000) {
  return new Promise((resolve) => {
    exec(`adb -s ${ip} ${cmd}`, { timeout }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        stdout: (stdout || '').trim(),
        stderr: (stderr || '').trim(),
      });
    });
  });
}

function signToken(user) {
  return jwt.sign(
    { email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

/* Middleware xác thực — bật bằng cách thêm requireAuth vào route */
function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.replace(/^Bearer\s+/i, '');
    if (!token) throw new Error('no token');
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// ============================================================
// HEALTH
// ============================================================
app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'tCloudPhone', version: '1.0.0', time: Date.now() });
});

// ============================================================
// AUTH
// ============================================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Thiếu thông tin (name, email, password)' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Mật khẩu phải ≥ 6 ký tự' });
    }
    const key = String(email).toLowerCase().trim();
    if (users.has(key)) {
      return res.status(409).json({ error: 'Email đã tồn tại' });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = { name, email: key, hash, createdAt: Date.now() };
    users.set(key, user);

    const token = signToken(user);
    res.json({ ok: true, token, user: { name, email: key } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const key = String(email || '').toLowerCase().trim();
    const user = users.get(key);
    if (!user) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng' });
    }
    const ok = await bcrypt.compare(password || '', user.hash);
    if (!ok) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng' });
    }
    const token = signToken(user);
    res.json({ ok: true, token, user: { name: user.name, email: key } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// ============================================================
// DEVICES
// (Bật requireAuth cho các route bên dưới nếu muốn bảo vệ)
// ============================================================
app.get('/api/devices', (req, res) => {
  res.json([...devices.values()]);
});

app.post('/api/devices', async (req, res) => {
  try {
    const { id, ip, name, model, android, res: resolution } = req.body || {};
    if (!id || !ip) {
      return res.status(400).json({ error: 'Thiếu id hoặc ip' });
    }

    const device = {
      id,
      ip,
      name: name || 'Thiết bị mới',
      model: model || 'Unknown',
      android: android || 'Android 13',
      res: resolution || '1080x2400',
      status: 'booting',
      battery: 100,
      ownerEmail: req.user?.email || null,
      createdAt: Date.now(),
    };
    devices.set(id, device);

    // Thử kết nối ADB ngầm
    adb(ip, 'connect ' + ip).then((r) => {
      const d = devices.get(id);
      if (d) d.status = r.ok ? 'online' : 'offline';
    });

    res.json({ ok: true, device });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/devices/:id', (req, res) => {
  const d = devices.get(req.params.id);
  if (d) exec(`adb disconnect ${d.ip}`);
  devices.delete(req.params.id);
  res.json({ ok: true });
});

// ============================================================
// DEVICE COMMANDS
// ============================================================
app.post('/api/devices/:id/cmd', async (req, res) => {
  const d = devices.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'Không tìm thấy thiết bị' });

  const map = {
    home:      'shell input keyevent KEYCODE_HOME',
    back:      'shell input keyevent KEYCODE_BACK',
    recents:   'shell input keyevent KEYCODE_APP_SWITCH',
    power:     'shell input keyevent KEYCODE_POWER',
    volup:     'shell input keyevent KEYCODE_VOLUME_UP',
    voldown:   'shell input keyevent KEYCODE_VOLUME_DOWN',
    screenshot:'exec-out screencap -p',
    rotate:    'shell settings put system accelerometer_rotation 0',
    reboot:    'reboot',
  };
  const cmd = map[req.body?.action];
  if (!cmd) return res.status(400).json({ error: 'Hành động không hợp lệ' });

  const result = await adb(d.ip, cmd);
  res.json(result);
});

app.post('/api/devices/:id/adb', async (req, res) => {
  const d = devices.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'Không tìm thấy thiết bị' });

  const cmd = req.body?.cmd;
  if (!cmd || typeof cmd !== 'string') {
    return res.status(400).json({ error: 'Thiếu cmd' });
  }
  const result = await adb(d.ip, cmd);
  res.json(result);
});

// ============================================================
// OPTIONAL: một số tiện ích ADB mở rộng
// ============================================================
app.post('/api/devices/:id/install', async (req, res) => {
  const d = devices.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'Không tìm thấy thiết bị' });
  const { apkUrl } = req.body || {};
  if (!apkUrl) return res.status(400).json({ error: 'Thiếu apkUrl' });
  const result = await adb(d.ip, `install -r "${apkUrl}"`, 120000);
  res.json(result);
});

app.get('/api/devices/:id/info', async (req, res) => {
  const d = devices.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'Không tìm thấy thiết bị' });
  const [model, version, battery] = await Promise.all([
    adb(d.ip, 'shell getprop ro.product.model'),
    adb(d.ip, 'shell getprop ro.build.version.release'),
    adb(d.ip, 'shell dumpsys battery | grep level'),
  ]);
  res.json({
    model: model.stdout,
    android: version.stdout,
    battery: battery.stdout,
  });
});

// ============================================================
// 404 + ERROR HANDLER
// ============================================================
app.use((req, res) => res.status(404).json({ error: 'Endpoint không tồn tại' }));
app.use((err, req, res, next) => {
  console.error('💥', err);
  res.status(500).json({ error: err.message });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log('==============================================');
  console.log(`✅ tCloudPhone API đang chạy tại port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}/api/health`);
  console.log('==============================================');
  if (JWT_SECRET === 'dev-secret-CHANGE-ME-in-production') {
    console.warn('⚠️  JWT_SECRET đang dùng giá trị mặc định — đổi trước khi deploy!');
  }
});

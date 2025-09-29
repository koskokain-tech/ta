require('dotenv').config(); // .env 파일 로드

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// =======================
// 미들웨어
// =======================
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());

// =======================
// MongoDB 연결
// =======================
mongoose.connect('mongodb://localhost:27017/discord_clone')
  .then(() => console.log('✅ MongoDB 연결 성공'))
  .catch(err => console.error('❌ MongoDB 연결 실패:', err));

// =======================
// User 스키마
// =======================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  nickname: { type: String, required: true },
  verified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  refreshToken: String
});

const User = mongoose.model('User', userSchema);

// =======================
// Nodemailer 세팅
// =======================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const JWT_SECRET = process.env.JWT_SECRET;

// =======================
// Auth API
// =======================

// 회원가입
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, nickname } = req.body;
    if (!email || !password || !nickname) {
      return res.status(400).json({ error: '모든 필드를 입력해주세요.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: '이미 존재하는 이메일입니다.' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1d' });

    const user = new User({
      email,
      password: hashedPassword,
      nickname,
      verificationToken
    });
    await user.save();

    await transporter.sendMail({
      to: email,
      subject: '이메일 인증',
      html: `<a href="http://localhost:3000/verify?token=${verificationToken}">이메일 인증하기</a>`
    });

    res.json({ message: '인증 이메일이 전송되었습니다.' });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 로그인
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !user.verified) {
      return res.status(400).json({ error: '이메일 또는 비밀번호가 잘못되었습니다.' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ error: '이메일 또는 비밀번호가 잘못되었습니다.' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    user.refreshToken = refreshToken;
    await user.save();

    res.json({ token, refreshToken, nickname: user.nickname });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 이메일 인증
app.get('/verify', async (req, res) => {
  const { token } = req.query;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ email: decoded.email, verificationToken: token });
    if (!user) return res.status(400).send('유효하지 않은 토큰입니다.');

    user.verified = true;
    user.verificationToken = undefined;
    await user.save();

    res.send('이메일 인증이 완료되었습니다.');
  } catch (e) {
    res.status(400).send('토큰이 만료되었거나 유효하지 않습니다.');
  }
});

// 비밀번호 찾기
app.post('/api/forgot', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: '존재하지 않는 이메일입니다.' });

    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000;
    await user.save();

    await transporter.sendMail({
      to: email,
      subject: '비밀번호 재설정',
      html: `<a href="http://localhost:3000/reset-password?token=${resetToken}">비밀번호 변경하기</a>`
    });

    res.json({ message: '비밀번호 재설정 링크가 이메일로 전송되었습니다.' });
  } catch (err) {
    console.error('forgot error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 비밀번호 재설정
app.post('/api/reset', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ error: '토큰이 만료되었거나 유효하지 않습니다.' });

    user.password = await bcrypt.hash(newPassword, 12);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: '비밀번호가 변경되었습니다.' });
  } catch (err) {
    console.error('reset error:', err);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 토큰 갱신
app.post('/api/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: '리프레시 토큰이 필요합니다.' });

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: '유효하지 않은 리프레시 토큰입니다.' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ token });
  } catch (e) {
    res.status(403).json({ error: '토큰이 만료되었습니다.' });
  }
});

// =======================
// 정적 파일
// =======================
app.use(express.static('public'));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =======================
// Socket.io (실시간 채팅)
// =======================
const users = new Map();
const lastMsgAt = new Map();

function escapeHTML(str = "") {
  return str.replace(/[&<>"']/g, s => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[s]));
}

function broadcastUsers() {
  io.emit('users', Array.from(users.values()));
}

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return next(new Error('User not found'));
    socket.userId = user._id;
    socket.nickname = user.nickname;
    next();
  } catch (e) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  users.set(socket.userId, socket.nickname);
  broadcastUsers();

  socket.on('chat', (msgRaw) => {
    const now = Date.now();
    const prev = lastMsgAt.get(socket.userId) || 0;
    if (now - prev < 300) return; // 스팸 방지

    lastMsgAt.set(socket.userId, now);

    const text = escapeHTML((msgRaw || '').slice(0, 500));
    if (!text) return;

    io.emit('message', {
      user: socket.nickname,
      text,
      at: new Date().toISOString()
    });
  });

  socket.on('disconnect', () => {
    users.delete(socket.userId);
    lastMsgAt.delete(socket.userId);
    broadcastUsers();
  });
});

// =======================
// 서버 실행
// =======================
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`🚀 서버 가동: http://localhost:${PORT}`);
});

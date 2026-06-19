import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'
import { v4 as uuidv4 } from 'uuid'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SECRET = 'motiv-rewards-secret-2024'
const ADMIN_SECRET = 'motiv-admin-2024'
const ADMIN_PASSWORD = 'motiv2024'

const adapter = new JSONFile(path.join(__dirname, 'db.json'))
const db = new Low(adapter, { users: [], activity: [] })
await db.read()

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname)))

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'No token' })
  try { req.user = jwt.verify(token, SECRET); next() }
  catch { res.status(401).json({ error: 'Invalid token' }) }
}

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'No token' })
  try {
    const d = jwt.verify(token, ADMIN_SECRET)
    if (!d.isAdmin) return res.status(403).json({ error: 'Not admin' })
    req.admin = d; next()
  } catch { res.status(401).json({ error: 'Invalid token' }) }
}

function sanitize(u) {
  const { password, ...rest } = u; return rest
}

function checkMilestones(user) {
  const milestones = [1,5,10,25,50,100]
  const newlyEarned = []
  for (const m of milestones) {
    if (user.totalClasses >= m && !user.earnedMilestones.includes(m)) {
      user.earnedMilestones.push(m)
      newlyEarned.push(m)
    }
  }
  return newlyEarned
}

// ── SIGNUP ──
app.post('/api/signup', async (req, res) => {
  await db.read()
  const { name, email, phone, password, birthday } = req.body
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
  if (db.data.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'Email already registered' })
  const hashed = await bcrypt.hash(password, 10)
  const user = {
    id: uuidv4(), name, email: email.toLowerCase(),
    phone: phone || '', password: hashed,
    birthday: birthday || '',
    points: 0, totalClasses: 0, totalReferrals: 0,
    currentStreak: 0, longestStreak: 0,
    lastClassWeek: null,
    earnedMilestones: [],
    referralCode: name.toUpperCase().replace(/\s+/g,'').slice(0,6) + Math.floor(Math.random()*100),
    joinedAt: new Date().toISOString(),
    moodHistory: []
  }
  db.data.users.push(user)
  await db.write()
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
  res.json({ token, user: sanitize(user) })
})

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  await db.read()
  const { email, password } = req.body
  const user = db.data.users.find(u => u.email === email.toLowerCase())
  if (!user) return res.status(401).json({ error: 'No account with that email' })
  if (!await bcrypt.compare(password, user.password))
    return res.status(401).json({ error: 'Wrong password' })
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
  res.json({ token, user: sanitize(user) })
})

// ── ME ──
app.get('/api/me', auth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id === req.user.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const activity = db.data.activity
    .filter(a => a.userId === user.id)
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 30)
  res.json({ user: sanitize(user), activity })
})

// ── LOG MOOD ──
app.post('/api/mood', auth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id === req.user.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const { score, note } = req.body
  user.moodHistory = user.moodHistory || []
  user.moodHistory.push({ score, note: note||'', date: new Date().toISOString() })
  await db.write()
  res.json({ success: true })
})

// ── ADMIN LOGIN ──
app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD)
    return res.status(401).json({ error: 'Wrong password' })
  const token = jwt.sign({ isAdmin: true }, ADMIN_SECRET, { expiresIn: '8h' })
  res.json({ token })
})

// ── ADMIN MEMBERS ──
app.get('/api/admin/members', adminAuth, async (req, res) => {
  await db.read()
  const q = (req.query.q||'').toLowerCase()
  const members = db.data.users
    .filter(u => !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q) || u.phone.includes(q))
    .map(sanitize)
    .sort((a,b) => b.points - a.points)
  res.json(members)
})

app.get('/api/admin/members/:id', adminAuth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id === req.params.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const activity = db.data.activity
    .filter(a => a.userId === user.id)
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt))
  res.json({ user: sanitize(user), activity })
})

// ── ADMIN AWARD CLASS ──
app.post('/api/admin/award', adminAuth, async (req, res) => {
  await db.read()
  const { userId, classType, points, instructor } = req.body
  const user = db.data.users.find(u => u.id === userId)
  if (!user) return res.status(404).json({ error: 'Not found' })

  user.points += points
  user.totalClasses += 1
  user.moodHistory = user.moodHistory || []
  user.earnedMilestones = user.earnedMilestones || []

  // streak logic
  const now = new Date()
  const weekNum = Math.floor(now.getTime() / (7*24*60*60*1000))
  if (user.lastClassWeek === weekNum - 1) {
    user.currentStreak = (user.currentStreak || 0) + 1
  } else if (user.lastClassWeek === weekNum) {
    // already attended this week, no change
  } else {
    user.currentStreak = 1
  }
  user.lastClassWeek = weekNum
  user.longestStreak = Math.max(user.longestStreak || 0, user.currentStreak)

  const newMilestones = checkMilestones(user)

  // birthday bonus check
  let birthdayBonus = false
  if (user.birthday) {
    const bMonth = new Date(user.birthday).getMonth()
    if (now.getMonth() === bMonth) {
      user.points += points // double points
      birthdayBonus = true
    }
  }

  db.data.activity.push({
    id: uuidv4(), userId, type: 'class',
    label: classType + (instructor ? ' · ' + instructor : ''),
    points: birthdayBonus ? points * 2 : points,
    instructor: instructor || '',
    awardedBy: 'staff',
    createdAt: new Date().toISOString()
  })

  await db.write()
  res.json({ user: sanitize(user), newMilestones, birthdayBonus })
})

// ── ADMIN REDEEM ──
app.post('/api/admin/redeem', adminAuth, async (req, res) => {
  await db.read()
  const { userId, rewardName, pointsCost } = req.body
  const user = db.data.users.find(u => u.id === userId)
  if (!user) return res.status(404).json({ error: 'Not found' })
  if (user.points < pointsCost) return res.status(400).json({ error: 'Not enough points' })
  user.points -= pointsCost
  db.data.activity.push({
    id: uuidv4(), userId, type: 'redeem',
    label: 'Redeemed: ' + rewardName,
    points: -pointsCost, awardedBy: 'staff',
    createdAt: new Date().toISOString()
  })
  await db.write()
  res.json({ user: sanitize(user) })
})

// ── ADMIN REFERRAL ──
app.post('/api/admin/referral', adminAuth, async (req, res) => {
  await db.read()
  const { userId, friendName } = req.body
  const user = db.data.users.find(u => u.id === userId)
  if (!user) return res.status(404).json({ error: 'Not found' })
  user.points += 100
  user.totalReferrals += 1
  db.data.activity.push({
    id: uuidv4(), userId, type: 'referral',
    label: 'Referral bonus — ' + friendName,
    points: 100, awardedBy: 'staff',
    createdAt: new Date().toISOString()
  })
  await db.write()
  res.json({ user: sanitize(user) })
})

// ── ADMIN STATS ──
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  await db.read()
  const users = db.data.users
  const activity = db.data.activity
  const totalMembers = users.length
  const totalClasses = activity.filter(a => a.type === 'class').length
  const totalReferrals = activity.filter(a => a.type === 'referral').length
  const activeThisWeek = users.filter(u => {
    const weekNum = Math.floor(Date.now() / (7*24*60*60*1000))
    return u.lastClassWeek === weekNum
  }).length
  res.json({ totalMembers, totalClasses, totalReferrals, activeThisWeek })
})

app.listen(3000, () => console.log('✦ Motiv Rewards running → http://localhost:3000'))

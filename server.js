import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import { createClient } from '@libsql/client'
import { v4 as uuidv4 } from 'uuid'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SECRET = 'motiv-rewards-secret-2024'
const ADMIN_SECRET = 'motiv-admin-2024'
const ADMIN_PASSWORD = 'motiv2024'

const db = createClient({
  url: process.env.TURSO_URL || 'libsql://motiv-rewards-craner16.aws-us-east-2.turso.io',
  authToken: process.env.TURSO_TOKEN
})

// Setup tables
await db.executeMultiple(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, phone TEXT,
    password TEXT, birthday TEXT, points INTEGER DEFAULT 0,
    totalClasses INTEGER DEFAULT 0, totalReferrals INTEGER DEFAULT 0,
    currentStreak INTEGER DEFAULT 0, longestStreak INTEGER DEFAULT 0,
    lastClassWeek INTEGER, lastClassDate TEXT, earnedMilestones TEXT DEFAULT '[]',
    friends TEXT DEFAULT '[]', referralCode TEXT, joinedAt TEXT,
    moodHistory TEXT DEFAULT '[]', classDates TEXT DEFAULT '[]'
  );
  CREATE TABLE IF NOT EXISTS activity (
    id TEXT PRIMARY KEY, userId TEXT, type TEXT, label TEXT,
    points INTEGER, instructor TEXT, awardedBy TEXT, createdAt TEXT
  );
  CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY, userId TEXT, userName TEXT, caption TEXT,
    imageData TEXT, visibility TEXT, milestoneN INTEGER, classType TEXT,
    userStats TEXT, likes TEXT DEFAULT '[]', comments TEXT DEFAULT '[]',
    createdAt TEXT
  );
  CREATE TABLE IF NOT EXISTS friend_requests (
    id TEXT PRIMARY KEY, fromId TEXT, toId TEXT, status TEXT, createdAt TEXT
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY, userId TEXT, type TEXT, message TEXT,
    fromName TEXT, read INTEGER DEFAULT 0, createdAt TEXT
  );
`)

const app = express()
app.use(cors())
app.use(express.json({ limit: '10mb' }))
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

function parseUser(row) {
  if (!row) return null
  return {
    ...row,
    points: Number(row.points), totalClasses: Number(row.totalClasses),
    totalReferrals: Number(row.totalReferrals), currentStreak: Number(row.currentStreak),
    longestStreak: Number(row.longestStreak),
    earnedMilestones: JSON.parse(row.earnedMilestones || '[]'),
    friends: JSON.parse(row.friends || '[]'),
    moodHistory: JSON.parse(row.moodHistory || '[]'),
    classDates: JSON.parse(row.classDates || '[]')
  }
}

function sanitize(u) {
  if (!u) return null
  const { password, ...rest } = u; return rest
}

async function getUser(id) {
  const r = await db.execute({ sql: 'SELECT * FROM users WHERE id=?', args: [id] })
  return parseUser(r.rows[0])
}

async function getUserByEmail(email) {
  const r = await db.execute({ sql: 'SELECT * FROM users WHERE email=?', args: [email.toLowerCase()] })
  return parseUser(r.rows[0])
}

async function saveUser(user) {
  await db.execute({
    sql: `INSERT OR REPLACE INTO users (id,name,email,phone,password,birthday,points,totalClasses,
          totalReferrals,currentStreak,longestStreak,lastClassWeek,lastClassDate,earnedMilestones,
          friends,referralCode,joinedAt,moodHistory,classDates)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    args: [user.id, user.name, user.email, user.phone||'', user.password, user.birthday||'',
           user.points, user.totalClasses, user.totalReferrals, user.currentStreak,
           user.longestStreak, user.lastClassWeek||null, user.lastClassDate||null,
           JSON.stringify(user.earnedMilestones||[]), JSON.stringify(user.friends||[]),
           user.referralCode, user.joinedAt, JSON.stringify(user.moodHistory||[]),
           JSON.stringify(user.classDates||[])]
  })
}

async function addNotification(userId, type, message, fromName) {
  await db.execute({
    sql: 'INSERT INTO notifications (id,userId,type,message,fromName,read,createdAt) VALUES (?,?,?,?,?,0,?)',
    args: [uuidv4(), userId, type, message, fromName||'', new Date().toISOString()]
  })
}

function checkMilestones(user) {
  const milestones = [1,5,10,25,50,100]
  const newlyEarned = []
  for (const m of milestones) {
    if (user.totalClasses >= m && !user.earnedMilestones.includes(m)) {
      user.earnedMilestones.push(m); newlyEarned.push(m)
    }
  }
  return newlyEarned
}

// ── SIGNUP ──
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, phone, password, birthday } = req.body
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
    const existing = await getUserByEmail(email)
    if (existing) return res.status(409).json({ error: 'Email already registered' })
    const hashed = await bcrypt.hash(password, 10)
    const user = {
      id: uuidv4(), name, email: email.toLowerCase(), phone: phone||'', password: hashed,
      birthday: birthday||'', points: 0, totalClasses: 0, totalReferrals: 0,
      currentStreak: 0, longestStreak: 0, lastClassWeek: null, lastClassDate: null,
      earnedMilestones: [], friends: [],
      referralCode: name.toUpperCase().replace(/\s+/g,'').slice(0,6)+Math.floor(Math.random()*100),
      joinedAt: new Date().toISOString(), moodHistory: [], classDates: []
    }
    await saveUser(user)
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
    res.json({ token, user: sanitize(user) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const user = await getUserByEmail(email)
    if (!user) return res.status(401).json({ error: 'No account with that email' })
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Wrong password' })
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
    res.json({ token, user: sanitize(user) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── ME ──
app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const acts = await db.execute({ sql: 'SELECT * FROM activity WHERE userId=? ORDER BY createdAt DESC LIMIT 30', args: [user.id] })
    const reqs = await db.execute({ sql: 'SELECT * FROM friend_requests WHERE toId=? AND status=?', args: [user.id, 'pending'] })
    const pendingRequests = await Promise.all(reqs.rows.map(async r => {
      const from = await getUser(r.fromId)
      return { id: r.id, from: from ? { id: from.id, name: from.name } : null }
    }))
    const unreadRes = await db.execute({ sql: 'SELECT COUNT(*) as c FROM notifications WHERE userId=? AND read=0', args: [user.id] })
    res.json({ user: sanitize(user), activity: acts.rows, pendingRequests, unreadNotifs: Number(unreadRes.rows[0].c) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── NOTIFICATIONS ──
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT * FROM notifications WHERE userId=? ORDER BY createdAt DESC LIMIT 20', args: [req.user.id] })
    res.json(r.rows.map(n => ({ ...n, read: Boolean(n.read) })))
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/notifications/read', auth, async (req, res) => {
  try {
    await db.execute({ sql: 'UPDATE notifications SET read=1 WHERE userId=?', args: [req.user.id] })
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── MOOD ──
app.post('/api/mood', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    user.moodHistory.push({ score: req.body.score, note: req.body.note||'', date: new Date().toISOString() })
    await saveUser(user)
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── POSTS ──
app.post('/api/posts', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const { caption, imageData, visibility, milestoneN, classType } = req.body
    const post = {
      id: uuidv4(), userId: req.user.id, userName: user.name,
      caption: caption||'', imageData: imageData||null,
      visibility: visibility||'friends', milestoneN: milestoneN||null, classType: classType||null,
      userStats: JSON.stringify({ totalClasses: user.totalClasses, currentStreak: user.currentStreak||0, points: user.points }),
      likes: '[]', comments: '[]', createdAt: new Date().toISOString()
    }
    await db.execute({
      sql: 'INSERT INTO posts (id,userId,userName,caption,imageData,visibility,milestoneN,classType,userStats,likes,comments,createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
      args: [post.id, post.userId, post.userName, post.caption, post.imageData, post.visibility, post.milestoneN, post.classType, post.userStats, post.likes, post.comments, post.createdAt]
    })
    for (const fid of user.friends) {
      await addNotification(fid, 'post', `${user.name} just posted a new class update ✦`, user.name)
    }
    res.json({ post: { ...post, userStats: JSON.parse(post.userStats), likes: [], comments: [] } })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/posts/feed', auth, async (req, res) => {
  try {
    const user = await getUser(req.user.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const friends = user.friends
    let rows = []
    if (friends.length > 0) {
      const placeholders = friends.map(() => '?').join(',')
      const r = await db.execute({
        sql: `SELECT * FROM posts WHERE (userId=? AND 1=1) OR (userId IN (${placeholders}) AND visibility='friends') ORDER BY createdAt DESC LIMIT 30`,
        args: [req.user.id, ...friends]
      })
      rows = r.rows
    } else {
      const r = await db.execute({ sql: 'SELECT * FROM posts WHERE userId=? ORDER BY createdAt DESC LIMIT 30', args: [req.user.id] })
      rows = r.rows
    }
    res.json(rows.map(p => ({ ...p, userStats: JSON.parse(p.userStats||'{}'), likes: JSON.parse(p.likes||'[]'), comments: JSON.parse(p.comments||'[]') })))
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/posts/:id/like', auth, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT * FROM posts WHERE id=?', args: [req.params.id] })
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' })
    const post = r.rows[0]
    const likes = JSON.parse(post.likes||'[]')
    const idx = likes.indexOf(req.user.id)
    if (idx > -1) likes.splice(idx,1)
    else {
      likes.push(req.user.id)
      if (post.userId !== req.user.id) {
        const liker = await getUser(req.user.id)
        await addNotification(post.userId, 'like', `${liker?.name||'Someone'} liked your post ❤️`, liker?.name)
      }
    }
    await db.execute({ sql: 'UPDATE posts SET likes=? WHERE id=?', args: [JSON.stringify(likes), req.params.id] })
    res.json({ likes: likes.length, liked: likes.includes(req.user.id) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/posts/:id/comment', auth, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT * FROM posts WHERE id=?', args: [req.params.id] })
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' })
    const post = r.rows[0]
    const user = await getUser(req.user.id)
    const comments = JSON.parse(post.comments||'[]')
    const comment = { id: uuidv4(), userId: req.user.id, userName: user?.name||'', text: req.body.text, createdAt: new Date().toISOString() }
    comments.push(comment)
    await db.execute({ sql: 'UPDATE posts SET comments=? WHERE id=?', args: [JSON.stringify(comments), req.params.id] })
    if (post.userId !== req.user.id) {
      await addNotification(post.userId, 'comment', `${user?.name||'Someone'} commented: "${req.body.text.slice(0,40)}"`, user?.name)
    }
    res.json({ comment })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── FRIENDS ──
app.post('/api/friends/request', auth, async (req, res) => {
  try {
    const toUser = await getUserByEmail(req.body.toEmail)
    if (!toUser) return res.status(404).json({ error: 'No user with that email' })
    if (toUser.id === req.user.id) return res.status(400).json({ error: "Can't add yourself" })
    const me = await getUser(req.user.id)
    if ((me.friends||[]).includes(toUser.id)) return res.status(400).json({ error: 'Already friends' })
    const existing = await db.execute({ sql: 'SELECT * FROM friend_requests WHERE fromId=? AND toId=? AND status=?', args: [req.user.id, toUser.id, 'pending'] })
    if (existing.rows.length) return res.status(400).json({ error: 'Request already sent' })
    await db.execute({ sql: 'INSERT INTO friend_requests (id,fromId,toId,status,createdAt) VALUES (?,?,?,?,?)', args: [uuidv4(), req.user.id, toUser.id, 'pending', new Date().toISOString()] })
    await addNotification(toUser.id, 'friend_request', `${me.name} wants to be friends on MōTIV`, me.name)
    res.json({ success: true, toName: toUser.name })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/friends/respond', auth, async (req, res) => {
  try {
    const { requestId, accept } = req.body
    const r = await db.execute({ sql: 'SELECT * FROM friend_requests WHERE id=? AND toId=?', args: [requestId, req.user.id] })
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' })
    const req2 = r.rows[0]
    await db.execute({ sql: 'UPDATE friend_requests SET status=? WHERE id=?', args: [accept?'accepted':'declined', requestId] })
    if (accept) {
      const me = await getUser(req.user.id)
      const them = await getUser(req2.fromId)
      if (me && them) {
        me.friends = [...new Set([...me.friends, them.id])]
        them.friends = [...new Set([...them.friends, me.id])]
        await saveUser(me); await saveUser(them)
        await addNotification(them.id, 'friend_accept', `${me.name} accepted your friend request 🎉`, me.name)
      }
    }
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/friends', auth, async (req, res) => {
  try {
    const me = await getUser(req.user.id)
    if (!me) return res.status(404).json({ error: 'Not found' })
    const friends = await Promise.all((me.friends||[]).map(async fid => {
      const f = await getUser(fid)
      if (!f) return null
      const daysSinceClass = f.lastClassDate ? Math.floor((Date.now()-new Date(f.lastClassDate))/(1000*60*60*24)) : null
      return { id:f.id, name:f.name, points:f.points, totalClasses:f.totalClasses, currentStreak:f.currentStreak||0, longestStreak:f.longestStreak||0, earnedMilestones:f.earnedMilestones||[], daysSinceClass }
    }))
    res.json(friends.filter(Boolean))
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/profile/:id', auth, async (req, res) => {
  try {
    const me = await getUser(req.user.id)
    const user = await getUser(req.params.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const isFriend = (me?.friends||[]).includes(user.id) || user.id===req.user.id
    const postsRes = await db.execute({ sql: 'SELECT * FROM posts WHERE userId=? ORDER BY createdAt DESC LIMIT 12', args: [user.id] })
    const posts = postsRes.rows.filter(p => isFriend || p.userId===req.user.id)
      .map(p => ({ ...p, userStats: JSON.parse(p.userStats||'{}'), likes: JSON.parse(p.likes||'[]'), comments: JSON.parse(p.comments||'[]') }))
    res.json({ user: sanitize(user), posts, isFriend })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

// ── ADMIN ──
app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' })
  const token = jwt.sign({ isAdmin: true }, ADMIN_SECRET, { expiresIn: '8h' })
  res.json({ token })
})

app.get('/api/admin/members', adminAuth, async (req, res) => {
  try {
    const q = (req.query.q||'').toLowerCase()
    const r = await db.execute({ sql: 'SELECT * FROM users ORDER BY points DESC', args: [] })
    let members = r.rows.map(parseUser).map(sanitize)
    if (q) members = members.filter(u => u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q) || (u.phone||'').includes(q))
    res.json(members)
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/admin/members/:id', adminAuth, async (req, res) => {
  try {
    const user = await getUser(req.params.id)
    if (!user) return res.status(404).json({ error: 'Not found' })
    const acts = await db.execute({ sql: 'SELECT * FROM activity WHERE userId=? ORDER BY createdAt DESC', args: [user.id] })
    res.json({ user: sanitize(user), activity: acts.rows })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/admin/award', adminAuth, async (req, res) => {
  try {
    const { userId, classType, points, instructor } = req.body
    const user = await getUser(userId)
    if (!user) return res.status(404).json({ error: 'Not found' })
    user.points += points; user.totalClasses += 1
    const now = new Date()
    const todayStr = now.toISOString().split('T')[0]
    if (!user.classDates.includes(todayStr)) user.classDates.push(todayStr)
    user.lastClassDate = now.toISOString()
    const weekNum = Math.floor(now.getTime()/(7*24*60*60*1000))
    if (user.lastClassWeek === weekNum-1) user.currentStreak = (user.currentStreak||0)+1
    else if (user.lastClassWeek !== weekNum) user.currentStreak = 1
    user.lastClassWeek = weekNum
    user.longestStreak = Math.max(user.longestStreak||0, user.currentStreak)
    const newMilestones = checkMilestones(user)
    let birthdayBonus = false
    if (user.birthday && new Date(user.birthday).getMonth()===now.getMonth()) {
      user.points += points; birthdayBonus = true
    }
    const awardedPts = birthdayBonus ? points*2 : points
    await saveUser(user)
    await db.execute({
      sql: 'INSERT INTO activity (id,userId,type,label,points,instructor,awardedBy,createdAt) VALUES (?,?,?,?,?,?,?,?)',
      args: [uuidv4(), userId, 'class', classType+(instructor?' · '+instructor:''), awardedPts, instructor||'', 'staff', now.toISOString()]
    })
    await addNotification(userId, 'points', `${awardedPts} points added for ${classType}${birthdayBonus?' 🎂':''}`, 'Motiv Staff')
    if (newMilestones.length > 0) {
      await addNotification(userId, 'milestone', `🎉 You hit ${newMilestones[0]} classes! New milestone unlocked.`, 'Motiv')
      for (const fid of user.friends) {
        await addNotification(fid, 'friend_milestone', `${user.name} just hit ${newMilestones[0]} classes! 🎉`, user.name)
      }
    }
    res.json({ user: sanitize(user), newMilestones, birthdayBonus })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/admin/redeem', adminAuth, async (req, res) => {
  try {
    const { userId, rewardName, pointsCost } = req.body
    const user = await getUser(userId)
    if (!user) return res.status(404).json({ error: 'Not found' })
    if (user.points < pointsCost) return res.status(400).json({ error: 'Not enough points' })
    user.points -= pointsCost
    await saveUser(user)
    await db.execute({ sql: 'INSERT INTO activity (id,userId,type,label,points,instructor,awardedBy,createdAt) VALUES (?,?,?,?,?,?,?,?)', args: [uuidv4(), userId, 'redeem', 'Redeemed: '+rewardName, -pointsCost, '', 'staff', new Date().toISOString()] })
    res.json({ user: sanitize(user) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/admin/referral', adminAuth, async (req, res) => {
  try {
    const { userId, friendName } = req.body
    const user = await getUser(userId)
    if (!user) return res.status(404).json({ error: 'Not found' })
    user.points += 100; user.totalReferrals += 1
    await saveUser(user)
    await db.execute({ sql: 'INSERT INTO activity (id,userId,type,label,points,instructor,awardedBy,createdAt) VALUES (?,?,?,?,?,?,?,?)', args: [uuidv4(), userId, 'referral', 'Referral bonus — '+friendName, 100, '', 'staff', new Date().toISOString()] })
    await addNotification(userId, 'referral', `Referral bonus added for ${friendName} — +100 pts ✦`, 'Motiv Staff')
    res.json({ user: sanitize(user) })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.post('/api/admin/message', adminAuth, async (req, res) => {
  try {
    const { userId, message } = req.body
    await addNotification(userId, 'message', message, 'Motiv Staff')
    res.json({ success: true })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const weekNum = Math.floor(Date.now()/(7*24*60*60*1000))
    const twoWeeksAgo = new Date(Date.now()-14*24*60*60*1000).toISOString()
    const [mCount, cCount, rCount, aCount, pCount, wbRes] = await Promise.all([
      db.execute('SELECT COUNT(*) as c FROM users'),
      db.execute('SELECT COUNT(*) as c FROM activity WHERE type=?', ['class']),
      db.execute('SELECT COUNT(*) as c FROM activity WHERE type=?', ['referral']),
      db.execute({ sql: 'SELECT COUNT(*) as c FROM users WHERE lastClassWeek=?', args: [weekNum] }),
      db.execute('SELECT COUNT(*) as c FROM posts'),
      db.execute({ sql: 'SELECT id,name,email,lastClassDate,totalClasses,currentStreak FROM users WHERE totalClasses>0 AND (lastClassDate IS NULL OR lastClassDate<?)', args: [twoWeeksAgo] })
    ])
    res.json({
      totalMembers: Number(mCount.rows[0].c),
      totalClasses: Number(cCount.rows[0].c),
      totalReferrals: Number(rCount.rows[0].c),
      activeThisWeek: Number(aCount.rows[0].c),
      totalPosts: Number(pCount.rows[0].c),
      winBack: wbRes.rows
    })
  } catch(e) { res.status(500).json({ error: e.message }) }
})

app.listen(3000, () => console.log('✦ Motiv running → http://localhost:3000'))

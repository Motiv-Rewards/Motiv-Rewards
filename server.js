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
const db = new Low(adapter, { users: [], activity: [], posts: [], friendRequests: [], notifications: [] })
await db.read()
if (!db.data.posts) db.data.posts = []
if (!db.data.friendRequests) db.data.friendRequests = []
if (!db.data.notifications) db.data.notifications = []
await db.write()

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

function sanitize(u) { const { password, ...rest } = u; return rest }

function checkMilestones(user) {
  const milestones = [1,5,10,25,50,100]
  const newlyEarned = []
  user.earnedMilestones = user.earnedMilestones || []
  for (const m of milestones) {
    if (user.totalClasses >= m && !user.earnedMilestones.includes(m)) {
      user.earnedMilestones.push(m); newlyEarned.push(m)
    }
  }
  return newlyEarned
}

function addNotification(userId, type, message, fromName) {
  db.data.notifications = db.data.notifications || []
  db.data.notifications.unshift({
    id: uuidv4(), userId, type, message,
    fromName: fromName || '', read: false,
    createdAt: new Date().toISOString()
  })
  if (db.data.notifications.length > 1000)
    db.data.notifications = db.data.notifications.slice(0, 1000)
}

// ── AUTH ──
app.post('/api/signup', async (req, res) => {
  await db.read()
  const { name, email, phone, password, birthday } = req.body
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
  if (db.data.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'Email already registered' })
  const hashed = await bcrypt.hash(password, 10)
  const user = {
    id: uuidv4(), name, email: email.toLowerCase(), phone: phone||'', password: hashed,
    birthday: birthday||'', points: 0, totalClasses: 0, totalReferrals: 0,
    currentStreak: 0, longestStreak: 0, lastClassWeek: null, lastClassDate: null,
    earnedMilestones: [], friends: [],
    referralCode: name.toUpperCase().replace(/\s+/g,'').slice(0,6)+Math.floor(Math.random()*100),
    joinedAt: new Date().toISOString(), moodHistory: [], classDates: []
  }
  db.data.users.push(user)
  await db.write()
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
  res.json({ token, user: sanitize(user) })
})

app.post('/api/login', async (req, res) => {
  await db.read()
  const { email, password } = req.body
  const user = db.data.users.find(u => u.email === email.toLowerCase())
  if (!user) return res.status(401).json({ error: 'No account with that email' })
  if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Wrong password' })
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' })
  res.json({ token, user: sanitize(user) })
})

app.get('/api/me', auth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id === req.user.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const activity = db.data.activity.filter(a => a.userId === user.id)
    .sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt)).slice(0,30)
  const pendingRequests = (db.data.friendRequests||[])
    .filter(r => r.toId === user.id && r.status === 'pending')
    .map(r => { const from = db.data.users.find(u => u.id === r.fromId); return { id: r.id, from: from?{id:from.id,name:from.name}:null } })
  const unreadNotifs = (db.data.notifications||[]).filter(n => n.userId === user.id && !n.read).length
  res.json({ user: sanitize(user), activity, pendingRequests, unreadNotifs })
})

// ── NOTIFICATIONS ──
app.get('/api/notifications', auth, async (req, res) => {
  await db.read()
  const notifs = (db.data.notifications||[]).filter(n => n.userId === req.user.id).slice(0,20)
  res.json(notifs)
})

app.post('/api/notifications/read', auth, async (req, res) => {
  await db.read()
  ;(db.data.notifications||[]).filter(n => n.userId === req.user.id).forEach(n => n.read = true)
  await db.write()
  res.json({ success: true })
})

// ── MOOD ──
app.post('/api/mood', auth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id === req.user.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  user.moodHistory = user.moodHistory || []
  user.moodHistory.push({ score: req.body.score, note: req.body.note||'', date: new Date().toISOString() })
  await db.write()
  res.json({ success: true })
})

// ── POSTS ──
app.post('/api/posts', auth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id === req.user.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const { caption, imageData, visibility, milestoneN, classType } = req.body
  const post = {
    id: uuidv4(), userId: req.user.id, userName: user.name,
    caption: caption||'', imageData: imageData||null,
    visibility: visibility||'friends', milestoneN: milestoneN||null,
    classType: classType||null,
    userStats: { totalClasses: user.totalClasses, currentStreak: user.currentStreak||0, points: user.points },
    likes: [], comments: [], createdAt: new Date().toISOString()
  }
  db.data.posts.unshift(post)
  if (db.data.posts.length > 500) db.data.posts = db.data.posts.slice(0,500)
  // notify friends
  ;(user.friends||[]).forEach(fid => {
    addNotification(fid, 'post', `${user.name} just posted a new class update ✦`, user.name)
  })
  await db.write()
  res.json({ post })
})

app.get('/api/posts/feed', auth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id === req.user.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const friendIds = new Set(user.friends||[])
  const feed = db.data.posts.filter(p => {
    if (p.userId === req.user.id) return true
    if (friendIds.has(p.userId) && p.visibility === 'friends') return true
    return false
  }).slice(0,30).map(p => {
    const poster = db.data.users.find(u => u.id === p.userId)
    return { ...p, userName: poster?.name||p.userName }
  })
  res.json(feed)
})

app.get('/api/posts/mine', auth, async (req, res) => {
  await db.read()
  res.json(db.data.posts.filter(p => p.userId === req.user.id).slice(0,20))
})

app.post('/api/posts/:id/like', auth, async (req, res) => {
  await db.read()
  const post = db.data.posts.find(p => p.id === req.params.id)
  if (!post) return res.status(404).json({ error: 'Not found' })
  post.likes = post.likes||[]
  const idx = post.likes.indexOf(req.user.id)
  if (idx > -1) post.likes.splice(idx,1)
  else {
    post.likes.push(req.user.id)
    if (post.userId !== req.user.id) {
      const liker = db.data.users.find(u => u.id === req.user.id)
      addNotification(post.userId, 'like', `${liker?.name||'Someone'} liked your post ❤️`, liker?.name)
    }
  }
  await db.write()
  res.json({ likes: post.likes.length, liked: post.likes.includes(req.user.id) })
})

app.post('/api/posts/:id/comment', auth, async (req, res) => {
  await db.read()
  const post = db.data.posts.find(p => p.id === req.params.id)
  if (!post) return res.status(404).json({ error: 'Not found' })
  const user = db.data.users.find(u => u.id === req.user.id)
  post.comments = post.comments||[]
  const comment = { id: uuidv4(), userId: req.user.id, userName: user?.name||'', text: req.body.text, createdAt: new Date().toISOString() }
  post.comments.push(comment)
  if (post.userId !== req.user.id) {
    addNotification(post.userId, 'comment', `${user?.name||'Someone'} commented: "${req.body.text.slice(0,40)}"`, user?.name)
  }
  await db.write()
  res.json({ comment })
})

// ── FRIENDS ──
app.post('/api/friends/request', auth, async (req, res) => {
  await db.read()
  const { toEmail } = req.body
  const toUser = db.data.users.find(u => u.email === toEmail.toLowerCase())
  if (!toUser) return res.status(404).json({ error: 'No user with that email' })
  if (toUser.id === req.user.id) return res.status(400).json({ error: "Can't add yourself" })
  const me = db.data.users.find(u => u.id === req.user.id)
  if ((me.friends||[]).includes(toUser.id)) return res.status(400).json({ error: 'Already friends' })
  const existing = (db.data.friendRequests||[]).find(r => r.fromId===req.user.id && r.toId===toUser.id && r.status==='pending')
  if (existing) return res.status(400).json({ error: 'Request already sent' })
  db.data.friendRequests.push({ id: uuidv4(), fromId: req.user.id, toId: toUser.id, status: 'pending', createdAt: new Date().toISOString() })
  addNotification(toUser.id, 'friend_request', `${me.name} wants to be friends on MōTIV`, me.name)
  await db.write()
  res.json({ success: true, toName: toUser.name })
})

app.post('/api/friends/respond', auth, async (req, res) => {
  await db.read()
  const { requestId, accept } = req.body
  const r = (db.data.friendRequests||[]).find(r => r.id===requestId && r.toId===req.user.id)
  if (!r) return res.status(404).json({ error: 'Request not found' })
  r.status = accept ? 'accepted' : 'declined'
  if (accept) {
    const me = db.data.users.find(u => u.id===req.user.id)
    const them = db.data.users.find(u => u.id===r.fromId)
    if (me && them) {
      me.friends = me.friends||[]; them.friends = them.friends||[]
      if (!me.friends.includes(them.id)) me.friends.push(them.id)
      if (!them.friends.includes(me.id)) them.friends.push(me.id)
      addNotification(them.id, 'friend_accept', `${me.name} accepted your friend request 🎉`, me.name)
    }
  }
  await db.write()
  res.json({ success: true })
})

app.get('/api/friends', auth, async (req, res) => {
  await db.read()
  const me = db.data.users.find(u => u.id===req.user.id)
  if (!me) return res.status(404).json({ error: 'Not found' })
  const friends = (me.friends||[]).map(fid => {
    const f = db.data.users.find(u => u.id===fid)
    if (!f) return null
    const daysSinceClass = f.lastClassDate ? Math.floor((Date.now()-new Date(f.lastClassDate))/(1000*60*60*24)) : null
    return { id:f.id, name:f.name, points:f.points, totalClasses:f.totalClasses, currentStreak:f.currentStreak||0, longestStreak:f.longestStreak||0, earnedMilestones:f.earnedMilestones||[], daysSinceClass }
  }).filter(Boolean)
  res.json(friends)
})

// ── PROFILE ──
app.get('/api/profile/:id', auth, async (req, res) => {
  await db.read()
  const me = db.data.users.find(u => u.id===req.user.id)
  const user = db.data.users.find(u => u.id===req.params.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const isFriend = (me?.friends||[]).includes(user.id) || user.id===req.user.id
  const posts = db.data.posts.filter(p => p.userId===user.id && (isFriend||p.userId===req.user.id)).slice(0,12)
  res.json({ user: sanitize(user), posts, isFriend })
})

// ── ADMIN ──
app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' })
  const token = jwt.sign({ isAdmin: true }, ADMIN_SECRET, { expiresIn: '8h' })
  res.json({ token })
})

app.get('/api/admin/members', adminAuth, async (req, res) => {
  await db.read()
  const q = (req.query.q||'').toLowerCase()
  const members = db.data.users
    .filter(u => !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q) || u.phone.includes(q))
    .map(sanitize).sort((a,b) => b.points-a.points)
  res.json(members)
})

app.get('/api/admin/members/:id', adminAuth, async (req, res) => {
  await db.read()
  const user = db.data.users.find(u => u.id===req.params.id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const activity = db.data.activity.filter(a => a.userId===user.id).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))
  res.json({ user: sanitize(user), activity })
})

app.post('/api/admin/award', adminAuth, async (req, res) => {
  await db.read()
  const { userId, classType, points, instructor } = req.body
  const user = db.data.users.find(u => u.id===userId)
  if (!user) return res.status(404).json({ error: 'Not found' })
  user.points += points; user.totalClasses += 1
  user.moodHistory = user.moodHistory||[]; user.earnedMilestones = user.earnedMilestones||[]
  user.classDates = user.classDates||[]
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
  db.data.activity.push({ id:uuidv4(), userId, type:'class', label:classType+(instructor?' · '+instructor:''), points:awardedPts, instructor:instructor||'', awardedBy:'staff', createdAt:now.toISOString() })
  // notify user
  addNotification(userId, 'points', `${awardedPts} points added for ${classType}${birthdayBonus?' (birthday bonus! 🎂)':''}`, 'Motiv Staff')
  if (newMilestones.length > 0) {
    addNotification(userId, 'milestone', `🎉 You hit ${newMilestones[0]} classes! New milestone unlocked.`, 'Motiv')
    // notify friends
    ;(user.friends||[]).forEach(fid => {
      addNotification(fid, 'friend_milestone', `${user.name} just hit ${newMilestones[0]} classes! 🎉`, user.name)
    })
  }
  await db.write()
  res.json({ user: sanitize(user), newMilestones, birthdayBonus })
})

app.post('/api/admin/redeem', adminAuth, async (req, res) => {
  await db.read()
  const { userId, rewardName, pointsCost } = req.body
  const user = db.data.users.find(u => u.id===userId)
  if (!user) return res.status(404).json({ error: 'Not found' })
  if (user.points < pointsCost) return res.status(400).json({ error: 'Not enough points' })
  user.points -= pointsCost
  db.data.activity.push({ id:uuidv4(), userId, type:'redeem', label:'Redeemed: '+rewardName, points:-pointsCost, awardedBy:'staff', createdAt:new Date().toISOString() })
  await db.write()
  res.json({ user: sanitize(user) })
})

app.post('/api/admin/referral', adminAuth, async (req, res) => {
  await db.read()
  const { userId, friendName } = req.body
  const user = db.data.users.find(u => u.id===userId)
  if (!user) return res.status(404).json({ error: 'Not found' })
  user.points += 100; user.totalReferrals += 1
  db.data.activity.push({ id:uuidv4(), userId, type:'referral', label:'Referral bonus — '+friendName, points:100, awardedBy:'staff', createdAt:new Date().toISOString() })
  addNotification(userId, 'referral', `Referral bonus added for ${friendName} — +100 pts ✦`, 'Motiv Staff')
  await db.write()
  res.json({ user: sanitize(user) })
})

app.post('/api/admin/message', adminAuth, async (req, res) => {
  await db.read()
  const { userId, message } = req.body
  const user = db.data.users.find(u => u.id===userId)
  if (!user) return res.status(404).json({ error: 'Not found' })
  addNotification(userId, 'message', message, 'Motiv Staff')
  await db.write()
  res.json({ success: true })
})

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  await db.read()
  const weekNum = Math.floor(Date.now()/(7*24*60*60*1000))
  const now = new Date()
  const twoWeeksAgo = new Date(now-14*24*60*60*1000).toISOString()
  const winBack = db.data.users.filter(u => {
    if (!u.lastClassDate) return u.totalClasses > 0
    return u.lastClassDate < twoWeeksAgo && u.totalClasses > 0
  }).map(u => ({ id:u.id, name:u.name, email:u.email, lastClassDate:u.lastClassDate, totalClasses:u.totalClasses, currentStreak:u.currentStreak||0 }))
  res.json({
    totalMembers: db.data.users.length,
    totalClasses: db.data.activity.filter(a=>a.type==='class').length,
    totalReferrals: db.data.activity.filter(a=>a.type==='referral').length,
    activeThisWeek: db.data.users.filter(u=>u.lastClassWeek===weekNum).length,
    totalPosts: (db.data.posts||[]).length,
    winBack
  })
})

app.listen(3000, () => console.log('✦ Motiv running → http://localhost:3000'))

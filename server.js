const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
require('dotenv').config();
const express = require('express');
const multer = require('multer');

const root = __dirname;
const storageRoot = process.env.PERSISTENT_DIRECTORY || root;
const uploadDirectory = path.join(storageRoot, 'uploads');
const dataDirectory = path.join(storageRoot, 'data');
fs.mkdirSync(uploadDirectory, { recursive: true });
fs.mkdirSync(dataDirectory, { recursive: true });

const ownerPassword = process.env.OWNER_PASSWORD;
const sessionSecret = process.env.SESSION_SECRET;
if (!ownerPassword || ownerPassword.length < 10) throw new Error('Set OWNER_PASSWORD to a unique password at least 10 characters long.');
if (!sessionSecret || sessionSecret.length < 32) throw new Error('Set SESSION_SECRET to a random secret at least 32 characters long.');

const app = express();
const database = new DatabaseSync(path.join(dataDirectory, 'portfolio.sqlite'));
database.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    organization TEXT NOT NULL DEFAULT '',
    website TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    filename TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    customer_id INTEGER REFERENCES customers(id),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender TEXT NOT NULL CHECK(sender IN ('customer', 'owner')),
    text TEXT NOT NULL,
    image_filename TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
if (!database.prepare('PRAGMA table_info(messages)').all().some(column => column.name === 'image_filename')) {
  database.exec('ALTER TABLE messages ADD COLUMN image_filename TEXT');
}
if (!database.prepare('PRAGMA table_info(conversations)').all().some(column => column.name === 'customer_id')) {
  database.exec('ALTER TABLE conversations ADD COLUMN customer_id INTEGER REFERENCES customers(id)');
}
database.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_customer_id ON conversations(customer_id) WHERE customer_id IS NOT NULL');

function parseCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').map(part => {
    const index = part.indexOf('=');
    return index < 0 ? ['', ''] : [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

function secureCookieOptions(maxAge) {
  return { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/', maxAge };
}

function ownerSignature(expiresAt) {
  return crypto.createHmac('sha256', sessionSecret).update(String(expiresAt)).digest('hex');
}

function isOwner(request) {
  const token = parseCookies(request).owner_auth || '';
  const [expiresText, signature] = token.split('.');
  const expiresAt = Number(expiresText);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || !signature) return false;
  const expected = Buffer.from(ownerSignature(expiresAt));
  const actual = Buffer.from(signature);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function requireOwner(request, response, next) {
  if (!isOwner(request)) return response.status(401).json({ error: 'Please sign in as the site owner.' });
  next();
}

function customerSignature(customerId, expiresAt) {
  return crypto.createHmac('sha256', sessionSecret).update(`customer:${customerId}:${expiresAt}`).digest('hex');
}

function getCustomerFromRequest(request) {
  const token = parseCookies(request).customer_auth || '';
  const [customerIdText, expiresText, signature] = token.split('.');
  const customerId = Number(customerIdText);
  const expiresAt = Number(expiresText);
  if (!Number.isSafeInteger(customerId) || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || !signature) return null;
  const expected = Buffer.from(customerSignature(customerId, expiresAt));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  return database.prepare('SELECT id, name, email, phone, organization, website FROM customers WHERE id = ?').get(customerId) || null;
}

function requireCustomer(request, response, next) {
  const customer = getCustomerFromRequest(request);
  if (!customer) return response.status(401).json({ error: 'Please sign in to your customer account.' });
  request.customer = customer;
  next();
}

function requireSiteAccess(request, response, next) {
  if (!isOwner(request) && !getCustomerFromRequest(request)) return response.status(401).json({ error: 'Create an account or sign in to view the portfolio.' });
  next();
}

function setCustomerCookie(response, customerId) {
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
  const token = `${customerId}.${expiresAt}.${customerSignature(customerId, expiresAt)}`;
  response.cookie('customer_auth', token, secureCookieOptions(30 * 24 * 60 * 60 * 1000));
}

function connectCustomerConversation(customerId, visitorId) {
  const visitorConversation = getConversation(visitorId);
  const accountConversation = database.prepare('SELECT id FROM conversations WHERE customer_id = ?').get(customerId);
  if (!visitorConversation) return accountConversation;
  if (!accountConversation) {
    database.prepare('UPDATE conversations SET customer_id = ? WHERE id = ?').run(customerId, visitorConversation.id);
    return visitorConversation;
  }
  if (visitorConversation.id === accountConversation.id) return accountConversation;
  database.exec('BEGIN');
  try {
    database.prepare('UPDATE messages SET conversation_id = ? WHERE conversation_id = ?').run(accountConversation.id, visitorConversation.id);
    database.prepare('DELETE FROM conversations WHERE id = ?').run(visitorConversation.id);
    database.prepare("UPDATE conversations SET updated_at = datetime('now') WHERE id = ?").run(accountConversation.id);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
  return accountConversation;
}

function ensureVisitor(request, response, next) {
  const cookies = parseCookies(request);
  let visitorId = cookies.visitor_id;
  if (!visitorId || !/^[a-f0-9-]{36}$/i.test(visitorId)) {
    visitorId = crypto.randomUUID();
    response.cookie('visitor_id', visitorId, secureCookieOptions(1000 * 60 * 60 * 24 * 365));
  }
  request.visitorId = visitorId;
  next();
}

function getConversationForRequest(request) {
  if (request.customer) {
    const accountConversation = database.prepare('SELECT id FROM conversations WHERE customer_id = ?').get(request.customer.id);
    if (accountConversation) return accountConversation;
  }
  return getConversation(request.visitorId);
}

const failedLogins = new Map();
function loginThrottle(request, response, next) {
  const now = Date.now();
  const key = request.ip;
  const entry = failedLogins.get(key);
  if (entry && entry.until > now && entry.count >= 8) return response.status(429).json({ error: 'Too many attempts. Please try again later.' });
  if (entry && entry.until <= now) failedLogins.delete(key);
  next();
}

const allowedTypes = new Map([
  ['image/jpeg', 'jpg'],
  ['image/png', 'png'],
  ['image/webp', 'webp'],
  ['image/gif', 'gif']
]);
const imageUpload = multer({
  storage: multer.diskStorage({
    destination: uploadDirectory,
    filename: (request, file, callback) => callback(null, `${crypto.randomUUID()}.${allowedTypes.get(file.mimetype) || 'bin'}`)
  }),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },
  fileFilter: (request, file, callback) => callback(null, allowedTypes.has(file.mimetype))
});

app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use('/uploads', requireSiteAccess, express.static(uploadDirectory, { maxAge: '1d', immutable: true }));
app.get('/studio', (request, response) => response.sendFile(path.join(root, 'studio.html')));
app.get('/', (request, response) => response.sendFile(path.join(root, 'index.html')));

app.get('/api/projects', requireSiteAccess, (request, response) => {
  const projects = database.prepare('SELECT id, title, category, filename, created_at AS createdAt FROM projects ORDER BY id DESC').all();
  response.json(projects.map(project => ({ ...project, imageUrl: `/uploads/${project.filename}`, year: new Date(`${project.createdAt}Z`).getFullYear() })));
});

app.use('/api/chat', ensureVisitor, (request, response, next) => {
  request.customer = getCustomerFromRequest(request);
  if (!request.customer) return response.status(401).json({ error: 'Create an account or sign in to chat.' });
  next();
});

app.post('/api/owner/login', loginThrottle, (request, response) => {
  const supplied = Buffer.from(String(request.body.password || ''));
  const expected = Buffer.from(ownerPassword);
  const matches = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  if (!matches) {
    const previous = failedLogins.get(request.ip);
    failedLogins.set(request.ip, { count: (previous?.count || 0) + 1, until: Date.now() + 15 * 60 * 1000 });
    return response.status(401).json({ error: 'That password did not match.' });
  }
  failedLogins.delete(request.ip);
  const expiresAt = Date.now() + 12 * 60 * 60 * 1000;
  response.cookie('owner_auth', `${expiresAt}.${ownerSignature(expiresAt)}`, secureCookieOptions(12 * 60 * 60 * 1000));
  response.json({ ok: true });
});

app.get('/api/owner/me', requireOwner, (request, response) => response.json({ ok: true }));
app.post('/api/owner/logout', (request, response) => {
  response.clearCookie('owner_auth', secureCookieOptions(0));
  response.json({ ok: true });
});

function normalizeCustomerInput(body) {
  const name = String(body.name || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const phone = String(body.phone || '').trim();
  const organization = String(body.organization || '').trim();
  const website = String(body.website || '').trim();
  if (!name || name.length > 80) throw new Error('Enter a name of 1 to 80 characters.');
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid email address.');
  if (phone.length > 30 || organization.length > 100 || website.length > 200) throw new Error('One of the contact details is too long.');
  if (website && !/^https?:\/\//i.test(website)) throw new Error('Website must start with http:// or https://.');
  return { name, email, phone, organization, website };
}

function accountProfile(customer) {
  return { id: customer.id, name: customer.name, email: customer.email, phone: customer.phone, organization: customer.organization, website: customer.website };
}

function isUniqueConstraint(error) {
  return error.code === 'SQLITE_CONSTRAINT_UNIQUE' || error.errcode === 2067;
}

app.post('/api/customer/register', ensureVisitor, loginThrottle, (request, response) => {
  if (getCustomerFromRequest(request)) return response.status(409).json({ error: 'You are already signed in. Sign out before creating another account.' });
  let profile;
  try { profile = normalizeCustomerInput(request.body); }
  catch (error) { return response.status(400).json({ error: error.message }); }
  const password = String(request.body.password || '');
  if (password.length < 12 || password.length > 256) return response.status(400).json({ error: 'Password must be between 12 and 256 characters.' });
  const passwordSalt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto.scryptSync(password, passwordSalt, 64).toString('hex');
  try {
    const result = database.prepare('INSERT INTO customers (name, email, password_salt, password_hash, phone, organization, website) VALUES (?, ?, ?, ?, ?, ?, ?)').run(profile.name, profile.email, passwordSalt, passwordHash, profile.phone, profile.organization, profile.website);
    const customerId = Number(result.lastInsertRowid);
    setCustomerCookie(response, customerId);
    connectCustomerConversation(customerId, request.visitorId);
    response.status(201).json({ customer: { id: customerId, ...profile } });
  } catch (error) {
    if (isUniqueConstraint(error)) return response.status(409).json({ error: 'An account with this email already exists. Sign in instead.' });
    throw error;
  }
});

app.post('/api/customer/login', ensureVisitor, loginThrottle, (request, response) => {
  const email = String(request.body.email || '').trim().toLowerCase();
  const password = String(request.body.password || '');
  const customer = database.prepare('SELECT id, name, email, phone, organization, website, password_salt AS passwordSalt, password_hash AS passwordHash FROM customers WHERE email = ?').get(email);
  const passwordHash = crypto.scryptSync(password, customer?.passwordSalt || 'invalid-customer-salt', 64);
  const expectedHash = Buffer.from(customer?.passwordHash || '0'.repeat(128), 'hex');
  const valid = customer && expectedHash.length === passwordHash.length && crypto.timingSafeEqual(passwordHash, expectedHash);
  if (!valid) {
    const previous = failedLogins.get(request.ip);
    failedLogins.set(request.ip, { count: (previous?.count || 0) + 1, until: Date.now() + 15 * 60 * 1000 });
    return response.status(401).json({ error: 'Email or password did not match.' });
  }
  failedLogins.delete(request.ip);
  setCustomerCookie(response, customer.id);
  connectCustomerConversation(customer.id, request.visitorId);
  response.json({ customer: accountProfile(customer) });
});

app.get('/api/customer/me', requireCustomer, (request, response) => response.json({ customer: request.customer }));
app.put('/api/customer/profile', requireCustomer, (request, response) => {
  let profile;
  try { profile = normalizeCustomerInput(request.body); }
  catch (error) { return response.status(400).json({ error: error.message }); }
  try {
    database.prepare('UPDATE customers SET name = ?, email = ?, phone = ?, organization = ?, website = ? WHERE id = ?').run(profile.name, profile.email, profile.phone, profile.organization, profile.website, request.customer.id);
    response.json({ customer: { id: request.customer.id, ...profile } });
  } catch (error) {
    if (isUniqueConstraint(error)) return response.status(409).json({ error: 'Another account already uses this email.' });
    throw error;
  }
});
app.post('/api/customer/logout', (request, response) => {
  response.clearCookie('customer_auth', secureCookieOptions(0));
  response.json({ ok: true });
});

app.post('/api/projects', requireOwner, imageUpload.single('image'), (request, response) => {
  const title = String(request.body.title || '').trim();
  const category = String(request.body.category || '');
  if (!title || title.length > 60 || !['Brand identity', 'Campaign', 'Digital'].includes(category)) {
    if (request.file) fs.unlinkSync(request.file.path);
    return response.status(400).json({ error: 'Enter a title and choose a valid category.' });
  }
  if (!request.file) return response.status(400).json({ error: 'Choose a JPEG, PNG, WebP, or GIF image under 4 MB.' });
  const result = database.prepare('INSERT INTO projects (title, category, filename) VALUES (?, ?, ?)').run(title, category, request.file.filename);
  response.status(201).json({ id: Number(result.lastInsertRowid), title, category, imageUrl: `/uploads/${request.file.filename}` });
});

app.delete('/api/projects/:id', requireOwner, (request, response) => {
  const project = database.prepare('SELECT filename FROM projects WHERE id = ?').get(Number(request.params.id));
  if (!project) return response.status(404).json({ error: 'Design not found.' });
  database.prepare('DELETE FROM projects WHERE id = ?').run(Number(request.params.id));
  fs.rm(path.join(uploadDirectory, project.filename), { force: true }, () => {});
  response.json({ ok: true });
});

function getConversation(visitorId) {
  return database.prepare('SELECT id FROM conversations WHERE visitor_id = ?').get(visitorId);
}

function listMessages(conversationId) {
  return database.prepare('SELECT id, sender, text, image_filename AS imageFilename, created_at AS createdAt FROM messages WHERE conversation_id = ? ORDER BY id').all(conversationId).map(message => ({
    id: message.id,
    sender: message.sender,
    text: message.text,
    imageUrl: message.imageFilename ? `/uploads/${message.imageFilename}` : null,
    createdAt: message.createdAt
  }));
}

function addMessage(conversationId, sender, text, imageFilename = null) {
  database.prepare('INSERT INTO messages (conversation_id, sender, text, image_filename) VALUES (?, ?, ?, ?)').run(conversationId, sender, text, imageFilename);
  database.prepare("UPDATE conversations SET updated_at = datetime('now') WHERE id = ?").run(conversationId);
}

function removeMessage(message) {
  database.prepare('DELETE FROM messages WHERE id = ?').run(message.id);
  if (message.imageFilename) fs.rmSync(path.join(uploadDirectory, message.imageFilename), { force: true });
  database.prepare("UPDATE conversations SET updated_at = datetime('now') WHERE id = ?").run(message.conversationId);
}

app.get('/api/chat/messages', (request, response) => {
  const conversation = getConversationForRequest(request);
  response.json(conversation ? listMessages(conversation.id) : []);
});

app.post('/api/chat/messages', imageUpload.single('image'), (request, response) => {
  const text = String(request.body.text || '').trim();
  if ((!text && !request.file) || text.length > 500) return response.status(400).json({ error: 'Add a message or attach a picture. Text must be 500 characters or fewer.' });
  let conversation = getConversation(request.visitorId);
  if (request.customer) conversation = database.prepare('SELECT id FROM conversations WHERE customer_id = ?').get(request.customer.id) || conversation;
  if (!conversation) {
    const result = database.prepare('INSERT INTO conversations (visitor_id, customer_id) VALUES (?, ?)').run(request.visitorId, request.customer?.id || null);
    conversation = { id: Number(result.lastInsertRowid) };
  }
  addMessage(conversation.id, 'customer', text, request.file?.filename);
  response.status(201).json({ ok: true });
});

app.patch('/api/chat/messages/:messageId', ensureVisitor, (request, response) => {
  const conversation = getConversationForRequest(request);
  const message = conversation && database.prepare("SELECT id FROM messages WHERE id = ? AND conversation_id = ? AND sender = 'customer'").get(Number(request.params.messageId), conversation.id);
  if (!message) return response.status(404).json({ error: 'Your message was not found.' });
  const text = String(request.body.text || '').trim();
  if (!text || text.length > 500) return response.status(400).json({ error: 'Messages must be between 1 and 500 characters.' });
  database.prepare('UPDATE messages SET text = ? WHERE id = ?').run(text, message.id);
  database.prepare("UPDATE conversations SET updated_at = datetime('now') WHERE id = ?").run(conversation.id);
  response.json({ ok: true });
});

app.delete('/api/chat/messages/:messageId', ensureVisitor, (request, response) => {
  const conversation = getConversationForRequest(request);
  const message = conversation && database.prepare("SELECT id, conversation_id AS conversationId, image_filename AS imageFilename FROM messages WHERE id = ? AND conversation_id = ? AND sender = 'customer'").get(Number(request.params.messageId), conversation.id);
  if (!message) return response.status(404).json({ error: 'Your message was not found.' });
  removeMessage(message);
  response.json({ ok: true });
});

app.get('/api/owner/conversations', requireOwner, (request, response) => {
  const conversations = database.prepare(`
    SELECT c.id, c.visitor_id AS visitorId, c.name, customers.name AS customerName, customers.email AS customerEmail, c.updated_at AS updatedAt,
      (SELECT COALESCE(NULLIF(text, ''), 'Picture') FROM messages WHERE conversation_id = c.id ORDER BY id DESC LIMIT 1) AS preview
    FROM conversations c LEFT JOIN customers ON customers.id = c.customer_id ORDER BY c.updated_at DESC
  `).all();
  response.json(conversations);
});

app.get('/api/owner/conversations/:id/messages', requireOwner, (request, response) => {
  const id = Number(request.params.id);
  if (!database.prepare('SELECT id FROM conversations WHERE id = ?').get(id)) return response.status(404).json({ error: 'Conversation not found.' });
  response.json(listMessages(id));
});

app.delete('/api/owner/conversations/:id', requireOwner, (request, response) => {
  const id = Number(request.params.id);
  const conversation = database.prepare('SELECT id FROM conversations WHERE id = ?').get(id);
  if (!conversation) return response.status(404).json({ error: 'Conversation not found.' });
  const images = database.prepare('SELECT image_filename AS filename FROM messages WHERE conversation_id = ? AND image_filename IS NOT NULL').all(id);
  database.prepare('DELETE FROM conversations WHERE id = ?').run(id);
  for (const image of images) fs.rmSync(path.join(uploadDirectory, image.filename), { force: true });
  response.json({ ok: true });
});

app.patch('/api/owner/conversations/:conversationId/messages/:messageId', requireOwner, (request, response) => {
  const conversationId = Number(request.params.conversationId);
  const message = database.prepare("SELECT id FROM messages WHERE id = ? AND conversation_id = ? AND sender = 'owner'").get(Number(request.params.messageId), conversationId);
  if (!message) return response.status(404).json({ error: 'Your reply was not found.' });
  const text = String(request.body.text || '').trim();
  if (!text || text.length > 500) return response.status(400).json({ error: 'Replies must be between 1 and 500 characters.' });
  database.prepare('UPDATE messages SET text = ? WHERE id = ?').run(text, message.id);
  database.prepare("UPDATE conversations SET updated_at = datetime('now') WHERE id = ?").run(conversationId);
  response.json({ ok: true });
});

app.delete('/api/owner/conversations/:conversationId/messages/:messageId', requireOwner, (request, response) => {
  const conversationId = Number(request.params.conversationId);
  const message = database.prepare("SELECT id, conversation_id AS conversationId, image_filename AS imageFilename FROM messages WHERE id = ? AND conversation_id = ? AND sender = 'owner'").get(Number(request.params.messageId), conversationId);
  if (!message) return response.status(404).json({ error: 'Your reply was not found.' });
  removeMessage(message);
  response.json({ ok: true });
});

app.post('/api/owner/conversations/:id/messages', requireOwner, imageUpload.single('image'), (request, response) => {
  const id = Number(request.params.id);
  const text = String(request.body.text || '').trim();
  if (!database.prepare('SELECT id FROM conversations WHERE id = ?').get(id)) return response.status(404).json({ error: 'Conversation not found.' });
  if ((!text && !request.file) || text.length > 500) return response.status(400).json({ error: 'Add a reply or attach a picture. Text must be 500 characters or fewer.' });
  addMessage(id, 'owner', text, request.file?.filename);
  response.status(201).json({ ok: true });
});

app.use((error, request, response, next) => {
  if (error instanceof multer.MulterError || error.message === 'Unexpected field') {
    return response.status(400).json({ error: 'Choose one JPEG, PNG, WebP, or GIF image under 4 MB.' });
  }
  console.error(error);
  response.status(500).json({ error: 'The server could not complete that request.' });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`Onuja Jonathan portfolio running at http://localhost:${port}`));
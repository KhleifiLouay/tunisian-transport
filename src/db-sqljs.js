
const fs = require('fs');
const path = require('path');

const DB_DIR = path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DB_DIR, 'transport.sqlite');

let SQL = null;
let db = null;

const queries = {
  createTables: `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','user','driver')) DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS trips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  origin TEXT NOT NULL,
  destination TEXT NOT NULL,
  date TEXT NOT NULL,
  price REAL NOT NULL,
  seats INTEGER NOT NULL DEFAULT 8,
  departure_time TEXT NOT NULL,
  driver_id INTEGER,
  FOREIGN KEY(driver_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS drivers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  full_name TEXT NOT NULL,
  id_number TEXT NOT NULL,
  available_date TEXT NOT NULL,
  available_time TEXT NOT NULL,
  cities TEXT NOT NULL,
  vehicle_model TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  trip_id INTEGER NOT NULL,
  booking_code TEXT UNIQUE NOT NULL,
  verified INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(trip_id) REFERENCES trips(id)
);`,
  listTrips: `SELECT * FROM trips ORDER BY date ASC`,
  getUserByEmail: `SELECT * FROM users WHERE email = ?`,
  getBookingsForUser: `SELECT b.id, b.trip_id, b.booking_code, b.verified, t.origin, t.destination, t.date, t.price, t.departure_time, b.created_at
                        FROM bookings b JOIN trips t ON t.id = b.trip_id WHERE b.user_id = ? AND b.verified = 0 ORDER BY b.created_at DESC`,
  createBooking: `INSERT INTO bookings (user_id, trip_id, booking_code) VALUES (?, ?, ?)`,
  listUsers: `SELECT id, name, email, role FROM users ORDER BY id ASC`,
  listAllBookings: `SELECT b.id, b.booking_code, b.verified, u.name as user_name, u.email, t.origin, t.destination, t.date, t.price, b.created_at
                    FROM bookings b JOIN users u ON u.id=b.user_id JOIN trips t ON t.id=b.trip_id
                    ORDER BY b.created_at DESC`,
  createUser: `INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)`,
  createTrip: `INSERT INTO trips (origin, destination, date, price, seats, departure_time) VALUES (?, ?, ?, ?, ?, ?)`,
  deleteTrip: `DELETE FROM trips WHERE id = ?`
};

async function init() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  const initSqlJs = require('sql.js');
  const SQLLoader = await initSqlJs({
    locateFile: file => require.resolve('sql.js/dist/sql-wasm.wasm')
  });
  SQL = SQLLoader;

  if (fs.existsSync(DB_FILE)) {
    const filebuffer = fs.readFileSync(DB_FILE);
    db = new SQL.Database(filebuffer);
  } else {
    db = new SQL.Database();
  }
  db.run(queries.createTables);
  save();
}

function save() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_FILE, buffer);
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function get(sql, params = []) {
  const rows = all(sql, params);
  return rows[0] || null;
}

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  stmt.step();
  stmt.free();
  save();
}

module.exports = { init, all, get, run, queries };

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const path = require('path');
const bcrypt = require('bcryptjs');
const dbw = require('./src/db-sqljs');
const QRCode = require('qrcode');
const crypto = require('crypto');

const app = express();

// Use fallback JWT secret for production if not set
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = 'loagi-transport-secret-key-2024-' + crypto.randomBytes(16).toString('hex');
  console.log('Warning: JWT_SECRET not set, using generated secret');
}

// Trust proxy for Render.com
app.set('trust proxy', 1);

// Health check endpoint for Render.com (must be before other middleware)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Generate unique booking code
function generateBookingCode() {
  return 'LG-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https://*.tile.openstreetmap.org", "blob:"],
      workerSrc: ["'self'", "blob:"],
    },
  },
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev'));
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function setLocals(req, res, next) {
  res.locals.user = null;
  const token = req.cookies['token'];
  if (token) {
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      res.locals.user = payload;
    } catch (e) {}
  }
  next();
}
app.use(setLocals);

function authRequired(role=null) {
  return (req, res, next) => {
    const token = req.cookies['token'];
    if (!token) return res.redirect('/login');
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      if (role && payload.role !== role) return res.status(403).send('Forbidden');
      req.user = payload;
      next();
    } catch (e) {
      return res.redirect('/login');
    }
  };
}

app.get('/', (req, res) => {
  const trips = dbw.all(dbw.queries.listTrips);
  res.render('index', { trips, user: res.locals.user });
});

app.get('/login', (req, res) => {
  if (res.locals.user) return res.redirect('/dashboard');
  res.render('auth/login', { error: null, user: null });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const u = dbw.get(dbw.queries.getUserByEmail, [email]);
  if (!u) return res.status(401).render('auth/login', { error: 'Invalid credentials', user: null });
  const ok = bcrypt.compareSync(password, u.password_hash);
  if (!ok) return res.status(401).render('auth/login', { error: 'Invalid credentials', user: null });
  const payload = { id: u.id, email: u.email, role: u.role, name: u.name };
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
  // Redirect based on role
  if (u.role === 'admin') {
    return res.redirect('/admin');
  }
  if (u.role === 'driver') {
    return res.redirect('/driver');
  }
  return res.redirect('/dashboard');
});

app.get('/auth/signup', (req, res) => {
  if (res.locals.user) return res.redirect('/dashboard');
  res.render('auth/signup', { error: null, user: null });
});

app.post('/auth/signup', async (req, res) => {
  const { name, email, confirm_email, password, confirm_password, role } = req.body;
  if (!name || !email || !confirm_email || !password || !confirm_password) {
    return res.status(400).render('auth/signup', { error: 'All fields are required.', user: null });
  }
  if (email !== confirm_email) {
    return res.status(400).render('auth/signup', { error: 'Emails do not match.', user: null });
  }
  if (password !== confirm_password) {
    return res.status(400).render('auth/signup', { error: 'Passwords do not match.', user: null });
  }
  const existingUser = dbw.get(dbw.queries.getUserByEmail, [email]);
  if (existingUser) {
    return res.status(400).render('auth/signup', { error: 'Email is already in use.', user: null });
  }
  const hash = bcrypt.hashSync(password, 10);
  const userRole = role === 'driver' ? 'driver' : 'user';
  try {
    dbw.run(dbw.queries.createUser, [name, email, hash, userRole]);
    res.redirect('/login');
  } catch (e) {
    res.status(500).render('auth/signup', { error: 'An error occurred. Please try again.', user: null });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.get('/driver', authRequired('driver'), (req, res) => {
  const driverInfo = dbw.get('SELECT * FROM drivers WHERE user_id = ?', [req.user.id]);
  const assignedTrips = dbw.all(`
    SELECT t.*, d.full_name as driver_name, d.vehicle_model
    FROM trips t
    LEFT JOIN drivers d ON d.user_id = t.driver_id
    WHERE t.driver_id = ?
    ORDER BY t.date ASC
  `, [req.user.id]);
  res.render('driver/dashboard', { driverInfo, assignedTrips, user: res.locals.user, verifyResult: null, verifyError: null });
});

// Driver verify booking code
app.post('/driver/verify-booking', authRequired('driver'), (req, res) => {
  const { booking_code } = req.body;
  const driverInfo = dbw.get('SELECT * FROM drivers WHERE user_id = ?', [req.user.id]);
  const assignedTrips = dbw.all(`
    SELECT t.*, d.full_name as driver_name, d.vehicle_model
    FROM trips t
    LEFT JOIN drivers d ON d.user_id = t.driver_id
    WHERE t.driver_id = ?
    ORDER BY t.date ASC
  `, [req.user.id]);

  if (!booking_code || booking_code.trim() === '') {
    return res.render('driver/dashboard', {
      driverInfo,
      assignedTrips,
      user: res.locals.user,
      verifyResult: null,
      verifyError: 'Please enter a booking code.'
    });
  }

  // Find the booking with this code
  const booking = dbw.get(`
    SELECT b.*, u.name as passenger_name, u.email as passenger_email,
           t.origin, t.destination, t.date, t.departure_time, t.driver_id
    FROM bookings b
    JOIN users u ON u.id = b.user_id
    JOIN trips t ON t.id = b.trip_id
    WHERE b.booking_code = ? AND b.verified = 0
  `, [booking_code.trim().toUpperCase()]);

  if (!booking) {
    return res.render('driver/dashboard', {
      driverInfo,
      assignedTrips,
      user: res.locals.user,
      verifyResult: null,
      verifyError: 'Invalid booking code or already verified/used.'
    });
  }

  // Check if this booking is for a trip assigned to this driver
  if (booking.driver_id !== req.user.id) {
    return res.render('driver/dashboard', {
      driverInfo,
      assignedTrips,
      user: res.locals.user,
      verifyResult: null,
      verifyError: 'This booking is not for your assigned trip.'
    });
  }

  // Save passenger info before deletion
  const passengerInfo = {
    passenger_name: booking.passenger_name,
    passenger_email: booking.passenger_email,
    origin: booking.origin,
    destination: booking.destination,
    date: booking.date,
    booking_code: booking.booking_code
  };

  // Delete the booking (QR code is now used and invalid)
  dbw.run('DELETE FROM bookings WHERE booking_code = ?', [booking_code.trim().toUpperCase()]);

  return res.render('driver/dashboard', {
    driverInfo,
    assignedTrips,
    user: res.locals.user,
    verifyResult: passengerInfo,
    verifyError: null
  });
});

app.post('/driver/availability', authRequired('driver'), (req, res) => {
  const { full_name, id_number, available_date, available_time, cities, vehicle_model } = req.body;
  try {
    // Check if driver info already exists
    const existing = dbw.get('SELECT * FROM drivers WHERE user_id = ?', [req.user.id]);
    if (existing) {
      // Update existing
      dbw.run('UPDATE drivers SET full_name = ?, id_number = ?, available_date = ?, available_time = ?, cities = ?, vehicle_model = ? WHERE user_id = ?',
        [full_name, id_number, available_date, available_time, cities, vehicle_model, req.user.id]);
    } else {
      // Create new
      dbw.run('INSERT INTO drivers (user_id, full_name, id_number, available_date, available_time, cities, vehicle_model) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [req.user.id, full_name, id_number, available_date, available_time, cities, vehicle_model]);
    }
    res.redirect('/driver');
  } catch (e) {
    res.status(400).send('Could not save driver information.');
  }
});

app.get('/dashboard', authRequired(), (req, res) => {
  // Redirect admins and drivers to their respective panels
  if (req.user.role === 'admin') {
    return res.redirect('/admin');
  }
  if (req.user.role === 'driver') {
    return res.redirect('/driver');
  }
  
  // Get all trips with driver information
  const allTrips = dbw.all(`
    SELECT t.*, d.full_name as driver_name, d.vehicle_model
    FROM trips t
    LEFT JOIN drivers d ON d.user_id = t.driver_id
    ORDER BY t.date ASC
  `);
  
  const now = new Date();
  now.setHours(0, 0, 0, 0); // Set to start of day for comparison
  
  // Filter trips: show all future trips (with or without driver)
  const trips = allTrips
    .map(trip => {
      // Parse trip date properly (format: YYYY-MM-DD HH:mm)
      const tripDateStr = trip.date;
      const tripDate = new Date(tripDateStr);
      
      // Check if trip is in the future
      const isFuture = tripDate >= now;
      
      if (isFuture) {
        // Calculate available seats
        const bookingsCount = dbw.get('SELECT COUNT(*) as count FROM bookings WHERE trip_id = ?', [trip.id]).count;
        const availableSeats = (trip.seats || 8) - bookingsCount;
        const hasDriver = trip.driver_id !== null && trip.driver_id !== undefined;
        return {
          ...trip,
          availableSeats: Math.max(0, availableSeats),
          hasDriver: hasDriver
        };
      }
      return null;
    })
    .filter(trip => trip !== null)
    .sort((a, b) => new Date(a.date) - new Date(b.date));
  
  const myBookings = dbw.all(dbw.queries.getBookingsForUser, [req.user.id]);
  const bookings = myBookings; // Ensure bookings is defined for the view
  const errorMessage = req.query.error || null;
  res.render('user/dashboard', { trips, myBookings, bookings, user: res.locals.user, errorMessage });
});

app.post('/book', authRequired(), async (req, res) => {
  const { trip_id } = req.body;
  const wantsJson = req.headers.accept && req.headers.accept.includes('application/json');

  // Check if user already booked this specific trip (prevent duplicate bookings for same trip)
  const existingTripBooking = dbw.get('SELECT * FROM bookings WHERE user_id = ? AND trip_id = ?', [req.user.id, trip_id]);
  if (existingTripBooking) {
    const errorMsg = 'You have already booked this trip. Each user can only book a trip once.';
    if (wantsJson) {
      return res.status(400).json({ success: false, error: errorMsg });
    }
    return res.redirect('/dashboard?error=' + encodeURIComponent(errorMsg));
  }

  // Check if user already has an active (unverified) booking for any trip
  const existingBooking = dbw.get('SELECT * FROM bookings WHERE user_id = ? AND verified = 0', [req.user.id]);
  if (existingBooking) {
    const errorMsg = 'You already have an active booking. Please complete or cancel your current booking before making a new one.';
    if (wantsJson) {
      return res.status(400).json({ success: false, error: errorMsg });
    }
    return res.redirect('/dashboard?error=' + encodeURIComponent(errorMsg));
  }

  const trip = dbw.get('SELECT * FROM trips WHERE id = ?', [trip_id]);
  if (!trip) {
    const errorMsg = 'Trip not found.';
    if (wantsJson) {
      return res.status(404).json({ success: false, error: errorMsg });
    }
    return res.redirect('/dashboard?error=' + encodeURIComponent(errorMsg));
  }

  const bookingCount = dbw.get('SELECT COUNT(*) as count FROM bookings WHERE trip_id = ? AND verified = 0', [trip_id]).count;
  const maxSeats = trip.seats || 8;
  const availableSeats = maxSeats - bookingCount;

  if (availableSeats <= 0) {
    const errorMsg = 'This trip is fully booked. No seats available.';
    if (wantsJson) {
      return res.status(400).json({ success: false, error: errorMsg });
    }
    return res.redirect('/dashboard?error=' + encodeURIComponent(errorMsg));
  }

  try {
    const bookingCode = generateBookingCode();
    dbw.run(dbw.queries.createBooking, [req.user.id, trip_id, bookingCode]);
    if (wantsJson) {
      return res.json({ success: true });
    }
    res.redirect('/dashboard');
  } catch (e) {
    const errorMsg = 'Booking failed. Please try again.';
    if (wantsJson) {
      return res.status(400).json({ success: false, error: errorMsg });
    }
    return res.redirect('/dashboard?error=' + encodeURIComponent(errorMsg));
  }
});

app.post('/book-with-ticket', authRequired(), async (req, res) => {
  try {
    // Get the active booking for the current user
    const myBookings = dbw.all(dbw.queries.getBookingsForUser, [req.user.id]);

    if (!myBookings || myBookings.length === 0) {
      return res.status(400).send('No bookings found. Please book a trip first.');
    }

    // Get the booking (only one active booking allowed)
    const booking = myBookings[0];

    const ticketData = {
      booking_code: booking.booking_code,
      origin: booking.origin,
      destination: booking.destination,
      date: booking.date,
      price: booking.price,
      departure_time: booking.departure_time || '08:00'
    };

    const totalCost = booking.price;

    // QR code contains ONLY the booking code for driver to scan/enter
    const qrCodeData = await QRCode.toDataURL(booking.booking_code, {
      width: 300,
      margin: 2,
      color: {
        dark: '#212529',
        light: '#ffffff'
      }
    });

    res.render('user/ticket', {
      user: req.user.name,
      email: req.user.email,
      ticketData,
      bookingCode: booking.booking_code,
      totalCost,
      qrCodeData,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred while generating the ticket.');
  }
});

app.post('/bookings/delete', authRequired(), (req, res) => {
  const { booking_id } = req.body;
  try {
    dbw.run('DELETE FROM bookings WHERE id = ?', [booking_id]);
    res.redirect('/dashboard');
  } catch (e) {
    res.status(400).send('Could not delete booking.');
  }
});

app.get('/admin', authRequired('admin'), (req, res) => {
  const users = dbw.all(dbw.queries.listUsers);
  const trips = dbw.all(dbw.queries.listTrips);
  const bookings = dbw.all(dbw.queries.listAllBookings);
  const userBookings = dbw.all(`SELECT b.id, u.name as user_name, u.email, t.origin, t.destination, t.date, t.price, b.created_at
                                FROM bookings b JOIN users u ON u.id=b.user_id JOIN trips t ON t.id=b.trip_id
                                ORDER BY u.name, b.created_at DESC`);
  
  // Get bookings per user for detailed view
  const usersWithBookings = users.map(user => {
    const userBookingsList = dbw.all(
      `SELECT b.id, t.origin, t.destination, t.date, t.price, b.created_at
       FROM bookings b JOIN trips t ON t.id = b.trip_id
       WHERE b.user_id = ? ORDER BY b.created_at DESC`,
      [user.id]
    );
    return {
      ...user,
      bookings: userBookingsList,
      totalBookings: userBookingsList.length,
      totalSpent: userBookingsList.reduce((sum, b) => sum + b.price, 0)
    };
  });
  
  // Get available drivers with their info
  const availableDrivers = dbw.all(`
    SELECT u.id, u.name, u.email, d.full_name, d.id_number, d.available_date, d.available_time, d.cities, d.vehicle_model
    FROM users u
    JOIN drivers d ON d.user_id = u.id
    WHERE u.role = 'driver'
    ORDER BY d.available_date, d.available_time
  `);
  
  // Get trips with driver info
  const tripsWithDrivers = trips.map(trip => {
    const driver = trip.driver_id ? dbw.get(`
      SELECT u.name, d.full_name, d.vehicle_model
      FROM users u
      JOIN drivers d ON d.user_id = u.id
      WHERE u.id = ?
    `, [trip.driver_id]) : null;
    return {
      ...trip,
      driver: driver
    };
  });
  
  res.render('admin/index', { users, trips, bookings, userBookings, usersWithBookings, availableDrivers, tripsWithDrivers, user: res.locals.user });
});

app.post('/admin/trips/assign-driver', authRequired('admin'), (req, res) => {
  const { trip_id, driver_id } = req.body;
  try {
    dbw.run('UPDATE trips SET driver_id = ? WHERE id = ?', [driver_id || null, trip_id]);
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send('Could not assign driver.');
  }
});

app.post('/admin/users', authRequired('admin'), (req, res) => {
  const { name, email, password, role } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  try {
    dbw.run(dbw.queries.createUser, [name, email, hash, role || 'user']);
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send('Could not create user.');
  }
});

app.post('/admin/users/update', authRequired('admin'), (req, res) => {
  const { id, name, email, role } = req.body;
  try {
    dbw.run('UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?', [name, email, role, id]);
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send('Could not update user.');
  }
});

app.post('/admin/users/delete', authRequired('admin'), (req, res) => {
  const { id } = req.body;
  try {
    // Delete user's bookings first (cascade)
    dbw.run('DELETE FROM bookings WHERE user_id = ?', [id]);
    // Then delete the user
    dbw.run('DELETE FROM users WHERE id = ?', [id]);
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send('Could not delete user.');
  }
});

app.post('/admin/trips', authRequired('admin'), (req, res) => {
  const { origin, destination, date, price, seats, departure_time } = req.body;
  try {
    // Check if this trip already exists
    const existingTrip = dbw.get(
      'SELECT * FROM trips WHERE origin = ? AND destination = ?',
      [origin, destination]
    );
    
    const tripSeats = seats || 8;
    const depTime = departure_time || '08:00';
    
    if (!existingTrip) {
      // Create the forward trip
      dbw.run(dbw.queries.createTrip, [origin, destination, date, price, tripSeats, depTime]);
      
      // Check if return trip exists
      const returnTripExists = dbw.get(
        'SELECT * FROM trips WHERE origin = ? AND destination = ?',
        [destination, origin]
      );
      
      // Create return trip if it doesn't exist - same day, different randomized time
      if (!returnTripExists) {
        // Parse the forward trip time
        const forwardTime = depTime.split(':');
        const forwardHour = parseInt(forwardTime[0]);
        
        // Generate a different random time (avoid same hour, between 6:00 and 20:00)
        let returnHour;
        do {
          returnHour = Math.floor(Math.random() * 15) + 6; // 6-20
        } while (returnHour === forwardHour);
        
        const returnMinute = Math.floor(Math.random() * 4) * 15; // 0, 15, 30, or 45
        const returnTime = `${returnHour.toString().padStart(2, '0')}:${returnMinute.toString().padStart(2, '0')}`;
        
        // Same date (not next day)
        const dateOnly = date.split(' ')[0]; // Get just the date part
        const returnDate = `${dateOnly} ${returnTime}`;
        
        dbw.run(dbw.queries.createTrip, [destination, origin, returnDate, price, tripSeats, returnTime]);
      }
    }
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send('Could not create trip.');
  }
});

app.post('/admin/trips/delete', authRequired('admin'), (req, res) => {
  const { id } = req.body;
  dbw.run(dbw.queries.deleteTrip, [id]);
  res.redirect('/admin');
});

// 404
app.use((req, res) => {
  res.status(404).render('misc/404', { user: res.locals.user });
});

// Helper function to ensure all trips have return routes
function ensureReturnTrips() {
  const allTrips = dbw.all(dbw.queries.listTrips);
  const existingRoutes = new Set();
  
  // Create a set of existing routes (both directions)
  allTrips.forEach(trip => {
    const routeKey = `${trip.origin}|${trip.destination}`;
    const returnKey = `${trip.destination}|${trip.origin}`;
    existingRoutes.add(routeKey);
    existingRoutes.add(returnKey);
  });
  
  // Find trips that don't have return routes and add them
  allTrips.forEach(trip => {
    const returnKey = `${trip.destination}|${trip.origin}`;
    const forwardKey = `${trip.origin}|${trip.destination}`;
    
    // Check if return trip exists
    const returnTripExists = dbw.get(
      'SELECT * FROM trips WHERE origin = ? AND destination = ?',
      [trip.destination, trip.origin]
    );
    
    if (!returnTripExists) {
      // Parse the forward trip time
      const forwardDepTime = trip.departure_time || '08:00';
      const forwardTime = forwardDepTime.split(':');
      const forwardHour = parseInt(forwardTime[0]);
      
      // Generate a different random time (avoid same hour, between 6:00 and 20:00)
      let returnHour;
      do {
        returnHour = Math.floor(Math.random() * 15) + 6; // 6-20
      } while (returnHour === forwardHour);
      
      const returnMinute = Math.floor(Math.random() * 4) * 15; // 0, 15, 30, or 45
      const returnTime = `${returnHour.toString().padStart(2, '0')}:${returnMinute.toString().padStart(2, '0')}`;
      
      // Same date (not next day) - extract date part from trip.date
      const dateOnly = trip.date.split(' ')[0]; // Get just the date part
      const returnDate = `${dateOnly} ${returnTime}`;
      
      // Create return trip with same price, seats, but different time
      const returnSeats = trip.seats || 8;
      dbw.run(dbw.queries.createTrip, [
        trip.destination,
        trip.origin,
        returnDate,
        trip.price,
        returnSeats,
        returnTime
      ]);
    }
  });
}

(async () => {
  await dbw.init();
  // Auto-seed defaults if empty
  const userCount = dbw.all('SELECT COUNT(*) as c FROM users')[0].c;
  const tripCount = dbw.all('SELECT COUNT(*) as c FROM trips')[0].c;
  if (userCount == 0) {
    const adminHash = bcrypt.hashSync('admin123', 10);
    const userHash = bcrypt.hashSync('user123', 10);
    dbw.run(dbw.queries.createUser, ['Admin', 'admin@tt.tn', adminHash, 'admin']);
    dbw.run(dbw.queries.createUser, ['User', 'user@tt.tn', userHash, 'user']);
  }
  
  // ALWAYS ensure default admin account exists on every deployment
  // This admin account will always be available for login on Render.com
  // Credentials: admin@loagi.tn / AdminLoagi2024!
  try {
    const defaultAdmin = dbw.get(dbw.queries.getUserByEmail, ['admin@loagi.tn']);
    if (!defaultAdmin) {
      const defaultAdminHash = bcrypt.hashSync('AdminLoagi2024!', 10);
      dbw.run(dbw.queries.createUser, ['System Admin', 'admin@loagi.tn', defaultAdminHash, 'admin']);
      console.log('Default admin account created: admin@loagi.tn');
    } else {
      // Update password in case it was changed - ensures consistent login on deployment
      const defaultAdminHash = bcrypt.hashSync('AdminLoagi2024!', 10);
      dbw.run('UPDATE users SET password_hash = ?, role = ? WHERE email = ?', [defaultAdminHash, 'admin', 'admin@loagi.tn']);
      console.log('Default admin account verified: admin@loagi.tn');
    }
  } catch (e) {
    console.log('Default admin setup note:', e.message);
  }

  // Keep legacy admin@gmail.com for backwards compatibility
  const adminGmail = dbw.get(dbw.queries.getUserByEmail, ['admin@gmail.com']);
  if (!adminGmail) {
    const adminGmailHash = bcrypt.hashSync('admin1234', 10);
    dbw.run(dbw.queries.createUser, ['Admin', 'admin@gmail.com', adminGmailHash, 'admin']);
  }
  
  // Migrate users table to support driver role if needed
  try {
    const tableInfo = dbw.all("PRAGMA table_info(users)");
    if (tableInfo.length > 0) {
      // Backup existing users data
      const allUsers = dbw.all('SELECT * FROM users');
      
      // Temporarily disable foreign keys
      dbw.run('PRAGMA foreign_keys = OFF');
      
      // Create backup table
      dbw.run('DROP TABLE IF EXISTS users_backup');
      dbw.run('CREATE TABLE users_backup AS SELECT * FROM users');
      
      // Drop and recreate users table with new constraint
      dbw.run('DROP TABLE users');
      dbw.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','user','driver')) DEFAULT 'user'
      )`);
      
      // Restore users data
      allUsers.forEach(user => {
        try {
          dbw.run('INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
            [user.id, user.name, user.email, user.password_hash, user.role]);
        } catch (e) {
          // Skip if duplicate or other error
        }
      });
      
      // Re-enable foreign keys
      dbw.run('PRAGMA foreign_keys = ON');
      
      // Clean up backup
      dbw.run('DROP TABLE IF EXISTS users_backup');
    }
  } catch (e) {
    // If migration fails, continue - table might already be correct
    console.log('Migration note:', e.message);
  }
  
  // Ensure driver@gmail.com exists
  try {
    const driverGmail = dbw.get(dbw.queries.getUserByEmail, ['driver@gmail.com']);
    if (!driverGmail) {
      const driverHash = bcrypt.hashSync('driver1234', 10);
      dbw.run(dbw.queries.createUser, ['Driver', 'driver@gmail.com', driverHash, 'driver']);
    }
  } catch (e) {
    // If this fails, the constraint might still need updating - will be handled on next restart
    console.log('Driver creation note:', e.message);
  }
  // Migrate existing trips to add seats, departure_time, and driver_id if missing
  const tableInfo = dbw.all("PRAGMA table_info(trips)");
  const hasSeats = tableInfo.some(col => col.name === 'seats');
  const hasDepartureTime = tableInfo.some(col => col.name === 'departure_time');
  const hasDriverId = tableInfo.some(col => col.name === 'driver_id');
  
  if (!hasSeats) {
    try {
      dbw.run('ALTER TABLE trips ADD COLUMN seats INTEGER DEFAULT 8');
    } catch (e) {
      // Ignore if fails
    }
  }
  if (!hasDepartureTime) {
    try {
      dbw.run('ALTER TABLE trips ADD COLUMN departure_time TEXT DEFAULT "08:00"');
    } catch (e) {
      // Ignore if fails
    }
  }
  if (!hasDriverId) {
    try {
      dbw.run('ALTER TABLE trips ADD COLUMN driver_id INTEGER');
    } catch (e) {
      // Ignore if fails
    }
  }
  
  // Create drivers table if it doesn't exist
  try {
    dbw.run(`CREATE TABLE IF NOT EXISTS drivers (
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
    )`);
  } catch (e) {
    // Ignore if fails
  }

  // Migrate bookings table to add booking_code and verified columns if missing
  try {
    const bookingsTableInfo = dbw.all("PRAGMA table_info(bookings)");
    const hasBookingCode = bookingsTableInfo.some(col => col.name === 'booking_code');
    const hasVerified = bookingsTableInfo.some(col => col.name === 'verified');

    if (!hasBookingCode) {
      // Need to recreate the bookings table with the new columns
      // First, backup existing bookings
      const existingBookings = dbw.all('SELECT * FROM bookings');

      // Drop old table and create new one
      dbw.run('DROP TABLE IF EXISTS bookings');
      dbw.run(`CREATE TABLE bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        trip_id INTEGER NOT NULL,
        booking_code TEXT UNIQUE NOT NULL,
        verified INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(trip_id) REFERENCES trips(id)
      )`);

      // Restore old bookings with generated booking codes
      existingBookings.forEach(booking => {
        const newCode = generateBookingCode();
        dbw.run('INSERT INTO bookings (user_id, trip_id, booking_code, verified, created_at) VALUES (?, ?, ?, ?, ?)',
          [booking.user_id, booking.trip_id, newCode, booking.verified || 0, booking.created_at]);
      });

      console.log('Migrated bookings table with booking_code column');
    } else if (!hasVerified) {
      // Just add verified column
      dbw.run('ALTER TABLE bookings ADD COLUMN verified INTEGER DEFAULT 0');
      console.log('Added verified column to bookings table');
    }
  } catch (e) {
    console.log('Bookings migration note:', e.message);
  }
  
  // Update existing trips without seats or departure_time
  const tripsToUpdate = dbw.all('SELECT * FROM trips WHERE seats IS NULL OR departure_time IS NULL OR seats = "" OR departure_time = ""');
  tripsToUpdate.forEach(trip => {
    const randomSeats = Math.floor(Math.random() * 9); // 0-8
    const hours = ['06:00', '07:00', '08:00', '09:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00'];
    const randomTime = hours[Math.floor(Math.random() * hours.length)];
    const finalSeats = trip.seats !== null && trip.seats !== '' ? trip.seats : randomSeats;
    const finalTime = trip.departure_time && trip.departure_time !== '' ? trip.departure_time : randomTime;
    dbw.run('UPDATE trips SET seats = ?, departure_time = ? WHERE id = ?', 
      [finalSeats, finalTime, trip.id]);
  });
  
  if (tripCount == 0) {
    // Seed initial trips with return routes, random seats, and departure times
    const hours = ['06:00', '07:00', '08:00', '09:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00'];
    const now = new Date();
    const initialTrips = [
      ['Tunis','Sousse', new Date(now.getTime() + 1*24*60*60*1000).toISOString().slice(0, 16).replace('T', ' '), 20, Math.floor(Math.random() * 9), hours[Math.floor(Math.random() * hours.length)]],
      ['Tunis','Sfax', new Date(now.getTime() + 2*24*60*60*1000).toISOString().slice(0, 16).replace('T', ' '), 36, Math.floor(Math.random() * 9), hours[Math.floor(Math.random() * hours.length)]],
      ['Sousse','Sidi Bouzid', new Date(now.getTime() + 3*24*60*60*1000).toISOString().slice(0, 16).replace('T', ' '), 28, Math.floor(Math.random() * 9), hours[Math.floor(Math.random() * hours.length)]],
      ['Tunis','Bizerte', new Date(now.getTime() + 4*24*60*60*1000).toISOString().slice(0, 16).replace('T', ' '), 15, Math.floor(Math.random() * 9), hours[Math.floor(Math.random() * hours.length)]],
      ['Tunis','Gabès', new Date(now.getTime() + 5*24*60*60*1000).toISOString().slice(0, 16).replace('T', ' '), 48, Math.floor(Math.random() * 9), hours[Math.floor(Math.random() * hours.length)]],
      ['Sfax','Gafsa', new Date(now.getTime() + 6*24*60*60*1000).toISOString().slice(0, 16).replace('T', ' '), 30, Math.floor(Math.random() * 9), hours[Math.floor(Math.random() * hours.length)]],
    ];
    
    // Add forward trips
    initialTrips.forEach(t => dbw.run(dbw.queries.createTrip, t));
    
    // Add return trips - same day, different randomized time
    initialTrips.forEach(t => {
      const [origin, destination, date, price, seats, depTime] = t;
      
      // Parse the forward trip time
      const forwardTime = depTime.split(':');
      const forwardHour = parseInt(forwardTime[0]);
      
      // Generate a different random time (avoid same hour, between 6:00 and 20:00)
      let returnHour;
      do {
        returnHour = Math.floor(Math.random() * 15) + 6; // 6-20
      } while (returnHour === forwardHour);
      
      const returnMinute = Math.floor(Math.random() * 4) * 15; // 0, 15, 30, or 45
      const returnTime = `${returnHour.toString().padStart(2, '0')}:${returnMinute.toString().padStart(2, '0')}`;
      
      // Same date (not next day)
      const dateOnly = date.split(' ')[0]; // Get just the date part
      const returnDate = `${dateOnly} ${returnTime}`;
      
      dbw.run(dbw.queries.createTrip, [destination, origin, returnDate, price, seats, returnTime]);
    });
  } else {
    // Ensure existing trips have return routes
    ensureReturnTrips();
  }

  const PORT = process.env.PORT || 3000;
  const server = app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
})();

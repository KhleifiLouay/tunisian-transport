
require('dotenv').config();
const bcrypt = require('bcryptjs');
const { init, run, queries } = require('../src/db-sqljs');

(async () => {
  await init();
  run('DELETE FROM bookings', []);
  run('DELETE FROM users', []);
  run('DELETE FROM trips', []);

  const adminHash = bcrypt.hashSync('admin123', 10);
  const userHash = bcrypt.hashSync('user123', 10);
  run(queries.createUser, ['Admin', 'admin@tt.tn', adminHash, 'admin']);
  run(queries.createUser, ['User', 'user@tt.tn', userHash, 'user']);

  const trips = [
    ['Tunis', 'Sousse', '2025-11-10 08:00', 20],
    ['Tunis', 'Sfax', '2025-11-11 07:30', 36],
    ['Sousse', 'Sidi Bouzid', '2025-11-12 09:00', 28],
    ['Tunis', 'Bizerte', '2025-11-13 10:00', 15],
    ['Tunis', 'Gabès', '2025-11-14 06:00', 48],
    ['Sfax', 'Gafsa', '2025-11-15 08:30', 30],
  ];
  trips.forEach(t => run(queries.createTrip, t));

  console.log('Database initialized with sample data.');
})();
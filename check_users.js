const dbw = require('./src/db-sqljs');

dbw.init().then(() => {
  const users = dbw.all('SELECT id, name, email, role FROM users');
  console.log('Saved Users:');
  users.forEach(u => console.log(`ID: ${u.id}, Name: ${u.name}, Email: ${u.email}, Role: ${u.role}`));
  process.exit(0);
}).catch(err => console.error(err));
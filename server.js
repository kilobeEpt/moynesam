const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./moynesam.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE,
                password TEXT,
                full_name TEXT,
                phone TEXT,
                email TEXT
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS Services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS Orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                address TEXT,
                phone TEXT,
                service_type TEXT,
                other_service TEXT,
                date_time TEXT,
                payment_type TEXT,
                status TEXT,
                cancel_reason TEXT,
                FOREIGN KEY(user_id) REFERENCES Users(id)
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS Content (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE,
                value TEXT
            )
        `);

        // Insert sample services
        const services = [
            'общий клининг',
            'генеральная уборка',
            'последстроительная уборка',
            'химчистка ковров и мебели'
        ];
        services.forEach(name => {
            db.run('INSERT OR IGNORE INTO Services (name) VALUES (?)', [name]);
        });

        // Insert sample users
        for (let i = 1; i <= 10; i++) {
            const login = `user${i}`;
            const password = bcrypt.hashSync(`password${i}`, 10);
            const full_name = `Пользователь ${i}`;
            const phone = `+7(900)-123-45-${i < 10 ? '0' + i : i}`;
            const email = `user${i}@example.com`;
            db.run('INSERT OR IGNORE INTO Users (login, password, full_name, phone, email) VALUES (?, ?, ?, ?, ?)', 
                [login, password, full_name, phone, email]);
        }

        // Insert admin user
        db.run('INSERT OR IGNORE INTO Users (login, password, full_name, phone, email) VALUES (?, ?, ?, ?, ?)', 
            ['adminka', bcrypt.hashSync('password', 10), 'Администратор', '+7(999)-999-99-99', 'admin@example.com']);

        // Insert sample orders
        const statuses = ['новая', 'в работе', 'выполнено', 'отменено'];
        for (let i = 1; i <= 10; i++) {
            const user_id = i;
            const address = `Адрес ${i}`;
            const phone = `+7(900)-123-45-${i < 10 ? '0' + i : i}`;
            const service_type = services[i % 4];
            const date_time = new Date(`2025-06-${i < 10 ? '0' + i : i}`).toISOString();
            const payment_type = i % 2 ? 'наличные' : 'банковская карта';
            const status = statuses[i % 4];
            const cancel_reason = status === 'отменено' ? 'Причина отмены' : null;
            db.run('INSERT OR IGNORE INTO Orders (user_id, address, phone, service_type, date_time, payment_type, status, cancel_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
                [user_id, address, phone, service_type, date_time, payment_type, status, cancel_reason]);
        }

        // Insert default content
        const content = [
            ['home_title', 'Чистота начинается с нас!'],
            ['home_subtitle', 'Профессиональные клининговые услуги для вашего дома и офиса.'],
            ['about_content', '«Мой Не Сам» — это ваш надежный партнер в создании чистоты и уюта. Мы предлагаем широкий спектр клининговых услуг для жилых и коммерческих помещений. Наша миссия — сделать вашу жизнь проще и комфортнее, предоставляя профессиональные услуги по уборке. С 2023 года мы помогаем тысячам клиентов поддерживать чистоту, используя современное оборудование и экологичные материалы. Доверьте уборку нам и наслаждайтесь свободным временем!']
        ];
        content.forEach(([key, value]) => {
            db.run('INSERT OR REPLACE INTO Content (key, value) VALUES (?, ?)', [key, value]);
        });
    });
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Токен отсутствует' });

    jwt.verify(token, 'secret', (err, user) => {
        if (err) return res.status(403).json({ error: 'Недействительный токен' });
        req.user = user;
        next();
    });
}

app.post('/api/register', (req, res) => {
    const { login, password, full_name, phone, email } = req.body;
    
    if (!login || login.length < 3) {
        return res.status(400).json({ error: 'Логин должен быть не короче 3 символов' });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен быть не короче 6 символов' });
    }
    if (!full_name || !/^[А-Яа-я\s]+$/.test(full_name)) {
        return res.status(400).json({ error: 'ФИО должно содержать только кириллицу и пробелы' });
    }
    if (!phone || !/^\+7\(\d{3}\)-\d{3}-\d{2}-\d{2}$/.test(phone)) {
        return res.status(400).json({ error: 'Телефон должен быть в формате +7(XXX)-XXX-XX-XX' });
    }
    if (!email || !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
        return res.status(400).json({ error: 'Некорректный формат email' });
    }

    const sanitizedLogin = sanitizeHtml(login);
    const sanitizedFullName = sanitizeHtml(full_name);
    const sanitizedPhone = sanitizeHtml(phone);
    const sanitizedEmail = sanitizeHtml(email);

    db.get('SELECT id FROM Users WHERE login = ? OR email = ?', [sanitizedLogin, sanitizedEmail], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        if (row) {
            return res.status(400).json({ error: 'Логин или email уже занят' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        db.run('INSERT INTO Users (login, password, full_name, phone, email) VALUES (?, ?, ?, ?, ?)', 
            [sanitizedLogin, hashedPassword, sanitizedFullName, sanitizedPhone, sanitizedEmail], 
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
                res.json({ message: 'Регистрация успешна' });
            }
        );
    });
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;
    const sanitizedLogin = sanitizeHtml(login);

    db.get('SELECT * FROM Users WHERE login = ?', [sanitizedLogin], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }

        if (sanitizedLogin === 'adminka' && password === 'password') {
            const token = jwt.sign({ id: user.id, isAdmin: true }, 'secret', { expiresIn: '1h' });
            return res.json({ token, userId: user.id, isAdmin: true });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }

        const token = jwt.sign({ id: user.id, isAdmin: false }, 'secret', { expiresIn: '1h' });
        res.json({ token, userId: user.id, isAdmin: false });
    });
});

app.get('/api/services', (req, res) => {
    db.all('SELECT * FROM Services', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(rows);
    });
});

app.post('/api/services', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    const { name } = req.body;
    const sanitizedName = sanitizeHtml(name);
    
    if (!sanitizedName || sanitizedName.length < 3) {
        return res.status(400).json({ error: 'Название услуги должно быть не короче 3 символов' });
    }

    db.run('INSERT INTO Services (name) VALUES (?)', [sanitizedName], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json({ message: 'Услуга добавлена' });
    });
});

app.delete('/api/services/:id', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    const id = req.params.id;
    db.run('DELETE FROM Services WHERE id = ?', [id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Услуга не найдена' });
        }
        res.json({ message: 'Услуга удалена' });
    });
});

app.get('/api/orders', authenticateToken, (req, res) => {
    db.all('SELECT * FROM Orders WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(rows);
    });
});

app.post('/api/orders', authenticateToken, (req, res) => {
    const { address, phone, service_type, other_service, date_time, payment_type } = req.body;
    
    if (!address) {
        return res.status(400).json({ error: 'Укажите адрес' });
    }
    if (!phone || !/^\+7\(\d{3}\)-\d{3}-\d{2}-\d{2}$/.test(phone)) {
        return res.status(400).json({ error: 'Телефон должен быть в формате +7(XXX)-XXX-XX-XX' });
    }
    if (!service_type && !other_service) {
        return res.status(400).json({ error: 'Выберите услугу или укажите иную' });
    }
    if (!date_time) {
        return res.status(400).json({ error: 'Укажите дату и время' });
    }
    if (!payment_type) {
        return res.status(400).json({ error: 'Выберите тип оплаты' });
    }

    const sanitizedAddress = sanitizeHtml(address);
    const sanitizedPhone = sanitizeHtml(phone);
    const sanitizedServiceType = sanitizeHtml(service_type);
    const sanitizedOtherService = sanitizeHtml(other_service);
    const sanitizedDateTime = sanitizeHtml(date_time);
    const sanitizedPaymentType = sanitizeHtml(payment_type);

    db.run('INSERT INTO Orders (user_id, address, phone, service_type, other_service, date_time, payment_type, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
        [req.user.id, sanitizedAddress, sanitizedPhone, sanitizedServiceType, sanitizedOtherService, sanitizedDateTime, sanitizedPaymentType, 'новая'], 
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json({ message: 'Заявка создана' });
        }
    );
});

app.get('/api/admin-orders', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    db.all('SELECT Orders.*, Users.full_name FROM Orders JOIN Users ON Orders.user_id = Users.id', [], (err, rows) => {
        if (err) {
            returnimgs
        }
        res.json(rows);
    });
});

app.patch('/api/admin-orders', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    const { id, status, cancel_reason } = req.body;
    const sanitizedStatus = sanitizeHtml(status);
    const sanitizedCancelReason = cancel_reason ? sanitizeHtml(cancel_reason) : null;

    if (!id || !sanitizedStatus) {
        return res.status(400).json({ error: 'Некорректные данные' });
    }

    db.run('UPDATE Orders SET status = ?, cancel_reason = ? WHERE id = ?', 
        [sanitizedStatus, sanitizedCancelReason, id], 
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Заявка не найдена' });
            }
            res.json({ message: 'Статус обновлен' });
        }
    );
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    db.all('SELECT id, login, full_name, phone, email FROM Users WHERE login != "adminka"', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(rows);
    });
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    const id = req.params.id;
    db.run('DELETE FROM Users WHERE id = ? AND login != "adminka"', [id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        db.run('DELETE FROM Orders WHERE user_id = ?', [id]);
        res.json({ message: 'Пользователь удален' });
    });
});

app.get('/api/content', (req, res) => {
    db.all('SELECT key, value FROM Content', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        const content = {};
        rows.forEach(row => {
            content[row.key] = row.value;
        });
        res.json(content);
    });
});

app.put('/api/content', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    const { home_title, home_subtitle, about_content } = req.body;
    
    if (!home_title || !home_subtitle || !about_content) {
        return res.status(400).json({ error: 'Все поля должны быть заполнены' });
    }

    const sanitizedHomeTitle = sanitizeHtml(home_title);
    const sanitizedHomeSubtitle = sanitizeHtml(home_subtitle);
    const sanitizedAboutContent = sanitizeHtml(about_content);

    db.serialize(() => {
        db.run('INSERT OR REPLACE INTO Content (key, value) VALUES (?, ?)', ['home_title', sanitizedHomeTitle]);
        db.run('INSERT OR REPLACE INTO Content (key, value) VALUES (?, ?)', ['home_subtitle', sanitizedHomeSubtitle]);
        db.run('INSERT OR REPLACE INTO Content (key, value) VALUES (?, ?)', ['about_content', sanitizedAboutContent], 
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
                res.json({ message: 'Контент обновлен' });
            }
        );
    });
});

// Serve index.html for all non-API routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
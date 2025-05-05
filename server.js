const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const winston = require('winston');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret'; // Use environment variable in production
const DB_PATH = path.join(__dirname, 'moynesam.db');

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

// Database setup
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        logger.error('Database connection error:', err.message);
        throw err;
    }
    logger.info('Connected to SQLite database');
});

// Initialize database tables
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            isAdmin BOOLEAN DEFAULT 0
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            address TEXT NOT NULL,
            phone TEXT NOT NULL,
            service_type TEXT NOT NULL,
            other_service TEXT,
            date_time DATETIME NOT NULL,
            payment_type TEXT NOT NULL,
            status TEXT DEFAULT 'новая',
            cancel_reason TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            photo_url TEXT,
            description TEXT
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS content (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            home_title TEXT,
            home_subtitle TEXT,
            about_content TEXT
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS cta_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Insert default data if not exists
    db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
        if (err) logger.error('Error checking users:', err.message);
        if (row.count === 0) {
            bcrypt.hash('admin123', 10, (err, hash) => {
                if (err) logger.error('Error hashing admin password:', err.message);
                db.run(`
                    INSERT INTO users (login, password, full_name, phone, email, isAdmin)
                    VALUES (?, ?, ?, ?, ?, ?)
                `, ['admin', hash, 'Админ', '+79999999999', 'admin@moynesam.ru', 1], (err) => {
                    if (err) logger.error('Error inserting default admin:', err.message);
                    else logger.info('Default admin created');
                });
            });
        }
    });
    db.get('SELECT COUNT(*) as count FROM services', (err, row) => {
        if (err) logger.error('Error checking services:', err.message);
        if (row.count === 0) {
            db.run(`
                INSERT INTO services (name, photo_url, description)
                VALUES (?, ?, ?), (?, ?, ?)
            `, [
                'Стандартная уборка', 'https://images.unsplash.com/photo-1600585154340-be6161a56a0c', 'Полная уборка помещений',
                'Генеральная уборка', 'https://images.unsplash.com/photo-1581578735764-2f38729f6804', 'Глубокая чистка всех поверхностей'
            ], (err) => {
                if (err) logger.error('Error inserting default services:', err.message);
            });
        }
    });
    db.get('SELECT COUNT(*) as count FROM content', (err, row) => {
        if (err) logger.error('Error checking content:', err.message);
        if (row.count === 0) {
            db.run(`
                INSERT INTO content (home_title, home_subtitle, about_content)
                VALUES (?, ?, ?)
            `, [
                'Чистота с любовью!',
                'Профессиональная уборка для дома и офиса.',
                '«Мой Не Сам» — команда профессионалов, делающая дома и офисы чище с 2023 года.'
            ], (err) => {
                if (err) logger.error('Error inserting default content:', err.message);
            });
        }
    });
});

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting for login endpoint
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit to 5 login attempts per IP
    message: 'Слишком много попыток входа, попробуйте снова через 15 минут'
});
app.use('/api/login', loginLimiter);

// Authentication middleware
const authenticate = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        logger.warn('No token provided');
        return res.status(401).json({ message: 'Требуется авторизация' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        db.get('SELECT * FROM users WHERE id = ?', [decoded.userId], (err, user) => {
            if (err || !user) {
                logger.warn('User not found for token:', token);
                return res.status(401).json({ message: 'Пользователь не найден' });
            }
            req.user = user;
            next();
        });
    } catch (err) {
        logger.error('Token verification error:', err.message);
        return res.status(401).json({ message: 'Неверный или истекший токен' });
    }
};

// Admin middleware
const isAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        logger.warn('Non-admin user attempted admin access:', req.user.id);
        return res.status(403).json({ message: 'Доступ только для администраторов' });
    }
    next();
};

// Global error handling middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err.message, err.stack);
    res.status(500).json({ message: 'Ошибка сервера' });
});

// Serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Check session
app.get('/api/check-session', authenticate, (req, res) => {
    res.json({ userId: req.user.id, isAdmin: req.user.isAdmin });
});

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { login, password, full_name, phone, email } = req.body;
        if (!login || !password || !full_name || !phone || !email) {
            return res.status(400).json({ message: 'Заполните все поля' });
        }
        const sanitizedLogin = sanitizeHtml(login.trim());
        const sanitizedFullName = sanitizeHtml(full_name.trim());
        const sanitizedPhone = sanitizeHtml(phone.trim());
        const sanitizedEmail = sanitizeHtml(email.trim());
        if (sanitizedLogin.length < 3) {
            return res.status(400).json({ message: 'Логин должен быть длиннее 2 символов' });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: 'Пароль должен быть длиннее 5 символов' });
        }
        if (!sanitizedPhone.match(/^\+7\d{10}$/)) {
            return res.status(400).json({ message: 'Неверный формат телефона' });
        }
        if (!sanitizedEmail.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
            return res.status(400).json({ message: 'Неверный формат email' });
        }
        db.get('SELECT id FROM users WHERE login = ?', [sanitizedLogin], async (err, row) => {
            if (err) {
                logger.error('Database error checking login:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            if (row) {
                return res.status(400).json({ message: 'Логин уже занят' });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(`
                INSERT INTO users (login, password, full_name, phone, email, isAdmin)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [sanitizedLogin, hashedPassword, sanitizedFullName, sanitizedPhone, sanitizedEmail, false], function(err) {
                if (err) {
                    logger.error('Database error inserting user:', err.message);
                    return res.status(500).json({ message: 'Ошибка сервера' });
                }
                logger.info('User registered:', sanitizedLogin);
                res.status(201).json({ message: 'Регистрация успешна' });
            });
        });
    } catch (error) {
        logger.error('Register error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { login, password } = req.body;
        if (!login || !password) {
            return res.status(400).json({ message: 'Заполните все поля' });
        }
        const sanitizedLogin = sanitizeHtml(login.trim());
        db.get('SELECT * FROM users WHERE login = ?', [sanitizedLogin], async (err, user) => {
            if (err) {
                logger.error('Database error fetching user:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            if (!user || !(await bcrypt.compare(password, user.password))) {
                logger.warn('Invalid login attempt:', sanitizedLogin);
                return res.status(401).json({ message: 'Неверный логин или пароль' });
            }
            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 60 * 60 * 1000 });
            logger.info('User logged in:', sanitizedLogin);
            res.json({ userId: user.id, isAdmin: user.isAdmin });
        });
    } catch (error) {
        logger.error('Login error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    logger.info('User logged out');
    res.json({ message: 'Выход выполнен' });
});

// Orders
app.get('/api/orders', authenticate, (req, res) => {
    db.all('SELECT * FROM orders WHERE user_id = ?', [req.user.id], (err, orders) => {
        if (err) {
            logger.error('Database error fetching orders:', err.message);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }
        res.json(orders);
    });
});

app.post('/api/orders', authenticate, async (req, res) => {
    try {
        const { address, phone, service_type, other_service, date_time, payment_type } = req.body;
        if (!address || !phone || !date_time || !payment_type || (!service_type && !other_service)) {
            return res.status(400).json({ message: 'Заполните все обязательные поля' });
        }
        const sanitizedAddress = sanitizeHtml(address.trim());
        const sanitizedPhone = sanitizeHtml(phone.trim());
        const sanitizedServiceType = sanitizeHtml(service_type ? service_type.trim() : '');
        const sanitizedOtherService = sanitizeHtml(other_service ? other_service.trim() : '');
        const sanitizedDateTime = sanitizeHtml(date_time.trim());
        const sanitizedPaymentType = sanitizeHtml(payment_type.trim());
        if (!sanitizedPhone.match(/^\+7\d{10}$/)) {
            return res.status(400).json({ message: 'Неверный формат телефона' });
        }
        db.run(`
            INSERT INTO orders (user_id, full_name, address, phone, service_type, other_service, date_time, payment_type, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            req.user.id,
            req.user.full_name,
            sanitizedAddress,
            sanitizedPhone,
            sanitizedServiceType || 'Иная услуга',
            sanitizedOtherService,
            sanitizedDateTime,
            sanitizedPaymentType,
            'новая'
        ], function(err) {
            if (err) {
                logger.error('Database error inserting order:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            logger.info('Order created:', this.lastID);
            res.status(201).json({ message: 'Заявка создана' });
        });
    } catch (error) {
        logger.error('Create order error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Admin Orders
app.get('/api/admin-orders', authenticate, isAdmin, (req, res) => {
    db.all('SELECT * FROM orders', (err, orders) => {
        if (err) {
            logger.error('Database error fetching admin orders:', err.message);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }
        res.json(orders);
    });
});

app.patch('/api/admin-orders', authenticate, isAdmin, async (req, res) => {
    try {
        const { id, status, cancel_reason } = req.body;
        if (!id) {
            return res.status(400).json({ message: 'ID заявки обязателен' });
        }
        db.get('SELECT * FROM orders WHERE id = ?', [id], (err, order) => {
            if (err) {
                logger.error('Database error fetching order:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            if (!order) {
                return res.status(404).json({ message: 'Заявка не найдена' });
            }
            const sanitizedStatus = status ? sanitizeHtml(status.trim()) : order.status;
            const sanitizedCancelReason = cancel_reason !== undefined ? sanitizeHtml(cancel_reason.trim()) : order.cancel_reason;
            if (status && !['новая', 'в работе', 'выполнено', 'отменено'].includes(sanitizedStatus)) {
                return res.status(400).json({ message: 'Неверный статус' });
            }
            if (cancel_reason !== undefined && sanitizedCancelReason && sanitizedCancelReason.length < 3) {
                return res.status(400).json({ message: 'Причина отмены должна быть длиннее 2 символов' });
            }
            db.run(`
                UPDATE orders SET status = ?, cancel_reason = ? WHERE id = ?
            `, [sanitizedStatus, sanitizedCancelReason, id], (err) => {
                if (err) {
                    logger.error('Database error updating order:', err.message);
                    return res.status(500).json({ message: 'Ошибка сервера' });
                }
                logger.info('Order updated:', id);
                res.json({ message: status ? 'Статус обновлен' : 'Причина обновлена' });
            });
        });
    } catch (error) {
        logger.error('Update admin order error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Services
app.get('/api/services', (req, res) => {
    db.all('SELECT * FROM services', (err, services) => {
        if (err) {
            logger.error('Database error fetching services:', err.message);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }
        res.json(services);
    });
});

app.post('/api/services', authenticate, isAdmin, async (req, res) => {
    try {
        const { name, photo_url, description } = req.body;
        const sanitizedName = sanitizeHtml(name ? name.trim() : '');
        const sanitizedPhotoUrl = sanitizeHtml(photo_url ? photo_url.trim() : '');
        const sanitizedDescription = sanitizeHtml(description ? description.trim() : '');
        if (!sanitizedName || sanitizedName.length < 3) {
            return res.status(400).json({ message: 'Название должно быть длиннее 2 символов' });
        }
        db.run(`
            INSERT INTO services (name, photo_url, description)
            VALUES (?, ?, ?)
        `, [
            sanitizedName,
            sanitizedPhotoUrl || 'https://images.unsplash.com/photo-1600585154340-be6161a56a0c',
            sanitizedDescription
        ], function(err) {
            if (err) {
                logger.error('Database error inserting service:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            logger.info('Service created:', this.lastID);
            res.status(201).json({ message: 'Услуга добавлена' });
        });
    } catch (error) {
        logger.error('Create service error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.put('/api/services/:id', authenticate, isAdmin, async (req, res) => {
    try {
        const { name, photo_url, description } = req.body;
        const id = parseInt(req.params.id);
        const sanitizedName = sanitizeHtml(name ? name.trim() : '');
        const sanitizedPhotoUrl = sanitizeHtml(photo_url ? photo_url.trim() : '');
        const sanitizedDescription = sanitizeHtml(description ? description.trim() : '');
        if (!sanitizedName || sanitizedName.length < 3) {
            return res.status(400).json({ message: 'Название должно быть длиннее 2 символов' });
        }
        db.get('SELECT * FROM services WHERE id = ?', [id], (err, service) => {
            if (err) {
                logger.error('Database error fetching service:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            if (!service) {
                return res.status(404).json({ message: 'Услуга не найдена' });
            }
            db.run(`
                UPDATE services SET name = ?, photo_url = ?, description = ? WHERE id = ?
            `, [
                sanitizedName,
                sanitizedPhotoUrl || service.photo_url,
                sanitizedDescription || service.description,
                id
            ], (err) => {
                if (err) {
                    logger.error('Database error updating service:', err.message);
                    return res.status(500).json({ message: 'Ошибка сервера' });
                }
                logger.info('Service updated:', id);
                res.json({ message: 'Услуга обновлена' });
            });
        });
    } catch (error) {
        logger.error('Update service error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.delete('/api/services/:id', authenticate, isAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    db.get('SELECT * FROM services WHERE id = ?', [id], (err, service) => {
        if (err) {
            logger.error('Database error fetching service:', err.message);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }
        if (!service) {
            return res.status(404).json({ message: 'Услуга не найдена' });
        }
        db.run('DELETE FROM services WHERE id = ?', [id], (err) => {
            if (err) {
                logger.error('Database error deleting service:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            logger.info('Service deleted:', id);
            res.json({ message: 'Услуга удалена' });
        });
    });
});

// Content
app.get('/api/content', (req, res) => {
    db.get('SELECT * FROM content LIMIT 1', (err, content) => {
        if (err) {
            logger.error('Database error fetching content:', err.message);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }
        res.json(content || {
            home_title: 'Чистота с любовью!',
            home_subtitle: 'Профессиональная уборка для дома и офиса.',
            about_content: '«Мой Не Сам» — команда профессионалов, делающая дома и офисы чище с 2023 года.'
        });
    });
});

app.put('/api/content', authenticate, isAdmin, async (req, res) => {
    try {
        const { home_title, home_subtitle, about_content } = req.body;
        const sanitizedHomeTitle = sanitizeHtml(home_title ? home_title.trim() : '');
        const sanitizedHomeSubtitle = sanitizeHtml(home_subtitle ? home_subtitle.trim() : '');
        const sanitizedAboutContent = sanitizeHtml(about_content ? about_content.trim() : '');
        if (!sanitizedHomeTitle || !sanitizedHomeSubtitle || !sanitizedAboutContent) {
            return res.status(400).json({ message: 'Заполните все поля' });
        }
        db.run(`
            INSERT OR REPLACE INTO content (id, home_title, home_subtitle, about_content)
            VALUES (1, ?, ?, ?)
        `, [sanitizedHomeTitle, sanitizedHomeSubtitle, sanitizedAboutContent], (err) => {
            if (err) {
                logger.error('Database error updating content:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            logger.info('Content updated');
            res.json({ message: 'Контент обновлен' });
        });
    } catch (error) {
        logger.error('Update content error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Users
app.get('/api/users', authenticate, isAdmin, (req, res) => {
    db.all('SELECT id, login, full_name, phone, email FROM users', (err, users) => {
        if (err) {
            logger.error('Database error fetching users:', err.message);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }
        res.json(users);
    });
});

app.delete('/api/users/:id', authenticate, isAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (id === req.user.id) {
        return res.status(400).json({ message: 'Нельзя удалить самого себя' });
    }
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
        if (err) {
            logger.error('Database error fetching user:', err.message);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }
        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }
        db.run('DELETE FROM users WHERE id = ?', [id], (err) => {
            if (err) {
                logger.error('Database error deleting user:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            db.run('DELETE FROM orders WHERE user_id = ?', [id], (err) => {
                if (err) {
                    logger.error('Database error deleting user orders:', err.message);
                }
                logger.info('User deleted:', id);
                res.json({ message: 'Пользователь удален' });
            });
        });
    });
});

// CTA
app.post('/api/cta', async (req, res) => {
    try {
        const { name, phone } = req.body;
        if (!name || !phone) {
            return res.status(400).json({ message: 'Заполните все поля' });
        }
        const sanitizedName = sanitizeHtml(name.trim());
        const sanitizedPhone = sanitizeHtml(phone.trim());
        if (!sanitizedPhone.match(/^\+7\d{10}$/)) {
            return res.status(400).json({ message: 'Неверный формат телефона' });
        }
        db.run(`
            INSERT INTO cta_submissions (name, phone)
            VALUES (?, ?)
        `, [sanitizedName, sanitizedPhone], function(err) {
            if (err) {
                logger.error('Database error inserting CTA:', err.message);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            logger.info('CTA submission created:', this.lastID);
            res.status(201).json({ message: 'Заявка отправлена' });
        });
    } catch (error) {
        logger.error('CTA error:', error.message);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Start server
app.listen(PORT, () => {
    logger.info(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Closing server...');
    db.close((err) => {
        if (err) logger.error('Error closing database:', err.message);
        logger.info('Database closed');
        process.exit(0);
    });
});
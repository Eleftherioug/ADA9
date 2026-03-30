const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

/* =========================
   JWT AUTH MIDDLEWARE
========================= */
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

/* =========================
   ROLE MIDDLEWARE
========================= */
function requireManager(req, res, next) {
    if (req.user.role === 'manager' || req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: 'Manager access required' });
}

function requireAdmin(req, res, next) {
    if (req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: 'Admin access required' });
}

/* =========================
   DB CONNECTION
========================= */
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

testConnection();

/* =========================
   AUTH ROUTES
========================= */

// REGISTER
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            role: role || 'employee'
        });

        res.status(201).json({
            message: 'User registered successfully',
            user: newUser
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// LOGIN (JWT)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValid = await bcrypt.compare(password, user.password);

        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// LOGOUT (JWT → just client discards token)
app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logged out (client should delete token)' });
});

/* =========================
   USER ROUTES
========================= */

// PROFILE
app.get('/api/users/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: ['id', 'name', 'email', 'role']
        });

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// GET ALL USERS (ADMIN ONLY)
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: ['id', 'name', 'email', 'role']
        });
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

/* =========================
   PROJECT ROUTES
========================= */

app.get('/api/projects', requireAuth, async (req, res) => {
    const projects = await Project.findAll();
    res.json(projects);
});

// CREATE PROJECT (MANAGER+)
app.post('/api/projects', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description } = req.body;

        const project = await Project.create({
            name,
            description,
            managerId: req.user.id
        });

        res.status(201).json(project);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// UPDATE PROJECT (MANAGER+)
app.put('/api/projects/:id', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description } = req.body;

        await Project.update(
            { name, description },
            { where: { id: req.params.id } }
        );

        const updated = await Project.findByPk(req.params.id);
        res.json(updated);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// DELETE PROJECT (ADMIN ONLY)
app.delete('/api/projects/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        await Project.destroy({ where: { id: req.params.id } });
        res.json({ message: 'Project deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

/* =========================
   TASK ROUTES
========================= */

// CREATE TASK (MANAGER+)
app.post('/api/projects/:id/tasks', requireAuth, requireManager, async (req, res) => {
    try {
        const { title, description, assignedUserId } = req.body;

        const task = await Task.create({
            title,
            description,
            projectId: req.params.id,
            assignedUserId
        });

        res.status(201).json(task);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create task' });
    }
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

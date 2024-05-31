const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const pool = new Pool({
    user: 'user',
    host: 'localhost',
    database: 'whiteboard_db',
    password: 'password',
    port: 5432,
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const SECRET_KEY = 'xxxxxxxxxxxxx';

function verifyJWT(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        req.userId = decoded.id;
        next();
    });
}

app.post('/register', async (req, res) => {
    const hashedPassword = bcrypt.hashSync(req.body.password, 8);
    const { username } = req.body;

    try {
        const result = await pool.query('INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id', [username, hashedPassword]);
        const token = jwt.sign({ id: result.rows[0].id }, SECRET_KEY, { expiresIn: 86400 });
        res.status(200).send({ auth: true, token });
    } catch (error) {
        res.status(500).send('Error registering user');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(404).send('No user found.');

        const user = result.rows[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: 86400 });
        res.status(200).send({ auth: true, token });
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

app.post('/whiteboards', verifyJWT, async (req, res) => {
    const { name } = req.body;

    try {
        const result = await pool.query('INSERT INTO whiteboards (name, owner_id) VALUES ($1, $2) RETURNING id', [name, req.userId]);
        res.status(201).send({ whiteboardId: result.rows[0].id });
    } catch (error) {
        res.status(500).send('Error creating whiteboard');
    }
});

app.post('/whiteboards/:id/invite', verifyJWT, async (req, res) => {
    const whiteboardId = req.params.id;
    const { username } = req.body;

    try {
        const result = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(404).send('User not found');

        await pool.query('INSERT INTO whiteboard_users (whiteboard_id, user_id) VALUES ($1, $2)', [whiteboardId, result.rows[0].id]);
        res.status(200).send('User invited successfully');
    } catch (error) {
        res.status(500).send('Error inviting user');
    }
});

app.put('/whiteboards/:id', verifyJWT, async (req, res) => {
    const whiteboardId = req.params.id;
    const { data } = req.body;

    try {
        await pool.query('UPDATE whiteboards SET data = $1 WHERE id = $2', [data, whiteboardId]);
        res.status(200).send('Whiteboard saved successfully');
    } catch (error) {
        res.status(500).send('Error saving whiteboard');
    }
});

const whiteboards = {};

wss.on('connection', (ws) => {
    let currentWhiteboardId;

    ws.on('message', (message) => {
        const data = JSON.parse(message);

        if (data.type === 'join') {
            currentWhiteboardId = data.whiteboardId;
            if (!whiteboards[currentWhiteboardId]) {
                whiteboards[currentWhiteboardId] = new Set();
            }
            whiteboards[currentWhiteboardId].add(ws);
        } else if (data.type === 'draw' || data.type === 'undo' || data.type === 'redo') {
            if (currentWhiteboardId && whiteboards[currentWhiteboardId]) {
                whiteboards[currentWhiteboardId].forEach(client => {
                    if (client !== ws && client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(data));
                    }
                });
            }
        }
    });

    ws.on('close', () => {
        if (currentWhiteboardId && whiteboards[currentWhiteboardId]) {
            whiteboards[currentWhiteboardId].delete(ws);
            if (whiteboards[currentWhiteboardId].size === 0) {
                delete whiteboards[currentWhiteboardId];
            }
        }
    });
});

server.listen(3000, () => {
    console.log('Server is listening on port 3000');
});

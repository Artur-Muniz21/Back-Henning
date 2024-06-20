var express = require('express');
var router = express.Router();
var sqlite3 = require("sqlite3");
var jwt = require('jsonwebtoken');
var bcrypt = require('bcrypt');

const db = new sqlite3.Database('./database/database.db');

db.run(`CREATE TABLE IF NOT EXISTS invalidated_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    expiry DATE NOT NULL
  )`, (err) => {
    if(err) {
      console.log('Erro ao criar a invalidated_tokens: ', err);
    } else {
      console.log('Tabela invalidated_tokens criada com sucesso!');
    }
  });

router.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', username, (err, row) => {
        if (!row) {
            console.log("Usuário não encontrado", err);
            return res.status(404).send({ error: 'Usuário não encontrado' });
        } else {
            bcrypt.compare(password, row.password, (err, result) => {
                if (err) {
                    console.log("Erro ao comparar as senhas", err);
                    return res.status(500).send({ error: 'Erro ao comparar as senhas' });
                } else if (!result) {
                    return res.status(401).send({ error: 'Senha incorreta' });
                } else {
                    const token = jwt.sign({ id: row.id }, '8c10472423dc7ac1b8fdb91c96793ae8d385da1af1a334950f9f22dbef19edad', { expiresIn: '15m' });
                    return res.status(200).send({ message: 'Login com sucesso', token });
                }
            });
        }
    });
});

router.post('/logout', (req, res) => {
    const token = req.headers['authorization'].split(' ')[1];
    const decodedToken = jwt.decode(token);
    const expiry = new Date(decodedToken.exp * 1000);
    db.run('INSERT INTO invalidated_tokens (token, expiry) VALUES (?, ?)', [token, expiry], (err) => {
        if (err) {
            console.log("Erro ao invalidar o token", err);
            return res.status(500).send({ error: 'Erro ao invalidar o token' });
        }
        res.status(200).send({ message: 'Logout com sucesso' });
    });
});

const checkInvalidatedToken = (req, res, next) => {
    const token = req.headers['authorization'].split(' ')[1];
    db.get('SELECT * FROM invalidated_tokens WHERE token = ?', token, (err, row) => {
        if (err) {
            console.log("Erro ao verificar o token invalidado", err);
            return res.status(500).send({ error: 'Erro ao verificar o token invalidado' });
        }
        if (row) {
            return res.status(401).send({ error: 'Token inválido' });
        }
        next();
    });
};

router.get('/protected-route', checkInvalidatedToken, (req, res) => {
    res.status(200).send({ message: 'Rota protegida acessada com sucesso' });
});

module.exports = router;
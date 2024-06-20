var express = require('express');
var router = express.Router();
var sqlite3 = require("sqlite3");
var bcrypt = require('bcrypt');
var verifyJWT = require('../auth/verify-token')

const db = new sqlite3.Database('./database/database.db');

// Criação da tabela se não existir
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  email TEXT UNIQUE,
  saldo DECIMAL(12,2)
)`, (err) => {
  if(err) {
    console.log('Erro ao criar a tabela users: ', err);
  } else {
    console.log('Tabela users criada com sucesso!');
  }
});

// Rota GET para listar todos os usuários
router.get('/', verifyJWT, (req, res, next) => {
  db.all('SELECT * FROM users', (err, users) => {
    if(err){
      console.log('Usuários não encontrados: ', err);
      return res.status(500).send({ error: "Usuários não encontrados" });
    }
    res.status(200).send(users);
  });
});

// Rota GET para obter usuário por ID
router.get('/:id', verifyJWT, (req, res) => {
  const { id } = req.params;
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
    if(err) {
      console.log('Erro ao obter o usuário: ', err);
      return res.status(500).send({ error: "Erro ao obter usuário" });
    }
    if(!user) {
      return res.status(404).send({ error: "Usuário não encontrado" });
    }
    res.status(200).send(user);
  });
});

// Rota para registro de usuário
router.post('/register', (req, res) => {
  console.log(req.body)
  const { username, password, email, saldo } = req.body

  db.get('SELECT * FROM users WHERE username = ?', username, (err, row) => {
    if (row) {
      console.log("Usuário já existe", err)
      return res.status(400).send({ error: 'Nome de usuário já existe' })
    } else {
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          console.log("Erro ao criar o hash da senha", err)
          return res.status(500).send({ error: 'Erro ao criar o hash da senha' })
        } else {
          db.run('INSERT INTO users (username, password, email, saldo) VALUES (?,?,?,?)', [username, hash, email, saldo], (err) => {
            if (err) {
              console.log("Erro ao criar o usuário", err)
              return res.status(500).send({ error: 'Erro ao criar o usuário' })
            } else {
              res.status(201).send({ message: "Usuário criado com sucesso" })
            }
          })
        }

      })
    }
  })
})

// Rota PUT para atualizar usuário
router.put('/:id', verifyJWT, (req, res) => {
  const { id } = req.params;
  const { username, password, email, saldo } = req.body;
  db.run(`UPDATE users SET username = ?, password = ?, email = ?, saldo = ? WHERE id = ?`,
    [username, password, email, saldo, id],
    (err) => {
      if(err) {
        console.log('Erro ao atualizar o usuário: ', err);
        return res.status(500).send({ error: "Erro ao atualizar usuário" });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }
      res.status(200).send({ message: "Usuário atualizado com sucesso" });
    }
  );
});

// Rota DELETE para excluir usuário por ID
router.delete('/:id', verifyJWT, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM users WHERE id = ?', [id], (err) => {
    if(err) {
      console.log('Erro ao excluir o usuário: ', err);
      return res.status(500).send({ error: "Erro ao excluir usuário" });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    res.status(200).send({ message: "Usuário excluído com sucesso" });
  });
});

module.exports = router;

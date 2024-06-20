var express = require('express');
var router = express.Router();
var sqlite3 = require("sqlite3");
const verifyJWT = require('../auth/verify-token');

const db = new sqlite3.Database('./database/database.db');

db.run("PRAGMA foreign_keys = ON;");

// Criação da tabela de produtos se não existir
db.run(`CREATE TABLE IF NOT EXISTS produtos (
  id_produto INTEGER PRIMARY KEY AUTOINCREMENT,
  nome_produto TEXT,
  valor_produto DECIMAL(12,2),
  parcela_produto INTEGER,
  data_compra_produto TEXT,
  user_id INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`, (err) => {
  if(err) {
    console.log('Erro ao criar a tabela produtos: ', err);
  } else {
    console.log('Tabela produtos criada com sucesso!');
  }
});

// Rota GET para listar todos os produtos
router.get('/', verifyJWT, (req, res, next) => {
  db.all('SELECT * FROM produtos', (err, produtos) => {
    if(err){
      console.log('Produtos não encontrados: ', err);
      return res.status(500).send({ error: "Produtos não encontrados" });
    }
    res.status(200).send(produtos);
  });
});

// Rota GET para obter produto por ID
router.get('/:id_produto', verifyJWT, (req, res) => {
  const { id_produto } = req.params;
  db.get('SELECT * FROM produtos WHERE id_produto = ?', [id_produto], (err, produto) => {
    if(err) {
      console.log('Erro ao obter o produto: ', err);
      return res.status(500).send({ error: "Erro ao obter produto" });
    }
    if(!produto) {
      return res.status(404).send({ error: "Produto não encontrado" });
    }
    res.status(200).send(produto);
  });
});

// Rota para registro de produto
router.post('/register', verifyJWT, (req, res) => {
  console.log(req.body);
  const { nome_produto, valor_produto, parcela_produto, data_compra_produto, user_id } = req.body;
  db.run(`INSERT INTO produtos (nome_produto, valor_produto, parcela_produto, data_compra_produto, user_id) VALUES (?, ?, ?, ?, ?)`, 
    [nome_produto, valor_produto, parcela_produto, data_compra_produto, user_id], (err) => {
    if(err){
      console.log('Erro ao cadastrar o produto: ', err);
      return res.status(500).send({ error: 'Erro ao criar produto' });
    }
    res.status(201).send({ message: "Produto criado com sucesso" });
  });
});

// Rota PUT para atualizar produto
router.put('/:id_produto', verifyJWT, (req, res) => {
  const { id_produto } = req.params;
  const { nome_produto, valor_produto, parcela_produto, data_compra_produto, user_id } = req.body;
  db.run(`UPDATE produtos SET nome_produto = ?, valor_produto = ?, parcela_produto = ?, data_compra_produto = ?, user_id = ? WHERE id_produto = ?`,
    [nome_produto, valor_produto, parcela_produto, data_compra_produto, user_id, id_produto],
    (err) => {
      if(err) {
        console.log('Erro ao atualizar o produto: ', err);
        return res.status(500).send({ error: "Erro ao atualizar produto" });
      }
      res.status(200).send({ message: "Produto atualizado com sucesso" });
    }
  );
});

// Rota DELETE para excluir produto por ID
router.delete('/:id_produto', verifyJWT, (req, res) => {
  const { id_produto } = req.params;
  db.run('DELETE FROM produtos WHERE id_produto = ?', [id_produto], (err) => {
    if(err) {
      console.log('Erro ao excluir o produto: ', err);
      return res.status(500).send({ error: "Erro ao excluir produto" });
    }
    res.status(200).send({ message: "Produto excluído com sucesso" });
  });
});

module.exports = router;
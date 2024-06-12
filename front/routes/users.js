var express = require('express');
var router = express.Router();


var express = require('express');
var router = express.Router();
const url = "https://musical-space-cod-gg4wjpv7xxwc9x7x-4000.app.github.dev/"

/* GET users listing. */
router.get('/', function (req, res, next) {

  fetch(url, { method: 'GET' })
    .then(async (res) => {
      if (!res.ok) {
        const err = await res.json()
        throw err
      }
      return res.json()
    })
    .then((users) => {
      let title = "Tela De Login"
      let cols = ["ID", "Usuário", "Sennha", "E-Mail", "Saldo R$"]
      res.render('users', { title, users, cols, error: "" }) 
    })
    .catch((error) => {
      console.log('Erro', error)
      res.render('users', { title: "Gestão de Usuários", error: "" })
    })
});
// POST new user
router.post("/", (req, res) => {
  const { username, password, email, saldo } = req.body
  fetch(url + '/register', {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, email, saldo })
  }).then(async (res) => {
    if (!res.ok) {
      const err = await res.json()
      throw err
    }
    return res.json()
  })
    .then((user) => {
      res.send(user)
    })
    .catch((error) => {
      res.status(500).send(error)
    })
})

module.exports = router;
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

//autenticação
var jwt = require('jsonwebtoken');
var bcrypt = require('bcrypt');
var rateLimit = require('express-rate-limit');
var session = require('express-session');

var app = express();
app.use(express.json());

//configurar requisições
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use('/login', limiter);

//Configuração de sessão
app.use(session({
  secret: '',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

//Rotas
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var produtosRouter = require('./routes/produtos');

//Endpoints
app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/produtos',produtosRouter);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


app.use(logger('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));




// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.send('erro: Not Found');
});

module.exports = app;

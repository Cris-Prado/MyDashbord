require('dotenv').config(); // Carregar variáveis de ambiente
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;

const path = require('path');

// Configuração para servir arquivos estáticos
app.use(express.static(path.join(__dirname, 'src/public')));

// Configuração do motor de template EJS
app.set('view engine', 'ejs');
app.set('views', __dirname + '/src/templates'); // Altera o diretório de visualizações

app.use(express.static(__dirname + '/src/public/'));


// Conexão com o banco de dados
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

db.connect(err => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        process.exit(1);
    }
    console.log('Conectado ao banco de dados.');
});

// Configuração do middleware
app.use(express.urlencoded({ extended: true }));

/* app.use(express.static(path.join(__dirname, '/src/public'))); // Para servir arquivos estáticos (CSS, JS, etc.)*/

// Configuração de Sessões
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }  // Defina como `true` se estiver usando HTTPS
}));

// Rota de Cadastro (Register)
app.get('/cadastro', (req, res) => {
    res.sendFile(__dirname + '/src/public/cadastro.html');
});

app.post('/cadastro', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'INSERT INTO usuarios (username, password) VALUES (?, ?)';
        db.query(query, [username, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ message: 'Usuário já cadastrado.' });
                }
                return res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
            }
            res.redirect('/login');  // Redireciona para a página de login após o cadastro
        });
    } catch (error) {
        res.status(500).json({ message: 'Erro no servidor.' });
    }
});

// Rota de Login
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/src/public/login.html');
});



app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM usuarios WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ message: 'Usuário ou senha incorretos.' });
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Usuário ou senha incorretos.' });
        }

        // Criando a sessão
        req.session.user = { id: user.id, username: user.username };

        res.redirect('/success');
    });
});

// Página de Sucesso após Login
app.get('/success', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');  // Redireciona se o usuário não estiver logado
    }
    res.render('success', { username: req.session.user.username });
});

// Rota de Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Erro ao sair.' });
        }
        res.redirect('/login');
    });
});

// Configure o cookie da sessão com tempo de expiração:
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true, // Defina como true se estiver usando HTTPS
        maxAge: 24 * 60 * 60 * 1000 // Tempo de vida do cookie: 24 horas
    }
}));


// Ao sair destrua a sessão
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Erro ao sair.' });
        }
        res.clearCookie('connect.sid'); // Remove o cookie de sessão
        res.redirect('/login');
    });
});


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true, // True se estiver usando HTTPS
        maxAge: 1 * 60 * 1000 // Expira em 30 minutos
    }
}));


// Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});


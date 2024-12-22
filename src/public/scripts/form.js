  // Recuperar o login salvo ao carregar a página
  window.onload = function () {
    const savedUsername = localStorage.getItem('username'); // Recupera o nome de usuário salvo
    if (savedUsername) {
        document.getElementById('username').value = savedUsername; // Preenche o campo de login
        document.getElementById('rememberMe').checked = true; // Marca a caixa de seleção
    }
};

// Função para gerenciar o login
function handleRememberMe(event) {
    const username = document.getElementById('username').value;
    const rememberMe = document.getElementById('rememberMe').checked;

    // Se o usuário marcar "Lembrar de mim", salve o nome de usuário
    if (rememberMe) {
        localStorage.setItem('username', username);
    } else {
        // Se desmarcar, remova o nome de usuário salvo
        localStorage.removeItem('username');
    }
}

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

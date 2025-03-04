const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('./db'); // Certifique-se de que db.js usa o método .promise()

const router = express.Router();

// Rota de registro de funcionario
/*router.post('/registrar-funcionario', (req, res) => {
    const { nome, email, senha } = req.body;

    // Verifica se o email já existe no banco de dados
    db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
        if (err) return res.status(500).send({ erro: err });

        if (result.length > 0) {
            // Se o usuário já existe, apenas atualiza a role para 'funcionario'
            db.query(
                'UPDATE usuarios SET role = ? WHERE email = ?',
                ['funcionario', email],
                (err) => {
                    if (err) return res.status(500).send({ erro: err });
                    res.status(200).send({ mensagem: 'Usuário atualizado para funcionário!' });
                }
            );
        } else {
            // Gera o hash da senha
            const senhaHash = bcrypt.hashSync(senha, 8); // 8 é o custo de processamento do bcrypt

            // Insere o funcionário no banco de dados com o role 'funcionario'
            db.query(
                'INSERT INTO usuarios (nome, email, senha, role) VALUES (?, ?, ?, ?)',
                [nome, email, senhaHash, 'funcionario'],
                (err) => {
                    if (err) return res.status(500).send({ erro: err });
                    res.status(201).send({ mensagem: 'Funcionário registrado com sucesso!' });
                }
            );
        }
    });
});*/


// Login
router.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const [results] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);

        if (results.length === 0) {
            return res.status(401).json({ message: 'Email ou senha inválidos' });
        }

        const usuario = results[0];
        const senhaValida = bcrypt.compareSync(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json({ message: 'Email ou senha inválidos' });
        }

        const token = jwt.sign(
            { id: usuario.id, nome: usuario.nome, role: usuario.role },
            'secreta',
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Login bem-sucedido!',
            token,
            usuario_id: usuario.id, // Incluindo o ID do usuário na resposta
            role: usuario.role,
            nome: usuario.nome
        });
    } catch (err) {
        console.error('Erro ao fazer login:', err);
        res.status(500).json({ message: 'Erro interno ao fazer login' });
    }
});


// Esqueci minha senha (enviar e-mail com o token)
router.post('/esqueci-senha', async (req, res) => {
    const { email } = req.body;

    try {
        const [results] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);

        if (results.length === 0) {
            return res.status(400).json({ message: 'Email não cadastrado' });
        }

        const token = jwt.sign({ id: results[0].id }, 'secreta', { expiresIn: '15m' });
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: '1lfsoftwares@gmail.com',
                pass: 'pfakcrxwhbszjoxi'
            }
        });

        const mailOptions = {
            from: 'lbarberoficial1@gmail.com',
            to: email,
            subject: 'Redefinição de Senha',
            text: `Clique no link para redefinir sua senha: http://localhost:3000/resetar-senha.html?token=${token}`
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: 'E-mail de redefinição enviado!' });
    } catch (err) {
        console.error('Erro ao enviar o email de redefinição de senha:', err);
        res.status(500).json({ message: 'Erro ao enviar o email' });
    }
});

// Redefinir senha (valida o token e atualiza a senha)
router.post('/resetar-senha/:token', (req, res) => {
    const { token } = req.params;
    const { senha } = req.body;

    if (!senha) {
        return res.status(400).json({ message: 'Senha é obrigatória' });
    }

    const senhaHash = bcrypt.hashSync(senha, 8);

    jwt.verify(token, 'secreta', (err, decoded) => {
        if (err) {
            return res.status(400).json({ message: 'Token inválido ou expirado' });
        }

        const userId = decoded.id;

        db.query('UPDATE usuarios SET senha = ? WHERE id = ?', [senhaHash, userId], (err) => {
            if (err) {
                console.error('Erro ao atualizar senha:', err);
                return res.status(500).json({ message: 'Erro ao redefinir senha' });
            }

            res.json({ message: 'Senha redefinida com sucesso!' });
        });
    });
});

// Rota para obter lista de funcionarios
router.get('/funcionarios', async (req, res) => {
    try {
        const [funcionarios] = await db.query('SELECT id, nome FROM usuarios WHERE role = ?', ['funcionario']);
        res.json(funcionarios);
    } catch (err) {
        console.error('Erro ao buscar funcionarios:', err);
        res.status(500).json({ message: 'Erro ao buscar funcionarios' });
    }
});


function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    try {
        const decoded = jwt.verify(token, secret);
        req.user = decoded; // Adiciona os dados do token no req.user para uso nas rotas
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Token inválido' });
    }
}

module.exports = authenticateToken;

module.exports = router;

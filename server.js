const express = require('express');  
const cors = require('cors');
const bodyParser = require('body-parser');
const authRoutes = require('./auth'); // Arquivo que contém as rotas de autenticação
const path = require('path');
const app = express();
const port = 3000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Lista de e-mails autorizados para administradores
const adminEmails = ['leonardoff24@gmail.com'];

// Middleware
app.use(cors()); // Permite CORS
app.use(bodyParser.json()); // Analisa o corpo das requisições como JSON
app.use('/auth', authRoutes); // Usa as rotas de autenticação definidas no arquivo auth.js
app.use(express.static('public')); // Serve os arquivos estáticos (HTML, CSS, JS)

// Conexão ao banco de dados (MySQL)
const db = require('./db'); // Certifique-se de que 'db.js' está configurado corretamente

const secret = 'secreta'; // Defina sua chave secreta

// Middleware de autenticação
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token não encontrado' });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.user = user;
        next();
    });
}

// Middleware para verificar se o usuário é administrador
async function updateAdminRoles() {
    try {
        const placeholders = adminEmails.map(() => '?').join(', ');
        const query = `UPDATE usuarios SET roles = 'admin' WHERE email IN (${placeholders})`;
        await db.query(query, adminEmails);
        console.log('Admin roles updated successfully!');
    } catch (error) {
        console.error('Error updating admin roles:', error);
    }
}

// Execute a função ao iniciar o servidor
updateAdminRoles();


// Rota para registrar usuário
app.post('/registrar', async (req, res) => {
    const { nome, email, senha, telefone } = req.body;

    if (!nome || !email || !senha || !telefone) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }

    try {
        // Verifica se o usuário já existe
        const [rows] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (rows.length > 0) {
            return res.status(400).json({ message: 'Usuário já registrado' });
        }

        // Criptografa a senha
        const hashedPassword = await bcrypt.hash(senha, 10);

        // Define o role do usuário (cliente por padrão)
        const role = 'cliente';  // Definido como cliente por padrão
        let roles = 'cliente';   // Se for um administrador, altere para 'admin'

        // Se o email estiver na lista de administradores, define o role como admin
        if (adminEmails.includes(email)) {
            roles = 'admin';  // Usuário é admin
        }

        // Insere o usuário no banco de dados
        await db.query(
            'INSERT INTO usuarios (nome, email, senha, telefone, role, roles) VALUES (?, ?, ?, ?, ?, ?)',
            [nome, email, hashedPassword, telefone, role, roles]
        );

        res.status(201).json({ message: 'Usuário registrado com sucesso' });
    } catch (error) {
        console.error('Erro ao registrar usuário:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

app.get('/agendamentos/horarios', async (req, res) => {
    const { data_agendada } = req.query;

    try {
        // Verifica os agendamentos para o dia específico
        const [rows] = await db.query('SELECT hora_inicio FROM agendamentos WHERE data_agendada = ?', [data_agendada]);

        res.json({
            agendamentos: rows
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao carregar horários.' });
    }
});


app.post('/registrar-funcionario', async (req, res) => {
    const { nome, email, senha, telefone } = req.body;
    console.log('Recebido POST para registrar funcionário:', req.body);

    try {
        // Verifica se o email já existe no banco de dados
        const [result] = await db.execute('SELECT * FROM usuarios WHERE email = ?', [email]);
        
        if (result.length > 0) {
            console.log('Email já registrado');
            return res.status(400).send({ mensagem: 'Email já registrado' });
        }

        // Gera o hash da senha de forma assíncrona para evitar bloqueio de operações
        const senhaHash = await bcrypt.hash(senha, 8);
        console.log('Hash da senha gerado:', senhaHash);

        // Insere o funcionario no banco de dados
        await db.execute(
            'INSERT INTO usuarios (nome, telefone, email, senha, role) VALUES (?, ?, ?, ?, ?)',
            [nome, telefone, email, senhaHash, 'funcionario']
        );
        console.log('Funcionário registrado com sucesso');
        res.status(201).send({ mensagem: 'Funcionário registrado com sucesso!' });
    } catch (error) {
        console.error('Erro no servidor:', error);
        res.status(500).send({ erro: 'Erro ao registrar funcionário' });
    }
});





app.post('/auth/resetar-senha', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        // Verifica o token
        const decoded = jwt.verify(token, secret);
        
        // Encripta a nova senha
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Atualiza a senha no banco de dados
        await db.query('UPDATE usuarios SET senha = ? WHERE id = ?', [hashedPassword, decoded.id]);

        res.status(200).json({ message: 'Senha redefinida com sucesso!' });
    } catch (error) {
        console.error('Erro ao redefinir a senha:', error);
        res.status(400).json({ message: 'Token inválido ou expirado.' });
    }
});
// Remova a rota duplicada de login no server.js, já que ela está no auth.js

// Rota para obter o ID do funcionario autenticado
app.get('/user-info', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Captura o token de 'Bearer <token>'
    
    if (!token) {
        return res.status(401).send({ mensagem: 'Token não fornecido' });
    }

    try {
        const decoded = jwt.verify(token, secret); // Decodifica o token usando a chave secreta
        res.send({ id: decoded.id, role: decoded.role });
    } catch (err) {
        res.status(401).send({ mensagem: 'Token inválido' });
    }
});


// Rota para obter a lista de funcionarios
app.get('/funcionarios', async (req, res) => {
    try {
        const [results] = await db.query("SELECT * FROM usuarios WHERE role = 'funcionario'"); // Filtra apenas os funcionarios
        res.status(200).json(results);
    } catch (error) {
        console.error('Erro ao carregar funcionarios:', error);
        res.status(500).json({ message: 'Erro ao carregar funcionarios' });
    }
});


/*app.get('/horarios-indisponiveis', async (req, res) => {
    const { data } = req.query;

    if (!data) {
        return res.status(400).json({ message: 'A data é obrigatória.' });
    }

    try {
        const [result] = await db.query(
            "SELECT hora_inicio, hora_fim FROM agendamentos WHERE data_agendada = ?",
            [data]
        );

        let horariosIndisponiveis = [];

        result.forEach(({ hora_inicio, hora_fim }) => {
            let inicio = hora_inicio.split(':').map(Number);
            let fim = hora_fim.split(':').map(Number);

            let horaAtual = inicio[0] * 60 + inicio[1]; // Converter para minutos
            let horaFim = fim[0] * 60 + fim[1];

            while (horaAtual < horaFim) {
                let horas = String(Math.floor(horaAtual / 60)).padStart(2, '0');
                let minutos = String(horaAtual % 60).padStart(2, '0');
                horariosIndisponiveis.push(`${horas}:${minutos}`);
                horaAtual += 30; // Avança de 30 em 30 minutos
            }
        });

        res.json({ horariosIndisponiveis });
    } catch (error) {
        console.error('Erro ao buscar horários indisponíveis:', error);
        res.status(500).json({ message: 'Erro interno do servidor' });
    }
});*/


app.get('/horarios-ocupados', async (req, res) => {
    const { data } = req.query;

    if (!data) {
        return res.status(400).json({ message: "Data é obrigatória." });
    }

    try {
        // Consulta os agendamentos para a data especificada
        const [result] = await db.query(
            "SELECT hora_inicio, hora_fim, quadra FROM agendamentos WHERE data_agendada = ?",
            [data]
        );

        let horariosOcupadosQuadra1 = new Set(); // Horários ocupados na quadra 1
        let horariosOcupadosQuadra2 = new Set(); // Horários ocupados na quadra 2
        let horariosInicioBloqueadosQuadra1 = new Set(); // Horários iniciais bloqueados na quadra 1
        let horariosInicioBloqueadosQuadra2 = new Set(); // Horários iniciais bloqueados na quadra 2
        let horasFimQuadra1 = new Set(); // Horas finais liberadas na quadra 1
        let horasFimQuadra2 = new Set(); // Horas finais liberadas na quadra 2

        result.forEach(agendamento => {
            let horaInicio = agendamento.hora_inicio.slice(0, 5); // Formato HH:MM
            let horaAtual = horaInicio;
            let ultimaHoraOcupada = agendamento.hora_fim.slice(0, 5); // Formato HH:MM
            let quadra = agendamento.quadra;

            // Adiciona o horário de início à lista de bloqueados
            if (quadra === 1) {
                horariosInicioBloqueadosQuadra1.add(horaInicio);
            } else if (quadra === 2) {
                horariosInicioBloqueadosQuadra2.add(horaInicio);
            }

            // Bloqueia todos os horários entre o início e o fim do agendamento
            while (horaAtual < ultimaHoraOcupada) {
                let [hora, minuto] = horaAtual.split(':').map(Number);
                let horaFormatada = `${String(hora).padStart(2, '0')}:${String(minuto).padStart(2, '0')}`;

                if (quadra === 1) {
                    horariosOcupadosQuadra1.add(horaFormatada);
                } else if (quadra === 2) {
                    horariosOcupadosQuadra2.add(horaFormatada);
                }

                // Avança 30 minutos
                minuto += 30;
                if (minuto === 60) { 
                    hora += 1; 
                    minuto = 0; 
                }
                horaAtual = `${String(hora).padStart(2, '0')}:${String(minuto).padStart(2, '0')}`;
            }

            // Adiciona a hora_fim à lista de horas finais
            if (quadra === 1) {
                horasFimQuadra1.add(ultimaHoraOcupada);
            } else if (quadra === 2) {
                horasFimQuadra2.add(ultimaHoraOcupada);
            }
        });

        console.log("Horários de início bloqueados na quadra 1:", [...horariosInicioBloqueadosQuadra1]);
        console.log("Horários de início bloqueados na quadra 2:", [...horariosInicioBloqueadosQuadra2]);
        console.log("Horários ocupados na quadra 1:", [...horariosOcupadosQuadra1]);
        console.log("Horários ocupados na quadra 2:", [...horariosOcupadosQuadra2]);
        console.log("Horas fim na quadra 1:", [...horasFimQuadra1]);
        console.log("Horas fim na quadra 2:", [...horasFimQuadra2]);

        res.json({ 
            horariosOcupadosQuadra1: [...horariosOcupadosQuadra1],
            horariosOcupadosQuadra2: [...horariosOcupadosQuadra2],
            horariosInicioBloqueadosQuadra1: [...horariosInicioBloqueadosQuadra1],
            horariosInicioBloqueadosQuadra2: [...horariosInicioBloqueadosQuadra2],
            horasFimQuadra1: [...horasFimQuadra1],
            horasFimQuadra2: [...horasFimQuadra2]
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erro ao buscar horários ocupados." });
    }
});

// Rota para buscar agendamentos do usuário
app.get('/meus-agendamentos', authenticateToken, async (req, res) => {
    const usuario_id = req.user.id; // Obtém o ID do usuário do token

    try {
        // Consulta os agendamentos do usuário, incluindo o ID do agendamento
        const [result] = await db.query(
            "SELECT id, data_agendada, hora_inicio, hora_fim, quadra FROM agendamentos WHERE usuario_id = ? ORDER BY data_agendada, hora_inicio",
            [usuario_id]
        );

        res.json(result);
    } catch (error) {
        console.error('Erro ao buscar agendamentos:', error);
        res.status(500).json({ message: "Erro ao buscar agendamentos." });
    }
});


app.delete('/cancelar-agendamento/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const usuario_id = req.user.id; // ID do usuário autenticado

    try {
        console.log(`Tentando excluir agendamento ID: ${id} do usuário ID: ${usuario_id}`);

        // Verifica se o agendamento pertence ao usuário antes de excluir
        const [agendamentos] = await db.query(
            "SELECT * FROM agendamentos WHERE id = ? AND usuario_id = ?",
            [id, usuario_id]
        );

        if (agendamentos.length === 0) {
            console.log("Agendamento não encontrado ou usuário não autorizado.");
            return res.status(403).json({ message: "Agendamento não encontrado ou não autorizado." });
        }

        // Remove o agendamento
        await db.query("DELETE FROM agendamentos WHERE id = ?", [id]);

        console.log("Agendamento removido com sucesso.");
        res.json({ message: "Agendamento cancelado com sucesso!" });
    } catch (error) {
        console.error('Erro ao cancelar agendamento:', error);
        res.status(500).json({ message: "Erro ao cancelar agendamento.", error: error.message });
    }
});



// Rota para salvar um novo agendamento
app.post('/agendar', async (req, res) => {
    try {
        const { usuario_id, data_agendada, hora_inicio, hora_fim, quadra } = req.body;

        // Verifica se todos os campos foram preenchidos
        if (!usuario_id || !data_agendada || !hora_inicio || !hora_fim || !quadra) {
            return res.status(400).json({ message: 'Preencha todos os campos' });
        }

        // Verifica se já existe um agendamento nesse horário e quadra
        const verificaAgendamento = `
            SELECT * FROM agendamentos 
            WHERE data_agendada = ? 
            AND quadra = ?
            AND (
                (hora_inicio >= ? AND hora_inicio < ?) 
                OR (hora_fim > ? AND hora_fim <= ?) 
                OR (hora_inicio <= ? AND hora_fim >= ?)
            )
        `;

        const [result] = await db.query(verificaAgendamento, [
            data_agendada, quadra, hora_inicio, hora_fim, hora_inicio, hora_fim, hora_inicio, hora_fim
        ]);

        if (result.length > 0) {
            return res.status(400).json({ message: 'Horário já reservado nesta quadra' });
        }

        // Insere o agendamento no banco de dados
        const inserirAgendamento = `
            INSERT INTO agendamentos (usuario_id, data_agendada, hora_inicio, hora_fim, quadra, created_at)
            VALUES (?, ?, ?, ?, ?, NOW())
        `;

        await db.query(inserirAgendamento, [usuario_id, data_agendada, hora_inicio, hora_fim, quadra]);

        return res.status(201).json({ message: 'Agendamento realizado com sucesso!' });

    } catch (error) {
        console.error('Erro ao salvar agendamento:', error);
        return res.status(500).json({ message: 'Erro interno do servidor' });
    }
});
  
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.user = user;
        next();
    });
}


// Rota para obter todos os agendamentos funcionario
app.get('/agendamentos', authenticateToken, async (req, res) => {
    try {
        // Consulta para buscar todos os agendamentos a partir da data atual
        const [agendamentos] = await db.query(`
            SELECT 
                a.id,
                u.nome AS nome_cliente,
                u.telefone AS telefone_cliente,
                a.data_agendada,
                a.hora_inicio,
                a.hora_fim,
                a.quadra
            FROM agendamentos a
            JOIN usuarios u ON a.usuario_id = u.id
            WHERE a.data_agendada >= CURDATE()
            ORDER BY a.data_agendada, a.hora_inicio
        `);

        res.json(agendamentos || []);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao buscar agendamentos' });
    }
});


// Rota para adicionar um bloqueio
app.post('/bloquear-horario', authenticateToken, async (req, res) => {
    console.log('Rota /bloquear-horario foi acessada');

    const usuarioId = req.user.id;
    const { data, hora_inicio, hora_fim } = req.body; // Data e horário que serão bloqueados

    try {
        // Verifica se o usuário é um funcionário
        const [[usuario]] = await db.query(`SELECT role FROM usuarios WHERE id = ?`, [usuarioId]);

        if (!usuario || usuario.role !== 'funcionario') {
            return res.status(403).json({ message: 'Acesso restrito a funcionários' }); // ⬅️ RETORNA AQUI
        }

        // Insere o bloqueio no banco de dados
        await db.query(`INSERT INTO bloqueios (data, hora_inicio, hora_fim) VALUES (?, ?, ?)`, 
            [data, hora_inicio, hora_fim]);

        return res.json({ message: 'Horário bloqueado com sucesso!' }); // ⬅️ RETORNA AQUI
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Erro ao bloquear o horário' }); // ⬅️ RETORNA AQUI
    }
});


app.get('/horarios-bloqueados', async (req, res) => {
    const { data } = req.query;

    if (!data) {
        return res.status(400).json({ message: "A data é obrigatória." });
    }

    try {
        const [bloqueios] = await db.query(
            `SELECT hora_inicio, hora_fim FROM bloqueios WHERE data = ?`, 
            [data]
        );

        let horariosBloqueados = [];

        bloqueios.forEach(bloqueio => {
            let horaInicio = bloqueio.hora_inicio;
            let horaFim = bloqueio.hora_fim;

            let horaAtual = horaInicio;
            while (horaAtual <= horaFim) {
                horariosBloqueados.push(horaAtual);

                let [hora, minuto] = horaAtual.split(":").map(Number);
                minuto += 30; // Incrementa 30 minutos

                if (minuto >= 60) {
                    minuto = 0;
                    hora += 1;
                }

                horaAtual = `${String(hora).padStart(2, '0')}:${String(minuto).padStart(2, '0')}`;
            }
        });

        console.log("Horários Bloqueados:", horariosBloqueados); // Log para depuração

        return res.json({ horariosBloqueados });

    } catch (error) {
        console.error("Erro ao buscar horários bloqueados:", error);
        return res.status(500).json({ message: "Erro ao buscar horários bloqueados." });
    }
});

// Rota para bloquear um dia inteiro
app.post('/bloquear-dia', authenticateToken, async (req, res) => {
    const usuarioId = req.user.id;
    const { data } = req.body; // Data que será bloqueada

    try {
        // Verifica se o usuário é um funcionário
        const [[usuario]] = await db.query(`SELECT role FROM usuarios WHERE id = ?`, [usuarioId]);

        if (!usuario || usuario.role !== 'funcionario') {
            return res.status(403).json({ message: 'Acesso restrito a funcionários' });
        }

        // Insere o bloqueio no banco de dados com hora início e fim
        await db.query(
            `INSERT INTO bloqueios (data, hora_inicio, hora_fim) VALUES (?, ?, ?)`,
            [data, '00:00:00', '23:59:59']
        );

        res.json({ message: 'Dia bloqueado com sucesso!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao bloquear o dia' });
    }
});

app.get('/bloqueios', authenticateToken, async (req, res) => {
    try {
        const [bloqueios] = await db.query(
            "SELECT id, data, hora_inicio, hora_fim FROM bloqueios WHERE data >= CURDATE()"
        );
        res.json(bloqueios);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao buscar bloqueios' });
    }
});


app.delete('/bloqueios/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query("DELETE FROM bloqueios WHERE id = ?", [id]);
        res.json({ message: 'Bloqueio removido com sucesso!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao remover bloqueio' });
    }
});





// Rota de login para administradores
app.post('/admin-login', async (req, res) => {
    const { email, password } = req.body;
    console.log("Email recebido:", email);
    console.log("Senha recebida:", password);

    if (!email || !password) {
        return res.status(400).json({ message: "E-mail e senha são obrigatórios." });
    }

    try {
        // Obtenha o usuário com base no email fornecido
        const result = await db.query('SELECT id, nome, email, senha FROM usuarios WHERE email = ?', [email]);

        // Verificando o retorno da consulta - o resultado é um array de arrays
        console.log("Resultado da consulta:", result);

        // Aqui, acessamos o primeiro item do array
        const user = result[0][0];  // Acessando o primeiro item do array que é o objeto do usuário
        if (!user) {
            console.log("Usuário não encontrado.");
            return res.status(404).json({ message: "Usuário não encontrado." });
        }

        console.log("Usuário encontrado:", user);

        // Verificação se o e-mail está na lista de administradores
        if (!adminEmails.includes(user.email)) {
            console.log("Acesso negado: O e-mail não está na lista de administradores.");
            return res.status(403).json({ message: 'Acesso negado' });
        }

        // Comparar a senha com a senha armazenada
        const isPasswordValid = await bcrypt.compare(password, user.senha); // Comparar a senha
        if (!isPasswordValid) {
            console.log("Senha inválida.");
            return res.status(401).json({ message: "Senha inválida." });
        }

        // Gerar token JWT
        const token = jwt.sign(
            { id: user.id, nome: user.nome, email: user.email }, // Inclua o e-mail no token
            'secreta', // Use a mesma chave secreta do login comum
            { expiresIn: '1h' } // Defina o tempo de expiração do token
        );

        // Se a senha estiver correta
        console.log("Login de administrador bem-sucedido.");
        res.status(200).json({ 
            message: "Login de administrador bem-sucedido.",
            token, // Retorne o token gerado
            isAdmin: true 
        });
    } catch (error) {
        console.error("Erro ao tentar fazer login de admin:", error);
        res.status(500).json({ message: "Erro no servidor." });
    }
});





// Protege a rota de administrador (página admin.html)
app.get('/admin', authenticateToken, (req, res) => {
    try {
        // Verifica se o e-mail do usuário está na lista de administradores
        if (!adminEmails.includes(req.user.email)) {
            return res.status(403).json({ message: 'Acesso negado' });
        }

        // Se for admin, envia o arquivo admin.html
        res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    } catch (error) {
        console.error('Erro ao verificar token:', error);
        res.status(403).json({ message: 'Token inválido' });
    }
});

// Rota para registrar um novo funcionario
app.post('/admin/funcionarios', authenticateToken, async (req, res) => {
    const { nome, telefone, email, senha } = req.body;

    try {
        // Verifica se o usuário atual é um administrador
        if (!adminEmails.includes(req.user.email)) {
            return res.status(403).json({ message: 'Acesso negado' });
        }

        // Insere o novo funcionario no banco de dados
        await db.query(
            `INSERT INTO usuarios (nome, telefone, email, senha, role) VALUES (?, ?, ?, ?, 'funcionario')`,
            [nome, telefone, email, senha]
        );

        res.status(201).json({ message: 'Funcionário registrado com sucesso' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao registrar funcionário' });
    }
});


// Rota para listar todos os funcionarios
app.get('/admin/funcionarios', authenticateToken, async (req, res) => {
    try {
        if (req.user.roles !== 'admin') {
            return res.status(403).json({ message: 'Acesso negado' });
        }

        const [funcionarios] = await db.query(`SELECT id, nome, email FROM usuarios WHERE role = 'funcionario'`);
        res.json(funcionarios);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao buscar funcionarios' });
    }
});


// Rota para excluir um funcionário
app.delete('/admin/funcionarios/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        console.log(req.user); // Verificar se os dados do usuário estão vindo corretamente

        // Verifica se o usuário autenticado tem permissão de admin
        // Verifica se o e-mail do usuário está na lista de administradores
        if (!adminEmails.includes(req.user.email)) {
            return res.status(403).json({ message: 'Acesso negado' });
        }
        // Exclui o funcionário apenas se ele realmente for um funcionário
        const [result] = await db.query(
            `DELETE FROM usuarios WHERE id = ? AND role = 'funcionario'`, 
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Funcionário não encontrado ou já excluído' });
        }

        res.json({ message: 'Funcionário excluído com sucesso' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao excluir funcionário' });
    }
});




// Inicia o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});

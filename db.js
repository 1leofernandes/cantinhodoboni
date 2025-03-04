const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'leonardo1234',
  database: 'resenha',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Teste de conexão
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log("Conexão com o banco de dados estabelecida com sucesso!");
    connection.release();
  } catch (err) {
    console.error("Erro ao conectar ao banco de dados:", err);
  }
})();

// Exporta o pool para uso em outros arquivos
module.exports = pool;

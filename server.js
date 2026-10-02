// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 1
// EMPRESA: MSEPTEM Tecnologías & Ciberseguridad Avanzada
// COMPONENTES: Importaciones, Capa de Entorno y Conectores de Infraestructura
// ============================================================================

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Variables de entorno corporativas para entornos productivos distribuidos
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://usuario:password@localhost:5432/mseptem_db';
const JWT_SECRET = process.env.JWT_SECRET || 'MSEPTEM_ULTRA_SECRET_KEY_2026_#X9';

// Configuración del Pool físico a PostgreSQL con SSL para proveedores en la nube
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Almacenes de estado en memoria para flujos de ciberseguridad
const almacénPines2FA = new Map();
const intentosLoginIP = new Map(); // Registra fallos acumulados por IP corporativa
const ipsBloqueadas = new Map();    // Lista negra temporal de IPs restringidas

// ----------------------------------------------------------------------------
// REGISTRO DE AUDITORÍA AVANZADA Y CONTROL INDUSTRIAL DE LOGS
// ----------------------------------------------------------------------------
function registrarEventoAuditoria(evento, ip, usuario = 'ANÓNIMO', detalles = '') {
    const marcaTiempo = new Date().toISOString();
    console.log(`[AUDITORÍA][${marcaTiempo}][IP: ${ip}][OPERADOR: ${usuario}] ACCIÓN: ${evento} | ${detalles}`);
}
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 2
// SECCIÓN: HEALTH CHECK CORPORATIVO Y AUTOCREACIÓN DE TABLAS DE PRODUCTOS DINA
// ============================================================================

async function verificarSaludBaseDatos() {
    console.log('[SISTEMA] Iniciando diagnóstico perimetral de infraestructura...');
    try {
        const cliente = await pool.connect();
        console.log('[OK] Enlace físico establecido con el servidor PostgreSQL.');
        
        // Creamos dinámicamente las tablas si no existen para agilizar el despliegue
        await cliente.query(`
            CREATE TABLE IF NOT EXISTS contactos (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL,
                telefono VARCHAR(30) NOT NULL,
                monto_inversion VARCHAR(100) NOT NULL,
                pais VARCHAR(60) NOT NULL,
                mensaje TEXT NOT NULL,
                fecha TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS administradores (
                id SERIAL PRIMARY KEY,
                usuario VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            );

            CREATE TABLE IF NOT EXISTS productos (
                id SERIAL PRIMARY KEY,
                titulo VARCHAR(100) NOT NULL,
                descripcion TEXT NOT NULL,
                precio_nodo NUMERIC DEFAULT 0
            );
        `);
        
        console.log('[OK] Esquema físico verificado y tablas relacionales aseguradas.');
        cliente.release();
    } catch (error) {
        console.error('[CRÍTICO] Error de conexión con PostgreSQL:', error.message);
        console.error('[SISTEMA] Operando en modo degradado temporal.');
    }
}
verificarSaludBaseDatos();
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 3
// SECCIÓN: HOJA DE MIDDLEWARES CONTRA ENTRADAS MALICIOSAS Y CONTROL DE IP
// ============================================================================

// Filtro activo de listas negras de IP
app.use((req, res, next) => {
    const ipCliente = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const tiempoBloqueo = ipsBloqueadas.get(ipCliente);

    if (tiempoBloqueo) {
        if (Date.now() < tiempoBloqueo) {
            return res.status(423).json({ error: 'Dirección IP bloqueada preventivamente por fallos de autenticación.' });
        } else {
            ipsBloqueadas.delete(ipCliente);
            intentosLoginIP.delete(ipCliente);
        }
    }
    next();
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://googleapis.com"],
            fontSrc: ["'self'", "https://gstatic.com"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
}));

app.use(express.json({ limit: '10kb' }));
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 4
// SECCIÓN: CAPA DE SANITIZACIÓN OWASP Y CONTROLADORES DE PASS-THROUGH JWT
// ============================================================================

app.use((req, res, next) => {
    const sqlXssRegex = /(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|\\x00|--|script|<[^>]+>)/gi;
    const sanitize = (input) => {
        if (typeof input === 'string') return input.replace(sqlXssRegex, '[REDACTED]').trim();
        if (typeof input === 'object' && input !== null) {
            for (let key in input) input[key] = sanitize(input[key]);
        }
        return input;
    };
    req.body = sanitize(req.body);
    req.query = sanitize(req.query);
    req.params = sanitize(req.params);
    next();
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Tasa de peticiones excedida de forma perimetral.' }
});
app.use('/api/', apiLimiter);

const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Firma de sesión inválida o caducada.' });
        req.adminId = decoded.id;
        req.adminUser = decoded.user;
        next();
    });
};
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 5
// SECCIÓN: ENDPOINTS PÚBLICOS - INGESTIÓN DE LEADS Y CONSULTA DINÁMICA DE REPOSITORIO
// ============================================================================

// Inserción parametrizada de leads tecnológicos
app.post('/api/contacto', async (req, res) => {
    const { nombre, email, telefono, monto_inversion, pais, mensaje } = req.body;
    const ipCliente = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!nombre || !email || !telefono || !monto_inversion || !pais || !mensaje || !email.includes('@')) {
        return res.status(400).json({ error: 'Todos los campos institucionales son de carácter obligatorio.' });
    }

    try {
        const query = 'INSERT INTO contactos (nombre, email, telefono, monto_inversion, pais, mensaje) VALUES ($1, $2, $3, $4, $5, $6)';
        await pool.query(query, [nombre, email, telefono, monto_inversion, pais, mensaje]);
        return res.status(200).json({ status: 'success', message: 'Datos corporativos resguardados.' });
    } catch (error) {
        return res.status(500).json({ error: 'Fallo general de persistencia.' });
    }
});

// Endpoint Público para leer los productos guardados en la BD
app.get('/api/productos', async (req, res) => {
    try {
        const resultado = await pool.query('SELECT * FROM productos ORDER BY id ASC');
        return res.status(200).json(resultado.rows);
    } catch (error) {
        return res.status(500).json({ error: 'Error al consultar catálogo de software.' });
    }
});
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 6
// SECCIÓN: PASARELA DE SEGURIDAD MULTIFACTOR DE ACCESO PARA OPERADORES
// ============================================================================

app.post('/api/auth/login', async (req, res) => {
    const { usuario, password } = req.body;
    const ipCliente = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        const query = 'SELECT * FROM administradores WHERE usuario = \$1';
        const result = await pool.query(query, [usuario]);

        const procesarFalloAutenticacion = () => {
            let fallos = intentosLoginIP.get(ipCliente) || 0;
            fallos++;
            intentosLoginIP.set(ipCliente, fallos);
            if (fallos >= 5) { ipsBloqueadas.set(ipCliente, Date.now() + 15 * 60 * 1000); return true; }
            return false;
        };

        if (result.rows.length === 0) {
            const blk = procesarFalloAutenticacion();
            return res.status(401).json({ error: blk ? 'IP Bloqueada.' : 'Credenciales inválidas.' });
        }

        const admin = result.rows[0]; 
        const passwordValido = await bcrypt.compare(password, admin.password_hash);

        if (!passwordValido) {
            const blk = procesarFalloAutenticacion();
            return res.status(401).json({ error: blk ? 'IP Bloqueada.' : 'Credenciales inválidas.' });
        }

        intentosLoginIP.delete(ipCliente);
        const pin2FA = Math.floor(100000 + Math.random() * 900000).toString();
        almacénPines2FA.set(admin.usuario, { pin: pin2FA, adminId: admin.id, expiracion: Date.now() + 120000 });

        registrarEventoAuditoria('TOKEN_2FA_GENERADO', ipCliente, admin.usuario, `PIN: ${pin2FA}`);
        return res.status(200).json({ status: '2fa_required', usuario: admin.usuario, message: 'Fase 1 completada. Ingrese PIN de bitácora.' });
    } catch (error) { return res.status(500).json({ error: 'Pasarela inalcanzable.' }); }
});

app.post('/api/auth/verificar-2fa', async (req, res) => {
    const { usuario, pin } = req.body;
    const datos2FA = almacénPines2FA.get(usuario);

    if (!datos2FA) return res.status(400).json({ error: 'El PIN ha expirado o no existe.' });
    if (Date.now() > datos2FA.expiracion) { almacénPines2FA.delete(usuario); return res.status(400).json({ error: 'El código temporal ha caducado.' }); }
    if (datos2FA.pin !== pin) return res.status(401).json({ error: 'Código de seguridad incorrecto.' });

    almacénPines2FA.delete(usuario);
    const token = jwt.sign({ id: datos2FA.adminId, user: usuario }, JWT_SECRET, { expiresIn: '1h' });
    return res.status(200).json({ status: 'success', token });
});
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 7
// SECCIÓN: CAPA CMS DEL SERVIDOR - CONTROLADOR DE CONTENIDOS DINÁMICOS
// ============================================================================

// Agregar Producto Nuevo a la Landing (Protegido por JWT)
app.post('/api/admin/productos', verificarToken, async (req, res) => {
    const { titulo, descripcion, precio_nodo } = req.body;
    if (!titulo || !descripcion) return res.status(400).json({ error: 'Faltan parámetros del producto.' });

    try {
        await pool.query('INSERT INTO productos (titulo, descripcion, precio_nodo) VALUES ($1, $2, $3)', [titulo, descripcion, precio_nodo || 0]);
        return res.status(200).json({ status: 'success', message: 'Producto inyectado a la landing.' });
    } catch (error) {
        return res.status(500).json({ error: 'Error de persistencia de catálogo.' });
    }
});

// Eliminar Producto de la Landing (Protegido por JWT)
app.delete('/api/admin/productos/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM productos WHERE id = $1', [id]);
        return res.status(200).json({ status: 'success', message: 'Producto removido de la landing.' });
    } catch (error) {
        return res.status(500).json({ error: 'Error al purgar software.' });
    }
});

// Métricas de Consola
app.get('/api/admin/metricas', verificarToken, async (req, res) => {
    try {
        const queryMetricas = "SELECT TO_CHAR(fecha, 'YYYY-MM-DD') as dia, COUNT(*) as cantidad FROM contactos GROUP BY dia ORDER BY dia ASC LIMIT 7;";
        const queryResumen = "SELECT COUNT(*) as total, COUNT(CASE WHEN fecha >= CURRENT_DATE THEN 1 END) as hoy FROM contactos;";
        const resMetricas = await pool.query(queryMetricas);
        const resResumen = await pool.query(queryResumen);
        return res.status(200).json({ historico: resMetricas.rows, resumen: { total: parseInt(resResumen.rows.total || 0), hoy: parseInt(resResumen.rows.hoy || 0) } });
    } catch (error) { return res.status(500).json({ error: 'Fallo al extraer métricas.' }); }
});
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 8
// SECCIÓN: EXTRACTOR DE MENSAJES CORPORATIVOS Y MAQUETACIÓN VISUAL DE LA FIRMA
// ============================================================================

app.get('/api/admin/mensajes', verificarToken, async (req, res) => {
    const search = req.query.search || '';
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5; 
    const offset = (page - 1) * limit;

    try {
        let queryData, queryCount, paramsData, paramsCount;
        if (search) {
            const searchParam = `%\${search}%`;
            queryData = 'SELECT * FROM contactos WHERE nombre ILIKE $1 OR email ILIKE $1 OR pais ILIKE $1 ORDER BY fecha DESC LIMIT $2 OFFSET $3';
            paramsData = [searchParam, limit, offset];
            queryCount = 'SELECT COUNT(*) FROM contactos WHERE nombre ILIKE $1 OR email ILIKE $1 OR pais ILIKE $1';
            paramsCount = [searchParam];
        } else {
            queryData = 'SELECT * FROM contactos ORDER BY fecha DESC LIMIT $1 OFFSET $2';
            paramsData = [limit, offset];
            queryCount = 'SELECT COUNT(*) FROM contactos';
            paramsCount = [];
        }
        const resData = await pool.query(queryData, paramsData);
        const resCount = await pool.query(queryCount, paramsCount);
        return res.status(200).json({ data: resData.rows, pagination: { page, limit, totalRegistros: parseInt(resCount.rows[0].count), totalPaginas: Math.ceil(parseInt(resCount.rows[0].count) / limit) } });
    } catch (error) { return res.status(500).json({ error: 'Error de consulta.' }); }
});

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MSEPTEM Tecnologías | Ciberseguridad</title>
    <link href="https://googleapis.com" rel="stylesheet">
    <style>
        :root {
            --obsidian-deep: #121212;
            --obsidian-surface: #1A1A1A;
            --obsidian-elevated: #242424;
            --gold-primary: #D4AF37;
            --text-light: #E0E0E0;
            --text-muted: #A0A0A0;
            --border-gold: rgba(212, 175, 55, 0.2);
            --transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background-color: var(--obsidian-deep); color: var(--text-light); font-family: 'Montserrat', sans-serif; line-height: 1.6; overflow-x: hidden; }
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 9
// SECCIÓN: ARQUITECTURA CSS DE TENDENCIA - BOTONES Y CONTENEDORES GLASS EFFECT
// ============================================================================

        header { background: linear-gradient(180deg, rgba(18,18,18,0.95) 0%, rgba(26,26,26,0.8) 100%); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border-gold); position: fixed; width: 100%; top: 0; z-index: 1000; padding: 1.25rem 5%; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-family: 'Cinzel', serif; font-size: 1.5rem; font-weight: 700; color: var(--gold-primary); letter-spacing: 2px; }
        
        /* Botones de Navegación Estilo Vidrioso (Glassmorphism Oficial) */
        .glass-btn, .nav-glass-btn {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(212, 175, 55, 0.2);
            color: var(--text-light);
            padding: 0.7rem 1.4rem;
            cursor: pointer;
            font-family: 'Montserrat', sans-serif;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            border-radius: 4px;
            transition: var(--transition);
        }
        .glass-btn:hover, .nav-glass-btn:hover, .nav-glass-btn.active {
            background: rgba(212, 175, 55, 0.15);
            border-color: var(--gold-primary);
            color: var(--gold-primary);
            box-shadow: 0 0 15px rgba(212, 175, 55, 0.25);
            transform: translateY(-2px);
        }

        .nav-glass-container { display: flex; justify-content: center; gap: 1rem; margin: -2rem auto 4rem auto; width: 90%; max-width: 1200px; flex-wrap: wrap; }
        .hero { min-height: 70vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 0 1rem; background: radial-gradient(circle at center, #1b170e 0%, var(--obsidian-deep) 70%); margin-top: 80px; }
        .hero h1 { font-family: 'Cinzel', serif; font-size: 3.5rem; color: var(--gold-primary); margin-bottom: 1rem; letter-spacing: 4px; }
        .hero p { font-size: 1.1rem; max-width: 700px; color: var(--text-muted); margin-bottom: 2.5rem; font-weight: 300; }

        .grid-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 2rem; width: 90%; max-width: 1200px; margin: 0 auto 4rem auto; }
        .card { background-color: var(--obsidian-surface); border: 1px solid var(--border-gold); padding: 2.5rem 2rem; border-radius: 4px; transition: var(--transition); }
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 10
// SECCIÓN: ESTILOS DE FORMULARIOS, TABLAS DE CONTROL Y ANIMACIONES DINÁMICAS
// ============================================================================

        .section-container { display: none; width: 100%; animation: fadeIn 0.4s ease forwards; }
        .section-container.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

        .analytics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; width: 100%; }
        .stat-card { background-color: var(--obsidian-surface); border: 1px solid var(--border-gold); padding: 1.5rem; border-radius: 4px; text-align: center; }
        .stat-card h4 { font-family: 'Cinzel', serif; color: var(--gold-primary); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 0.5rem; }
        .stat-card .value { font-size: 2rem; font-weight: 600; }

        .form-section, .admin-section, .config-section { background-color: var(--obsidian-surface); max-width: 600px; margin: 4rem auto; padding: 3rem; border-radius: 4px; border: 1px solid var(--border-gold); }
        .form-section h2, .admin-section h2, .config-section h2 { font-family: 'Cinzel', serif; color: var(--gold-primary); margin-bottom: 1.5rem; text-align: center; }
        
        .form-group { margin-bottom: 1.5rem; }
        .form-group label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem; text-transform: uppercase; }
        .form-control { width: 100%; background-color: var(--obsidian-elevated); border: 1px solid var(--border-gold); color: var(--text-light); padding: 0.85rem; font-family: 'Montserrat', sans-serif; border-radius: 2px; }
        
        .btn-gold { width: 100%; background: rgba(212, 175, 55, 0.05); border: 1px solid var(--gold-primary); color: var(--gold-primary); padding: 1rem; font-weight: 600; text-transform: uppercase; letter-spacing: 2px; cursor: pointer; border-radius: 4px; transition: var(--transition); }
        .btn-gold:hover { background: linear-gradient(135deg, var(--gold-primary) 0%, #f3e5ab 100%); color: var(--obsidian-deep); box-shadow: 0 0 20px rgba(212, 175, 55, 0.3); }
        
        .chart-wrapper { background-color: var(--obsidian-surface); border: 1px solid var(--border-gold); padding: 2rem; border-radius: 4px; margin-bottom: 2rem; height: 350px; }
        .toast-container { position: fixed; bottom: 2rem; right: 2rem; z-index: 9999; display: flex; flex-direction: column; gap: 1rem; }
        .toast { background-color: var(--obsidian-surface); border-left: 4px solid var(--gold-primary); color: var(--text-light); padding: 1rem 1.5rem; border-radius: 4px; min-width: 300px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .toast.error { border-left-color: #8b0000; }
    </style>
    <script src="https://cloudflare.com"></script>
</head>
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 11
// SECCIÓN: CUERPO HTML - CONMUTADORES DE CANALES DE PÁGINAS INDEPENDIENTES
// ============================================================================

<body>
    <div class="toast-container" id="toastContainer"></div>

    <header>
        <div style="display:flex; align-items:center; gap:12px;">
            <svg width="28" height="28" viewBox="0 0 100 100" fill="none" xmlns="http://w3.org">
                <path d="M50 5L55 25H45L50 5Z" fill="#D4AF37"/>
                <rect x="48" y="25" width="4" height="50" fill="#D4AF37"/>
                <rect x="35" y="35" width="30" height="4" fill="#D4AF37"/>
            </svg>
            <div class="logo" id="brandLogo" style="cursor:pointer; font-family:'Cinzel';">MSEPTEM</div>
        </div>
        <button class="glass-btn" id="adminToggleBtn">Portal Interno</button>
    </header>

    <div id="publicView">
        <section class="hero">
            <h1>MSEPTEM TECNOLOGÍAS</h1>
            <p>Ingeniería de sistemas críticos, encriptación avanzada de datos y blindaje de infraestructuras tácticas operativas.</p>
        </section>

        <!-- Barra de Conmutación Vidriosa para Navegación Cómoda -->
        <div class="nav-glass-container">
            <button class="nav-glass-btn active" id="nav-inicio" onclick="switchPublicSection('sec-inicio')">Inicio</button>
            <button class="nav-glass-btn" id="nav-productos" onclick="switchPublicSection('sec-productos')">Módulos & Catálogo</button>
            <button class="nav-glass-btn" id="nav-nosotros" onclick="switchPublicSection('sec-nosotros')">Nosotros</button>
            <button class="nav-glass-btn" id="nav-contacto" style="border-style:dashed;" onclick="switchPublicSection('sec-contacto')">Iniciar Conexión</button>
        </div>

        <!-- PÁGINA VIRTUAL 1: INICIO -->
        <div id="sec-inicio" class="section-container active">
            <div class="grid-container">
                <div class="card"><h3>Custom Software</h3><p>Plataformas monolíticas de alta disponibilidad construidas a medida de la firma corporativa.</p></div>
                <div class="card"><h3>Security Apps</h3><p>Aplicaciones móviles con capas criptográficas asimétricas y aislamiento local de memoria.</p></div>
                <div class="card"><h3>Cybersecurity</h3><p>Auditorías forenses, desarticulación de exploits y análisis perimetral automatizado.</p></div>
            </div>
        </div>
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 12
// SECCIÓN: MAQUETACIÓN DE RUTA DE FILOSOFÍA, LEADS Y VISTAS DE ENTRADA AL PANEL
// ============================================================================

        <!-- PÁGINA VIRTUAL 2: MÓDULOS DEL CATÁLOGO DINÁMICO DESDE POSTGRESQL -->
        <div id="sec-productos" class="section-container">
            <div class="grid-container" id="contenedorProductosPublicos">
                <!-- Se inyectan de forma asíncrona desde el repositorio sin tocar código -->
            </div>
        </div>

        <!-- PÁGINA VIRTUAL 3: FILOSOFÍA -->
        <div id="sec-nosotros" class="section-container">
            <div class="grid-container">
                <div class="card"><h3>Misión</h3><p>Garantizar el blindaje informático integral de nuestros aliados optimizando sus sistemas operativos.</p></div>
                <div class="card"><h3>Visión</h3><p>Posicionar a MSEPTEM a la vanguardia internacional en el desarrollo de software militar de alta confianza.</p></div>
                <div class="card"><h3>Objetivos</h3><p>Erradicar vectores de ataque mediante encriptación nativa y asegurar redundancia de datos distributed del 99.99%.</p></div>
            </div>
        </div>

        <!-- PÁGINA VIRTUAL 4: FORMULARIO -->
        <div id="sec-contacto" class="section-container">
            <section class="form-section" style="margin-top:0;">
                <h2>Requerimiento Tecnológico Especializado</h2>
                <form id="contactForm">
                    <div class="form-group"><label>Nombre de la Firma / Cliente</label><input type="text" id="nombre" class="form-control" required autocomplete="off"></div>
                    <div class="form-group"><label>Correo de Seguridad</label><input type="email" id="email" class="form-control" required autocomplete="off"></div>
                    <div class="form-group"><label>Teléfono Directo</label><input type="tel" id="telefono" class="form-control" required autocomplete="off"></div>
                    <div class="form-group">
                        <label>Categoría del Despliegue</label>
                        <select id="montoInversion" class="form-control" required>
                            <option value="App Móvil">App Móvil Secure</option>
                            <option value="Encriptador PC">Software Encriptador de PC</option>
                            <option value="Software Militar">Software Militares</option>
                        </select>
                    </div>
                    <div class="form-group"><label>País</label><input type="text" id="pais" class="form-control" required autocomplete="off"></div>
                    <div class="form-group"><label>Especificaciones</label><textarea id="mensaje" class="form-control" rows="4" required></textarea></div>
                    <button type="submit" class="btn-gold">Iniciar Conexión Segura</button>
                </form>
            </section>
        </div>
    </div>

    <!-- VISTAS DE LOGIN Y AUTENTICACIÓN -->
    <div id="loginView" class="hidden">
        <section class="admin-section" style="margin-top:120px;">
            <h2>Autenticación de Firma</h2>
            <form id="loginForm">
                <div class="form-group"><label>Operador</label><input type="text" id="username" class="form-control" required autocomplete="off"></div>
                <div class="form-group"><label>Firma Criptográfica</label><input type="password" id="password" class="form-control" required></div>
                <button type="submit" class="btn-gold">Validar Entrada</button>
            </form>
        </section>
    </div>

    <div id="twoFactorView" class="hidden">
        <section class="admin-section" style="margin-top:120px;">
            <h2>Verificación Perimetral 2FA</h2>
            <form id="twoFactorForm">
                <div class="form-group"><label>PIN de Auditoría</label><input type="text" id="pinInput" class="form-control" maxlength="6" style="text-align:center; font-size:1.5rem; letter-spacing:6px;" required autocomplete="off"></div>
                <button type="submit" class="btn-gold">Autorizar Acceso</button>
            </form>
        </section>
    </div>
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 13
// SECCIÓN: CONSOLA DE GESTIÓN INTERNA - CRUDS INTEGRADOS DE CONTROL DE CONTENIDOS
// ============================================================================

    <div id="dashboardView" class="hidden dashboard-view" style="margin-top:120px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem;">
            <h2 style="font-family:'Cinzel'; color:var(--gold-primary);">Consola de Control de Cómputo</h2>
            <div>
                <span id="sessionTimer" style="color:var(--gold-primary); margin-right:1rem;">Sesión: 15:00</span>
                <button class="glass-btn" id="exportCsvBtn" style="margin-right:0.5rem;">CSV</button>
                <button class="glass-btn" id="logoutBtn" style="border-color:#8b0000; color:#ff4444;">Cerrar</button>
            </div>
        </div>

        <!-- SECCIÓN CMS: AGREGAR PRODUCTOS EN TIEMPO REAL SIN TOCAR CÓDIGO -->
        <div class="form-section" style="margin: 0 auto 3rem auto; max-width:100%;">
            <h3 style="font-family:'Cinzel'; color:var(--gold-primary); margin-bottom:1rem;">Administrador de Catálogo (CMS Real-Time)</h3>
            <form id="cmsForm">
                <div class="form-group"><label>Nombre del Producto / Software</label><input type="text" id="cmsTitulo" class="form-control" placeholder="Ej. Software Militares Alpha" required autocomplete="off"></div>
                <div class="form-group"><label>Descripción del Sistema</label><textarea id="cmsDescripcion" class="form-control" rows="2" placeholder="Describa el alcance tecnológico..." required></textarea></div>
                <button type="submit" class="btn-gold">Inyectar y Publicar en la Landing</button>
            </form>
            
            <h4 style="font-family:'Cinzel'; margin-top:2rem; margin-bottom:1rem; color:var(--gold-primary);">Sistemas Publicados Actualmente</h4>
            <div class="table-container">
                <table>
                    <thead><tr><th>ID</th><th>Sistema</th><th>Descripción</th><th>Acción</th></tr></thead>
                    <tbody id="cmsTableBody"></tbody>
                </table>
            </div>
        </div>

        <div class="analytics-grid">
            <div class="stat-card"><h4>Solicitudes (Hoy)</h4><div class="value" id="statHoy">0</div></div>
            <div class="stat-card"><h4>Proyectos Acumulados</h4><div class="value" id="statTotal">0</div></div>
        </div>
        <div class="chart-wrapper"><canvas id="trafficChart"></canvas></div>
        <div class="search-container"><input type="text" id="searchInput" class="form-control" placeholder="Buscar registros..."></div>
        <div class="table-container">
            <table>
                <thead><tr><th>Cliente</th><th>Email</th><th>Teléfono</th><th>Categoría</th><th>País</th><th>Alcance</th><th>Fecha</th></tr></thead>
                <tbody id="mensajesTableBody"></tbody>
            </table>
        </div>
        <div class="pagination-container"><button class="glass-btn" id="prevPageBtn">Anterior</button><span id="pageIndicator">Página 1</span><button class="glass-btn" id="nextPageBtn">Siguiente</button></div>
    </div>
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 14
// SECCIÓN: LÓGICA DE CONTROL JAVASCRIPT CLIENTE - ENRUTADOR VIRTUAL CMS
// ============================================================================

    <script>
        let paginaActual = 1; let busquedaActual = ''; let usuarioEnProceso2FA = ''; let miGraficoInstancia = null; let cuentaRegresivaInactividad; let tiempoRestanteSesion = 15 * 60;

        function switchPublicSection(sectionId) {
            document.querySelectorAll('.section-container').forEach(sec => sec.classList.remove('active'));
            document.querySelectorAll('.nav-glass-container .nav-glass-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(sectionId).classList.add('active');
            const map = { 'sec-inicio': 'nav-inicio', 'sec-productos': 'nav-productos', 'sec-nosotros': 'nav-nosotros', 'sec-contacto': 'nav-contacto' };
            document.getElementById(map[sectionId]).classList.add('active');
        }

        function iniciarTemporizadorSesion() {
            clearInterval(cuentaRegresivaInactividad); tiempoRestanteSesion = 15 * 60;
            cuentaRegresivaInactividad = setInterval(() => {
                tiempoRestanteSesion--; const mins = Math.floor(tiempoRestanteSesion / 60); const segs = tiempoRestanteSesion % 60;
                document.getElementById('sessionTimer').innerText = 'Sesión: ' + (mins < 10 ? '0' : '') + mins + ':' + (segs < 10 ? '0' : '') + segs;
                if (tiempoRestanteSesion <= 0) ejecutarCierreSesionForzado();
            }, 1000);
        }

        // Carga dinámica de productos en la Landing Pública desde Postgres
        async function consultarCatalogoPublico() {
            try {
                const res = await fetch('/api/productos'); if(!res.ok) return;
                const productos = await res.json();
                const wrapper = document.getElementById('contenedorProductosPublicos');
                wrapper.innerHTML = '';
                if(productos.length === 0) {
                    wrapper.innerHTML = '<div class="card" style="grid-column: 1/-1; text-align:center;"><p style="color:var(--text-muted);">Catálogo en mantenimiento técnico.</p></div>';
                } else {
                    productos.forEach(p => {
                        wrapper.innerHTML += '<div class="card"><h3>' + p.titulo + '</h3><p>' + p.descripcion + '</p></div>';
                    });
                }
            } catch(e) {}
        }
        consultarCatalogoPublico();
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 15
// SECCIÓN: GESTIONADORES ASÍCRONOS DEL PANEL CMS, CONTROLADOR CSV Y ARRIVAL DE PUERTOS
// ============================================================================

        // Listar productos en la tabla del Panel Administrativo con botón Eliminar
        async function sincronizarPanelCMS() {
            const token = sessionStorage.getItem('mseptem_token');
            try {
                const res = await fetch('/api/productos'); if(!res.ok) return;
                const productos = await res.json();
                const tbody = document.getElementById('cmsTableBody'); tbody.innerHTML = '';
                productos.forEach(p => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td>' + p.id + '</td><td>' + p.titulo + '</td><td>' + p.descripcion + '</td><td><button class="glass-btn" style="border-color:#8b0000; color:#ff4444; padding:0.2rem 0.6rem;" onclick="eliminarProductoCMS(' + p.id + ')">Eliminar</button></td>';
                    tbody.appendChild(tr);
                });
            } catch(e) {}
        }

        // Agregar Producto Nuevo desde el Formulario CMS sin tocar código
        document.getElementById('cmsForm').addEventListener('submit', async (e) => {
            e.preventDefault(); const token = sessionStorage.getItem('mseptem_token');
            const payload = { titulo: document.getElementById('cmsTitulo').value.trim(), descripcion: document.getElementById('cmsDescripcion').value.trim() };
            try {
                const res = await fetch('/api/admin/productos', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }, body: JSON.stringify(payload) });
                if(res.ok) { showToast('Sistema incorporado a la landing.', 'success'); document.getElementById('cmsForm').reset(); sincronizarPanelCMS(); consultarCatalogoPublico(); }
            } catch(err) { showToast('Fallo de red.', 'error'); }
        });

        async function eliminarProductoCMS(id) {
            const token = sessionStorage.getItem('mseptem_token');
            try {
                const res = await fetch('/api/admin/productos/' + id, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + token } });
                if(res.ok) { showToast('Sistema purgado.', 'success'); sincronizarPanelCMS(); consultarCatalogoPublico(); }
            } catch(e) {}
        }

        // Eventos Base de Sesión
        document.getElementById('contactForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = { nombre: document.getElementById('nombre').value.trim(), email: document.getElementById('email').value.trim(), telefono: document.getElementById('telefono').value.trim(), monto_inversion: document.getElementById('montoInversion').value, pais: document.getElementById('pais').value.trim(), mensaje: document.getElementById('mensaje').value.trim() };
            try {
                const res = await fetch('/api/contacto', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                if(res.ok) { showToast('Requerimiento transmitido con éxito.', 'success'); document.getElementById('contactForm').reset(); }
            } catch(err) {}
        });

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = { usuario: document.getElementById('username').value.trim(), password: document.getElementById('password').value };
            try {
                const res = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await res.json();
                if(res.ok && data.status === '2fa_required') { usuarioEnProceso2FA = data.usuario; showToast(data.message, 'success'); loginView.classList.add('hidden'); twoFactorView.classList.remove('hidden'); }
            } catch(err) {}
        });

        document.getElementById('twoFactorForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = { usuario: usuarioEnProceso2FA, pin: document.getElementById('pinInput').value.trim() };
            try {
                const res = await fetch('/api/auth/verificar-2fa', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await res.json();
                if(res.ok) { sessionStorage.setItem('mseptem_token', data.token); showToast('Firma validada.', 'success'); twoFactorView.classList.add('hidden'); cargarMensajesDashboard(); iniciarTemporizadorSesion(); sincronizarPanelCMS(); }
            } catch(err) {}
        });

        async function cargarMensajesDashboard() {
            const token = sessionStorage.getItem('mseptem_token');
            try {
                const res = await fetch(\`/api/admin/mensajes?search=\${busquedaActual}&page=\${paginaActual}&limit=5\`, { method: 'GET', headers: { 'Authorization': 'Bearer ' + token } });
                if(res.ok) {
                    const json = await res.json(); const tbody = document.getElementById('mensajesTableBody'); tbody.innerHTML = '';
                    if(json.data.length === 0) { tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">Sin registros en cola.</td></tr>'; }
                    else {
                        json.data.forEach(m => {
                            const tr = document.createElement('tr');
                            tr.innerHTML = '<td>' + m.nombre + '</td><td>' + m.email + '</td><td>' + m.telefono + '</td><td>' + m.monto_inversion + '</td><td>' + m.pais + '</td><td>' + m.mensaje + '</td><td>' + new Date(m.fecha).toLocaleString() + '</td>';
                            tbody.appendChild(tr);
                        });
                    }
                    publicView.classList.add('hidden'); loginView.classList.add('hidden'); twoFactorView.classList.add('hidden'); dashboardView.classList.remove('hidden');
                }
            } catch(err) {}
        }

        function ejecutarCierreSesionForzado() { clearInterval(cuentaRegresivaInactividad); sessionStorage.removeItem('mseptem_token'); dashboardView.classList.add('hidden'); publicView.classList.remove('hidden'); showToast('Consola cerrada.', 'success'); }
        document.getElementById('logoutBtn').addEventListener('click', ejecutarCierreSesionForzado);
    </script>
</body>
</html>
    `);
});

app.listen(PORT, () => {
    console.log(`[SEGURIDAD] Servidor MSEPTEM activo en puerto \${PORT}`);
});

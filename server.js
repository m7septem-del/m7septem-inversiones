// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 1
// EMPRESA: MSEPTEM Inversiones
// ESTÁNDAR: Ciberseguridad Avanzada (OWASP Top 10) & Estética Obsidian & Gold
// COMPONENTES: Diagnóstico de Infraestructura y Capa Perimetral de Seguridad
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
    console.log(`[AUDITORÍA][\${marcaTiempo}][IP: \${ip}][OPERADOR: \${usuario}] ACCIÓN: \${evento} | \${detalles}`);
}
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 2
// SECCIÓN: HEALTH CHECK CORPORATIVO Y FILTRO PERIMETRAL DE IPS BLOQUEADAS
// ============================================================================

async function verificarSaludBaseDatos() {
    console.log('[SISTEMA] Iniciando diagnóstico perimetral de infraestructura...');
    try {
        const cliente = await pool.connect();
        console.log('[OK] Enlace físico establecido con el servidor PostgreSQL.');
        
        const queryTablas = `
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name IN ('contactos', 'administradores');
        `;
        const res = await cliente.query(queryTablas);
        const tablasExistentes = res.rows.map(r => r.table_name);
        
        if (!tablasExistentes.includes('contactos') || !tablasExistentes.includes('administradores')) {
            console.warn('[ADVERTENCIA] Esquema incompleto. Inyecte la base de datos estructural.');
        } else {
            console.log('[OK] Esquema físico verificado: Estructuras corporativas en línea.');
        }
        
        cliente.release();
    } catch (error) {
        console.error('[CRÍTICO] Error de conexión con PostgreSQL:', error.message);
        console.error('[SISTEMA] Operando en modo degradado temporal hasta restablecer enlace.');
    }
}
verificarSaludBaseDatos();

// Middleware para validar si la dirección IP se encuentra en lista negra temporal
app.use((req, res, next) => {
    const ipCliente = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const tiempoBloqueo = ipsBloqueadas.get(ipCliente);

    if (tiempoBloqueo) {
        if (Date.now() < tiempoBloqueo) {
            return res.status(423).json({ error: 'Dirección IP bloqueada preventivamente por múltiples fallos de autenticación.' });
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
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 3
// SECCIÓN: SANITIZACIÓN ANTI-INYECCIÓN, LIMITADOR DE RITMO Y FILTRO JWT
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
    message: { error: 'Tasa de peticiones excedida de forma perimetral.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', apiLimiter);

const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ');

    if (!token) return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Firma de sesión inválida o caducada.' });
        req.adminId = decoded.id;
        req.adminUser = decoded.user;
        next();
    });
};
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 4
// SECCIÓN: ENDPOINTS PÚBLICOS - REGISTRO DE LEADS E INICIO DE AUTENTICACIÓN
// ============================================================================

app.post('/api/contacto', async (req, res) => {
    const { nombre, email, telefono, monto_inversion, pais, mensaje } = req.body;
    const ipCliente = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!nombre || !email || !telefono || !monto_inversion || !pais || !mensaje || !email.includes('@')) {
        registrarEventoAuditoria('INTENTO_CONTACTO_FALLIDO', ipCliente, 'ANÓNIMO', 'Estructura inválida o incompleta enviada.');
        return res.status(400).json({ error: 'Todos los campos institucionales son de carácter obligatorio.' });
    }

    try {
        const query = 'INSERT INTO contactos (nombre, email, telefono, monto_inversion, pais, mensaje) VALUES (\$1, \$2, \$3, \$4, \$5, \$6) RETURNING id';
        await pool.query(query, [nombre, email, telefono, monto_inversion, pais, mensaje]);
        return res.status(200).json({ status: 'success', message: 'Datos corporativos resguardados en el historial de la firma.' });
    } catch (error) {
        return res.status(500).json({ error: 'Fallo general de persistencia en infraestructura.' });
    }
});

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
            if (fallos >= 5) {
                ipsBloqueadas.set(ipCliente, Date.now() + 15 * 60 * 1000);
                registrarEventoAuditoria('IP_BLOQUEADA_FUERZA_BRUTA', ipCliente, usuario, 'Se han registrado 5 fallos consecutivos de login.');
                return true;
            }
            return false;
        };

        if (result.rows.length === 0) {
            const bloqueoActivado = procesarFalloAutenticacion();
            return res.status(401).json({ error: bloqueoActivado ? 'IP bloqueada por múltiples intentos fallidos.' : 'Credenciales del operador inválidas.' });
        }

        const admin = result.rows[0]; 
        const passwordValido = await bcrypt.compare(password, admin.password_hash);

        if (!passwordValido) {
            const bloqueoActivado = procesarFalloAutenticacion();
            return res.status(401).json({ error: bloqueoActivado ? 'IP bloqueada por múltiples intentos fallidos.' : 'Credenciales del operador inválidas.' });
        }

        intentosLoginIP.delete(ipCliente);

        const pin2FA = Math.floor(100000 + Math.random() * 900000).toString();
        almacénPines2FA.set(admin.usuario, { pin: pin2FA, adminId: admin.id, expiracion: Date.now() + 120000 });

        registrarEventoAuditoria('TOKEN_2FA_GENERADO', ipCliente, admin.usuario, `PIN temporal asignado: \${pin2FA} (Validez de 120s)`);

        return res.status(200).json({ 
            status: '2fa_required', 
            usuario: admin.usuario,
            message: 'Primer factor validado. Ingrese el código reflejado en los registros de la firma.' 
        });
    } catch (error) {
        return res.status(500).json({ error: 'Pasarela de autenticación inaccesible temporalmente.' });
    }
});
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 5
// SECCIÓN: ENDPOINTS PROTEGIDOS POR JWT - CONTROL DE ACCESO INTERNO Y ANALÍTICAS
// ============================================================================

app.post('/api/auth/verificar-2fa', async (req, res) => {
    const { usuario, pin } = req.body;
    const ipCliente = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const datos2FA = almacénPines2FA.get(usuario);

    if (!datos2FA) return res.status(400).json({ error: 'El PIN ha expirado o no ha sido solicitado.' });
    if (Date.now() > datos2FA.expiracion) { almacénPines2FA.delete(usuario); return res.status(400).json({ error: 'El código temporal ha caducado.' }); }
    if (datos2FA.pin !== pin) { registrarEventoAuditoria('VIOLACION_PERMISO_2FA', ipCliente, usuario, 'PIN erróneo.'); return res.status(401).json({ error: 'Código de seguridad incorrecto.' }); }

    almacénPines2FA.delete(usuario);
    const token = jwt.sign({ id: datos2FA.adminId, user: usuario }, JWT_SECRET, { expiresIn: '1h' });
    registrarEventoAuditoria('ACCESO_CONCEDIDO', ipCliente, usuario, 'Autenticación multifactor completada.');

    return res.status(200).json({ status: 'success', token });
});

app.post('/api/admin/update-password', verificarToken, async (req, res) => {
    const { passwordActual, passwordNuevo } = req.body;
    try {
        const queryBusqueda = 'SELECT * FROM administradores WHERE id = \$1';
        const resultBusqueda = await pool.query(queryBusqueda, [req.adminId]);
        const admin = resultBusqueda.rows[0];
        const validacionActual = await bcrypt.compare(passwordActual, admin.password_hash);

        if (!validacionActual) return res.status(401).json({ error: 'La verificación de la clave actual ha fallado.' });

        const nuevoHash = await bcrypt.hash(passwordNuevo, 10);
        await pool.query('UPDATE administradores SET password_hash = \$1 WHERE id = \$2', [nuevoHash, req.adminId]);
        return res.status(200).json({ status: 'success', message: 'Firma digital corporativa reestructurada.' });
    } catch (error) { return res.status(500).json({ error: 'Error del motor al reescribir hashes.' }); }
});

app.get('/api/admin/metricas', verificarToken, async (req, res) => {
    try {
        const queryMetricas = "SELECT TO_CHAR(fecha, 'YYYY-MM-DD') as dia, COUNT(*) as cantidad FROM contactos GROUP BY dia ORDER BY dia ASC LIMIT 7;";
        const queryResumen = "SELECT COUNT(*) as total, COUNT(CASE WHEN fecha >= CURRENT_DATE THEN 1 END) as hoy FROM contactos;";
        
        const resMetricas = await pool.query(queryMetricas);
        const resResumen = await pool.query(queryResumen);

        return res.status(200).json({
            historico: resMetricas.rows,
            resumen: { total: parseInt(resResumen.rows[0].total || 0), hoy: parseInt(resResumen.rows[0].hoy || 0) }
        });
    } catch (error) { return res.status(500).json({ error: 'Fallo al extraer métricas analíticas reales.' }); }
});
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 6
// SECCIÓN: EXTRACTOR DE BITÁCORA MULTICOLUMNA Y ARRANQUE DE TOKEN VISUAL CSS3
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
            queryData = 'SELECT id, nombre, email, telefono, monto_inversion, pais, mensaje, fecha FROM contactos WHERE nombre ILIKE \$1 OR email ILIKE \$1 OR pais ILIKE \$1 ORDER BY fecha DESC LIMIT \$2 OFFSET \$3';
            paramsData = [searchParam, limit, offset];
            queryCount = 'SELECT COUNT(*) FROM contactos WHERE nombre ILIKE \$1 OR email ILIKE \$1 OR pais ILIKE \$1';
            paramsCount = [searchParam];
        } else {
            queryData = 'SELECT id, nombre, email, telefono, monto_inversion, pais, mensaje, fecha FROM contactos ORDER BY fecha DESC LIMIT \$1 OFFSET \$2';
            paramsData = [limit, offset];
            queryCount = 'SELECT COUNT(*) FROM contactos';
            paramsCount = [];
        }

        const resData = await pool.query(queryData, paramsData);
        const resCount = await pool.query(queryCount, paramsCount);
        const totalRegistros = parseInt(resCount.rows[0].count);
        const totalPaginas = Math.ceil(totalRegistros / limit);

        return res.status(200).json({
            data: resData.rows,
            pagination: { page, limit, totalRegistros, totalPaginas }
        });
    } catch (error) { return res.status(500).json({ error: 'Error de consulta en el almacén transaccional.' }); }
});

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MSEPTEM Inversiones | Capital Privado</title>
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

        header { background: linear-gradient(180deg, rgba(18,18,18,0.95) 0%, rgba(26,26,26,0.8) 100%); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border-gold); position: fixed; width: 100%; top: 0; z-index: 1000; padding: 1.25rem 5%; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-family: 'Cinzel', serif; font-size: 1.5rem; font-weight: 700; color: var(--gold-primary); letter-spacing: 2px; }
        .nav-btn { background: none; border: 1px solid var(--border-gold); color: var(--gold-primary); padding: 0.5rem 1rem; cursor: pointer; font-family: 'Montserrat', sans-serif; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; transition: var(--transition); }
        .nav-btn:hover { background-color: var(--gold-primary); color: var(--obsidian-deep); }
        .hero { min-height: 80vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 0 1rem; background: radial-gradient(circle at center, #1e1b13 0%, var(--obsidian-deep) 70%); margin-top: 60px; }
        .hero h1 { font-family: 'Cinzel', serif; font-size: 3.5rem; color: var(--gold-primary); margin-bottom: 1rem; letter-spacing: 4px; }
        .hero p { font-size: 1.1rem; max-width: 600px; color: var(--text-muted); margin-bottom: 2.5rem; font-weight: 300; }
        .grid-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 2rem; width: 90%; max-width: 1200px; margin: -4rem auto 4rem auto; }
        .card { background-color: var(--obsidian-surface); border: 1px solid var(--border-gold); padding: 2.5rem 2rem; border-radius: 4px; transition: var(--transition); }
        .card:hover { transform: translateY(-5px); border-color: var(--gold-primary); box-shadow: 0 10px 30px rgba(212, 175, 55, 0.1); }
        .card h3 { font-family: 'Cinzel', serif; color: var(--gold-primary); margin-bottom: 1rem; }
        .analytics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; width: 100%; }
        .stat-card { background-color: var(--obsidian-surface); border: 1px solid var(--border-gold); padding: 1.5rem; border-radius: 4px; text-align: center; }
        .stat-card h4 { font-family: 'Cinzel', serif; color: var(--gold-primary); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 0.5rem; letter-spacing: 1px; }
        .stat-card .value { font-size: 2rem; font-weight: 600; color: var(--text-light); }
        .form-section, .admin-section, .config-section { background-color: var(--obsidian-surface); max-width: 550px; margin: 4rem auto; padding: 3rem; border-radius: 4px; border: 1px solid var(--border-gold); }
        .form-section h2, .admin-section h2, .config-section h2 { font-family: 'Cinzel', serif; color: var(--gold-primary); margin-bottom: 1.5rem; text-align: center; letter-spacing: 1px; }
        .form-group { margin-bottom: 1.5rem; }
        .form-group label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem; text-transform: uppercase; }
        .form-control { width: 100%; background-color: var(--obsidian-elevated); border: 1px solid var(--border-gold); color: var(--text-light); padding: 0.85rem; font-family: 'Montserrat', sans-serif; border-radius: 2px; transition: var(--transition); }
        .form-control:focus { outline: none; border-color: var(--gold-primary); box-shadow: 0 0 5px rgba(212, 175, 55, 0.3); }
        .btn-gold { width: 100%; background: linear-gradient(135deg, #b8860b 0%, var(--gold-primary) 100%); color: var(--obsidian-deep); border: none; padding: 1rem; font-weight: 600; text-transform: uppercase; letter-spacing: 2px; cursor: pointer; transition: var(--transition); }
        .btn-gold:hover { background: linear-gradient(135deg, var(--gold-primary) 0%, #f3e5ab 100%); box-shadow: 0 0 15px rgba(212, 175, 55, 0.4); }
        .hidden { display: none !important; }
        .dashboard-view { max-width: 1200px; margin: 100px auto 4rem auto; padding: 0 2rem; }
        .chart-wrapper { background-color: var(--obsidian-surface); border: 1px solid var(--border-gold); padding: 2rem; border-radius: 4px; margin-bottom: 2rem; width: 100%; max-height: 400px; }
        .search-container { margin-bottom: 1.5rem; display: flex; width: 100%; max-width: 400px; }
        .pagination-container { display: flex; justify-content: center; align-items: center; gap: 1rem; margin-top: 1.5rem; padding: 1rem 0; }
        .table-container { width: 100%; overflow-x: auto; background-color: var(--obsidian-surface); border: 1px solid var(--border-gold); border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 1rem 1.5rem; border-bottom: 1px solid rgba(212, 175, 55, 0.1); }
        th { background-color: var(--obsidian-elevated); color: var(--gold-primary); font-family: 'Cinzel', serif; font-size: 0.9rem; }
        tr:hover { background-color: rgba(212, 175, 55, 0.02); }
        .toast-container { position: fixed; bottom: 2rem; right: 2rem; z-index: 9999; display: flex; flex-direction: column; gap: 1rem; }
        .toast { background-color: var(--obsidian-surface); border-left: 4px solid var(--gold-primary); color: var(--text-light); padding: 1rem 1.5rem; border-radius: 4px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); min-width: 300px; animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
        .toast.error { border-left-color: #8b0000; }
        @keyframes slideIn { from { opacity: 0; transform: translateX(100%); } to { opacity: 1; transform: translateX(0); } }
        @keyframes fadeOut { to { opacity: 0; transform: translateY(-10px); } }
    </style>
    <script src="https://cloudflare.com"></script>
</head>
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 7
// SECCIÓN: MAQUETACIÓN ESTRUCTURAL DE FORMULARIOS AMPLIADOS Y DASHBOARD ANALÍTICO
// ============================================================================

<body>
    <div class="toast-container" id="toastContainer"></div>

    <header>
        <div class="logo" id="brandLogo" style="cursor:pointer;">MSEPTEM</div>
        <button class="nav-btn" id="adminToggleBtn">Portal Interno</button>
    </header>

    <div id="publicView">
        <section class="hero">
            <h1>MSEPTEM INVERSIONES</h1>
            <p>Arquitectura financiera avanzada y gestión de patrimonio institucional bajo los más estrictos estándares globales de seguridad corporativa.</p>
        </section>
        <div class="grid-container">
            <div class="card"><h3>Private Equity</h3><p>Acceso exclusivo a vehículos de inversión en mercados privados y activos alternativos de alto rendimiento.</p></div>
            <div class="card"><h3>Wealth Management</h3><p>Estrategias personalizadas de preservación y crecimiento patrimonial con mitigación activa de riesgos.</p></div>
            <div class="card"><h3>Corporate Security</h3><p>Estructuras tecnológicas y operativas blindadas para transacciones corporativas de alta confianza.</p></div>
        </div>

        <section class="form-section" style="max-width: 700px; margin: 2rem auto;">
            <h2>Simulador de Capital Alternativo</h2>
            <div class="form-group">
                <label>Inversión Inicial ($ USD)</label>
                <input type="number" id="simMonto" class="form-control" value="50000" step="5000">
            </div>
            <div class="form-group">
                <label>Plazo Estimado (Años)</label>
                <input type="range" id="simPlazo" min="1" max="10" value="5" class="form-control" oninput="document.getElementById('plazoVal').innerText = this.value">
                <span id="plazoVal" style="color:var(--gold-primary); font-size:0.9rem;">5</span> <span style="color:var(--text-muted); font-size:0.9rem;">Años</span>
            </div>
            <div class="form-group">
                <label>Tasa de Rendimiento Anual Esperada (% APR)</label>
                <select id="simTasa" class="form-control">
                    <option value="0.12">Clase A (12% Retorno Preferente)</option>
                    <option value="0.18" selected>Clase Alpha Premium (18% Co-Inversión)</option>
                    <option value="0.24">Clase Oportunística (24% Mercado Privado)</option>
                </select>
            </div>
            <button type="button" class="btn-gold" id="btnCalcularSim">Proyectar Retorno Estimado</button>
            <div id="simResultado" style="margin-top:2rem; text-align:center; display:none; border-top:1px dashed var(--border-gold); padding-top:1.5rem;">
                <p style="font-size:0.9rem; color:var(--text-muted); text-transform:uppercase;">Patrimonio Proyectado Final</p>
                <h3 id="simTotal" style="font-family:'Cinzel'; color:var(--gold-primary); font-size:2.2rem; margin-bottom:0.5rem;">$0.00</h3>
                <p style="font-size:0.85rem; color:var(--text-muted);">*Cálculo de interés compuesto ilustrativo para firmas asociadas.</p>
            </div>
        </section>

        <section class="form-section">
            <h2>Contacto Institucional</h2>
            <form id="contactForm">
                <div class="form-group"><label>Nombre Completo</label><input type="text" id="nombre" class="form-control" required autocomplete="off"></div>
                <div class="form-group"><label>Correo Corporativo</label><input type="email" id="email" class="form-control" required autocomplete="off"></div>
                <div class="form-group"><label>Teléfono Corporativo</label><input type="tel" id="telefono" class="form-control" placeholder="+1 234 567 890" required autocomplete="off"></div>
                <div class="form-group">
                    <label>Monto Estimado de Inversión</label>
                    <select id="montoInversion" class="form-control" required>
                        <option value="" disabled selected>Seleccione un rango corporativo</option>
                        <option value="tier_1">$250,000 USD - $1,000,000 USD</option>
                        <option value="tier_2">$1,000,000 USD - $5,000,000 USD</option>
                        <option value="tier_3">$5,000,000 USD+</option>
                    </select>
                </div>
                <div class="form-group"><label>País de Origen de la Firma</label><input type="text" id="pais" class="form-control" placeholder="Ej. Venezuela, España, etc." required autocomplete="off"></div>
                <div class="form-group"><label>Requerimiento Institucional</label><textarea id="mensaje" class="form-control" rows="4" required></textarea></div>
                <button type="submit" class="btn-gold">Iniciar Conexión Segura</button>
            </form>
        </section>
    </div>

    <div id="loginView" class="hidden">
        <section class="admin-section" style="margin-top: 120px;">
            <h2>Autenticación de Firma</h2>
            <form id="loginForm">
                <div class="form-group"><label>Identificador del Operador</label><input type="text" id="username" class="form-control" required autocomplete="off"></div>
                <div class="form-group"><label>Clave de Acceso Criptográfica</label><input type="password" id="password" class="form-control" required></div>
                <button type="submit" class="btn-gold">Validar Credenciales</button>
            </form>
        </section>
    </div>

    <div id="twoFactorView" class="hidden">
        <section class="admin-section" style="margin-top: 120px;">
            <h2>Verificación Perimetral 2FA</h2>
            <form id="twoFactorForm">
                <div class="form-group">
                    <label>Código Temporal de Acceso (PIN)</label>
                    <input type="text" id="pinInput" class="form-control" placeholder="6 dígitos" required autocomplete="off" maxlength="6" style="text-align:center; font-size:1.5rem; letter-spacing:8px;">
                </div>
                <button type="submit" class="btn-gold">Autorizar Entrada</button>
            </form>
        </section>
    </div>

    <div id="dashboardView" class="hidden dashboard-view" style="margin-top:120px; padding: 0 5%;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem;">
            <h2 style="font-family:'Cinzel'; color:var(--gold-primary);">Consola de Comunicaciones</h2>
            <div style="display:flex; align-items:center;">
                <span id="sessionTimer" style="font-size:0.85rem; color:var(--gold-primary); margin-right:1.5rem; border:1px solid var(--border-gold); padding:0.4rem 0.8rem; border-radius:2px;">Sesión Segura: 15:00</span>
                <button class="nav-btn" id="goConfigBtn" style="margin-right: 1rem;">Seguridad / Firma</button>
                <button class="nav-btn" id="exportCsvBtn" style="border-color: var(--gold-primary); margin-right: 1rem;">Exportar (CSV)</button>
                <button class="nav-btn" id="logoutBtn" style="border-color:#8b0000; color:#ff4444;">Cerrar Consola</button>
            </div>
        </div>
        <div class="analytics-grid">
            <div class="stat-card"><h4>Comunicaciones Recibidas (Hoy)</h4><div class="value" id="statHoy">0</div></div>
            <div class="stat-card"><h4>Historial Acumulado Total</h4><div class="value" id="statTotal">0</div></div>
        </div>
        <div class="chart-wrapper"><canvas id="trafficChart" style="width:100%; height:100%; max-height:320px CONTAINER;"></canvas></div>
        <div class="search-container"><input type="text" id="searchInput" class="form-control" placeholder="Buscar por remitente, correo o país..." style="border-radius: 4px;"></div>
        <div class="table-container">
            <table>
                <thead>
                    <tr><th>Remitente</th><th>Contacto Electrónico</th><th>Teléfono</th><th>Inversión Proyectada</th><th>País Firma</th><th>Requerimiento Corporativo</th><th>Registro Fecha</th></tr>
                </thead>
                <tbody id="mensajesTableBody"></tbody>
            </table>
        </div>
        <div class="pagination-container">
            <button class="nav-btn" id="prevPageBtn">Anterior</button>
            <span id="pageIndicator" style="font-size:0.9rem; color:var(--text-muted)">Página 1 de 1</span>
            <button class="nav-btn" id="nextPageBtn">Siguiente</button>
        </div>
    </div>

    <div id="configView" class="hidden">
        <section class="config-section" style="margin-top: 120px;">
            <h2>Actualizar Firma Digital</h2>
            <form id="updatePasswordForm">
                <div class="form-group"><label>Clave Criptográfica Actual</label><input type="password" id="passwordActual" class="form-control" required></div>
                <div class="form-group"><label>Nueva Clave Corporativa (Min 8 Caracteres)</label><input type="password" id="passwordNuevo" class="form-control" required></div>
                <div style="display:flex; gap:1rem;"><button type="submit" class="btn-gold">Confirmar Nueva Firma</button><button type="button" class="nav-btn" id="backToDashBtn" style="width:40%;">Volver</button></div>
            </form>
        </section>
    </div>
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 8
// SECCIÓN: RENDERIZADO ANALÍTICO DE MÉTRICAS, TEMPORIZADOR Y ARRANQUE EXPRESS
// ============================================================================

    <script>
        let paginaActual = 1;
        let busquedaActual = '';
        let usuarioEnProceso2FA = '';
        let miGraficoInstancia = null;
        let cuentaRegresivaInactividad;
        let tiempoRestanteSesion = 15 * 60; 

        document.getElementById('btnCalcularSim').addEventListener('click', () => {
            const monto = parseFloat(document.getElementById('simMonto').value);
            const plazo = parseInt(document.getElementById('simPlazo').value);
            const tasa = parseFloat(document.getElementById('simTasa').value);
            if(isNaN(monto) || monto <= 0) { showToast('Por favor ingrese un capital de inversión válido.', 'error'); return; }
            const resultadoCompuesto = monto * Math.pow((1 + tasa), plazo);
            document.getElementById('simTotal').innerText = '$ ' + resultadoCompuesto.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
            document.getElementById('simResultado').style.display = 'block';
            showToast('Proyección patrimonial calculada con éxito.', 'success');
        });

        function iniciarTemporizadorSesion() {
            clearInterval(cuentaRegresivaInactividad);
            tiempoRestanteSesion = 15 * 60;
            cuentaRegresivaInactividad = setInterval(() => {
                tiempoRestanteSesion--;
                const minutos = Math.floor(tiempoRestanteSesion / 60);
                const segundos = tiempoRestanteSesion % 60;
                document.getElementById('sessionTimer').innerText = 'Sesión Segura: ' + (minutos < 10 ? '0' : '') + minutos + ':' + (segundos < 10 ? '0' : '') + segundos;
                if (tiempoRestanteSesion <= 0) { clearInterval(cuentaRegresivaInactividad); ejecutarCierreSesionForzado(); }
            }, 1000);
        }

        function resetearTemporizadorPorActividad() { if (sessionStorage.getItem('mseptem_token')) { tiempoRestanteSesion = 15 * 60; } }
        window.onload = () => { ['click', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(evt => document.addEventListener(evt, resetearTemporizadorPorActividad, true)); };

        const adminToggleBtn = document.getElementById('adminToggleBtn');
        const publicView = document.getElementById('publicView');
        const loginView = document.getElementById('loginView');
        const twoFactorView = document.getElementById('twoFactorView');
        const dashboardView = document.getElementById('dashboardView');
        const configView = document.getElementById('configView');

        document.getElementById('brandLogo').addEventListener('click', () => {
            if(!sessionStorage.getItem('mseptem_token')) {
                publicView.classList.remove('hidden'); loginView.classList.add('hidden');
                twoFactorView.classList.add('hidden'); dashboardView.classList.add('hidden'); configView.classList.add('hidden');
            }
        });

        adminToggleBtn.addEventListener('click', () => {
            const token = sessionStorage.getItem('mseptem_token');
            if(token) { cargarMensajesDashboard(); } 
            else {
                publicView.classList.add('hidden'); dashboardView.classList.add('hidden');
                configView.classList.add('hidden'); twoFactorView.classList.add('hidden'); loginView.classList.remove('hidden');
            }
        });

        document.getElementById('goConfigBtn').addEventListener('click', () => { dashboardView.classList.add('hidden'); configView.classList.remove('hidden'); });
        document.getElementById('backToDashBtn').addEventListener('click', () => { configView.classList.add('hidden'); dashboardView.classList.remove('hidden'); });

        let searchTimeout;
        document.getElementById('searchInput').addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            busquedaActual = e.target.value.trim();
            searchTimeout = setTimeout(() => { paginaActual = 1; cargarMensajesDashboard(); }, 400);
        });

        document.getElementById('prevPageBtn').addEventListener('click', () => { if (paginaActual > 1) { paginaActual--; cargarMensajesDashboard(); } });
        document.getElementById('nextPageBtn').addEventListener('click', () => { paginaActual++; cargarMensajesDashboard(); });

        async function renderizarGraficoMetricas() {
            const token = sessionStorage.getItem('mseptem_token');
            try {
                const response = await fetch('/api/admin/metricas', { method: 'GET', headers: { 'Authorization': 'Bearer ' + token } });
                if(!response.ok) return;
                const datosMetricas = await response.json();
                document.getElementById('statHoy').innerText = datosMetricas.resumen.hoy;
                document.getElementById('statTotal').innerText = datosMetricas.resumen.total;
                const etiquetasDias = datosMetricas.historico.map(r => r.dia);
                const volumetriaDatos = datosMetricas.historico.map(r => parseInt(r.cantidad));
                const ctx = document.getElementById('trafficChart').getContext('2d');
                if (miGraficoInstancia) { miGraficoInstancia.destroy(); }
                miGraficoInstancia = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: etiquetasDias.length ? etiquetasDias : ['Sin Datos'],
                        datasets: [{
                            label: 'Volumen de Requerimientos Institucionales',
                            data: volumetriaDatos.length ? volumetriaDatos : [],
                            borderColor: '#D4AF37',
                            backgroundColor: 'rgba(212, 175, 55, 0.05)',
                            borderWidth: 2,
                            tension: 0.3,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#E0E0E0', font: { family: 'Montserrat' } } } },
                        scales: {
                            x: { grid: { color: 'rgba(212,175,55,0.05)' }, ticks: { color: '#A0A0A0' } },
                            y: { grid: { color: 'rgba(212,175,55,0.05)' }, ticks: { color: '#A0A0A0', stepSize: 1 } }
                        }
                    }
                });
            } catch (err) { console.error('Error al pintar la analítica visual.'); }
        }

        document.getElementById('contactForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = {
                nombre: document.getElementById('nombre').value.trim(),
                email: document.getElementById('email').value.trim(),
                telefono: document.getElementById('telefono').value.trim(),
                monto_inversion: document.getElementById('montoInversion').value,
                pais: document.getElementById('pais').value.trim(),
                mensaje: document.getElementById('mensaje').value.trim()
            };
            const xssPattern = /<script[^>]*>([\s\S]*?)<\/script>|<[^>]+>/gi;
            if (xssPattern.test(payload.nombre) || xssPattern.test(payload.mensaje) || xssPattern.test(payload.telefono)) { showToast('Patrón sintáctico prohibido detectado.', 'error'); return; }
            try {
                const response = await fetch('/api/contacto', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await response.json();
                if (response.ok) { showToast('Transmisión exitosa: ' + data.message, 'success'); document.getElementById('contactForm').reset(); } 
                else { showToast('Error: ' + data.error, 'error'); }
            } catch (error) { showToast('Fallo en la comunicación perimetral.', 'error'); }
        });

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = { usuario: document.getElementById('username').value.trim(), password: document.getElementById('password').value };
            try {
                const response = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await response.json();
                if (response.ok && data.status === '2fa_required') {
                    usuarioEnProceso2FA = data.usuario;
                    showToast(data.message, 'success');
                    loginView.classList.add('hidden'); twoFactorView.classList.remove('hidden');
                } else { showToast('Error: ' + data.error, 'error'); }
            } catch (error) { showToast('Error en la pasarela de autenticación.', 'error'); }
        });

        document.getElementById('twoFactorForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = { usuario: usuarioEnProceso2FA, pin: document.getElementById('pinInput').value.trim() };
            try {
                const response = await fetch('/api/auth/verificar-2fa', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await response.json();
                if (response.ok) {
                    sessionStorage.setItem('mseptem_token', data.token);
// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 8
// SECCIÓN: COMPORTAMIENTO INTERACTIVO CLIENTE, EXPORTACIÓN Y ESCUCHA ACTIVADA
// ============================================================================

                showToast('Firma validada. Concediendo acceso...', 'success');
                document.getElementById('twoFactorForm').reset();
                twoFactorView.classList.add('hidden');
                cargarMensajesDashboard();
                iniciarTemporizadorSesion();
            } else { 
                showToast('Error: ' + data.error, 'error'); 
            }
        } catch (error) { 
            showToast('Fallo crítico en factor de doble verificación.', 'error'); 
        }
    });

    // Procesamiento seguro del cambio de firma criptográfica
    document.getElementById('updatePasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = sessionStorage.getItem('mseptem_token');
        const payload = { 
            passwordActual: document.getElementById('passwordActual').value, 
            passwordNuevo: document.getElementById('passwordNuevo').value 
        };
        try {
            const response = await fetch('/api/admin/update-password', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }, 
                body: JSON.stringify(payload) 
            });
            const data = await response.json();
            if (response.ok) { 
                showToast('Firma actualizada. Autentíquese nuevamente.', 'success'); 
                ejecutarCierreSesionForzado(); 
            } else { 
                showToast('Error: ' + data.error, 'error'); 
            }
        } catch (error) { 
            showToast('Error al reestructurar firma criptográfica.', 'error'); 
        }
    });

    // Sincronización de la bitácora multicriterio en tiempo real
    async function cargarMensajesDashboard() {
        const token = sessionStorage.getItem('mseptem_token');
        try {
            const response = await fetch(\`/api/admin/mensajes?search=\${busquedaActual}&page=\${paginaActual}&limit=5\`, { 
                method: 'GET', 
                headers: { 'Authorization': 'Bearer ' + token } 
            });
            if(response.ok) {
                const resJson = await response.json();
                const mensajes = resJson.data;
                const pag = resJson.pagination;
                const tbody = document.getElementById('mensajesTableBody');
                tbody.innerHTML = '';
                
                if(mensajes.length === 0) { 
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No hay comunicaciones entrantes en el registro corporativo.</td></tr>'; 
                } else {
                    mensajes.forEach(m => {
                        const tr = document.createElement('tr');
                        const rangosMonto = { tier_1: '\$250K - \$1M', tier_2: '\$1M - \$5M', tier_3: '\$5M+' };
                        const inversionFormateada = rangosMonto[m.monto_inversion] || m.monto_inversion;
                        tr.innerHTML = '<td>' + m.nombre + '</td><td>' + m.email + '</td><td>' + m.telefono + '</td><td style="color:var(--gold-primary); font-weight:600;">' + inversionFormateada + '</td><td>' + m.pais + '</td><td>' + m.mensaje + '</td><td>' + new Date(m.fecha).toLocaleString() + '</td>';
                        tbody.appendChild(tr);
                    });
                }
                
                document.getElementById('pageIndicator').innerText = \`Página \${pag.page} de \${pag.totalPaginas || 1}\`;
                document.getElementById('prevPageBtn').disabled = pag.page <= 1;
                document.getElementById('nextPageBtn').disabled = pag.page >= pag.totalPaginas;
                
                publicView.classList.add('hidden'); 
                loginView.classList.add('hidden'); 
                configView.classList.add('hidden'); 
                twoFactorView.classList.add('hidden');
                dashboardView.classList.remove('hidden');
                
                renderizarGraficoMetricas();
            } else { 
                ejecutarCierreSesionForzado(); 
                showToast('Sesión inválida o expirada.', 'error'); 
            }
        } catch (error) { 
            showToast('Fallo al sincronizar consola corporativa.', 'error'); 
        }
    }

    // Exportador integral de auditorías físicas a formato CSV
    document.getElementById('exportCsvBtn').addEventListener('click', async () => {
        const token = sessionStorage.getItem('mseptem_token');
        try {
            const response = await fetch(\`/api/admin/mensajes?search=\${busquedaActual}&page=1&limit=1000\`, { 
                method: 'GET', 
                headers: { 'Authorization': 'Bearer ' + token } 
            });
            if(response.ok) {
                const resJson = await response.json();
                const mensajes = resJson.data;
                if(mensajes.length === 0) { 
                    showToast('No existen registros para exportar.', 'error'); 
                    return; 
                }
                
                let csvContent = "\\uFEFF"; // BOM para compatibilidad utf-8 (Acentos y caracteres en Excel)
                csvContent += "ID,Remitente,Contacto,Telefono,Rango Inversion,Pais,Requerimiento,Fecha\\n";
                mensajes.forEach(m => { 
                    csvContent += \`\${m.id},"\${m.nombre}","\${m.email}","\${m.telefono}","\${m.monto_inversion}","\${m.pais}","\${m.mensaje}","\${new Date(m.fecha).toLocaleString()}"\\n\`; 
                });
                
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.setAttribute("href", url); 
                link.setAttribute("download", \`MSEPTEM_AUDIT_\${new Date().toISOString().slice(0,10)}.csv\`);
                document.body.appendChild(link); 
                link.click(); 
                document.body.removeChild(link);
            }
        } catch (error) { 
            showToast('Error de empaquetado al exportar la bitácora.', 'error'); 
        }
    });

    // Protocolo preventivo por inactividad prolongada de operadores
    function ejecutarCierreSesionForzado() {
        clearInterval(cuentaRegresivaInactividad);
        sessionStorage.removeItem('mseptem_token');
        dashboardView.classList.add('hidden'); 
        configView.classList.add('hidden'); 
        publicView.classList.remove('hidden');
        showToast('Consola de administración cerrada de forma segura.', 'success');
    }

    document.getElementById('logoutBtn').addEventListener('click', ejecutarCierreSesionForzado);
    </script>
</body>
</html>
    `);
});

// Inicialización del servidor web seguro y bindeo de puertos dinámicos para producción
app.listen(PORT, () => {
    console.log(`[SEGURIDAD] Servidor MSEPTEM activo y enlazado en puerto ${PORT}`);
});

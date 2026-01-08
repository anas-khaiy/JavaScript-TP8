/**
 * POINT D'ENTRÉE PRINCIPAL DU SERVEUR
 */
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const connectDB = require('./config/db');
const errorHandler = require('./middlewares/errorHandler');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Connexion à la base de données MongoDB
connectDB();

// 2. Middlewares de Sécurité (Bonnes pratiques)
app.use(helmet()); // Protège les en-têtes HTTP contre les vulnérabilités communes
app.use(mongoSanitize()); // Empêche les injections NoSQL en supprimant les caractères '$' ou '.'

// 3. Limiteur de requêtes pour prévenir les attaques par force brute
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Fenêtre de 15 minutes
    max: 10, // Max 10 tentatives par IP
    message: {
        success: false,
        message: 'Trop de tentatives de connexion. Veuillez réessayer après 15 minutes'
    }
});

// 4. Middlewares de parsing (Analyse des données entrantes)
app.use(express.json()); // Pour lire le JSON dans req.body
app.use(express.urlencoded({ extended: true })); // Pour lire les formulaires classiques
app.use(cookieParser()); // Pour extraire les cookies des en-têtes (utile pour JWT/Refresh Token)

// 5. Configuration de la Gestion des Sessions
// Note: Utilise MemoryStore par défaut. Pour la prod, connectez Redis ici.
app.use(session({
    secret: process.env.SESSION_SECRET, // Clé pour signer le cookie de session
    resave: false, // Ne pas sauvegarder la session si elle n'a pas été modifiée
    saveUninitialized: false, // Ne pas créer de session vide pour les visiteurs anonymes
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Cookie sécurisé (HTTPS) uniquement en production
        httpOnly: true, // Empêche l'accès au cookie via le JavaScript client (Protection XSS)
        maxAge: 24 * 60 * 60 * 1000 // Durée de vie : 24 heures
    }
}));

// 6. Application des limiteurs sur les routes sensibles
app.use('/api/auth/login-session', loginLimiter);
app.use('/api/auth/login-jwt', loginLimiter);

// 7. Définition des Routes
app.use('/api/auth', require('./routes/authRoutes'));

// Route de bienvenue
app.get('/', (req, res) => {
    res.send('API d\'authentification (Sessions + JWT) - Opérationnelle');
});

// 8. Gestion centralisée des erreurs (doit être le DERNIER middleware)
app.use(errorHandler);

// Lancement du serveur
app.listen(PORT, () => {
    console.log(`🚀 Serveur actif sur http://localhost:${PORT}`);
});


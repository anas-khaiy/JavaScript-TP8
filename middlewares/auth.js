const { verifyAccessToken } = require('../utils/tokenUtils');

/**
 * MIDDLEWARES POUR L'AUTHENTIFICATION PAR SESSIONS
 * Basé sur les cookies de session stockés sur le serveur (MemoryStore/Redis)
 */

// Vérifie si l'utilisateur possède une session active
exports.isAuthenticatedWithSession = (req, res, next) => {
    if (req.session && req.session.userId) {
        return next();
    }

    res.status(401).json({
        success: false,
        message: 'Accès refusé. Veuillez vous connecter (Session requise).'
    });
};

// Vérifie les permissions (rôles) basées sur la session
exports.authorizeWithSession = (roles) => {
    return (req, res, next) => {
        if (!req.session || !req.session.userRole) {
            return res.status(401).json({
                success: false,
                message: 'Accès non autorisé'
            });
        }

        if (!roles.includes(req.session.userRole)) {
            return res.status(403).json({
                success: false,
                message: 'Droits insuffisants pour accéder à cette ressource'
            });
        }

        next();
    };
};

/**
 * MIDDLEWARES POUR L'AUTHENTIFICATION PAR JWT
 * Vérifie le token Bearer envoyé dans les en-têtes de la requête
 */

// Vérifie la validité du Access Token JWT
exports.isAuthenticatedWithJWT = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        // Le format standard est "Bearer <TOKEN>"
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: 'Accès non autorisé. Token manquant ou format incorrect'
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyAccessToken(token); // On utilise l'utilitaire de vérification

        // On injecte les données décodées (id, role) dans req.user pour usage ultérieur
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'Accès non autorisé. Token invalide ou expiré',
            error: error.message
        });
    }
};

// Vérifie les rôles de l'utilisateur authentifié par JWT
exports.authorizeWithJWT = (roles) => {
    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res.status(401).json({
                success: false,
                message: 'Accès non autorisé. Authentification requise'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Accès interdit. Vous n\'avez pas les droits nécessaires (JWT)'
            });
        }

        next();
    };
};


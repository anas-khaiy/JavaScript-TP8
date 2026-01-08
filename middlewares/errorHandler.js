// Middleware de gestion des erreurs
const errorHandler = (err, req, res, next) => {
    console.error(err.stack);

    // Erreurs Mongoose de validation
    if (err.name === 'ValidationError') {
        const messages = Object.values(err.errors).map(val => val.message);
        return res.status(400).json({
            success: false,
            error: messages.join(', ')
        });
    }

    // Erreur de duplication MongoDB
    if (err.code === 11000) {
        return res.status(400).json({
            success: false,
            error: 'Cette valeur existe déjà dans la base de données'
        });
    }

    // Erreur d'ID MongoDB invalide
    if (err.name === 'CastError') {
        return res.status(400).json({
            success: false,
            error: 'Identifiant invalide'
        });
    }

    // Erreur JWT
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            error: 'Token invalide'
        });
    }

    // Erreur d'expiration JWT
    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            success: false,
            error: 'Token expiré'
        });
    }

    // Erreur serveur par défaut
    res.status(err.statusCode || 500).json({
        success: false,
        error: process.env.NODE_ENV === 'production'
            ? 'Erreur serveur'
            : err.message
    });
};

module.exports = errorHandler;

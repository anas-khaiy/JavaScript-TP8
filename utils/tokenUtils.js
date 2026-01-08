const jwt = require('jsonwebtoken');
require('dotenv').config();

// Générer un token d'accès
exports.generateAccessToken = (userId, role) => {
    return jwt.sign(
        { id: userId, role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRY }
    );
};

// Générer un token de rafraîchissement
exports.generateRefreshToken = (userId) => {
    return jwt.sign(
        { id: userId },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
    );
};

// Vérifier un token d'accès
exports.verifyAccessToken = (token) => {
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        throw new Error('Token invalide ou expiré');
    }
};

// Vérifier un token de rafraîchissement
exports.verifyRefreshToken = (token) => {
    try {
        return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (error) {
        throw new Error('Token de rafraîchissement invalide ou expiré');
    }
};

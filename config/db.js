const mongoose = require('mongoose');
require('dotenv').config();

// Options de connexion pour éviter les avertissements de dépréciation
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('MongoDB connecté avec succès');
    } catch (error) {
        console.error('Erreur de connexion à MongoDB:', error.message);
        // Quitte le processus avec un code d'erreur
        process.exit(1);
    }
};

module.exports = connectDB;

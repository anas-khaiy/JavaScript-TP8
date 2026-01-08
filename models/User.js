const mongoose = require('mongoose');
const bcrypt = require('bcrypt');


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Le nom d\'utilisateur est requis'],
        unique: true, // Empêche les doublons
        trim: true,
        minlength: [3, 'Le nom d\'utilisateur doit contenir au moins 3 caractères']
    },
    email: {
        type: String,
        required: [true, 'L\'email est requis'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Veuillez fournir un email valide']
    },
    password: {
        type: String,
        required: [true, 'Le mot de passe est requis'],
        minlength: [6, 'Le mot de passe doit contenir au moins 6 caractères'],
        select: false // Sécurité : ce champ ne sera pas inclus par défaut dans les find()
    },
    role: {
        type: String,
        enum: ['user', 'admin'], // Rôles autorisés
        default: 'user'
    },
    refreshToken: {
        type: String,
        select: false // Utilisé uniquement pour l'authentification JWT
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// MIDDLEWARE : S'exécute automatiquement avant chaque sauvegarde (save)
userSchema.pre('save', async function () {
    // Si le mot de passe n'a pas été modifié, on ne fait rien
    if (!this.isModified('password')) return;

    // Hachage sécurisé du mot de passe avec BCrypt
    const salt = await bcrypt.genSalt(12); // Génère un "sel" pour renforcer le hachage
    this.password = await bcrypt.hash(this.password, salt); // Remplace le mot de passe en clair par le hash
});

// MÉTHODE PERSONNALISÉE : Pour vérifier le mot de passe lors de la connexion
userSchema.methods.comparePassword = async function (candidatePassword) {
    try {
        // Compare le mot de passe fourni avec le hash stocké en base
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw new Error(error);
    }
};


const User = mongoose.model('User', userSchema);

module.exports = User;

const User = require('../models/User');
const {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken
} = require('../utils/tokenUtils');



// Inscription - Crée l'utilisateur et initialise la session serveur
exports.registerWithSession = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // 1. Vérifier les doublons
        const existingUser = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Cet email ou nom d\'utilisateur est déjà utilisé'
            });
        }

        // 2. Création de l'utilisateur (le mot de passe est haché dans User.js)
        const user = await User.create({
            username,
            email,
            password
        });

        user.password = undefined; // Sécurité : on ne renvoie pas le mot de passe haché

        // 3. Stockage des informations dans la session (MemoryStore par défaut)
        req.session.userId = user._id;
        req.session.userRole = user.role;

        res.status(201).json({
            success: true,
            message: 'Inscription réussie (Session)',
            data: user
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erreur lors de l\'inscription',
            error: error.message
        });
    }
};

// Connexion d'un utilisateur (Session)
exports.loginWithSession = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({
                success: false,
                message: 'Email ou mot de passe incorrect'
            });
        }

        // Créer une session
        req.session.userId = user._id;
        req.session.userRole = user.role;

        user.password = undefined;

        res.status(200).json({
            success: true,
            message: 'Connexion réussie (Session)',
            data: user
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la connexion',
            error: error.message
        });
    }
};

// Déconnexion - Détruit la session sur le serveur et vide le cookie côté client
exports.logoutWithSession = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Erreur déconnexion' });
        }
        res.clearCookie('connect.sid'); // Supprime le cookie de session par défaut d'Express
        res.status(200).json({ success: true, message: 'Déconnexion réussie' });
    });
};

// Profil - Récupère les données de l'utilisateur à partir de l'ID stocké en session
exports.getProfileWithSession = async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) return res.status(404).json({ success: false, message: 'Non trouvé' });

        res.status(200).json({ success: true, data: user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
};


// Inscription - Crée l'utilisateur et renvoie un Access Token
exports.registerWithJWT = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const existingUser = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Identifiants déjà utilisés' });
        }

        const user = await User.create({ username, email, password });

        // Génération des deux tokens (Access et Refresh)
        const accessToken = generateAccessToken(user._id, user.role);
        const refreshToken = generateRefreshToken(user._id);

        // On stocke le Refresh Token en base pour pouvoir l'invalider plus tard
        user.refreshToken = refreshToken;
        await user.save();

        user.password = undefined;
        user.refreshToken = undefined;

        // Envoi du Refresh Token dans un cookie HTTP-Only (sécurisé)
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
        });

        res.status(201).json({
            success: true,
            message: 'Inscription réussie (JWT)',
            accessToken,
            data: user
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur inscription JWT', error: error.message });
    }
};

// Connexion avec JWT
exports.loginWithJWT = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({
                success: false,
                message: 'Email ou mot de passe incorrect'
            });
        }

        const accessToken = generateAccessToken(user._id, user.role);
        const refreshToken = generateRefreshToken(user._id);

        user.refreshToken = refreshToken;
        await user.save();

        user.password = undefined;
        user.refreshToken = undefined;

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
        });

        res.status(200).json({
            success: true,
            message: 'Connexion réussie (JWT)',
            accessToken,
            data: user
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erreur lors de la connexion',
            error: error.message
        });
    }
};

// Déconnexion - Invalide le Refresh Token en base et efface le cookie
exports.logoutWithJWT = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            // On supprime le token de la base pour empêcher toute nouvelle génération de Access Token
            await User.findOneAndUpdate({ refreshToken }, { $unset: { refreshToken: 1 } });
        }
        res.clearCookie('refreshToken');
        res.status(200).json({ success: true, message: 'Déconnexion réussie (JWT)' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
};

// Refresh Token - Génère un nouveau Access Token si le Refresh Token est valide
exports.refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) return res.status(401).json({ success: false, message: 'Token manquant' });

        const decoded = verifyRefreshToken(refreshToken);
        const user = await User.findOne({ _id: decoded.id, refreshToken });

        if (!user) return res.status(401).json({ success: false, message: 'Token invalide' });

        // On génère un nouveau token de courte durée
        const accessToken = generateAccessToken(user._id, user.role);
        res.status(200).json({ success: true, accessToken });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Token expiré/invalide' });
    }
};

// Profil JWT - Utilise les données décodées injectées dans req.user par le middleware
exports.getProfileWithJWT = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.status(200).json({ success: true, data: user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
};

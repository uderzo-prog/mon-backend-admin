// server.js
const express = require('express');
// const bcrypt = require('bcryptjs'); // <-- Supprimez ou commentez cette ligne
const crypto = require('crypto'); // <-- Ajoutez cette ligne
const util = require('util'); // Pour promisifier crypto.scrypt
const cors = require('cors');
require('dotenv').config();

// Promisify scrypt pour pouvoir l'utiliser avec await/async
const scryptAsync = util.promisify(crypto.scrypt);

const app = express();
const PORT = process.env.PORT || 3000;

// ... (le reste de vos middlewares et configuration CORS) ...

let usersDB = []; // Simule notre "table" d'utilisateurs.

async function loadInitialUsers() { // Rendre la fonction async
    if (usersDB.length === 0) {
        // Hacher les mots de passe avec scrypt pour les utilisateurs par défaut
        // Un "salt" est nécessaire pour scrypt. Il doit être stocké avec le hash.
        const salt1 = crypto.randomBytes(16).toString('hex'); // Générer un salt unique
        const hash1 = await scryptAsync('410336Z', salt1, 64); // 64 est la longueur du hash en octets
        usersDB.push({
            username: '23FOP6',
            passwordHash: hash1.toString('hex'), // Stocker le hash en hex
            passwordSalt: salt1, // Stocker le salt
            fullName: 'AMONCHI ROGER COPERNIC'
        });

        const saltAdmin = crypto.randomBytes(16).toString('hex');
        const hashAdmin = await scryptAsync('1111', saltAdmin, 64);
        usersDB.push({
            username: 'uderzo',
            passwordHash: hashAdmin.toString('hex'),
            passwordSalt: saltAdmin,
            fullName: 'Administrateur',
            _isSpecialAdmin: true
        });
        console.log('Utilisateurs par défaut chargés dans la DB en mémoire avec scrypt.');
    }
}
loadInitialUsers(); // Appeler la fonction asynchrone

// --- Routes d'API ---

// Route d'enregistrement (Création de compte)
app.post('/api/register', async (req, res) => {
    const { username, password, fullName } = req.body;

    if (!username || !password || !fullName) {
        return res.status(400).json({ message: 'Veuillez fournir un nom d\'utilisateur, un mot de passe et un nom complet.' });
    }

    const existingUser = usersDB.find(u => u.username === username);
    if (existingUser) {
        return res.status(409).json({ message: 'Cet identifiant existe déjà.' });
    }

    try {
        // Générer un salt unique pour ce mot de passe
        const salt = crypto.randomBytes(16).toString('hex');
        // Hacher le mot de passe avec scrypt
        const passwordHashBuffer = await scryptAsync(password, salt, 64); // 64 octets pour le hash

        const newUser = {
            username,
            passwordHash: passwordHashBuffer.toString('hex'), // Convertir le Buffer en chaîne hexadécimale
            passwordSalt: salt, // Stocker le salt avec le hash
            fullName
        };
        usersDB.push(newUser);

        res.status(201).json({ message: 'Inscription réussie.' });
    } catch (error) {
        console.error('Erreur lors de l\'inscription:', error);
        res.status(500).json({ message: 'Erreur serveur lors de l\'inscription.' });
    }
});

// Route de connexion
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Veuillez fournir un identifiant et un mot de passe.' });
    }

    const user = usersDB.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ message: 'Identifiant ou mot de passe incorrect.' });
    }

    try {
        // Hacher le mot de passe fourni avec le salt stocké pour l'utilisateur
        const hashedPasswordProvidedBuffer = await scryptAsync(password, user.passwordSalt, 64);
        const hashedPasswordProvided = hashedPasswordProvidedBuffer.toString('hex');

        // Comparer le nouveau hash avec le hash stocké
        if (hashedPasswordProvided === user.passwordHash) {
            const userPublicData = {
                username: user.username,
                fullName: user.fullName,
                isAdmin: user._isSpecialAdmin || false
            };
            res.status(200).json({ message: 'Connexion réussie.', user: userPublicData });
        } else {
            res.status(401).json({ message: 'Identifiant ou mot de passe incorrect.' });
        }

    } catch (error) {
        console.error('Erreur lors de la connexion:', error);
        res.status(500).json({ message: 'Erreur serveur lors de la connexion.' });
    }
});

// ... (Démarrage du serveur) ...
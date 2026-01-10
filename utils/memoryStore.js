/**
 * In-Memory User Store (Fallback)
 * Only for local testing when MongoDB is unavailable.
 * Not for production use.
 */

const bcrypt = require('bcryptjs');

const users = [];

const findByEmail = async (email) => {
    return users.find(u => u.email.toLowerCase() === email.toLowerCase());
};

const createUser = async ({ fullName, email, password }) => {
    const exists = await findByEmail(email);
    if (exists) throw new Error('duplicate_email');
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);
    const user = {
        id: String(users.length + 1),
        fullName,
        email: email.toLowerCase(),
        password: hashed,
        createdAt: new Date(),
        lastLogin: null,
        isActive: true,
    };
    users.push(user);
    return { ...user, password: undefined };
};

const comparePassword = async (candidate, hashed) => {
    return bcrypt.compare(candidate, hashed);
};

const updateLastLogin = async (email) => {
    const u = await findByEmail(email);
    if (u) u.lastLogin = new Date();
};

module.exports = {
    findByEmail,
    createUser,
    comparePassword,
    updateLastLogin,
    _users: users,
};

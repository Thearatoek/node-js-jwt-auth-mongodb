
const validator = require('validator');

exports.validateSignup = (req, res, next) => {
    const { username, email, password, roles } = req.body;
    const errors = [];

    // Check required fields
    if (!username) errors.push("Username is required");
    if (!email) errors.push("Email is required");
    if (!password) errors.push("Password is required");

    if (errors.length > 0) {
        return res.status(400).send({ message: errors.join(', ') });
    }

    // Validate username
    if (username.length < 3 || username.length > 30) {
        errors.push("Username must be between 3 and 30 characters");
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        errors.push("Username can only contain letters, numbers, and underscores");
    }

    // Validate email
    if (!validator.isEmail(email)) {
        errors.push("Invalid email format");
    }

    const emailDomain = email.split('@')[1];
    if (emailDomain !== 'gmail.com') {
        errors.push("Only Gmail addresses (@gmail.com) are allowed");
    }

    // Validate password
    if (password.length < 8) {
        errors.push("Password must be at least 8 characters");
    }

    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
        errors.push("Password must contain uppercase, lowercase, number, and special character");
    }

    // Validate roles
    if (roles && roles.length > 0) {
        const validRoles = ['user', 'moderator', 'admin'];
        const invalidRoles = roles.filter(role => !validRoles.includes(role));

        if (invalidRoles.length > 0) {
            errors.push(`Invalid roles: ${invalidRoles.join(', ')}`);
        }
    }

    if (errors.length > 0) {
        return res.status(400).send({ message: errors.join('. ') });
    }

    next();
};
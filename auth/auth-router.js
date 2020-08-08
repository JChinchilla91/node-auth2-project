const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

const router = require('express').Router();

const Users = require('../users/users-model.js');

router.post('/register', (req, res) => {
    let user = req.body;

    const hash = bcryptjs.hashSync(user.password, 12);
    user.password = hash;

    try {
        const saved = Users.add(user);
        res.status(201).json(saved);
    } catch (err) {
        console.log(err);
        res.status(500).json(err);
    };
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;

    Users.findBy({ username: username })
    .first()
    .then(user => {
        if (user && bcryptjs.compareSync(password, user.password)) {
            // generate token and include it in the response
            const token = generateToken(user);
            res.status(200).json({ message: 'Access granted', token});
        } else {
            res.status(401).json({ message: 'Incorrect credentials' });
        }
    })
    .catch(err => {
        res.status(500).json({ message: err.message })
    });
});



function generateToken(user) {
    const payload = {
        subject: user.id,
        username: user.username,
        department: user.department
    };

    const options = {
        expiresIn: '1h'
    };

    const secret = secrets.jwtSecret;

    return jwt.sign(payload, secret, options);
};

module.exports = router;
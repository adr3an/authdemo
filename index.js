const express = require('express');
const app = express();
const User = require('./models/user');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');

mongoose.connect('mongodb://localhost:27017/authdemo', {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
    useFindAndModify: false
})
    .then(() => {
        console.log('connected');
    })
    .catch(err => {
        console.log(err);
    })

app.set('view engine', 'ejs');
app.set('views', 'views');

app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'notagoodsecret' }));

const requireLogin = (req, res, next) => {
    if (!req.session.user_id) {
        return res.redirect('/login');
    }
    next();
}

app.get('/secret', requireLogin, (req, res) => {
    res.render('secret');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/', (req, res) => {
    res.send('This is the Homepage');
})

app.post('/register', async (req, res) => {
    const { password, username } = req.body;
    const user = new User({ username, password });
    await user.save();
    req.session.user_id = user._id;
    res.redirect('/secret');
});

app.get('/login', (req, res) => {
    res.render('login');
});
app.post('/logout', (req, res) => {
    req.session.user_id = null;
    res.redirect('/login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const foundUser = await User.findAndValidate(username, password);
    if (foundUser) {
        req.session.user_id = foundUser._id;
        res.redirect('/secret');

    } else {
        res.send('Try Again');
    }
});

app.listen(3000, () => {
    console.log('App is live');
})
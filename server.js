const path = require('path');

const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const expressSetion = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(expressSetion);
const csrf = require('csurf');
const flash = require('connect-flash');

const adminRouter = require('./routes/admin');
const shopRouter = require('./routes/shop');
const authRoutes = require('./routes/auth');
const errorController = require('./controllers/404');
const mongoConnect = require('./util/database').mongoConnect;
const User = require('./models/user');

dotenv.config();

const app = express();

const store = new MongoDBStore({
    uri: process.env.MONGODB_URI,
    collection: 'sessions'
});

const csrfProtection = csrf();

app.set('view engine', 'ejs');
app.set('views', 'views');

app.use(bodyParser.urlencoded({extended: false}));
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressSetion({
    secret: 'MY_SECRET',
    cookie: {
        maxAge: 3600000
    },
    resave: false,
    saveUninitialized: false,
    store: store
}))
app.use(csrfProtection);
app.use(flash());

app.use((req, res, next) => {
    if (!req.session.user) {
        return next();
    }
    User.findById(req.session.user._id)
    .then(user => {
        req.user = new User(user.email, user.password, user.borrowedItems, user._id.toString());
        next();
    })
    .catch(err => console.log(err))
})

app.use((req, res, next) => {
    res.locals.isAuthenticated = req.session.isLoggedIn;
    res.locals.csrfToken = req.csrfToken();
    next();
})

app.use('/admin', adminRouter);
app.use(shopRouter);
app.use(authRoutes);

app.use(errorController.get404);


mongoConnect(() => {
    app.listen(8080);
});
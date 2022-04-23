require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const logger = require('morgan');

const GoogleStrategy = require('passport-google-oidc');
const ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
const ensureLoggedIn = ensureLogIn();

const SQLiteStore = require('connect-sqlite3')(session);
const db = require('./db');

const fortune = require('fortune-teller')

const fs = require('fs');
const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');

const https = require('https');
const httpsOptions = {
    key: tlsServerKey,
    cert: tlsServerCrt
};

const app = express();
const server = https.createServer(httpsOptions, app);
/**
 * Listen on provided port, on all network interfaces.
 */
server.listen(8443);
server.on('listening', onListening);

/**
 * Event listener for HTTP server "listening" event.
 */
function onListening() {
    const addr = server.address();
    const bind = typeof addr === 'string'
        ? 'pipe ' + addr
        : 'port ' + addr.port;
    console.log('Listening on ' + bind);
}

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(session({
    secret: 'keyboard cat',
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
    store: new SQLiteStore({ db: 'sessions.db', dir: './var/db' })
}));
app.use(passport.authenticate('session'));

app.use(function(req, res, next) {
    var msgs = req.session.messages || [];
    res.locals.messages = msgs;
    res.locals.hasMessages = !! msgs.length;
    req.session.messages = [];
    next();
});

passport.use(new GoogleStrategy({
    clientID: process.env['GOOGLE_CLIENT_ID'],
    clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
    callbackURL: '/oauth2/redirect/google',
    scope: [ 'profile' ]
}, function verify(issuer, profile, cb) {
    db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
        issuer,
        profile.id
    ], function(err, row) {
        if (err) { return cb(err); }
        if (!row) {
            db.run('INSERT INTO users (name) VALUES (?)', [
                profile.displayName
            ], function(err) {
                if (err) { return cb(err); }
                var id = this.lastID;
                db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
                    id,
                    issuer,
                    profile.id
                ], function(err) {
                    if (err) { return cb(err); }
                    var user = {
                        id: id,
                        name: profile.displayName
                    };
                    return cb(null, user);
                });
            });
        } else {
            db.get('SELECT * FROM users WHERE id = ?', [ row.user_id ], function(err, row) {
                if (err) { return cb(err); }
                if (!row) { return cb(null, false); }
                return cb(null, row);
            });
        }
    });
}));

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

app.get('/login',
    (req, res) => {
        res.sendFile('login.html', {root: __dirname})
    })

app.get('/login/google', passport.authenticate('google'));

app.get('/oauth2/redirect/google', passport.authenticate('google', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/login'
}));

app.get('/logout', function(req, res, next) {
    req.logout();
    res.redirect('/');
});

app.get('/', ensureLoggedIn,
    (req, res) => {
        var r = fortune.fortune()
        res.send(r)
    })

app.use(
    function (err, req, res, next) {
        console.error(err.stack)
        res.status(500).send('Something broke!')
    })
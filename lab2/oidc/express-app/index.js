const express = require('express')
const logger = require('morgan')

const Client = require('node-radius-client');
const {
    dictionaries: {
        rfc2865: {
            file,
            attributes,
        },
    },
} = require('node-radius-utils');
const client = new Client({
    host: '10.0.2.5',
    dictionaries: [
        file,
    ],
});

const passport = require('passport')

const FSDB = require('file-system-db');
const db = new FSDB('./db.json', false);

const crypto = require('crypto');
var salt1 = crypto.randomBytes(6).toString('hex');
var salt2 = crypto.randomBytes(6).toString('hex');

(async () => {
    db.set('walrus', (await hash('walrus', salt1)))
    db.set('manel', (await hash('manel', salt2)))
})()

const cookieSession = require('cookie-session');
const OpenIDConnectStrategy = require('passport-openidconnect');

const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits

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
app.use(cookieParser());
app.use(express.urlencoded({extended: true}))
app.use(cookieSession({
    keys: ['secret1', 'secret2']
}));

passport.use('oidc-keycloak',
    new OpenIDConnectStrategy(
        {
            issuer: 'http://localhost:8080/auth/realms/nsaa',
            authorizationURL: 'http://localhost:8080/auth/realms/nsaa/protocol/openid-connect/auth',
            tokenURL: 'http://localhost:8080/auth/realms/nsaa/protocol/openid-connect/token',
            userInfoURL: 'http://localhost:8080/auth/realms/nsaa/protocol/openid-connect/userinfo',
            clientID: process.env['KEYCLOAK_CLIENT_ID'],
            clientSecret: process.env['KEYCLOAK_CLIENT_SECRET'],
            callbackURL: 'https://localhost:8443/oidc/redirect/keycloak'
        },
        function (issuer, profile, done) {
            if (profile.username !== null) {
                const user = {
                    username: profile.username,
                    description: 'Keycloak user'
                }
                return done(null, user)
            }
            return done(null, false)
        }
    ));

// https://accounts.google.com/.well-known/openid-configuration
passport.use('oidc-google',
    new OpenIDConnectStrategy(
        {
            issuer: 'https://accounts.google.com',
            authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenURL: 'https://oauth2.googleapis.com/token',
            userInfoURL: 'https://openidconnect.googleapis.com/v1/userinfo',
            clientID: process.env['GOOGLE_CLIENT_ID'],
            clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
            callbackURL: 'https://localhost:8443/oidc/redirect/google',
            scope: ['profile']
        },
        function (issuer, profile, done) {
            if (profile.displayName !== null) {
                const user = {
                    username: profile.displayName,
                    description: 'Google user'
                }
                return done(null, user)
            }
            return done(null, false)
        }
    ));

passport.use('register',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            session: false
        },
        async function (username, password, done) {
            pass = db.get(username)
            if (pass === null) {
                salt = crypto.randomBytes(6).toString('hex');
                db.set(username, (await hash(password, salt)))
                const user = {
                    username: username,
                    description: 'Local user'
                }
                return done(null, user)
            }
            return done(null, false)
        }
    ))

passport.use('local',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            session: false
        },
        async function (username, password, done) {
            pass = db.get(username)

            if (pass != null) {
                if (await verify(password, pass)) {
                    const user = {
                        username: username,
                        description: 'Local user'
                    }
                    return done(null, user)
                }
            }
            return done(null, false)
        }
    ))

passport.use('local-radius',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            session: false
        },
        async function (username, password, done) {
            let result = await client.accessRequest({
                secret: 'hello1234',
                attributes: [
                    [attributes.USER_NAME, username],
                    [attributes.USER_PASSWORD, password],
                ],
            })
            if (result.code === 'Access-Accept') {
                const user = {
                    username: username,
                    description: 'Radius user'
                }
                return done(null, user)
            }
            return done(null, false)
        }
    ))

passport.use('jwt',
    new JwtStrategy(
        {
            jwtFromRequest: ExtractJwt.fromExtractors([(req) => req.cookies.jwt]),
            secretOrKey: jwtSecret,
            issuer: 'localhost:8443',
            audience: 'localhost:8443'
        },
        function (jwt_payload, done) {
            if (jwt_payload.sub !== null) {
                const user = {
                    username: jwt_payload.sub,
                    description: 'the only user that deserves to contact the fortune teller'
                }
                return done(null, user)
            }
            return done(null, false)
        }
    ))

app.use(passport.initialize())

app.get('/register',
    (req, res) => {
        res.sendFile('register.html', {root: __dirname})
    })

app.get('/login',
    (req, res) => {
        res.sendFile('login.html', {root: __dirname})
    })

app.get('/login/radius',
    (req, res) => {
        res.sendFile('login_radius.html', {root: __dirname})
    })

app.post('/register',
    passport.authenticate('register', {failureRedirect: '/login', session: false}),
    (req, res) => {
        build_jwt(req, res)
        res.redirect('/')
    }
)

app.post('/login',
    passport.authenticate('local', {failureRedirect: '/login', session: false}),
    (req, res) => {
        build_jwt(req, res)
        res.redirect('/')
    }
)

app.post('/login-radius',
    passport.authenticate('local-radius', {failureRedirect: '/login', session: false}),
    (req, res) => {
        build_jwt(req, res)
        res.redirect('/')
    }
)

app.get('/login/keycloak',
    passport.authenticate('oidc-keycloak'));

app.get('/oidc/redirect/keycloak',
    passport.authenticate('oidc-keycloak', {failureRedirect: '/login', session: false}),
    (req, res) => {
        const jwtClaims = {
            sub: req.user.username,
            iss: 'localhost:8443',
            aud: 'localhost:8443',
            exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
            role: 'user'
        }

        const token = jwt.sign(jwtClaims, jwtSecret)
        res.cookie('jwt', token, {
            httpOnly: false,
            secure: false,
        })

        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
        res.redirect('/');
    });

app.get('/login/google',
    passport.authenticate('oidc-google'));

app.get('/oidc/redirect/google',
    passport.authenticate('oidc-google', {failureRedirect: '/login', session: false}),
    (req, res) => {
        const jwtClaims = {
            sub: req.user.username,
            iss: 'localhost:8443',
            aud: 'localhost:8443',
            exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
            role: 'user'
        }

        const token = jwt.sign(jwtClaims, jwtSecret)
        res.cookie('jwt', token, {
            httpOnly: false,
            secure: false,
        })

        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
        res.redirect('/');
    });

app.get('/logout',
    passport.authenticate('jwt', {session: false}),
    (req, res) => {
        res.clearCookie('jwt');
        res.redirect('/');
        res.end();
    })

app.get('/',
    passport.authenticate('jwt', {failureRedirect: '/login', session: false}),
    (req, res) => {
        var r = fortune.fortune()
        res.send(r)
    })

app.get('/profile',
    passport.authenticate('jwt', {session: false}),
    function (req, res) {
        res.json(req.user.username);
    }
);

app.use(
    function (err, req, res, next) {
        console.error(err.stack)
        res.status(500).send('Something broke!')
    })

async function hash(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(salt + ":" + derivedKey.toString('hex'))
        });
    })
}

async function verify(password, hash) {
    return new Promise((resolve, reject) => {
        const [salt, key] = hash.split(":")
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(key == derivedKey.toString('hex'))
        });
    })
}

function build_jwt(req, res) {
    const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost:8443',
        aud: 'localhost:8443',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user'
    }

    const token = jwt.sign(jwtClaims, jwtSecret)
    res.cookie('jwt', token, {
        httpOnly: false,
        secure: false,
    })

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
}
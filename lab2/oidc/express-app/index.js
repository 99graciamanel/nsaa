const express = require('express')
const logger = require('morgan')

const passport = require('passport')

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
            authorizationURL: 'http://localhost:8080/auth/realms/nsaa/protocol/openid-connect/auth"',
            tokenURL: 'http://localhost:8080/auth/realms/nsaa/protocol/openid-connect/token',
            userInfoURL: 'http://localhost:8080/auth/realms/nsaa/protocol/openid-connect/userinfo',
            clientID: process.env['KEYCLOAK_CLIENT_ID'],
            clientSecret: process.env['KEYCLOAK_CLIENT_SECRET'],
            callbackURL: 'https://localhost:8443/oidc/redirect/keycloak'
        },
        function (issuer, profile, done) {
            if (profile.displayName !== null) {
                const user = {
                    username: profile.displayName,
                    description: 'the only user that deserves to contact the fortune teller'
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
            scope: [ 'profile' ]
        },
        function (issuer, profile, done) {
            if (profile.displayName !== null) {
                const user = {
                    username: profile.displayName,
                    description: 'the only user that deserves to contact the fortune teller'
                }
                return done(null, user)
            }
            return done(null, false)
        }
    ));

passport.use('local',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            session: false
        },
        function (username, password, done) {
            if (username === 'walrus' && password === 'walrus') {
                const user = {
                    username: 'walrus',
                    description: 'the only user that deserves to contact the fortune teller'
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

app.get('/login',
    (req, res) => {
        res.sendFile('login.html', {root: __dirname})
    })

app.post('/login',
    passport.authenticate('local', {failureRedirect: '/login', session: false}),
    (req, res) => {
        build_jwt(req, res)
        res.redirect('/')
    }
)

app.get('/login/keycloak',
    passport.authenticate('oidc-keycloak'));

app.get('/oidc/redirect/google',
    passport.authenticate('oidc-keycloak', {failureRedirect: '/login', session: false}),
    (req, res) => {
        console.log(req.user.username)
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

app.get('/login/google',
    passport.authenticate('oidc-google'));

app.get('/oidc/redirect/google',
    passport.authenticate('oidc-google', {failureRedirect: '/login', session: false}),
    (req, res) => {
        console.log(req.user.username)
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
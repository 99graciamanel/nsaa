const express = require('express')
const logger = require('morgan')

const passport = require('passport')
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
            jwtFromRequest: ExtractJwt.fromExtractors([(req) => req.cookies.session]),
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
        const jwtClaims = {
            sub: req.user.username,
            iss: 'localhost:8443',
            aud: 'localhost:8443',
            exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
            role: 'user'
        }

        const token = jwt.sign(jwtClaims, jwtSecret)
        res.cookie('session', token, {
            httpOnly: false,
            secure: false,
        })

        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)

        res.redirect('/')
    }
)

app.get('/logout',
    passport.authenticate('jwt', {session: false}),
    (req, res) => {
        res.clearCookie('session');
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
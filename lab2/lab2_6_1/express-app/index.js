const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const jwt = require('jsonwebtoken')
var cookieParser = require('cookie-parser')

const port = 3000
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits

const app = express()
app.use(logger('dev'))
app.use(cookieParser());

passport.use('local',
    new LocalStrategy(
        {
            usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
            passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
            session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
        },
        function (username, password, done) {
            if (username === 'walrus' && password === 'walrus') {
                const user = {
                    username: 'walrus',
                    description: 'the only user that deserves to contact the fortune teller'
                }
                return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler
            }
            return done(null, false)  // in passport returning false as the user object means that the authentication process failed.
        }
    ))

passport.use('jwt',
    new JwtStrategy(
        {
            jwtFromRequest: ExtractJwt.fromExtractors([(req) => req.cookies.session]),
            secretOrKey: jwtSecret,
            issuer: 'localhost:3000',
            audience: 'localhost:3000'
        },
        function (jwt_payload, done) {
            if (jwt_payload.sub === 'walrus') {
                const user = {
                    username: 'walrus',
                    description: 'the only user that deserves to contact the fortune teller'
                }
                return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler
            }
            return done(null, false)
        }
    ))

app.use(express.urlencoded({extended: true})) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

app.get('/',
    passport.authenticate('jwt', {session: false}),
    (req, res) => {
        res.send('hello world')
    })

app.get('/login',
    (req, res) => {
        res.sendFile('login.html', {root: __dirname})
    })

app.post('/login',
    passport.authenticate('local', {failureRedirect: '/login', session: false}),
    (req, res) => {
        // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
        // This is what ends up in our JWT
        const jwtClaims = {
            sub: req.user.username,
            iss: 'localhost:3000',
            aud: 'localhost:3000',
            exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
            role: 'user' // just to show a private JWT field
        }

        // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
        const token = jwt.sign(jwtClaims, jwtSecret)
        res.cookie("session", token, {
            httpOnly: false,
            secure: false,
        }).json(token)
        // Just for testing, send the JWT directly to the browser. Later on we should send the token inside a cookie.

        // And let us log a link to the jwt.iot debugger, for easy checking/verifying:
        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    }
)

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

app.listen(port,
    () => {
        console.log(`Example app listening at http://localhost:${port}`)
    })
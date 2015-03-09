'use strict';

// N.B. Encoding problems are being caused by jsonwebtoken
// https://github.com/auth0/node-jsonwebtoken/pull/59

var app = require('express')(),
    cookieParser = require('cookie-parser'),
    jwt = require('jsonwebtoken'),
    passport = require('passport'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
    fs = require('fs');

var https = require('https');
console.warn('Not verifying HTTPS certificates');
https.globalAgent.options.rejectUnauthorized = false;

var adfsSigningPublicKey = fs.readFileSync('ADFS-Signing.cer'); // Exported from ADFS
function validateAccessToken(accessToken) {
    var payload = null;
    try {
        payload = jwt.verify(accessToken, adfsSigningPublicKey);
    }
    catch(e) {
        console.warn('Dropping unverified accessToken', e);
    }
    return payload;
}

// Configure passport to integrate with ADFS
var strategy = new OAuth2Strategy({
        authorizationURL: 'https://your.adfs.server/adfs/oauth2/authorize',
        tokenURL: 'https://your.adfs.server/adfs/oauth2/token',
        clientID: 'some-uid-or-other', // This is just a UID I generated and registered
        clientSecret: 'shhh-its-a-secret', // This is ignored but required by the OAuth2Strategy
        callbackURL: 'http://localhost:3000/callback'
    },
    function(accessToken, refreshToken, profile, done) {
        if (refreshToken) {
            console.log('Received but ignoring refreshToken (truncated)', refreshToken.substr(0, 25));
        } else {
            console.log('No refreshToken received');
        }
        done(null, profile);
    });
strategy.authorizationParams = function(options) {
  return {
    resource: 'urn:relying:party:trust:identifier' // An identifier corresponding to the RPT
  };
};
strategy.userProfile = function(accessToken, done) {
    done(null, accessToken);
};
passport.use('provider', strategy);
passport.serializeUser(function(user, done) {
    done(null, user);
});
passport.deserializeUser(function(user, done) {
    done(null, user);
});

// Configure express app
app.use(cookieParser());
app.use(passport.initialize());

app.get('/login', passport.authenticate('provider'));
app.get('/callback', passport.authenticate('provider'), function(req, res) {
    // Beware XSRF...
    res.cookie('accessToken', req.user);
    res.redirect('/');
});
app.get('/', function (req, res) {
    req.user = validateAccessToken(req.cookies['accessToken']);
    res.send(
        !req.user ? '<a href="/login">Log In</a>' : '<a href="/logout">Log Out</a>' +
        '<pre>' + JSON.stringify(req.user, null, 2) + '</pre>');
});
app.get('/logout', function (req, res) {
    res.clearCookie('accessToken');
    res.redirect('/');
});

app.listen(3000);
console.log('Express server started on port 3000');

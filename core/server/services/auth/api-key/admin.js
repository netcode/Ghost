const jwt = require('jsonwebtoken');
const url = require('url');
const models = require('../../../models');
const errors = require('@tryghost/errors');
const {i18n} = require('../../../lib/common');
const _ = require('lodash');

let JWT_OPTIONS = {
    algorithms: ['HS256'],
    maxAge: '5m'
};

/**
 * Extract 'Ghost' auth type and  JWT token from raw authorization header.
 * Eg. Authorization: Ghost* ${JWT}
 * @param {string} header
 * @returns {Object} {scheme,token}
 */
const _extractTokenFromHeader = function extractTokenFromHeader(header) {
    const [scheme, token] = header.split(' ');
    const allwedScheme = ['ghost', 'ghosttoken']; //Its in lower case to do the comparison case insensitive
    
    //Ignore any authorization header that is not Ghost
    //Accept Ghost auth headers, ex: Ghost ${JWT}, GhostToken ${JWT}
    if (!allwedScheme.includes(scheme.toLowerCase())){
        return {scheme: null, token: null};
    }

    return {
        scheme: scheme.toLowerCase(), //to save the caller function(s) to do this step
        token
    };
};

/**
 * Extract JWT token from admin API URL query
 * Eg. ${ADMIN_API_URL}/?token=${JWT}
 * @param {string} reqUrl
 */
const _extractTokenFromUrl = function extractTokenFromUrl(reqUrl) {
    const {query} = url.parse(reqUrl, true);
    return query.token;
};

/**
 * Decode the JWT token
 * @param {string} token JWT to be decoded
 * @returns {Array} [apiKeyId, error] each one can be null but not at the same time
 */
const _decodeJWT = function decodeJWTToken(jwtToken){ //eslint-disable-line no-unused-vars
    const decoded = jwt.decode(jwtToken, {complete: true});
    
    if (!decoded || !decoded.header) {
        return [ 
            null, 
            new errors.BadRequestError({
                message: i18n.t('errors.middleware.auth.invalidToken'),
                code: 'INVALID_JWT'
            }) 
        ];
    }

    const apiKeyId = decoded.header.kid;
    if (!apiKeyId) {
        return [ 
            null, 
            new errors.BadRequestError({
                message: i18n.t('errors.middleware.auth.adminApiKidMissing'),
                code: 'MISSING_ADMIN_API_KID'
            }) 
        ];
    }

    return [apiKeyId , null]; //finally no error
};

/**
 * Verify JWT token 
 * @param {*} req 
 * @param {string} jwtToken 
 * @param {string} secret 
 * @param {*} jwtOptions 
 * @returns {*} error | null
 */
const _verifyJWT = function verifyJWTToken(req, jwtToken, secret, jwtOptions){ //eslint-disable-line no-unused-vars
    // Decoding from hex and transforming into bytes is here to
    // keep comparison of the bytes that are stored in the secret.
    // Useful context:
    // https://github.com/auth0/node-jsonwebtoken/issues/208#issuecomment-231861138
    const jwtSecret = Buffer.from(secret, 'hex');
    const {pathname} = url.parse(req.originalUrl);
    const [hasMatch, version = 'v2', api = 'admin'] = pathname.match(/ghost\/api\/([^/]+)\/([^/]+)\/(.+)*/); // eslint-disable-line no-unused-vars
    // ensure the token was meant for this api version
    const options = Object.assign({
        audience: new RegExp(`\/?${version}\/${api}\/?$`) // eslint-disable-line no-useless-escape
    }, jwtOptions);

    try {
        jwt.verify(jwtToken, jwtSecret, options);
    } catch (err) {
        if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
            return new errors.UnauthorizedError({
                message: i18n.t('errors.middleware.auth.invalidTokenWithMessage', {message: err.message}),
                code: 'INVALID_JWT',
                err
            });
        }

        // unknown error
        return new errors.InternalServerError({err});
    }
};

const authenticate = (req, res, next) => {
    // CASE: we don't have an Authorization header so allow fallthrough to other
    // auth middleware or final "ensure authenticated" check
    if (!req.headers || !req.headers.authorization) {
        req.api_key = null;
        return next();
    }
    const {scheme, token} = _extractTokenFromHeader(req.headers.authorization);

    if (!token) {
        return next(new errors.UnauthorizedError({
            message: i18n.t('errors.middleware.auth.incorrectAuthHeaderFormat'),
            code: 'INVALID_AUTH_HEADER'
        }));
    }
    //Integration API Tokens
    if (scheme === 'ghost'){
        return authenticateWithToken(req, res, next, {token, JWT_OPTIONS});
    }

    //Personal API Token
    if (scheme === 'ghosttoken'){
        return authenticateWithPersonalToken(req, res, next, {token, JWT_OPTIONS});
    }
};

const authenticateWithUrl = (req, res, next) => {
    const token = _extractTokenFromUrl(req.originalUrl);
    if (!token) {
        return next(new errors.UnauthorizedError({
            message: i18n.t('errors.middleware.auth.invalidTokenWithMessage', {message: 'No token found in URL'}),
            code: 'INVALID_JWT'
        }));
    }
    // CASE: Scheduler publish URLs can have long maxAge but controllerd by expiry and neverBefore
    return authenticateWithToken(req, res, next, {token, JWT_OPTIONS: _.omit(JWT_OPTIONS, 'maxAge')});
};

/**
 * Admin API key authentication flow:
 * 1. extract the JWT token from the `Authorization: Ghost xxxx` header or from URL(for schedules)
 * 2. decode the JWT to extract the api_key id from the "key id" header claim
 * 3. find a matching api_key record
 * 4. verify the JWT (matching secret, matching URL path, not expired)
 * 5. place the api_key object on `req.api_key`
 *
 * There are some specifcs of the JWT that we expect:
 * - the "Key ID" header parameter should be set to the id of the api_key used to sign the token
 *   https://tools.ietf.org/html/rfc7515#section-4.1.4
 * - the "Audience" claim should match the requested API path
 *   https://tools.ietf.org/html/rfc7519#section-4.1.3
 */
const authenticateWithToken = (req, res, next, {token, JWT_OPTIONS}) => {
    const [apiKeyId, decodeError] = _decodeJWT(token);
    if (decodeError){
        return next(decodeError);
    }

    models.ApiKey.findOne({id: apiKeyId}).then((apiKey) => {
        if (!apiKey) {
            return next(new errors.UnauthorizedError({
                message: i18n.t('errors.middleware.auth.unknownAdminApiKey'),
                code: 'UNKNOWN_ADMIN_API_KEY'
            }));
        }

        if (apiKey.get('type') !== 'admin') {
            return next(new errors.UnauthorizedError({
                message: i18n.t('errors.middleware.auth.invalidApiKeyType'),
                code: 'INVALID_API_KEY_TYPE'
            }));
        }

        const verifyError = _verifyJWT(req,token,apiKey.get('secret'),JWT_OPTIONS);
        if (verifyError){
            return next(verifyError);
        }

        // authenticated OK, store the api key on the request for later checks and logging
        req.api_key = apiKey;
        next(); 
    }).catch((err) => {
        next(new errors.InternalServerError({err}));
    });
};

/**
 * Authenticate using user personal API token
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @param {*} param3 
 */
const authenticateWithPersonalToken = (req,res,next, {token, JWT_OPTIONS}) => {
    const [userId, decodeError] = _decodeJWT(token);
    if (decodeError){
        return next(decodeError);
    }

    models.User.findOne({id: userId}).then((user) => {
        if (!user) {
            return next(new errors.UnauthorizedError({
                message: i18n.t('errors.middleware.auth.unknownAdminApiKey'),
                code: 'UNKNOWN_ADMIN_API_KEY'
            }));
        }

        const verifyError = _verifyJWT(req,token,user.get('api_token'),JWT_OPTIONS);
        if (verifyError){
            return next(verifyError);
        }

        // authenticated OK, store the api key on the request for later checks and logging
        req.user = user;
        next();
    }).catch((err) => {
        next(new errors.InternalServerError({err}));
    });
};

module.exports = {
    authenticate,
    authenticateWithUrl
};

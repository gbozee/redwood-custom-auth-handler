"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExternalAuthHandler = exports.DbInterface = void 0;
const crypto_js_1 = __importDefault(require("crypto-js"));
const md5_1 = __importDefault(require("md5"));
const _uuid = __importStar(require("uuid"));
const _cors = __importStar(require("@redwoodjs/api/dist/cors"));
const DbAuthError = __importStar(require("@redwoodjs/api/dist/functions/dbAuth/errors"));
const _shared = __importStar(require("@redwoodjs/api/dist/functions/dbAuth/shared"));
const _transforms = __importStar(require("@redwoodjs/api/dist/transforms"));
class DbInterface {
    dbAccessor;
    db;
    constructor(db, authModelAccessor) {
        this.db = db;
        this.dbAccessor = this.db[authModelAccessor];
    }
    async getUniqueUser(obj, select) {
        const user = await this.dbAccessor.findUnique({
            where: obj,
            select,
        });
        return user;
    }
    async saveUserData(userObj, data) {
        return await this.dbAccessor.update({
            where: userObj,
            data,
        });
    }
    async findUserByToken(userObj, kind = "reset") {
        console.log(userObj);
        return await this.dbAccessor.findFirst({
            where: userObj,
        }, kind);
    }
}
exports.DbInterface = DbInterface;
class ExternalAuthHandler {
    event;
    context;
    options;
    cookie;
    params;
    dbInterface;
    // dbCredentialAccessor: any
    headerCsrfToken;
    hasInvalidSession;
    session;
    sessionCsrfToken;
    corsContext;
    sessionExpiresDate;
    webAuthnExpiresDate;
    // class constant: list of auth methods that are supported
    static get METHODS() {
        return [
            "forgotPassword",
            "getToken",
            "login",
            "logout",
            "resetPassword",
            "signup",
            "validateResetToken",
            "webAuthnRegOptions",
            "webAuthnRegister",
            "webAuthnAuthOptions",
            "webAuthnAuthenticate",
            "verifyEmail",
            "sendEmailToken",
            "changeEmail",
        ];
    }
    // class constant: maps the auth functions to their required HTTP verb for access
    static get VERBS() {
        return {
            forgotPassword: "POST",
            getToken: "GET",
            login: "POST",
            logout: "POST",
            resetPassword: "POST",
            signup: "POST",
            validateResetToken: "POST",
            webAuthnRegOptions: "GET",
            webAuthnRegister: "POST",
            webAuthnAuthOptions: "GET",
            webAuthnAuthenticate: "POST",
            verifyEmail: "POST",
            sendEmailToken: "GET",
            changeEmail: "POST",
        };
    }
    static get PAST_EXPIRES_DATE() {
        return new Date("1970-01-01T00:00:00.000+00:00").toUTCString();
    } // generate a new token (standard UUID)
    // generate a new token (standard UUID)
    static get CSRF_TOKEN() {
        return _uuid.v4();
    }
    static get AVAILABLE_WEBAUTHN_TRANSPORTS() {
        return ["usb", "ble", "nfc", "internal"];
    }
    // returns the set-cookie header to mark the cookie as expired ("deletes" the session)
    /**
     * The header keys are case insensitive, but Fastify prefers these to be lowercase.
     * Therefore, we want to ensure that the headers are always lowercase and unique
     * for compliance with HTTP/2.
     *
     * @see: https://www.rfc-editor.org/rfc/rfc7540#section-8.1.2
     */
    get _deleteSessionHeader() {
        return {
            "set-cookie": [
                "session=",
                ...this._cookieAttributes({ expires: "now" }),
            ].join(";"),
        };
    }
    constructor(event, context, options) {
        this.event = event;
        this.context = context;
        this.options = options;
        this.cookie = _shared.extractCookie(this.event);
        this._validateOptions();
        this.params = this._parseBody();
        this.dbInterface = this.options.dbInterface;
        // this.dbCredentialAccessor = this.options.credentialModelAccessor
        //   ? this.db[this.options.credentialModelAccessor]
        //   : null
        this.headerCsrfToken = this.event.headers["csrf-token"];
        this.hasInvalidSession = false;
        const sessionExpiresAt = new Date();
        sessionExpiresAt.setSeconds(sessionExpiresAt.getSeconds() +
            this.options.login.expires);
        this.sessionExpiresDate = sessionExpiresAt.toUTCString();
        const webAuthnExpiresAt = new Date();
        webAuthnExpiresAt.setSeconds(webAuthnExpiresAt.getSeconds() +
            (this.options?.webAuthn?.expires || 0));
        this.webAuthnExpiresDate = webAuthnExpiresAt.toUTCString();
        // Note that we handle these headers differently in functions/graphql.ts
        // because it's handled by graphql-yoga, so we map the cors config to yoga config
        // See packages/graphql-server/src/__tests__/mapRwCorsToYoga.test.ts
        if (options.cors) {
            this.corsContext = _cors.createCorsContext(options.cors);
        }
        try {
            const [session, csrfToken] = _shared.decryptSession(_shared.getSession(this.cookie));
            this.session = session;
            this.sessionCsrfToken = csrfToken;
        }
        catch (e) {
            // if session can't be decrypted, keep track so we can log them out when
            // the auth method is called
            if (e instanceof DbAuthError.SessionDecryptionError) {
                this.hasInvalidSession = true;
            }
            else {
                throw e;
            }
        }
    } // Actual function that triggers everything else to happen: `login`, `signup`,
    // etc. is called from here, after some checks to make sure the request is good
    async invoke() {
        const request = _transforms.normalizeRequest(this.event);
        let corsHeaders = {};
        if (this.corsContext) {
            corsHeaders = this.corsContext.getRequestHeaders(request);
            // Return CORS headers for OPTIONS requests
            if (this.corsContext.shouldHandleCors(request)) {
                return this._buildResponseWithCorsHeaders({ body: "", statusCode: 200 }, corsHeaders);
            }
        }
        // if there was a problem decryption the session, just return the logout
        // response immediately
        if (this.hasInvalidSession) {
            return this._buildResponseWithCorsHeaders(this._ok(...this._logoutResponse()), corsHeaders);
        }
        try {
            const method = this._getAuthMethod();
            // get the auth method the incoming request is trying to call
            if (!ExternalAuthHandler.METHODS.includes(method)) {
                return this._buildResponseWithCorsHeaders(this._notFound(), corsHeaders);
            }
            // make sure it's using the correct verb, GET vs POST
            if (this.event.httpMethod !== ExternalAuthHandler.VERBS[method]) {
                return this._buildResponseWithCorsHeaders(this._notFound(), corsHeaders);
            }
            // call whatever auth method was requested and return the body and headers
            const [body, headers, options = { statusCode: 200 }] = await this[method]();
            return this._buildResponseWithCorsHeaders(this._ok(body, headers, options), corsHeaders);
        }
        catch (e) {
            if (e instanceof DbAuthError.WrongVerbError) {
                return this._buildResponseWithCorsHeaders(this._notFound(), corsHeaders);
            }
            else {
                return this._buildResponseWithCorsHeaders(this._badRequest(e.message || e), corsHeaders);
            }
        }
    }
    async forgotPassword() {
        // const { enabled = true } = this.options.forgotPassword
        // if (!enabled) {
        //   throw new DbAuthError.FlowNotEnabledError(
        //     (this.options.forgotPassword as ForgotPasswordFlowOptions)?.errors
        //       ?.flowNotEnabled || `Forgot password flow is not enabled`
        //   )
        // }
        const { username } = this.params;
        // was the username sent in at all?
        if (!username || username.trim() === "") {
            throw new DbAuthError.UsernameRequiredError(this.options.forgotPassword?.errors
                ?.usernameRequired || `Username is required`);
        }
        let user;
        try {
            user = await this.dbInterface.getUniqueUser({
                [this.options.authFields.username]: username,
            });
        }
        catch (e) {
            throw new DbAuthError.GenericError();
        }
        if (user) {
            const tokenExpires = new Date();
            tokenExpires.setSeconds(tokenExpires.getSeconds() +
                this.options.forgotPassword.expires);
            // generate a token
            let token = (0, md5_1.default)(_uuid.v4());
            const buffer = Buffer.from(token);
            token = buffer.toString("base64").replace("=", "").substring(0, 16);
            try {
                // set token and expires time
                user = await this.dbInterface.saveUserData({
                    [this.options.authFields.id]: user[this.options.authFields.id],
                }, {
                    [this.options.authFields.resetToken]: token,
                    [this.options.authFields.resetTokenExpiresAt]: tokenExpires,
                });
            }
            catch (e) {
                throw new DbAuthError.GenericError();
            }
            // call user-defined handler in their functions/auth.js
            const response = await this.options.forgotPassword.handler(this._sanitizeUser(user));
            return [
                response ? JSON.stringify(response) : "",
                {
                    ...this._deleteSessionHeader,
                },
            ];
        }
        else {
            throw new DbAuthError.UsernameNotFoundError(this.options.forgotPassword?.errors
                ?.usernameNotFound || `Username '${username} not found`);
        }
    }
    async getToken() {
        try {
            const user = await this._getCurrentUser(); // need to return *something* for our existing Authorization header stuff
            // to work, so return the user's ID in case we can use it for something
            // in the future
            return [user.id];
        }
        catch (e) {
            if (e instanceof DbAuthError.NotLoggedInError) {
                return this._logoutResponse();
            }
            else {
                return this._logoutResponse({
                    error: e.message,
                });
            }
        }
    }
    async changeEmail() {
        try {
            const user = await this._getCurrentUser(); // need to return *something* for our existing Authorization header stuff
            // to work, so return the user's ID in case we can use it for something
            // in the future
            if (user.email === this.params.email || !this.params.email) {
                throw new DbAuthError.UsernameRequiredError("A different email must be provided");
            }
            const handlerUser = await this.options.changeEmail.handler(user);
            return this._loginResponse(handlerUser);
        }
        catch (e) {
            if (e instanceof DbAuthError.NotLoggedInError) {
                return this._logoutResponse();
            }
            else {
                return this._logoutResponse({
                    error: e.message,
                });
            }
        }
    }
    async sendEmailToken() {
        try {
            const user = await this._getCurrentUser(); // need to return *something* for our existing Authorization header stuff
            // to work, so return the user's ID in case we can use it for something
            // in the future
            const handlerUser = await this.options.sendEmailToken.handler(user);
            if (handlerUser == null ||
                handlerUser[this.options.authFields.id] == null) {
                throw new DbAuthError.NoUserIdError();
            }
            return this._loginResponse(handlerUser);
        }
        catch (e) {
            if (e instanceof DbAuthError.NotLoggedInError) {
                return this._logoutResponse();
            }
            else {
                return this._logoutResponse({
                    error: e.message,
                });
            }
        }
    }
    async verifyEmail() {
        const { emailToken } = this.params;
        // is the resetToken present?
        if (emailToken == null || String(emailToken).trim() === "") {
            throw new DbAuthError.ResetTokenRequiredError(this.options.verifyEmail?.errors?.resetTokenRequired);
        }
        let user = await this._findUserByToken(emailToken, "email");
        const response = await this.options.verifyEmail.handler(this._sanitizeUser(user));
        // returning the user from the handler means to log them in automatically
        if (response) {
            return this._loginResponse(user);
        }
        else {
            return this._logoutResponse({});
        }
    }
    async login() {
        // const { enabled = true } = this.options.login
        // if (!enabled) {
        //   throw new DbAuthError.FlowNotEnabledError(
        //     (this.options.login as LoginFlowOptions)?.errors?.flowNotEnabled ||
        //       `Login flow is not enabled`
        //   )
        // }
        const { username, password } = this.params;
        const dbUser = await this._verifyUser(username, password);
        const handlerUser = await this.options.login.handler(dbUser);
        if (handlerUser == null ||
            handlerUser[this.options.authFields.id] == null) {
            throw new DbAuthError.NoUserIdError();
        }
        return this._loginResponse(handlerUser);
    }
    logout() {
        return this._logoutResponse();
    }
    async resetPassword() {
        // const { enabled = true } = this.options.resetPassword
        // if (!enabled) {
        //   throw new DbAuthError.FlowNotEnabledError(
        //     (this.options.resetPassword as ResetPasswordFlowOptions)?.errors
        //       ?.flowNotEnabled || `Reset password flow is not enabled`
        //   )
        // }
        const { password, resetToken } = this.params;
        // is the resetToken present?
        if (resetToken == null || String(resetToken).trim() === "") {
            throw new DbAuthError.ResetTokenRequiredError(this.options.resetPassword?.errors?.resetTokenRequired);
        }
        // is password present?
        if (password == null || String(password).trim() === "") {
            throw new DbAuthError.PasswordRequiredError();
        }
        let user = await this._findUserByToken(resetToken);
        const [hashedPassword] = this._hashPassword(password, user.salt);
        if (!this.options.resetPassword
            .allowReusedPassword &&
            user.hashedPassword === hashedPassword) {
            throw new DbAuthError.ReusedPasswordError(this.options.resetPassword?.errors?.reusedPassword);
        }
        try {
            // if we got here then we can update the password in the database
            user = await this.dbInterface.saveUserData({
                [this.options.authFields.id]: user[this.options.authFields.id],
            }, {
                [this.options.authFields.hashedPassword]: hashedPassword,
                [this.options.authFields.resetToken]: null,
                [this.options.authFields.resetTokenExpiresAt]: null,
            });
        }
        catch (e) {
            throw new DbAuthError.GenericError();
        }
        // call the user-defined handler so they can decide what to do with this user
        const response = await this.options.resetPassword.handler(this._sanitizeUser(user));
        // returning the user from the handler means to log them in automatically
        if (response) {
            return this._loginResponse(user);
        }
        else {
            return this._logoutResponse({});
        }
    }
    async signup() {
        // const { enabled = true } = this.options.signup
        // if (!enabled) {
        //   throw new DbAuthError.FlowNotEnabledError(
        //     (this.options.signup as SignupFlowOptions)?.errors?.flowNotEnabled ||
        //       `Signup flow is not enabled`
        //   )
        // }
        const userOrMessage = await this._createUser();
        // at this point `user` is either an actual user, in which case log the
        // user in automatically, or it's a string, which is a message to show
        // the user (something like "please verify your email")
        if (typeof userOrMessage === "object") {
            const user = userOrMessage;
            return this._loginResponse(user, 201);
        }
        else {
            const message = userOrMessage;
            return [JSON.stringify({ message }), {}, { statusCode: 201 }];
        }
    }
    async validateResetToken() {
        // is token present at all?
        if (this.params.resetToken == null ||
            String(this.params.resetToken).trim() === "") {
            throw new DbAuthError.ResetTokenRequiredError(this.options.resetPassword?.errors?.resetTokenRequired);
        }
        const user = await this._findUserByToken(this.params.resetToken);
        return [
            JSON.stringify(this._sanitizeUser(user)),
            {
                ...this._deleteSessionHeader,
            },
        ];
    }
    // validates that we have all the ENV and options we need to login/signup
    _validateOptions() {
        // must have a SESSION_SECRET so we can encrypt/decrypt the cookie
        if (!process.env.SESSION_SECRET) {
            throw new DbAuthError.NoSessionSecretError();
        }
        // must have an expiration time set for the session cookie
        if (this.options?.login?.enabled !== false &&
            !this.options?.login?.expires) {
            throw new DbAuthError.NoSessionExpirationError();
        }
        // must have a login handler to actually log a user in
        if (this.options?.login?.enabled !== false &&
            !this.options?.login?.handler) {
            throw new DbAuthError.NoLoginHandlerError();
        }
        // must have a signup handler to define how to create a new user
        if (this.options?.signup?.enabled !== false &&
            !this.options?.signup?.handler) {
            throw new DbAuthError.NoSignupHandlerError();
        }
        // must have a forgot password handler to define how to notify user of reset token
        if (this.options?.forgotPassword?.enabled !== false &&
            !this.options?.forgotPassword?.handler) {
            throw new DbAuthError.NoForgotPasswordHandlerError();
        }
        // must have a reset password handler to define what to do with user once password changed
        if (this.options?.resetPassword?.enabled !== false &&
            !this.options?.resetPassword?.handler) {
            throw new DbAuthError.NoResetPasswordHandlerError();
        }
        // must have webAuthn config if credentialModelAccessor present and vice versa
        // if (
        //   (this.options?.credentialModelAccessor && !this.options?.webAuthn) ||
        //   (this.options?.webAuthn && !this.options?.credentialModelAccessor)
        // ) {
        //   throw new DbAuthError.NoWebAuthnConfigError()
        // }
        // if (
        //   this.options?.webAuthn?.enabled &&
        //   (!this.options?.webAuthn?.name ||
        //     !this.options?.webAuthn?.domain ||
        //     !this.options?.webAuthn?.origin ||
        //     !this.options?.webAuthn?.credentialFields)
        // ) {
        //   throw new DbAuthError.MissingWebAuthnConfigError()
        // }
    }
    // removes sensative fields from user before sending over the wire
    _sanitizeUser(user) {
        const sanitized = JSON.parse(JSON.stringify(user));
        delete sanitized[this.options.authFields.hashedPassword];
        delete sanitized[this.options.authFields.salt];
        return sanitized;
    }
    // parses the event body into JSON, whether it's base64 encoded or not
    _parseBody() {
        if (this.event.body) {
            if (this.event.isBase64Encoded) {
                return JSON.parse(Buffer.from(this.event.body || "", "base64").toString("utf-8"));
            }
            else {
                return JSON.parse(this.event.body);
            }
        }
        else {
            return {};
        }
    } // returns all the cookie attributes in an array with the proper expiration date
    //
    // pass the argument `expires` set to "now" to get the attributes needed to expire
    // the session, or "future" (or left out completely) to set to `futureExpiresDate`
    _cookieAttributes({ expires = "now", options = {}, }) {
        const cookieOptions = { ...this.options.cookie, ...options } || {
            ...options,
        };
        const meta = Object.keys(cookieOptions)
            .map((key) => {
            const optionValue = cookieOptions[key];
            // Convert the options to valid cookie string
            if (optionValue === true) {
                return key;
            }
            else if (optionValue === false) {
                return null;
            }
            else {
                return `${key}=${optionValue}`;
            }
        })
            .filter((v) => v);
        const expiresAt = expires === "now" ? ExternalAuthHandler.PAST_EXPIRES_DATE : expires;
        meta.push(`Expires=${expiresAt}`);
        return meta;
    }
    // encrypts a string with the SESSION_SECRET
    _encrypt(data) {
        return crypto_js_1.default.AES.encrypt(data, process.env.SESSION_SECRET);
    }
    // returns the Set-Cookie header to be returned in the request (effectively creates the session)
    _createSessionHeader(data, csrfToken) {
        const session = JSON.stringify(data) + ";" + csrfToken;
        const encrypted = this._encrypt(session);
        const cookie = [
            `session=${encrypted.toString()}`,
            ...this._cookieAttributes({ expires: this.sessionExpiresDate }),
        ].join(";");
        return { "set-cookie": cookie };
    }
    // checks the CSRF token in the header against the CSRF token in the session and
    // throw an error if they are not the same (not used yet)
    _validateCsrf() {
        if (this.sessionCsrfToken !== this.headerCsrfToken) {
            throw new DbAuthError.CsrfTokenMismatchError();
        }
        return true;
    }
    async _findUserByToken(token, kind = "reset") {
        const tokenExpires = new Date();
        tokenExpires.setSeconds(tokenExpires.getSeconds() -
            this.options.forgotPassword.expires);
        const searchKey = kind === "reset" ? "resetToken" : "emailToken";
        const user = await this.dbInterface.findUserByToken({
            [this.options.authFields[searchKey]]: token,
        }, kind);
        // user not found with the given token
        if (!user) {
            throw new DbAuthError.ResetTokenInvalidError(kind === "reset"
                ? this.options.resetPassword?.errors
                    ?.resetTokenInvalid
                : this.options.verifyEmail?.errors
                    ?.emailTokenInvalid);
        }
        // token has expired
        const key = kind === "email" ? "emailTokenExpiresAt" : "resetTokenExpiresAt";
        if (user[this.options.authFields[key]] < tokenExpires) {
            await this._clearResetToken(user);
            throw new DbAuthError.ResetTokenExpiredError(kind === "reset"
                ? this.options.resetPassword?.errors
                    ?.resetTokenExpired
                : this.options.verifyEmail?.errors
                    ?.emailTokenExpired);
        }
        return user;
    }
    async _clearResetToken(user) {
        try {
            await this.dbInterface.saveUserData({
                [this.options.authFields.id]: user[this.options.authFields.id],
            }, {
                [this.options.authFields.resetToken]: null,
                [this.options.authFields.resetTokenExpiresAt]: null,
            });
        }
        catch (e) {
            throw new DbAuthError.GenericError();
        }
    }
    // verifies that a username and password are correct, and returns the user if so
    async _verifyUser(username, password) {
        // do we have all the query params we need to check the user?
        if (!username ||
            username.toString().trim() === "" ||
            !password ||
            password.toString().trim() === "") {
            throw new DbAuthError.UsernameAndPasswordRequiredError(this.options.login?.errors?.usernameOrPasswordMissing);
        }
        let user;
        try {
            // does user exist?
            user = await this.dbInterface.getUniqueUser({
                [this.options.authFields.username]: username,
            });
        }
        catch (e) {
            throw new DbAuthError.GenericError();
        }
        if (!user) {
            throw new DbAuthError.UserNotFoundError(username, this.options.login?.errors?.usernameNotFound);
        }
        // is password correct?
        const [hashedPassword, _salt] = this._hashPassword(password, user[this.options.authFields.salt]);
        if (hashedPassword === user[this.options.authFields.hashedPassword]) {
            return user;
        }
        else {
            throw new DbAuthError.IncorrectPasswordError(username, this.options.login?.errors?.incorrectPassword);
        }
    }
    // gets the user from the database and returns only its ID
    async _getCurrentUser() {
        if (!this.session?.id) {
            throw new DbAuthError.NotLoggedInError();
        }
        const select = {
            [this.options.authFields.id]: true,
            [this.options.authFields.username]: true,
        };
        if (this.options.webAuthn?.enabled && this.options.authFields.challenge) {
            select[this.options.authFields.challenge] = true;
        }
        let user;
        try {
            user = await this.dbInterface.getUniqueUser({
                [this.options.authFields.id]: this.session?.id,
            }, select);
        }
        catch (e) {
            throw new DbAuthError.GenericError(e.message);
        }
        if (!user) {
            throw new DbAuthError.UserNotFoundError();
        }
        return user;
    }
    // creates and returns a user, first checking that the username/password
    // values pass validation
    async _createUser() {
        const { username, password, ...userAttributes } = this.params;
        if (this._validateField("username", username) &&
            this._validateField("password", password)) {
            let user;
            try {
                user = await this.dbInterface.getUniqueUser({
                    [this.options.authFields.username]: username,
                });
            }
            catch (error) {
                //some endpoints might throw an error when record doesn't exist
                user = null;
            }
            if (user) {
                throw new DbAuthError.DuplicateUsernameError(username, this.options.signup?.errors?.usernameTaken);
            } // if we get here everything is good, call the app's signup handler and let
            // them worry about scrubbing data and saving to the DB
            const [hashedPassword, salt] = this._hashPassword(password);
            const newUser = await this.options.signup.handler({
                username,
                hashedPassword,
                salt,
                userAttributes,
            });
            return newUser;
        }
    } // hashes a password using either the given `salt` argument, or creates a new
    // salt and hashes using that. Either way, returns an array with [hash, salt]
    _hashPassword(text, salt) {
        const useSalt = salt || crypto_js_1.default.lib.WordArray.random(128 / 8).toString();
        return [
            crypto_js_1.default
                .PBKDF2(text, useSalt, {
                keySize: 256 / 32,
            })
                .toString(),
            useSalt,
        ];
    } // figure out which auth method we're trying to call
    _getAuthMethod() {
        // try getting it from the query string, /.redwood/functions/auth?method=[methodName]
        let methodName = this.event.queryStringParameters
            ?.method;
        if (!ExternalAuthHandler.METHODS.includes(methodName) && this.params) {
            // try getting it from the body in JSON: { method: [methodName] }
            try {
                methodName = this.params.method;
            }
            catch (e) {
                // there's no body, or it's not JSON, `handler` will return a 404
            }
        }
        return methodName;
    } // checks that a single field meets validation requirements and
    // currently checks for presense only
    _validateField(name, value) {
        // check for presense
        if (!value || value.trim() === "") {
            throw new DbAuthError.FieldRequiredError(name, this.options.signup?.errors?.fieldMissing);
        }
        else {
            return true;
        }
    }
    _loginResponse(user, statusCode = 200) {
        const sessionData = { id: user[this.options.authFields.id] };
        // TODO: this needs to go into graphql somewhere so that each request makes
        // a new CSRF token and sets it in both the encrypted session and the
        // csrf-token header
        const csrfToken = ExternalAuthHandler.CSRF_TOKEN;
        return [
            sessionData,
            {
                "csrf-token": csrfToken,
                ...this._createSessionHeader(sessionData, csrfToken),
            },
            { statusCode },
        ];
    }
    _logoutResponse(response) {
        return [
            response ? JSON.stringify(response) : "",
            {
                ...this._deleteSessionHeader,
            },
        ];
    }
    _ok(body, headers = {}, options = { statusCode: 200 }) {
        return {
            statusCode: options.statusCode,
            body: typeof body === "string" ? body : JSON.stringify(body),
            headers: { "Content-Type": "application/json", ...headers },
        };
    }
    _notFound() {
        return {
            statusCode: 404,
        };
    }
    _badRequest(message) {
        return {
            statusCode: 400,
            body: JSON.stringify({ error: message }),
            headers: { "Content-Type": "application/json" },
        };
    }
    _buildResponseWithCorsHeaders(response, corsHeaders) {
        return {
            ...response,
            headers: {
                ...(response.headers || {}),
                ...corsHeaders,
            },
        };
    }
}
exports.ExternalAuthHandler = ExternalAuthHandler;

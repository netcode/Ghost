function SessionMiddleware({sessionService}) {
    async function createSession(req, res, next) {
        try {
            await sessionService.createSessionForUser(req, res, req.user);
            res.sendStatus(201);
        } catch (err) {
            next(err);
        }
    }

    async function destroySession(req, res, next) {
        try {
            await sessionService.destroyCurrentSession(req);
            res.sendStatus(204);
        } catch (err) {
            next(err);
        }
    }

    async function authenticate(req, res, next) {
        try {
            const user = await sessionService.getUserForSession(req, res);
            if (user){ //dont override the req.user if there is no user retrived from the database
                req.user = user;
            }
            next();
        } catch (err) {
            next(err);
        }
    }

    return {
        createSession: createSession,
        destroySession: destroySession,
        authenticate: authenticate
    };
}

module.exports = SessionMiddleware;

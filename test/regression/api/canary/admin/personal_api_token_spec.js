const should = require('should');
const supertest = require('supertest');
const config = require('../../../../../core/shared/config');
const testUtils = require('../../../../utils');
const localUtils = require('./utils');
const ghost = testUtils.startGhost;


describe('Peronal API Token', function () {
    let request;
    let otherUser;
    describe('As Owner', function () {
        before(function () {

            return ghost()
                .then(function () {
                    request = supertest.agent(config.get('url'));
                })
                .then(function () {
                    // create another user, eg. editor
                    return testUtils.createUser({
                        user: testUtils.DataGenerator.forKnex.createUser({email: 'test+1@ghost.org'}),
                        role: testUtils.DataGenerator.Content.roles[1].name
                    });
                })
                .then(function (theOtherUser) {
                    otherUser = theOtherUser;
                    return localUtils.doAuth(request);
                });
        });

        it('Can read his own token', function () {
            return request.get(localUtils.API.getApiQuery(`users/me/`))
                .set('Origin', config.get('url'))
                .expect('Content-Type', /json/)
                .expect('Cache-Control', testUtils.cacheRules.private)
                .expect(200)
                .then((res) => {
                    const jsonResponse = res.body;
                    should.exist(jsonResponse.users[0].api_token)
                    should.notEqual(jsonResponse.users[0].api_token, null);
                });
        });

        it('Can\'t read other people token', function () {
            return request.get(localUtils.API.getApiQuery(`users/${otherUser.id}/`))
                .set('Origin', config.get('url'))
                .expect('Content-Type', /json/)
                .expect('Cache-Control', testUtils.cacheRules.private)
                .expect(200)
                .then((res) => {
                    const jsonResponse = res.body;
                    should.equal(jsonResponse.users[0].api_token, null);
                });
        });

        it('Can generate a new token', function () {
            return request.post(localUtils.API.getApiQuery(`users/generate_token/`))
                .set('Origin', config.get('url'))
                .expect('Content-Type', /json/)
                .expect('Cache-Control', testUtils.cacheRules.private)
                .expect(200)
                .then((res) => {
                    const jsonResponse = res.body;
                    should.exist(jsonResponse.user.api_token)
                    should.notEqual(jsonResponse.user.api_token, null);
                    return jsonResponse.user.api_token;
                })
                .then((api_token)=> {
                    return request.get(localUtils.API.getApiQuery(`users/me/`))
                            .set('Origin', config.get('url'))
                            .expect('Content-Type', /json/)
                            .expect('Cache-Control', testUtils.cacheRules.private)
                            .expect(200)
                            .then((res) => {
                                const jsonResponse = res.body;
                                should.exist(jsonResponse.users[0].api_token)
                                should.equal(jsonResponse.users[0].api_token, api_token);
                            });
                });
        });

    });
});

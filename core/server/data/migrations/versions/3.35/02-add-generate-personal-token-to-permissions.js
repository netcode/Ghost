const ObjectId = require('bson-objectid');
const logging = require('../../../../../shared/logging');

module.exports = {
    config: {
        transaction: true
    },
    async up(options) {
        const connection = options.transacting;

        const existingIdentityPermission = await connection('permissions').where({
            action_type: 'generateToken',
            object_type: 'user'
        }).first();

        if (existingIdentityPermission) {
            logging.warn('Permission for user:generateToken already added');
            return;
        }

        logging.info('Adding permission for user:generateToken');

        const date = connection.raw('CURRENT_TIMESTAMP');

        await connection('permissions').insert({
            id: ObjectId.generate(),
            name: 'Generate Personal API Token',
            action_type: 'generateToken',
            object_type: 'user',
            created_at: date,
            created_by: 1,
            updated_at: date,
            updated_by: 1
        });
    },
    async down(options) {
        const connection = options.transacting;

        const existingIdentityPermission = await connection('permissions').where({
            action_type: 'generateToken',
            object_type: 'user'
        }).first();

        if (!existingIdentityPermission) {
            logging.warn('Permission for user:generateToken already removed');
            return;
        }

        logging.info('Removing permission for user:generateToken');

        await connection('permissions').where({
            action_type: 'generateToken',
            object_type: 'user'
        }).del();
    }
};
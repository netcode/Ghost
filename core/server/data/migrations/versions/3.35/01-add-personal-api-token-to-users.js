const commands = require('../../../schema').commands;

module.exports = {
    config: {
        transaction: true
    },
    up: commands.createColumnMigration({
        table: 'users',
        column: 'api_token',
        columnDefinition: {
            type: 'string',
            maxlength: 64, //to handle 64 chars sha256 token
            nullable: true
        },
        dbIsInCorrectState: hasColumn => hasColumn === true,
        operation: commands.addColumn,
        operationVerb: 'Adding'
    }),
    down: commands.createColumnMigration({
        table: 'users',
        column: 'api_token',
        columnDefinition: {
            type: 'string',
            maxlength: 64,
            nullable: true
        },
        dbIsInCorrectState: hasColumn => hasColumn === false,
        operation: commands.dropColumn,
        operationVerb: 'Removing'
    })
};
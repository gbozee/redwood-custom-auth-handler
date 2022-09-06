# redwood-custom-auth-handler

This library is an extension of the default *DbAuthhandler* provided by `@redwoodjs/api` without hard-coding any database specific action.

it is useful when you have a third party auth service hosting the database information for users and want to delegate all saving actions to it.

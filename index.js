'use strict'

const Hapi = require('hapi')
const adldapFactory = require('adldap')()
const config = require('./lib/config.js')
const auth = require('./lib/auth.js')

// Create a server with a host and port
const server = new Hapi.Server()
server.connection({ 
    port: config.server.port
})

// Add the route
server.route({
    method: 'GET',
    path:'/isflagged/{username}', 
    handler: function (request, reply) {
        isFlagged(request.params.username).then(reply)
    },
    config: {
        cors: {
            origin: ['*'],
            additionalHeaders: ['cache-control', 'x-requested-with']
        }
    }    
})

// Start the server
server.register(require('hapi-pino'), (err) => {
    if (err) {
        console.error(err)
        process.exit(1)
    }  
      
    server.start((err) => {
        if (err) { 
            server.logger().error('Could not start server at %s', server.info.url) 
        }
        else {
            server.logger().info('Server running at: %s', server.info.uri)
        }
    })   
})

// **************************************************************
//  functions
// **************************************************************
function isFlagged(username) {
    var flaggedStatus = { isflagged: null, flaggedreason: null }

    // Create AD hook
    const client = adldapFactory({
        searchUser: auth.user.username,
        searchUserPass: auth.user.password,
        ldapjs: {
            url: 'ldaps://ldap.domain',
            searchBase: 'dc=some,dc=path,dc=com',
            scope: 'sub',
            attributes: ['dn', 'cn', 'sn', 'givenName', 'mail', 'memberOf', 'AccountFlagged', 'AccountFlaggedReason']
        }
    })
    
    return client.bind()
        .then(() => {
            return client.findUser(username)
            .then((user) => {
                if (user.AccountFlaggedReason) {
                    flaggedStatus.isflagged = true
                    flaggedStatus.flaggedreason = user.AccountFlaggedReason
                    server.logger().info("Compromised account: %s", username) 
                }   
                else { flaggedStatus.isflagged = false }   
            })
            .catch((err) => server.logger().error(err))
            .then(() => {              
              client.unbind()
              return flaggedStatus
            });
        })
        .catch((err) => server.logger().error(err))
}

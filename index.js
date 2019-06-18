'use strict';

let Session = require('./lib/session'), Realm = require('./lib/realm').Realm, wss = require('ws'), EventEmitter = require('events').EventEmitter;

class WampRouter extends EventEmitter {
    constructor  (auth) {
        super();
        this.realms = {};
        this.handle_methods = auth && auth.handle_methods || ((details, cb) => cb(null, "anonymous"));
        this.authenticate = auth && auth.authenticate || ((details, secret, cb) => cb());
        this.authorize = auth && auth.authorize || ((details, method, uri, cb) => cb(null, true));
    }

    get_realm(realm_name, callback) {
        if (this.realms.hasOwnProperty(realm_name)) callback(this.realms[realm_name]);
        else {
            let realm = new Realm(realm_name);
            this.realms[realm_name] = realm;
            callback(realm);
        }
    }

    listen(options) {
        if (!options.disableProtocolCheck) options.handleProtocols = (protocols, request) => protocols && protocols.includes("wamp.2.json") && "wamp.2.json";
        let server = new wss.Server(options);
        server.on('connection', wsclient => new Session(this, wsclient));
        return server;
    }
}

module.exports = WampRouter;

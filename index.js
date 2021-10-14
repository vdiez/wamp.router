'use strict';

const WSS = require('ws').Server, Session = require('./lib/session'), Realm = require('./lib/realm').Realm;

const silentLogger = {info() {}, warn() {}, error() {}, verbose() {}, debug() {}, silly() {}};

class WampRouter {
    constructor({logger, auth}) {
        this.logger = {...silentLogger, ...logger};
        this.realms = {};
        this.handle_methods = auth?.handle_methods || ((details, cb) => cb(null, 'anonymous'));
        this.authenticate = auth?.authenticate || ((details, secret, cb) => cb());
        this.authorize = auth?.authorize || ((details, method, uri, cb) => cb(null, true));
    }

    get_realm(realm_name) {
        if (!this.realms.hasOwnProperty(realm_name)) this.realms[realm_name] = new Realm(this, realm_name);
        return this.realms[realm_name];
    }

    listen(options, callback) {
        if (!options.disableProtocolCheck) options.handleProtocols = protocols => protocols?.has?.('wamp.2.json') ? 'wamp.2.json' : null;
        const server = new WSS(options, callback);
        server.on('connection', wsclient => new Session(this, wsclient));
        return server;
    }
}

module.exports = WampRouter;

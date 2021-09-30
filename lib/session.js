'use strict';

const wss = require('ws');
const WAMP = require('./protocol');
const errors = require('./errors');
const id = require('./id');
const handlers = require('./handlers');

class Session {
    constructor(router, ws) {
        this.router = router;
        this.ws = ws;
        this.details = {};
        this.realm = null;
        this.id = id();
        this.logger = router.logger;

        ws.on('close', () => this.realm?.remove_session(this));
        ws.on('message', data => this.handle(data));
    }

    toString() {
        return `Session ${this.id} authid ${this.details.authid}`;
    }

    auth_error(err) {
        this.logger.error(`${this} authorization failed:`, err);
        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
    }

    send(message, callback) {
        if (this.ws.readyState === wss.OPEN) {
            this.ws.send(JSON.stringify(message), callback);
            this.logger.silly(`Sending message to session ${this}:`, message);
        }
    }

    close(code, reason, details) {
        this.logger.info(`Closing session ${this}. Errors: `, code, reason, details);
        this.send([code, details || {}, reason], () => this.ws.close());
    }

    handle(message) {
        try {message = JSON.parse(message);}
        catch (e) {
            this.logger.error(`${this} could not parse message:`, e);
            this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
            return;
        }
        this.logger.silly(`Received message from ${this}:`, message);

        if (!Array.isArray(message)) {
            this.logger.error(`${this} message is not Array`);
            this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
            return;
        }
        const message_type = message.shift();
        if (handlers.hasOwnProperty(message_type)) {
            if (handlers[message_type].requires_realm && !this.realm) {
                this.logger.error(`${this} tried to ${handlers[message_type].label} but did not join any realm`);
                this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                return;
            }
            handlers[message_type].exec.apply(this, message);
        }
        else {
            this.logger.error(`${this} unknown message_type:`, message_type);
            this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
        }
    }
}

module.exports = Session;

'use strict';

const WAMP = require('./protocol');
const errors = require('./errors');

module.exports = {
    [WAMP.HELLO]: {
        label: 'HELLO',
        exec(realm_name, details) {
            if (this.realm) {
                this.logger.error(`Session ${this} tried to join realm ${realm_name} but it already joined realm ${this.realm.name}`);
                this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                return;
            }
            this.details = details || {};
            this.details.requested_realm = realm_name;
            this.router.handle_methods(this.details, (err, method, extra) => {
                if (err) this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                else if (method === 'anonymous') {
                    const realm = this.router.get_realm(realm_name);
                    const details = realm.add_session(this);
                    details.authid = 'anonymous';
                    details.authmethod = 'anonymous';
                    this.details.authenticating = false;
                    this.details.authmethod = 'anonymous';
                    this.send([WAMP.WELCOME, this.id, details]);
                }
                else {
                    this.details.authenticating = true;
                    details.authmethod = method;
                    this.send([WAMP.CHALLENGE, method, extra || {}]);
                    this.logger.info(`Challenge sent to ${this} to join realm ${realm_name}`);
                }
            });
        }
    },
    [WAMP.AUTHENTICATE]: {
        label: 'AUTHENTICATE',
        exec(secret) {
            if (this.realm) {
                this.logger.error(`${this} tried to authenticate to join realm ${this.details.requested_realm} but it already joined realm ${this.realm.name}`);
                this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                return;
            }
            if (!this.details.authenticating) {
                this.logger.error(`${this} tried to authenticate to join realm ${this.details.requested_realm} but it was not challenged to do so`);
                this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                return;
            }
            this.router.authenticate(this.details, secret, err => {
                if (err) {
                    this.logger.error(`${this} failed authentication:`, err);
                    this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    return;
                }
                const realm = this.router.get_realm(this.details.requested_realm);
                const details = realm.add_session(this);
                details.authid = this.details.authid;
                details.authmethod = this.details.authmethod;
                this.details.authenticating = false;
                this.send([WAMP.WELCOME, this.id, details]);
            });
        }
    },
    [WAMP.GOODBYE]: {
        label: 'GOODBYE',
        requires_realm: true,
        exec() {
            this.logger.info(`${this} goodbyes ${this.realm.name}`);
            this.close(WAMP.GOODBYE, errors.GOODBYE_OUT);
        }
    },
    [WAMP.REGISTER]: {
        label: 'REGISTER',
        requires_realm: true,
        exec(request_id, options = {}, uri) {
            this.router.authorize(this.details, 'register', uri, (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to register procedure ${uri}`);
                    this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                }
                else this.realm.create_registration(this, request_id, options, uri);
            });
        }
    },
    [WAMP.UNREGISTER]: {
        label: 'UNREGISTER',
        requires_realm: true,
        exec(request_id, registration_id) {
            this.router.authorize(this.details, 'register', this.realm.registration_uri(registration_id), (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to register (unregister) procedure ${this.realm.registration_uri(registration_id)}`);
                    this.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                }
                else this.realm.remove_registration(this, request_id, registration_id);
            });
        }
    },
    [WAMP.CALL]: {
        label: 'CALL',
        requires_realm: true,
        exec(request_id, options = {}, uri, args, kwargs) {
            this.router.authorize(this.details, 'call', uri, (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to call procedure ${uri}`);
                    this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NOT_AUTHORIZED]);
                }
                else this.realm.call_registration(this, request_id, options, uri, args, kwargs);
            });
        }
    },
    [WAMP.CANCEL]: {
        label: 'CANCEL',
        requires_realm: true,
        exec(request_id, options = {}) {
            this.router.authorize(this.details, 'call', this.realm.call_uri(request_id), (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to call (cancel - PROTOCOL VIOLATION) procedure ${this.realm.call_uri(request_id)}`);
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                }
                else this.realm.cancel_call(this, request_id, options);
            });
        }
    },
    [WAMP.YIELD]: {
        label: 'YIELD',
        requires_realm: true,
        exec(invocation_id, options = {}, args, kwargs) {
            this.router.authorize(this.details, 'register', this.realm.invocation_uri(invocation_id), (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to register (yield - PROTOCOL VIOLATION) procedure ${this.realm.invocation_uri(invocation_id)}`);
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                }
                else this.realm.call_result(this, invocation_id, options, args, kwargs);
            });
        }
    },
    [WAMP.ERROR]: {
        label: 'ERROR',
        requires_realm: true,
        exec(request_type, invocation_id, details, error, args, kwargs) {
            if (request_type !== WAMP.INVOCATION) {
                this.logger.warn(`${this} ignore error (request type is not invocation)`);
                this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                return;
            }
            this.router.authorize(this.details, 'register', this.realm.invocation_uri(invocation_id), (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to register (error - PROTOCOL VIOLATION) procedure ${this.realm.invocation_uri(invocation_id)}`);
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                }
                else this.realm.call_error(this, invocation_id, details, error, args, kwargs);
            });
        }
    },
    [WAMP.SUBSCRIBE]: {
        label: 'SUBSCRIBE',
        requires_realm: true,
        exec(request_id, options = {}, uri) {
            this.router.authorize(this.details, 'subscribe', uri, (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to subscribe topic ${uri}`);
                    this.send([WAMP.ERROR, WAMP.SUBSCRIBE, request_id, {}, errors.NOT_AUTHORIZED]);
                }
                else this.realm.create_subscription(this, request_id, options, uri);
            });
        }
    },
    [WAMP.UNSUBSCRIBE]: {
        label: 'UNSUBSCRIBE',
        requires_realm: true,
        exec(request_id, subscription_id) {
            this.router.authorize(this.details, 'subscribe', this.realm.subscription_uri(subscription_id), (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to subscribe (unsubscribe) topic ${this.realm.subscription_uri(subscription_id)}`);
                    this.send([WAMP.ERROR, WAMP.UNSUBSCRIBE, request_id, {}, errors.NOT_AUTHORIZED]);
                }
                else this.realm.remove_subscription(this, request_id, subscription_id);
            });
        }
    },
    [WAMP.PUBLISH]: {
        label: 'PUBLISH',
        requires_realm: true,
        exec(request_id, options = {}, uri, args, kwargs) {
            this.router.authorize(this.details, 'publish', uri, (err, allowed) => {
                if (err) this.auth_error(err);
                else if (!allowed) {
                    this.logger.error(`${this} not authorized to publish in topic ${uri}`);
                    if (options.acknowledge === true) this.send([WAMP.ERROR, WAMP.PUBLISH, request_id, {}, errors.NOT_AUTHORIZED]);
                }
                else this.realm.publish(this, request_id, options, uri, args, kwargs);
            });
        }
    },
};

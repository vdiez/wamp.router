'use strict';

let WAMP = require('./protocol');
let errors = require('./errors');
let wss = require('ws');
let id = () => Math.floor(Math.random() * 9007199254740992);

function Session (router, wsclient) {
    this.router = router;
    this.secure_details = {};
    this.realm = null;
    this.id = id();
    wsclient.on('close', () => this.cleanup());
    wsclient.on('message', data => this.handle(data));

    this.set_realm = function(realm) {
        this.realm = realm;
    };

    this.send = function(message, callback) {
        if (wsclient.readyState === wss.OPEN) wsclient.send(JSON.stringify(message), callback);
    };

    this.close = function (code, reason, details) {
        this.send([code, details || {}, reason], () => wsclient.close());
    };

    this.cleanup = function() {
        if (this.realm) this.realm.remove_session(this);
    };

    this.handle = function(message) {
        try {message = JSON.parse(message);}
        catch (e) {this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);}

        if (!Array.isArray(message)) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
        let message_type = message.shift();
        switch (message_type) {
            case WAMP.HELLO: {
                let [realm_name, details] = message;
                if (this.realm === null) {
                    this.secure_details = details || {};
                    this.secure_details.requested_realm = realm_name;
                    this.router.handle_methods(this.secure_details, (err, method, extra) => {
                        if (err) this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        else if (method === "anonymous") {
                            this.router.get_realm(realm_name, realm => {
                                if (realm.get_session(this.id)) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                                let details = realm.join_session(this);
                                details.authid = "anonymous";
                                details.authmethod = "anonymous";
                                this.secure_details.authenticating = false;
                                this.secure_details.authmethod = "anonymous";
                                this.send([WAMP.WELCOME, this.id, details]);
                            });
                        }
                        else {
                            this.secure_details.authenticating = true;
                            details.authmethod = method;
                            this.send([WAMP.CHALLENGE, method, extra || {}]);
                        }
                    });
                }
                else this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                break;
            }

            case WAMP.AUTHENTICATE: {
                let secret = message.shift();
                if (this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                if (!this.secure_details.authenticating) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authenticate(this.secure_details, secret, err => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    this.router.get_realm(this.secure_details.requested_realm, realm => {
                        if (realm.get_session(this.id)) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                        let details = realm.join_session(this);
                        details.authid = this.secure_details.authid;
                        details.authmethod = this.secure_details.authmethod;
                        this.secure_details.authenticating = false;
                        this.send([WAMP.WELCOME, this.id, details]);
                    });
                });
                break;
            }

            case WAMP.GOODBYE: {
                this.close(WAMP.GOODBYE, errors.GOODBYE_OUT);
                break;
            }

            case WAMP.REGISTER: {
                let [request_id, options, uri] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "register", uri, (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                    if (this.realm.registrations_by_uri[uri]) return this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
                    let registration = {session_id: this.id, request_id, uri, options, id: id()};
                    this.realm.registrations_by_uri[uri] = registration;
                    this.realm.registrations_by_id[registration.id] = registration;
                    this.send([WAMP.REGISTERED, request_id, registration.id]);
                });
                break;
            }

            case WAMP.CALL: {
                let [request_id, options, uri, args, kwargs] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "call", uri, (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NOT_AUTHORIZED]);
                    let registration = this.realm.registrations_by_uri[uri];
                    if (!registration) return this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
                    let invocation = {session_id: this.id, request_id, uri, options, args, kwargs, id: id()};
                    this.realm.invocations[invocation.id] = invocation;
                    let callee = this.realm.get_session(registration.session_id);
                    let details = {procedure: uri};
                    if (options.receive_progress) details.receive_progress = true;
                    if (callee) callee.send([WAMP.INVOCATION, invocation.id, registration.id, details, args, kwargs]);
                });
                break;
            }

            case WAMP.UNREGISTER: {
                let [request_id, registration_id] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "unregister", this.realm.registration_uri(registration_id), (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                    let registration = this.realm.registrations_by_id[registration_id];
                    if (!registration || registration.session_id !== this.id) return this.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NO_SUCH_REGISTRATION]);
                    this.send([WAMP.UNREGISTERED, request_id]);
                    delete this.realm.registrations_by_id[registration_id];
                    delete this.realm.registrations_by_uri[registration.uri];
                });
                break;
            }

            case WAMP.YIELD: {
                let [invocation_id, options, args, kwargs] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "register", this.realm.invocation_uri(invocation_id), (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    let invocation = this.realm.invocations[invocation_id];
                    if (!invocation) return;
                    let registration = this.realm.registrations_by_uri[invocation.uri];
                    if (!registration || this.id !== registration.session_id) return;
                    let caller = this.realm.get_session(invocation.session_id);
                    let details = {};
                    if (options.progress) {
                        if (!caller) this.send([WAMP.INTERRUPT, invocation_id, {mode: "killnowait"}]);
                        details.progress = true;
                    }
                    if (caller) caller.send([WAMP.RESULT, invocation.request_id, details, args, kwargs]);
                    if (!details.progress || !caller) delete this.realm.invocations[invocation_id];
                });
                break;
            }

            case WAMP.ERROR: {
                let [request_type, invocation_id, details, error, args, kwargs] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                if (request_type !== WAMP.INVOCATION) return;
                this.router.authorize(this.secure_details, "register", this.realm.invocation_uri(invocation_id), (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    let invocation = this.realm.invocations[invocation_id];
                    if (!invocation) return;
                    let registration = this.realm.registrations_by_uri[invocation.uri];
                    if (!registration || this.id !== registration.session_id) return;
                    let caller = this.realm.get_session(invocation.session_id);
                    if (caller) caller.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, details, error, args, kwargs]);
                    delete this.realm.invocations[invocation_id];
                });
                break;
            }

            case WAMP.SUBSCRIBE: {
                let [request_id, options, uri] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "subscribe", uri, (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.SUBSCRIBE, request_id, {}, errors.NOT_AUTHORIZED]);
                    let subscription = {session_id: this.id, request_id, uri, options, id: id()};
                    if (!this.realm.subscriptions_by_uri.hasOwnProperty(uri)) this.realm.subscriptions_by_uri[uri] = [];
                    this.realm.subscriptions_by_uri[uri].push(subscription);
                    this.realm.subscriptions_by_id[subscription.id] = subscription;
                    this.send([WAMP.SUBSCRIBED, request_id, subscription.id]);
                });
                break;
            }

            case WAMP.UNSUBSCRIBE: {
                let [request_id, subscription_id] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "unsubscribe", this.realm.subscription_uri(subscription_id), (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.UNSUBSCRIBE, request_id, {}, errors.NOT_AUTHORIZED]);
                    let subscription = this.realm.subscriptions_by_id[subscription_id];
                    if (!subscription || subscription.session_id !== this.id) return this.send([WAMP.ERROR, WAMP.UNSUBSCRIBE, request_id, {}, errors.NO_SUCH_SUBSCRIPTION]);
                    this.send([WAMP.UNSUBSCRIBED, request_id]);
                    delete this.realm.subscriptions_by_id[subscription_id];
                    this.realm.subscriptions_by_uri[subscription.uri] = this.realm.subscriptions_by_uri[subscription.uri].filter(subscription => subscription.session_id !== this.id);
                    if (!this.realm.subscriptions_by_uri[subscription.uri].length) delete this.realm.subscriptions_by_uri[subscription.uri];
                });
                break;
            }

            case WAMP.PUBLISH: {
                let [request_id, options, uri, args, kwargs] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "publish", uri, (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.PUBLISH, request_id, {}, errors.NOT_AUTHORIZED]);
                    let publication_id = id();
                    if (this.realm.subscriptions_by_uri.hasOwnProperty(uri)) {
                        this.realm.subscriptions_by_uri[uri].forEach(subscription => {
                            if (subscription.session_id !== this.id || options.exclude_me === false) {
                                let subscriber = this.realm.get_session(subscription.session_id);
                                if (subscriber) subscriber.send([WAMP.EVENT, subscription.id, publication_id, {topic: uri}, args, kwargs]);
                            }
                        })
                    }
                });
                break;
            }

            default: {
                this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
            }
        }
    };
}

module.exports = Session;

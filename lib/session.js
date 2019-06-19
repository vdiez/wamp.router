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
                let [request_id, options = {}, uri] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "register", uri, (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                    if (!this.realm.registrations_by_uri[uri]) this.realm.registrations_by_uri[uri] = {callees: [], callee_ids: {}, round_robin: 0};
                    if (this.realm.registrations_by_uri[uri].callee_ids[this.id]) return this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
                    let registration = {session_id: this.id, request_id, uri, options, counter: 0, id: id()};
                    options.invoke = options.invoke || 'single';
                    if (!this.realm.registrations_by_uri[uri].callees.length) this.realm.registrations_by_uri[uri].invoke = options.invoke;
                    else {
                        if (this.realm.registrations_by_uri[uri].invoke === 'single') return this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
                        if (options.invoke !== this.realm.registrations_by_uri[uri].invoke) return this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
                    }
                    this.realm.registrations_by_uri[uri].callee_ids[this.id] = registration;
                    this.realm.registrations_by_uri[uri].callees.push(registration);
                    this.realm.registrations_by_id[registration.id] = registration;
                    this.send([WAMP.REGISTERED, request_id, registration.id]);
                });
                break;
            }

            case WAMP.UNREGISTER: {
                let [request_id, registration_id] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "register", this.realm.registration_uri(registration_id), (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                    let registration = this.realm.registrations_by_id[registration_id];
                    if (!registration || registration.session_id !== this.id) return this.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NO_SUCH_REGISTRATION]);
                    this.send([WAMP.UNREGISTERED, request_id]);
                    delete this.realm.registrations_by_id[registration_id];
                    this.realm.registrations_by_uri[registration.uri].callees = this.realm.registrations_by_uri[registration.uri].callees.filter(registration => registration.session_id !== this.id);
                    delete this.realm.registrations_by_uri[registration.uri].callee_ids[this.id];
                });
                break;
            }

            case WAMP.CALL: {
                let [request_id, options = {}, uri, args, kwargs] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "call", uri, (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NOT_AUTHORIZED]);
                    let registrations = this.realm.registrations_by_uri[uri];
                    if (!registrations || !registrations.callees.length) return this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
                    let registration;
                    if (registrations.invoke === "single" || registrations.invoke === "first") registration = registrations.callees[0];
                    else if (registrations.invoke === "last") registration = registrations.callees[registrations.callees.length - 1];
                    else if (registrations.invoke === "roundrobin") {
                        if (registrations.round_robin >= registrations.callees.length) registrations.round_robin = 0;
                        registration = registrations.callees[registrations.round_robin];
                        registrations.round_robin++;
                    }
                    else if (registrations.invoke === "random") registration = registrations.callees[Math.floor(Math.random() * registrations.callees.length)];
                    else if (registrations.invoke === "load") registration = registrations.callees.reduce((min, callee) => {if (!min || callee.counter < min.counter) return callee; return min;}, null);
                    registration.counter++;
                    let invocation = {session_id: this.id, request_id, registration_id: registration.id, uri, options, args, kwargs, id: id()};
                    this.realm.invocations[invocation.id] = invocation;
                    this.realm.calls[request_id] = {session_id: this.id, request_id, registration_id: registration.id, uri, invocation_id: invocation.id};
                    let callee = this.realm.get_session(registration.session_id);
                    let details = {procedure: uri};
                    if (options.receive_progress) details.receive_progress = true;
                    if (options.disclose_me || registration.options.disclose_caller) details.caller = this.id;
                    if (callee) callee.send([WAMP.INVOCATION, invocation.id, registration.id, details, args, kwargs]);
                });
                break;
            }

            case WAMP.CANCEL: {
                let [request_id, options = {}] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "call", this.realm.call_uri(request_id), (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.CANCEL, request_id, {}, errors.NOT_AUTHORIZED]);
                    let call = this.realm.calls[request_id];
                    if (!call) return;
                    let registration = this.realm.registrations_by_id[call.registration_id];
                    if (!registration) return this.send([WAMP.ERROR, WAMP.CANCEL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
                    let invocation = this.realm.invocations[call.invocation_id];
                    if (!invocation) return;

                    let supported_by_callee = false;
                    let callee = this.realm.get_session(registration.session_id);
                    if (!callee) return this.send([WAMP.ERROR, WAMP.CANCEL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
                    if (callee.secure_details && callee.secure_details.roles && callee.secure_details.roles.callee && callee.secure_details.roles.callee.call_canceling) supported_by_callee = true;
                    if (!supported_by_callee || options.mode === "skip" || options.mode === "killnowait") {
                        this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, error]);
                        delete this.realm.invocations[call.invocation_id];
                        delete this.realm.calls[request_id];
                        registration.counter--;
                    }
                    if (supported_by_callee && (options.mode === "killnowait" || options.mode === "kill")) callee.send([WAMP.INTERRUPT, invocation.id, {mode: options.mode}]);
                });
                break;
            }

            case WAMP.YIELD: {
                let [invocation_id, options = {}, args, kwargs] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "register", this.realm.invocation_uri(invocation_id), (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    let invocation = this.realm.invocations[invocation_id];
                    if (!invocation) {
                        if (options.progress) this.send([WAMP.INTERRUPT, invocation_id, {mode: "killnowait"}]);
                        return;
                    }
                    let registration = this.realm.registrations_by_id[invocation.registration_id];
                    if (!registration || this.id !== registration.session_id) return;
                    let caller = this.realm.get_session(invocation.session_id);
                    let details = {};
                    if (options.progress) {
                        if (!caller) this.send([WAMP.INTERRUPT, invocation_id, {mode: "killnowait"}]);
                        if (!invocation.options.receive_progress) return;
                        details.progress = true;
                    }
                    if (caller) caller.send([WAMP.RESULT, invocation.request_id, details, args, kwargs]);
                    if (!details.progress || !caller) {
                        delete this.realm.invocations[invocation_id];
                        delete this.realm.calls[invocation.request_id];
                        registration.counter--;
                    }
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
                    let registration = this.realm.registrations_by_id[invocation.registration_id];
                    if (!registration || this.id !== registration.session_id) return;
                    let caller = this.realm.get_session(invocation.session_id);
                    if (caller) caller.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, details, error, args, kwargs]);
                    delete this.realm.invocations[invocation_id];
                    delete this.realm.calls[invocation.request_id];
                    registration.counter--;
                });
                break;
            }

            case WAMP.SUBSCRIBE: {
                let [request_id, options = {}, uri] = message;
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
                this.router.authorize(this.secure_details, "subscribe", this.realm.subscription_uri(subscription_id), (err, allowed) => {
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
                let [request_id, options = {}, uri, args, kwargs] = message;
                if (!this.realm) return this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                this.router.authorize(this.secure_details, "publish", uri, (err, allowed) => {
                    if (err) return this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                    else if (!allowed) return this.send([WAMP.ERROR, WAMP.PUBLISH, request_id, {}, errors.NOT_AUTHORIZED]);
                    let publication_id = id();
                    let details = {topic: uri};
                    if (options.disclose_me) details.publisher = this.id;
                    if (this.realm.subscriptions_by_uri.hasOwnProperty(uri)) {
                        this.realm.subscriptions_by_uri[uri].forEach(subscription => {
                            if (subscription.session_id !== this.id || options.exclude_me === false) {
                                if (subscription.options.disclose_publisher) details.publisher = this.id;
                                let subscriber = this.realm.get_session(subscription.session_id);
                                if (subscriber) subscriber.send([WAMP.EVENT, subscription.id, publication_id, details, args, kwargs]);
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

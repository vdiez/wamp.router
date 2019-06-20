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
    this.logger = router.logger;
    wsclient.on('close', () => this.cleanup());
    wsclient.on('message', data => this.handle(data));

    this.set_realm = function(realm) {
        this.realm = realm;
    };

    this.send = function(message, callback) {
        if (wsclient.readyState === wss.OPEN) {
            wsclient.send(JSON.stringify(message), callback);
            this.logger.debug("Sending message to session ", this.id, ", authid ", this.secure_details.authid, ":", message);
        }
    };

    this.close = function (code, reason, details) {
        this.logger.info("Closing session ", this.id, ", authid ", this.secure_details.authid, ". Errors: ", code, reason, details);
        this.send([code, details || {}, reason], () => wsclient.close());
    };

    this.cleanup = function() {
        if (this.realm) this.realm.remove_session(this);
    };

    this.cancel_call = function(request_id) {
        this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
    };

    this.handle = function(message) {
        try {message = JSON.parse(message);}
        catch (e) {
            this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " could not parse message:", e);
            this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
            return;
        }
        this.logger.debug("Received message from session ", this.id, ", authid ", this.secure_details.authid, ":", message);

        if (!Array.isArray(message)) {
            this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " message is not Array");
            this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
            return;
        }
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
                                if (realm.get_session(this.id)) {
                                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to join realm ", realm_name, " but it's already a member");
                                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                                    return;
                                }
                                let details = realm.join_session(this);
                                details.authid = "anonymous";
                                details.authmethod = "anonymous";
                                this.secure_details.authenticating = false;
                                this.secure_details.authmethod = "anonymous";
                                this.send([WAMP.WELCOME, this.id, details]);
                                this.logger.info("New session ", this.id, ", authid ", this.secure_details.authid, " joined realm ", realm_name);
                            });
                        }
                        else {
                            this.secure_details.authenticating = true;
                            details.authmethod = method;
                            this.send([WAMP.CHALLENGE, method, extra || {}]);
                            this.logger.info("Challenge sent to session ", this.id, ", authid ", this.secure_details.authid, " to join realm ", realm_name);
                        }
                    });
                }
                else {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to join realm ", realm_name, " but it already joined realm", this.realm.name);
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                }
                break;
            }

            case WAMP.AUTHENTICATE: {
                let secret = message.shift();
                if (this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to authenticate to join realm ", this.secure_details.requested_realm, " but it already joined realm", this.realm.name);
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                if (!this.secure_details.authenticating) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to authenticate to join realm ", this.secure_details.requested_realm, " but it was not challenged to do so");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authenticate(this.secure_details, secret, err => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " failed authentication: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    this.router.get_realm(this.secure_details.requested_realm, realm => {
                        if (realm.get_session(this.id)) {
                            this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to join realm ", realm.name, " but it's already a member");
                            this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                            return;
                        }
                        let details = realm.join_session(this);
                        details.authid = this.secure_details.authid;
                        details.authmethod = this.secure_details.authmethod;
                        this.secure_details.authenticating = false;
                        this.send([WAMP.WELCOME, this.id, details]);
                        this.logger.info("New session ", this.id, ", authid ", this.secure_details.authid, " joined realm ", realm.name);
                    });
                });
                break;
            }

            case WAMP.GOODBYE: {
                this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " goodbyes ", this.realm.name);
                this.close(WAMP.GOODBYE, errors.GOODBYE_OUT);
                break;
            }

            case WAMP.REGISTER: {
                let [request_id, options = {}, uri] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to REGISTER but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "register", uri, (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to register procedure ", uri);
                        this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                        return;
                    }
                    if (!this.realm.registrations_by_uri[uri]) this.realm.registrations_by_uri[uri] = {callees: [], callee_ids: {}, round_robin: 0};
                    if (this.realm.registrations_by_uri[uri].callee_ids[this.id]) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " already registered procedure ", uri);
                        this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
                        return;
                    }
                    let registration = {session_id: this.id, request_id, uri, options, counter: 0, id: id()};
                    options.invoke = options.invoke || 'single';
                    if (!this.realm.registrations_by_uri[uri].callees.length) this.realm.registrations_by_uri[uri].invoke = options.invoke;
                    else {
                        if (this.realm.registrations_by_uri[uri].invoke === 'single') {
                            this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " cannot register new instance of single procedure ", uri);
                            this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
                            return;
                        }
                        if (options.invoke !== this.realm.registrations_by_uri[uri].invoke) {
                            this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " cannot register new instance with different invoke policy of procedure ", uri);
                            this.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
                            return;
                        }
                    }
                    this.realm.registrations_by_uri[uri].callee_ids[this.id] = registration;
                    this.realm.registrations_by_uri[uri].callees.push(registration);
                    this.realm.registrations_by_id[registration.id] = registration;
                    this.send([WAMP.REGISTERED, request_id, registration.id]);
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " registered new instance of procedure ", uri, ". Policy: ", options.invoke);
                });
                break;
            }

            case WAMP.UNREGISTER: {
                let [request_id, registration_id] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to UNREGISTER but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "register", this.realm.registration_uri(registration_id), (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to register (unregister) procedure ", this.realm.registration_uri(registration_id));
                        this.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
                        return;
                    }
                    let registration = this.realm.registrations_by_id[registration_id];
                    if (!registration || registration.session_id !== this.id) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " cannot unregister (registration not found in its session) ", this.realm.registration_uri(registration_id));
                        this.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NO_SUCH_REGISTRATION]);
                        return;
                    }
                    this.send([WAMP.UNREGISTERED, request_id]);
                    delete this.realm.registrations_by_id[registration_id];
                    this.realm.registrations_by_uri[registration.uri].callees = this.realm.registrations_by_uri[registration.uri].callees.filter(registration => registration.session_id !== this.id);
                    delete this.realm.registrations_by_uri[registration.uri].callee_ids[this.id];
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " unregistered instance of procedure ", this.realm.registration_uri(registration_id));
                });
                break;
            }

            case WAMP.CALL: {
                let [request_id, options = {}, uri, args, kwargs] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to CALL but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "call", uri, (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to call procedure ", uri);
                        this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NOT_AUTHORIZED]);
                        return;
                    }
                    let registrations = this.realm.registrations_by_uri[uri];
                    if (!registrations || !registrations.callees.length) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " cannot call (registration not found) ", uri);
                        this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
                        return;
                    }
                    let registration;
                    if (registrations.invoke === "single" || registrations.invoke === "first") registration = registrations.callees[0];
                    else if (registrations.invoke === "last") registration = registrations.callees[registrations.callees.length - 1];
                    else if (registrations.invoke === "roundrobin") {
                        if (registrations.round_robin >= registrations.callees.length) registrations.round_robin = 0;
                        registration = registrations.callees[registrations.round_robin];
                        registrations.round_robin++;
                    }
                    else if (registrations.invoke === "random") registration = registrations.callees[Math.floor(Math.random() * registrations.callees.length)];
                    else if (registrations.invoke === "load") registration = registrations.callees.reduce((min, callee) => (!min || callee.counter < min.counter) ? callee : min, null);
                    if (!registration) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " failed call (registration selection) ", uri);
                        this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
                        return;
                    }
                    registration.counter++;
                    let invocation = {session_id: this.id, request_id, callee_id: registration.session_id, registration_id: registration.id, uri, options, args, kwargs, invocation_id: id()};
                    this.realm.invocations[invocation.invocation_id] = invocation;
                    this.realm.calls[request_id] = invocation;
                    let callee = this.realm.get_session(registration.session_id);
                    let details = {procedure: uri};
                    if (options.receive_progress) details.receive_progress = true;
                    if (options.disclose_me || registration.options.disclose_caller) details.caller = this.id;
                    if (callee) callee.send([WAMP.INVOCATION, invocation.invocation_id, registration.id, details, args, kwargs]);
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " called ", uri);
                });
                break;
            }

            case WAMP.CANCEL: {
                let [request_id, options = {}] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to CANCEL but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "call", this.realm.call_uri(request_id), (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to call (cancel - PROTOCOL VIOLATION) procedure ", this.realm.call_uri(request_id));
                        this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                        return;
                    }
                    let call = this.realm.calls[request_id];
                    if (!call) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore cancel call (call not found) ", this.realm.call_uri(request_id));
                        return;
                    }
                    let registration = this.realm.registrations_by_id[call.registration_id];
                    if (!registration) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore cancel call (registration not found) ", this.realm.call_uri(request_id));
                        return;
                    }
                    let invocation = this.realm.invocations[call.invocation_id];
                    if (!invocation) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore cancel call (invoke not found) ", this.realm.call_uri(request_id));
                        return;
                    }

                    let supported_by_callee = false;
                    let callee = this.realm.get_session(registration.session_id);
                    if (!callee) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore cancel call (callee not found) ", this.realm.call_uri(request_id));
                        return;
                    }
                    if (callee.secure_details && callee.secure_details.roles && callee.secure_details.roles.callee && callee.secure_details.roles.callee.call_canceling) supported_by_callee = true;
                    if (!supported_by_callee || options.mode === "skip" || options.mode === "killnowait") {
                        this.send([WAMP.ERROR, WAMP.CALL, request_id, {}, error]);
                        delete this.realm.invocations[call.invocation_id];
                        delete this.realm.calls[request_id];
                        registration.counter--;
                        this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " cancelled call ", this.realm.call_uri(request_id));
                    }
                    if (supported_by_callee && (options.mode === "killnowait" || options.mode === "kill")) {
                        callee.send([WAMP.INTERRUPT, invocation.invocation_id, {mode: options.mode}]);
                        this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " requested interrupt of call ", this.realm.call_uri(request_id));
                    }
                });
                break;
            }

            case WAMP.YIELD: {
                let [invocation_id, options = {}, args, kwargs] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to YIELD but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "register", this.realm.invocation_uri(invocation_id), (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to register (yield - PROTOCOL VIOLATION) procedure ", this.realm.invocation_uri(invocation_id));
                        this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                        return;
                    }
                    let invocation = this.realm.invocations[invocation_id];
                    if (!invocation) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore yield (invocation not found) from procedure ", this.realm.invocation_uri(invocation_id));
                        if (options.progress) {
                            this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " request interrupt (progress yield and invocation not found) for procedure ", this.realm.invocation_uri(invocation_id));
                            this.send([WAMP.INTERRUPT, invocation_id, {mode: "killnowait"}]);
                        }
                        return;
                    }
                    let registration = this.realm.registrations_by_id[invocation.registration_id];
                    if (!registration || this.id !== registration.session_id) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore yield (registration not found in session) from procedure ", this.realm.invocation_uri(invocation_id));
                        return;
                    }
                    let caller = this.realm.get_session(invocation.session_id);
                    let details = {};
                    if (options.progress) {
                        if (!caller) this.send([WAMP.INTERRUPT, invocation_id, {mode: "killnowait"}]);
                        if (!invocation.options.receive_progress) {
                            this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore progress yield (registered without 'receive_progress') from procedure ", this.realm.invocation_uri(invocation_id));
                            return;
                        }
                        details.progress = true;
                    }
                    if (caller) caller.send([WAMP.RESULT, invocation.request_id, details, args, kwargs]);
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " yielded from procedure ", this.realm.invocation_uri(invocation_id));
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
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to ERROR but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                if (request_type !== WAMP.INVOCATION) {
                    this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore error (request type is not invocation)");
                    return;
                }
                this.router.authorize(this.secure_details, "register", this.realm.invocation_uri(invocation_id), (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to register (error - PROTOCOL VIOLATION) procedure ", this.realm.invocation_uri(invocation_id));
                        this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                        return;
                    }
                    let invocation = this.realm.invocations[invocation_id];
                    if (!invocation) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore error (invocation not found) from procedure ", this.realm.invocation_uri(invocation_id));
                        return;
                    }
                    let registration = this.realm.registrations_by_id[invocation.registration_id];
                    if (!registration || this.id !== registration.session_id) {
                        this.logger.warn("Session ", this.id, ", authid ", this.secure_details.authid, " ignore yield (registration not found) from procedure ", this.realm.invocation_uri(invocation_id));
                        return;
                    }
                    let caller = this.realm.get_session(invocation.session_id);
                    if (caller) caller.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, details, error, args, kwargs]);
                    delete this.realm.invocations[invocation_id];
                    delete this.realm.calls[invocation.request_id];
                    registration.counter--;
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " returned error from procedure ", this.realm.invocation_uri(invocation_id));
                });
                break;
            }

            case WAMP.SUBSCRIBE: {
                let [request_id, options = {}, uri] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to SUBSCRIBE but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "subscribe", uri, (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to subscribe topic ", uri);
                        this.send([WAMP.ERROR, WAMP.SUBSCRIBE, request_id, {}, errors.NOT_AUTHORIZED]);
                        return;
                    }
                    let subscription = {session_id: this.id, request_id, uri, options, id: id()};
                    if (!this.realm.subscriptions_by_uri.hasOwnProperty(uri)) this.realm.subscriptions_by_uri[uri] = [];
                    this.realm.subscriptions_by_uri[uri].push(subscription);
                    this.realm.subscriptions_by_id[subscription.id] = subscription;
                    this.send([WAMP.SUBSCRIBED, request_id, subscription.id]);
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " subscribed to topic ", uri);
                });
                break;
            }

            case WAMP.UNSUBSCRIBE: {
                let [request_id, subscription_id] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to UNSUBSCRIBE but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "subscribe", this.realm.subscription_uri(subscription_id), (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to subscribe (unsubscribe) topic ", this.realm.subscription_uri(subscription_id));
                        this.send([WAMP.ERROR, WAMP.UNSUBSCRIBE, request_id, {}, errors.NOT_AUTHORIZED]);
                        return;
                    }
                    let subscription = this.realm.subscriptions_by_id[subscription_id];
                    if (!subscription || subscription.session_id !== this.id) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " cannot unsubscribe (subscription not found) ", this.realm.subscription_uri(subscription_id));
                        this.send([WAMP.ERROR, WAMP.UNSUBSCRIBE, request_id, {}, errors.NO_SUCH_SUBSCRIPTION]);
                        return;
                    }
                    this.send([WAMP.UNSUBSCRIBED, request_id]);
                    delete this.realm.subscriptions_by_id[subscription_id];
                    this.realm.subscriptions_by_uri[subscription.uri] = this.realm.subscriptions_by_uri[subscription.uri].filter(subscription => subscription.session_id !== this.id);
                    if (!this.realm.subscriptions_by_uri[subscription.uri].length) delete this.realm.subscriptions_by_uri[subscription.uri];
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " unsubscribed to topic ", this.realm.subscription_uri(subscription_id));
                });
                break;
            }

            case WAMP.PUBLISH: {
                let [request_id, options = {}, uri, args, kwargs] = message;
                if (!this.realm) {
                    this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " tried to PUBLISH but did not join any realm");
                    this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
                    return;
                }
                this.router.authorize(this.secure_details, "publish", uri, (err, allowed) => {
                    if (err) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " authorization failed: ", err);
                        this.close(WAMP.ABORT, errors.AUTHORIZATION_FAILED);
                        return;
                    }
                    if (!allowed && options.acknowledge === true) {
                        this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " not authorized to publish in topic ", uri);
                        this.send([WAMP.ERROR, WAMP.PUBLISH, request_id, {}, errors.NOT_AUTHORIZED]);
                        return;
                    }
                    let publication_id = id();
                    if (this.realm.subscriptions_by_uri.hasOwnProperty(uri)) {
                        this.realm.subscriptions_by_uri[uri].forEach(subscription => {
                            if (subscription.session_id !== this.id || options.exclude_me === false) {
                                let details = {topic: uri};
                                if (options.disclose_me) details.publisher = this.id;
                                if (subscription.options.disclose_publisher) details.publisher = this.id;
                                let subscriber = this.realm.get_session(subscription.session_id);
                                if (subscriber) subscriber.send([WAMP.EVENT, subscription.id, publication_id, details, args, kwargs]);
                            }
                        })
                    }
                    if (options.acknowledge) this.send([WAMP.PUBLISHED, request_id, publication_id]);
                    this.logger.info("Session ", this.id, ", authid ", this.secure_details.authid, " published to topic ", uri);
                });
                break;
            }

            default: {
                this.logger.error("Session ", this.id, ", authid ", this.secure_details.authid, " unknown message_type: ", message_type);
                this.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
            }
        }
    };
}

module.exports = Session;

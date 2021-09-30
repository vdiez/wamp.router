'use strict';

const id = require('./id');
const WAMP = require('./protocol');
const errors = require('./errors');
const meta = require('./meta');
const wildcard = require('./wildcard');

class Realm {
    constructor(router, name) {
        this.name = name;
        this.logger = router.logger;
        this.sessions = {};
        this.invocations = {};
        this.calls = {};
        this.registrations_by_id = {};
        this.registrations_by_uri = {};
        this.subscriptions_by_id = {};
        this.subscriptions_by_uri = {};
        this.fake_session = {id: id(), send() {}, toString() {return `Realm ${name}`;}};
        for (const registration in meta.registrations) {
            if (meta.registrations.hasOwnProperty(registration)) this.create_registration(this.fake_session, id(), {}, registration);
        }
    }

    create_registration(session, request_id, options = {}, uri) {
        if (meta.registrations.hasOwnProperty(uri) && session !== this.fake_session) {
            this.logger.error(`${session} not authorized to publish in meta topic ${uri}`);
            return session.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.NOT_AUTHORIZED]);
        }

        if (!this.registrations_by_uri[uri]) this.registrations_by_uri[uri] = {callees: [], callee_ids: {}, round_robin: 0};
        const registrations = this.registrations_by_uri[uri];
        if (registrations.callee_ids[session.id]) {
            this.logger.error(`${session} already registered procedure ${uri}`);
            return session.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
        }
        const registration = {session_id: session.id, request_id, uri, options, counter: 0, id: id()};
        if (!options.invoke || !meta.allowed_invokes.includes(options.invoke)) options.invoke = 'single';
        if (!registrations.callees.length) registrations.invoke = options.invoke;
        else {
            if (registrations.invoke === 'single') {
                this.logger.error(`${session} cannot register new instance of single procedure ${uri}`);
                return session.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
            }
            if (options.invoke !== registrations.invoke) {
                this.logger.error(`${session} cannot register new instance with different invoke policy of procedure ${uri}`);
                return session.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
            }
        }
        registrations.callee_ids[session.id] = registration;
        registrations.callees.push(registration);
        this.registrations_by_id[registration.id] = registration;
        session.send([WAMP.REGISTERED, request_id, registration.id]);
        if (registrations.callees.length === 1) {
            this.publish(this.fake_session, id(), {}, 'wamp.registration.on_create', [session.id, {
                id: registration.id,
                created: new Date().toISOString(),
                uri,
                match: options.match,
                invoke: registrations.invoke
            }]);
        }
        this.publish(this.fake_session, id(), {}, 'wamp.registration.on_register', [session.id, registration.id]);
        this.logger.info(`${session} registered new instance of procedure ${uri}. Policy: ${options.invoke}`);
    }

    remove_registration(session, request_id, registration_id) {
        const registration = this.registrations_by_id[registration_id];
        if (!registration || registration.session_id !== session.id) {
            this.logger.error(`${session} cannot unregister (registration not found in its session) ${registration.uri}`);
            session.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NO_SUCH_REGISTRATION]);
            return;
        }
        session.send([WAMP.UNREGISTERED, request_id]);
        delete this.registrations_by_id[registration_id];
        this.registrations_by_uri[registration.uri].callees = this.registrations_by_uri[registration.uri].callees.filter(registration => registration.session_id !== session.id);
        delete this.registrations_by_uri[registration.uri].callee_ids[session.id];
        this.publish(this.fake_session, id(), {}, 'wamp.registration.on_unregister', [session.id, registration.id]);
        this.logger.info(`${session} unregistered instance of procedure ${registration.uri}`);
        if (!this.registrations_by_uri[registration.uri].callees.length) {
            delete this.registrations_by_uri[registration.uri];
            this.publish(this.fake_session, id(), {}, 'wamp.registration.on_delete', [session.id, registration.id]);
            this.logger.info(`Procedure ${registration.uri} removed as there are no further callees`);
        }
    }

    match_registrations(uri, forbidden = []) {
        const registrations = this.registrations_by_uri[uri];
        const callees = forbidden?.length ? registrations?.callees?.filter(registration => !forbidden.includes(registration.session_id)) : registrations?.callees;

        if (!callees?.length) {
            const prefix_matches = [];
            const wildcard_matches = [];
            for (const registration_id in this.registrations_by_id) {
                if (this.registrations_by_id.hasOwnProperty(registration_id)) {
                    const registration = this.registrations_by_id[registration_id];
                    if (registration.options?.match === 'prefix' && uri.startsWith(registration.uri) && !forbidden?.includes(registration.session_id)) prefix_matches.push(registration);
                    if (registration.options?.match === 'wildcard' && wildcard.match(uri, registration.uri) && !forbidden?.includes(registration.session_id)) wildcard_matches.push(registration);
                }
            }
            if (prefix_matches.length) return prefix_matches.reduce((best, registration) => (!best || registration.uri.length > best.uri.length) ? registration : best, null);
            if (wildcard_matches.length) return wildcard_matches.reduce((best, registration) => (!best || wildcard.weight(registration.uri, best.uri) > 0) ? registration : best, null);
        }
        else {
            if (registrations.invoke === 'single' || registrations.invoke === 'first') return callees[0];
            if (registrations.invoke === 'last') return callees[callees.length - 1];
            if (registrations.invoke === 'roundrobin') {
                for (let i = 0; i < registrations.callees.length; i++) {
                    if (registrations.round_robin >= registrations.callees.length) registrations.round_robin = 0;
                    const registration = registrations.callees[registrations.round_robin++];
                    if (!forbidden.includes(registration.session_id)) return registration;
                }
            }
            if (registrations.invoke === 'random') return callees[Math.floor(Math.random() * callees.length)];
            if (registrations.invoke === 'load') return callees.reduce((min, callee) => (!min || callee.counter < min.counter) ? callee : min, null);
        }
    }

    call_registration(session, request_id, options, uri, args, kwargs) {
        const registration = this.match_registrations(uri);
        if (!registration) {
            this.logger.error(`${session} failed call (registration not found) ${uri}`);
            session.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
            return;
        }
        const details = {procedure: uri};
        if (options.receive_progress) details.receive_progress = true;
        if (options.disclose_me || registration.options.disclose_caller) details.caller = session.id;
        this.logger.info(`${session} called ${uri}`);
        if (registration.session_id === this.fake_session.id && meta.registrations.hasOwnProperty(uri)) {
            const result = meta.registrations[uri].call(this, details, args, kwargs);
            session.send([WAMP.RESULT, request_id, {}, result.args, result.kwargs]);
            this.logger.info(`${session} yielded from meta procedure ${uri}`);
        }
        else {
            registration.counter++;
            const invocation = {session_id: session.id, request_id, callee_id: registration.session_id, registration_id: registration.id, uri, options, unavailable: [], details, args, kwargs, invocation_id: id()};
            this.invocations[invocation.invocation_id] = invocation;
            this.calls[request_id] = invocation;
            const callee = this.sessions[registration.session_id];
            if (callee) callee.send([WAMP.INVOCATION, invocation.invocation_id, registration.id, details, args, kwargs]);
            this.logger.info(`${session} called procedure ${uri} on callee ${callee}`);
        }
    }

    cancel_call(session, request_id, options) {
        const call = this.calls[request_id];
        if (!call) {
            this.logger.warn(`${session} ignore cancel call (call not found) ${call.uri}`);
            return;
        }
        const invocation = this.invocations[call.invocation_id];
        if (!invocation) {
            this.logger.warn(`${session} ignore cancel call (invoke not found) ${call.uri}`);
            delete this.calls[request_id];
            return;
        }
        const registration = this.registrations_by_id[call.registration_id];
        if (!registration) {
            this.logger.warn(`${session} ignore cancel call (registration not found) ${call.uri}`);
            delete this.invocations[call.invocation_id];
            delete this.calls[request_id];
            return;
        }

        const callee = this.sessions[registration.session_id];
        if (!callee) {
            this.logger.warn(`${session} ignore cancel call (callee not found) ${call.uri}`);
            return;
        }
        if (callee.details?.roles?.callee?.call_canceling || !meta.cancel_modes.includes(options.mode)) options.mode = 'skip';
        if (options.mode === 'skip' || options.mode === 'killnowait') {
            session.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.CALL_CANCELLED]);
            delete this.invocations[call.invocation_id];
            delete this.calls[request_id];
            this.logger.info(`${session} cancelled call ${call.uri}`);
        }
        if (options.mode === 'killnowait' || options.mode === 'kill') {
            callee.send([WAMP.INTERRUPT, invocation.invocation_id, {mode: options.mode}]);
            call.killed = true;
            this.logger.info(`${session} requested interrupt of call ${call.uri}`);
        }
    }

    call_result(session, invocation_id, options, args, kwargs) {
        const invocation = this.invocations[invocation_id];
        if (!invocation) {
            this.logger.warn(`${session} ignore yield (invocation not found) from procedure ${invocation.id}`);
            return;
        }
        const registration = this.registrations_by_id[invocation.registration_id];
        if (!registration || session.id !== registration.session_id) {
            delete this.invocations[invocation_id];
            delete this.calls[invocation.request_id];
            this.logger.warn(`${session} ignore yield (registration not found in session) from procedure ${invocation.id}`);
            return;
        }
        const caller = this.sessions[invocation.session_id];
        const details = {};
        if (options.progress) {
            if (!caller) session.send([WAMP.INTERRUPT, invocation_id, {mode: 'killnowait'}]);
            if (!invocation.options.receive_progress) {
                this.logger.warn(`${session} ignore progress yield (called without "receive_progress") from procedure ${invocation.id}`);
                return;
            }
            details.progress = true;
        }
        if (caller) caller.send([WAMP.RESULT, invocation.request_id, details, args, kwargs]);
        this.logger.info(`${session} yielded from procedure ${invocation.id}`);
        if (!details.progress || !caller) {
            delete this.invocations[invocation_id];
            delete this.calls[invocation.request_id];
            registration.counter--;
        }
    }

    call_error(session, invocation_id, details, error, args, kwargs) {
        const invocation = this.invocations[invocation_id];
        if (!invocation) {
            this.logger.warn(`${session} ignore error (invocation not found) from procedure ${invocation.id}`);
            return;
        }
        const registration = this.registrations_by_id[invocation.registration_id];
        if (!registration || session.id !== registration.session_id) {
            this.logger.warn(`${session} ignore error (registration not found) from procedure ${invocation.id}`);
            delete this.invocations[invocation_id];
            delete this.calls[invocation.request_id];
            return;
        }
        registration.counter--;
        const caller = this.sessions[invocation.session_id];
        if (caller) {
            if (error === errors.UNAVAILABLE && !invocation.killed) {
                invocation.unavailable.push(invocation.callee_id);
                const registration = this.match_registrations(invocation.uri, invocation.unavailable);
                if (!registration) {
                    caller.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, details, errors.CALLEE_UNAVAILABLE, args, kwargs]);
                    this.logger.info(`${session} call to procedure ${invocation.uri} failed due to unavailable callees`);
                }
                else {
                    const callee = this.sessions[registration.session_id];
                    if (callee) {
                        invocation.callee_id = registration.session_id;
                        invocation.registration_id = registration.id;
                        callee.send([WAMP.INVOCATION, invocation.invocation_id, registration.id, invocation.details, invocation.args, invocation.kwargs]);
                        this.logger.info(`${session} call to procedure ${invocation.uri} rerouted to callee ${callee} due to unavalability`);
                        return;
                    }
                }
            }
            caller.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, details, error, args, kwargs]);
        }
        delete this.invocations[invocation_id];
        delete this.calls[invocation.request_id];
        this.logger.info(`${session} returned error from procedure ${invocation.id}`);
    }

    create_subscription(session, request_id, options, uri) {
        if (!this.subscriptions_by_uri.hasOwnProperty(uri)) this.subscriptions_by_uri[uri] = {subscribers: [], subscriber_ids: {}};
        if (this.subscriptions_by_uri[uri].subscriber_ids[session.id]) {
            this.logger.warn(`${session} already subscribed to topic ${uri}. Sending same subscription ID`);
            return session.send([WAMP.SUBSCRIBED, request_id, this.subscriptions_by_uri[uri].subscriber_ids[session.id].id]);
        }
        const subscription = {session_id: session.id, request_id, uri, options, id: id()};
        this.subscriptions_by_uri[uri].subscriber_ids[session.id] = subscription;
        this.subscriptions_by_uri[uri].subscribers.push(subscription);
        this.subscriptions_by_id[subscription.id] = subscription;
        session.send([WAMP.SUBSCRIBED, request_id, subscription.id]);
        if (this.subscriptions_by_uri[uri].subscribers.length === 1) {
            this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_create', [session.id, {
                id: subscription.id,
                created: new Date().toISOString(),
                uri,
                match: options.match
            }]);
        }
        this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_subscribe', [session.id, subscription.id]);
        this.logger.info(`${session} subscribed to topic ${uri}`);
    }

    remove_subscription(session, request_id, subscription_id) {
        const subscription = this.subscriptions_by_id[subscription_id];
        if (!subscription || subscription.session_id !== session.id) {
            this.logger.error(`${session} cannot unsubscribe (subscription not found) ${subscription.uri}`);
            return session.send([WAMP.ERROR, WAMP.UNSUBSCRIBE, request_id, {}, errors.NO_SUCH_SUBSCRIPTION]);
        }
        session.send([WAMP.UNSUBSCRIBED, request_id]);
        delete this.subscriptions_by_id[subscription_id];
        this.subscriptions_by_uri[subscription.uri].subscribers = this.subscriptions_by_uri[subscription.uri].subscribers.filter(subscription => subscription.session_id !== session.id);
        delete this.subscriptions_by_uri[subscription.uri].subscriber_ids[session.id];
        this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_unsubscribe', [session.id, subscription.id]);
        this.logger.info(`${session} unsubscribed from topic ${subscription.id}`);

        if (!this.subscriptions_by_uri[subscription.uri].subscribers.length) {
            delete this.subscriptions_by_uri[subscription.uri];
            this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_delete', [session.id, subscription.id]);
            this.logger.info(`Subscription ${subscription.id} removed as there are no further subscribers`);
        }
    }

    publish(session, request_id, options, uri, args, kwargs) {
        if (meta.events.includes(uri) && session !== this.fake_session) {
            this.logger.error(`${session} not authorized to publish in meta topic ${uri}`);
            session.send([WAMP.ERROR, WAMP.PUBLISH, request_id, {}, errors.NOT_AUTHORIZED]);
            return;
        }
        const publication_id = id();
        const subscribers = (this.subscriptions_by_uri[uri]?.subscribers || []);

        for (const subscription_id in this.subscriptions_by_id) {
            if (this.subscriptions_by_id.hasOwnProperty(subscription_id)) {
                const subscription = this.subscriptions_by_id[subscription_id];
                if (subscription.options?.match === 'prefix' && uri.startsWith(subscription.uri) && !subscribers.includes(subscription)) subscribers.push(subscription);
                if (subscription.options?.match === 'wildcard' && wildcard.match(uri, subscription.uri) && !subscribers.includes(subscription)) subscribers.push(subscription);
            }
        }
        subscribers.forEach(subscription => {
            if (subscription.session_id === session.id && options.exclude_me !== false) return;
            if (options.exclude?.includes?.(subscription.session_id)) return;
            if (options.exclude_authid?.includes?.(this.sessions[subscription.session_id].details.authid)) return;
            if (options.exclude_authrole?.includes?.(this.sessions[subscription.session_id].details.authrole)) return;
            if (options.eligible?.length && !options.eligible.includes(subscription.session_id)) return;
            if (options.eligible_authid?.length && !options.eligible_authid?.includes(this.sessions[subscription.session_id].details.authid)) return;
            if (options.eligible_authrole?.length && !options.eligible_authrole?.includes(this.sessions[subscription.session_id].details.authrole)) return;
            const details = {topic: uri};
            if (options.disclose_me) details.publisher = session.id;
            if (subscription.options.disclose_publisher) details.publisher = session.id;
            const subscriber = this.sessions[subscription.session_id];
            if (subscriber) subscriber.send([WAMP.EVENT, subscription.id, publication_id, details, args, kwargs]);
        });
        if (options.acknowledge) session.send([WAMP.PUBLISHED, request_id, publication_id]);
        this.logger.info(`${session} published to topic ${uri}`);
    }

    registration_uri(id) {
        if (this.registrations_by_id[id]) return this.registrations_by_id[id].uri;
    }

    invocation_uri(id) {
        if (this.invocations[id] && this.invocations[id].uri) return this.invocations[id].uri;
    }

    call_uri(id) {
        if (this.calls[id] && this.calls[id].uri) return this.calls[id].uri;
    }

    subscription_uri(id) {
        if (this.subscriptions_by_id[id]) return this.subscriptions_by_id[id].uri;
    }

    add_session(session) {
        if (this.sessions[session.id]) {
            this.logger.error(`${session} tried to join realm ${this.name} but it's already a member`);
            session.close(WAMP.ABORT, errors.PROTOCOL_VIOLATION);
            return;
        }
        session.realm = this;
        this.publish(this.fake_session, id(), {}, 'wamp.session.on_join', [{
            session: session.id,
            authid: session.details.authid,
            authrole: session.details.authrole,
            authmethod: session.details.authmethod,
            authprovider: session.details.authprovider,
            transport: 'ws'
        }]);
        this.sessions[session.id] = session;
        this.logger.info(`${session} joined realm ${this.name}`);
        return {
            realm: this.name,
            roles: {
                broker: {
                    features: {
                        publisher_exclusion: true,
                        publisher_identification: true,
                        pattern_based_subscription: true,
                        subscriber_blackwhite_listing: true,
                        //subscription_meta_api: true,
                        //session_meta_api: true
                    }
                },
                dealer: {
                    features: {
                        progressive_call_results: true,
                        call_canceling: true,
                        caller_identification: true,
                        shared_registration: true,
                        pattern_based_registration: true,
                        call_reroute: true,
                        //registration_meta_api: true,
                        //session_meta_api: true
                    }
                }
            }
        };
    }

    remove_session(session) {
        if (this.sessions.hasOwnProperty(session.id)) {
            delete this.sessions[session.id];
            for (const uri in this.registrations_by_uri) {
                if (this.registrations_by_uri.hasOwnProperty(uri)) {
                    this.registrations_by_uri[uri].callees = this.registrations_by_uri[uri].callees.filter(registration => registration.session_id !== session.id);
                    delete this.registrations_by_uri[uri].callee_ids[session.id];
                    if (!this.registrations_by_uri[uri].callees.length) delete this.registrations_by_uri[uri];
                }
            }
            for (const id in this.registrations_by_id) {
                if (this.registrations_by_id.hasOwnProperty(id) && this.registrations_by_id[id].session_id === session.id) delete this.registrations_by_id[id];
            }
            for (const id in this.invocations) {
                if (this.invocations.hasOwnProperty(id)) {
                    if (this.invocations[id].callee_id === session.id) {
                        this.sessions[this.invocations[id].session_id]?.send([WAMP.ERROR, WAMP.CALL, this.invocations[id].request_id, {}, errors.NO_SUCH_PROCEDURE]);
                    }
                    if (this.invocations[id].session_id === session.id) delete this.invocations[id];
                }
            }
            for (const id in this.calls) {
                if (this.calls.hasOwnProperty(id) && this.calls[id].session_id === session.id) delete this.calls[id];
            }
            for (const uri in this.subscriptions_by_uri) {
                if (this.subscriptions_by_uri.hasOwnProperty(uri)) {
                    this.subscriptions_by_uri[uri].subscribers = this.subscriptions_by_uri[uri].subscribers.filter(subscription => subscription.session_id !== session.id);
                    delete this.subscriptions_by_uri[uri].subscriber_ids[session.id];
                    if (!this.subscriptions_by_uri[uri].subscribers.length) delete this.subscriptions_by_uri[uri];
                }
            }
            for (const id in this.subscriptions_by_id) {
                if (this.subscriptions_by_id.hasOwnProperty(id) && this.subscriptions_by_id[id].session_id === session.id) delete this.subscriptions_by_id[id];
            }
            session.realm = null;
            this.publish(this.fake_session, id(), {}, 'wamp.session.on_leave', [{
                session: session.id,
                authid: session.details.authid,
                authrole: session.details.authrole
            }]);
            this.logger.warn(`${session} left realm ${this.name}`);
        }
    }
}

exports.Realm = Realm;

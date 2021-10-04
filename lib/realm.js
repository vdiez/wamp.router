'use strict';

const id = require('./id');
const WAMP = require('./protocol');
const errors = require('./errors');
const meta = require('./meta');
const wildcard = require('./wildcard');

const match_functions = {
    prefix: (uri, prefix) => uri.startsWith(prefix),
    wildcard: (uri, wildcard) => wildcard.match(uri, wildcard)
};

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

        const registration_id = id();
        const now = new Date().toISOString();
        const registration = this.registrations_by_uri[uri] || {callees: [], callee_ids: {}, round_robin: 0, id: registration_id, uri, options, created: now};

        if (registration.callee_ids[session.id]) {
            this.logger.error(`${session} already registered procedure ${uri}`);
            return session.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
        }
        if (!options.invoke || !meta.allowed_invokes.includes(options.invoke)) options.invoke = 'single';
        if (!options.match || !meta.allowed_match.includes(options.match)) options.match = 'exact';

        if (registration.callees.length) {
            if (registration.options.invoke === 'single') {
                this.logger.error(`${session} cannot register new instance of single procedure ${uri}`);
                return session.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_ALREADY_EXISTS]);
            }
            if (options.invoke !== registration.options.invoke) {
                this.logger.error(`${session} cannot register new instance with different invoke policy of procedure ${uri}`);
                return session.send([WAMP.ERROR, WAMP.REGISTER, request_id, {}, errors.PROCEDURE_EXISTS_INVOCATION_POLICY_CONFLICT]);
            }
        }

        if (!this.registrations_by_uri[uri]) {
            this.registrations_by_uri[uri] = registration;
            this.registrations_by_id[registration.id] = registration;
            this.publish(this.fake_session, id(), {}, 'wamp.registration.on_create', [session.id, {
                id: registration.id,
                created: registration.created,
                uri,
                match: options.match,
                invoke: registration.invoke
            }]);
        }

        const callee = {session_id: session.id, created: now, request_id, options, counter: 0, registration_id};
        registration.callee_ids[session.id] = callee;
        registration.callees.push(callee);
        session.send([WAMP.REGISTERED, request_id, registration.id]);
        this.publish(this.fake_session, id(), {}, 'wamp.registration.on_register', [session.id, registration.id]);
        this.logger.info(`${session} registered new instance of procedure ${uri}. Policy: ${options.invoke}`);
    }

    remove_registration(session, request_id, registration_id) {
        const registration = this.registrations_by_id[registration_id];
        if (!registration || !registration.callee_ids.hasOwnProperty(session.id)) {
            this.logger.error(`${session} cannot unregister (registration not found in its session) ${registration.uri}`);
            session.send([WAMP.ERROR, WAMP.UNREGISTER, request_id, {}, errors.NO_SUCH_REGISTRATION]);
            return;
        }
        session.send([WAMP.UNREGISTERED, request_id]);
        delete registration.callee_ids[session.id];
        registration.callees = registration.callees.filter(registration => registration.session_id !== session.id);
        this.publish(this.fake_session, id(), {}, 'wamp.registration.on_unregister', [session.id, registration.id]);
        this.logger.info(`${session} unregistered instance of procedure ${registration.uri}`);
        if (!registration.callees.length) {
            delete this.registrations_by_uri[registration.uri];
            delete this.registrations_by_id[registration_id];
            this.publish(this.fake_session, id(), {}, 'wamp.registration.on_delete', [session.id, registration.id]);
            this.logger.info(`Procedure ${registration.uri} removed as there are no further callees`);
        }
    }

    match_registrations(uri, forbidden = [], try_all_matching_policies = true, match = 'exact', only_registration = false) {
        let registration;

        if (match === 'exact') registration = this.registrations_by_uri[uri];
        else {
            const matches = [];
            for (const registered_uri in this.registrations_by_uri) {
                if (this.registrations_by_uri.hasOwnProperty(registered_uri) && match_functions[match](uri, registered_uri)) {
                    for (let i = 0; i < this.registrations_by_uri[registered_uri].callees.length; i++) {
                        const callee = this.registrations_by_uri[registered_uri].callees[i];
                        if (!forbidden?.includes(callee.session_id) && callee.options?.match === match) {
                            matches.push(this.registrations_by_uri[registered_uri]);
                            break;
                        }
                    }
                }
            }
            if (matches.length) registration = matches.reduce((best, registration) => {
                if (!best) return registration;
                if (match === 'prefix' && registration.uri.length > best.uri.length) return registration;
                if (match === 'wildcard' && wildcard.weight(registration.uri, best.uri) > 0) return registration;
                return best;
            }, null);
        }

        if (registration && only_registration) return registration;

        let callees = (registration?.callees || []).filter(registration => registration.options.match === match);
        if (forbidden?.length) callees = callees.filter(registration => !forbidden.includes(registration.session_id));

        if (callees.length) {
            if (registration.invoke === 'single' || registration.invoke === 'first') return callees[0];
            if (registration.invoke === 'last') return callees[callees.length - 1];
            if (registration.invoke === 'roundrobin') {
                for (let i = 0; i < registration.callees.length; i++) {
                    if (registration.round_robin >= registration.callees.length) registration.round_robin = 0;
                    const callee = registration.callees[registration.round_robin++];
                    if (!forbidden.includes(callee.session_id)) return callee;
                }
            }
            if (registration.invoke === 'random') return callees[Math.floor(Math.random() * callees.length)];
            if (registration.invoke === 'load') return callees.reduce((min, callee) => (!min || callee.counter < min.counter) ? callee : min, null);
        }
        if (try_all_matching_policies) {
            if (match === 'exact') return this.match_registrations(uri, forbidden, true, 'prefix');
            if (match === 'prefix') return this.match_registrations(uri, forbidden, true, 'wildcard');
        }
    }

    call_registration(session, request_id, options, uri, args, kwargs) {
        const callee = this.match_registrations(uri);
        if (!callee) {
            this.logger.error(`${session} failed call (callee not found) ${uri}`);
            session.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
            return;
        }
        const details = {procedure: uri};
        if (options.receive_progress) details.receive_progress = true;
        if (options.disclose_me || callee.options.disclose_caller) details.caller = session.id;
        this.logger.info(`${session} called ${uri}`);
        if (callee.session_id === this.fake_session.id && meta.registrations.hasOwnProperty(uri)) {
            const result = meta.registrations[uri].call(this, args, kwargs, details, session);
            if (result.error) session.send([WAMP.ERROR, WAMP.CALL, request_id, result.details, result.error, result.args, result.kwargs]);
            else session.send([WAMP.RESULT, request_id, {}, result.args, result.kwargs]);
            this.logger.info(`${session} yielded from meta procedure ${uri}`);
        }
        else {
            const callee_session = this.sessions[callee.session_id];
            if (!callee_session) {
                this.logger.error(`${session} failed call (callee session not found) ${uri}`);
                session.send([WAMP.ERROR, WAMP.CALL, request_id, {}, errors.NO_SUCH_PROCEDURE]);
                return;
            }
            callee.counter++;
            const invocation = {session_id: session.id, request_id, callee_id: callee.session_id, registration_id: callee.registration_id, uri, options, unavailable: [], details, args, kwargs, invocation_id: id()};
            this.invocations[invocation.invocation_id] = invocation;
            this.calls[request_id] = invocation;
            if (callee_session) callee_session.send([WAMP.INVOCATION, invocation.invocation_id, callee.registration_id, details, args, kwargs]);
            this.logger.info(`${session} called procedure ${uri} on callee ${callee_session}`);
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
        const callee = this.sessions[invocation.callee_id];
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
        if (!registration?.callee_ids?.hasOwnProperty(session.id) || invocation.callee_id !== session.id) {
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
            registration.callee_ids[invocation.callee_id].counter--;
        }
    }

    call_error(session, invocation_id, details, error, args, kwargs) {
        const invocation = this.invocations[invocation_id];
        if (!invocation) {
            this.logger.warn(`${session} ignore error (invocation not found) from procedure ${invocation.id}`);
            return;
        }
        const registration = this.registrations_by_id[invocation.registration_id];
        if (!registration?.callee_ids?.hasOwnProperty(session.id) || invocation.callee_id !== session.id) {
            this.logger.warn(`${session} ignore error (registration not found) from procedure ${invocation.id}`);
            delete this.invocations[invocation_id];
            delete this.calls[invocation.request_id];
            return;
        }
        registration.callee_ids[invocation.callee_id].counter--;
        const caller = this.sessions[invocation.session_id];
        if (caller) {
            if (error === errors.UNAVAILABLE && !invocation.killed) {
                invocation.unavailable.push(invocation.callee_id);
                const callee = this.match_registrations(invocation.uri, invocation.unavailable);
                if (!callee) {
                    caller.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, details, errors.CALLEE_UNAVAILABLE, args, kwargs]);
                    this.logger.info(`${session} call to procedure ${invocation.uri} failed due to unavailable callees`);
                }
                else {
                    const callee_session = this.sessions[callee.session_id];
                    if (callee_session) {
                        invocation.callee_id = callee.session_id;
                        callee.send([WAMP.INVOCATION, invocation.invocation_id, registration.id, invocation.details, invocation.args, invocation.kwargs]);
                        this.logger.info(`${session} call to procedure ${invocation.uri} rerouted to callee ${callee} due to unavalability`);
                        return;
                    }
                }
            }
            else caller.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, details, error, args, kwargs]);
        }
        delete this.invocations[invocation_id];
        delete this.calls[invocation.request_id];
        this.logger.info(`${session} returned error from procedure ${invocation.id}`);
    }

    create_subscription(session, request_id, options, uri) {
        const subscription_id = id();
        const now = new Date().toISOString();

        const subscription = this.subscriptions_by_uri[uri] || {subscribers: [], subscriber_ids: {}, id: subscription_id, uri, options, created: now};
        if (subscription.subscriber_ids[session.id]) {
            this.logger.warn(`${session} already subscribed to topic ${uri}. Sending same subscription ID`);
            return session.send([WAMP.SUBSCRIBED, request_id, subscription.subscriber_ids[session.id].id]);
        }
        if (!this.subscriptions_by_uri.hasOwnProperty(uri)) {
            this.subscriptions_by_uri[uri] = subscription;
            this.subscriptions_by_id[subscription.id] = subscription;
            this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_create', [session.id, {
                id: subscription.id,
                created: now,
                uri,
                match: options.match
            }]);
        }
        const subscriber = {session_id: session.id, created: now, request_id, uri, options, subscription_id};
        subscription.subscriber_ids[session.id] = subscriber;
        subscription.subscribers.push(subscriber);
        session.send([WAMP.SUBSCRIBED, request_id, subscription.id]);
        this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_subscribe', [session.id, subscription.id]);
        this.logger.info(`${session} subscribed to topic ${uri}`);
    }

    remove_subscription(session, request_id, subscription_id) {
        const subscription = this.subscriptions_by_id[subscription_id];
        if (!subscription || !subscription.subscriber_ids.hasOwnProperty(session.id)) {
            this.logger.error(`${session} cannot unsubscribe (subscription not found) ${subscription.uri}`);
            return session.send([WAMP.ERROR, WAMP.UNSUBSCRIBE, request_id, {}, errors.NO_SUCH_SUBSCRIPTION]);
        }
        session.send([WAMP.UNSUBSCRIBED, request_id]);
        delete subscription.subscriber_ids[session.id];
        subscription.subscribers = subscription.subscribers.filter(subscription => subscription.session_id !== session.id);
        this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_unsubscribe', [session.id, subscription.id]);
        this.logger.info(`${session} unsubscribed from topic ${subscription.uri}`);
        if (!subscription.subscribers.length) {
            delete this.subscriptions_by_uri[subscription.uri];
            delete this.subscriptions_by_id[subscription_id];
            this.publish(this.fake_session, id(), {}, 'wamp.subscription.on_delete', [session.id, subscription.id]);
            this.logger.info(`Subscription ${subscription.uri} removed as there are no further subscribers`);
        }
    }

    match_subscriptions(uri, try_all_matching_policies = true, match = 'exact', result = [], only_subscriptions = false) {
        let subscription;

        if (match === 'exact') {
            subscription = this.subscriptions_by_uri[uri];
            if (subscription) {
                if (only_subscriptions) result.push(subscription);
                else {
                    for (let i = 0; i < subscription.subscribers.length; i++) {
                        if (subscription.subscribers[i].options.match === match) {
                            result.push(subscription.subscribers[i]);
                        }
                    }
                }
            }
        }
        else {
            for (const registered_uri in this.subscriptions_by_uri) {
                if (this.subscriptions_by_uri.hasOwnProperty(registered_uri) && match_functions[match](uri, registered_uri)) {
                    if (only_subscriptions) {
                        result.push(this.subscriptions_by_uri[registered_uri]);
                    }
                    else {
                        for (let i = 0; i < this.subscriptions_by_uri[registered_uri].subscribers.length; i++) {
                            if (this.subscriptions_by_uri[registered_uri].subscribers[i].options.match === match) {
                                result.push(this.subscriptions_by_uri[registered_uri].subscribers[i]);
                            }
                        }
                    }
                }
            }
        }
        if (try_all_matching_policies) {
            if (match === 'exact') return this.match_subscriptions(uri, true, 'prefix', result, only_subscriptions);
            if (match === 'prefix') return this.match_subscriptions(uri, true, 'wildcard', result, only_subscriptions);
        }
        return result;
    }

    publish(session, request_id, options, uri, args, kwargs) {
        if (meta.events.includes(uri) && session !== this.fake_session) {
            this.logger.error(`${session} not authorized to publish in meta topic ${uri}`);
            session.send([WAMP.ERROR, WAMP.PUBLISH, request_id, {}, errors.NOT_AUTHORIZED]);
            return;
        }
        const publication_id = id();
        const subscribers = this.match_subscriptions(uri);

        subscribers.forEach(subscription => {
            const subscriber = this.sessions[subscription.session_id];
            if (subscriber) return;
            if (subscription.session_id === session.id && options.exclude_me !== false) return;
            if (options.exclude?.includes?.(subscription.session_id)) return;
            if (options.exclude_authid?.includes?.(subscriber.details.authid)) return;
            if (options.exclude_authrole?.includes?.(subscriber.details.authrole)) return;
            if (options.eligible?.length && !options.eligible.includes(subscription.session_id)) return;
            if (options.eligible_authid?.length && !options.eligible_authid?.includes(subscriber.details.authid)) return;
            if (options.eligible_authrole?.length && !options.eligible_authrole?.includes(subscriber.details.authrole)) return;
            const details = {topic: uri};
            if (options.disclose_me) details.publisher = session.id;
            if (subscription.options.disclose_publisher) details.publisher = session.id;
            subscriber.send([WAMP.EVENT, subscription.id, publication_id, details, args, kwargs]);
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
                        subscription_meta_api: true,
                        session_meta_api: true
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
                        registration_meta_api: true,
                        session_meta_api: true
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
                    const registration = this.registrations_by_uri[uri];
                    registration.callees = registration.callees.filter(registration => registration.session_id !== session.id);
                    delete registration.callee_ids[session.id];
                    if (!registration.callees.length) {
                        delete this.registrations_by_uri[uri];
                        delete this.registrations_by_id[registration.id];
                    }
                }
            }
            for (const id in this.invocations) {
                if (this.invocations.hasOwnProperty(id)) {
                    const invocation = this.invocations[id];
                    if (invocation.callee_id === session.id) {
                        this.sessions[invocation.session_id]?.send([WAMP.ERROR, WAMP.CALL, invocation.request_id, {}, errors.NO_SUCH_PROCEDURE]);
                        delete this.invocations[id];
                        delete this.calls[invocation.request_id];
                    }
                    if (invocation.session_id === session.id) {
                        delete this.invocations[id];
                        delete this.calls[invocation.request_id];
                    }
                }
            }
            for (const uri in this.subscriptions_by_uri) {
                if (this.subscriptions_by_uri.hasOwnProperty(uri)) {
                    const subscription = this.subscriptions_by_uri[uri];
                    subscription.subscribers = subscription.subscribers.filter(subscription => subscription.session_id !== session.id);
                    delete subscription.subscriber_ids[session.id];
                    if (!subscription.subscribers.length) {
                        delete this.subscriptions_by_uri[uri];
                        delete this.subscriptions_by_id[subscription.id];
                    }
                }
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

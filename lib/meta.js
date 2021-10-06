'use strict';

const errors = require('./errors');
const WAMP = require('./protocol');

//strict URI check allowing empty URI components
//const valid_uri = /^(([0-9a-z_]+\.)|\.)*([0-9a-z_]+)?$/;
//strict URI check disallowing empty URI components
const valid_uri_no_empty = /^([0-9a-z_]+\.)*([0-9a-z_]+)$/;

const allowed_match = ['exact', 'prefix', 'wildcard'];

module.exports.cancel_modes = ['skip', 'kill', 'killnowait'];

module.exports.allowed_invokes = ['single', 'roundrobin', 'random', 'first', 'last', 'load'];

module.exports.allowed_match = allowed_match;

module.exports.roles = {
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
};

module.exports.events = [
    'wamp.registration.on_create',
    'wamp.registration.on_register',
    'wamp.registration.on_unregister',
    'wamp.registration.on_delete',
    'wamp.subscription.on_create',
    'wamp.subscription.on_subscribe',
    'wamp.subscription.on_unsubscribe',
    'wamp.subscription.on_delete',
    'wamp.session.on_join',
    'wamp.session.on_leave'
];

module.exports.registrations = {
    'wamp.registration.list'() {
        const args = {};
        module.exports.allowed_match.forEach(match => {args[match] = [];});
        for (const registration_id in this.registrations_by_id) {
            if (this.registrations_by_id.hasOwnProperty(registration_id)) {
                const registration = this.registrations_by_id[registration_id];
                args[registration.options?.match || 'exact'].push(registration);
            }
        }
        return {args: [args]};
    },
    'wamp.registration.lookup'([uri] = [], {match = 'exact'} = {}) {
        if (!uri) return {args: [null]};
        if (!match || !allowed_match.includes(match)) match = 'exact';
        const registration = this.match_registrations(uri, [], false, match, true);
        return {args: [registration?.id || null]};
    },
    'wamp.registration.match'([uri] = []) {
        if (!uri) return {args: [null]};
        const registration = this.match_registrations(uri, [], true, 'exact', true);
        return {args: [registration.id || null]};
    },
    'wamp.registration.get'([id] = []) {
        if (!id) return {error: errors.NO_SUCH_REGISTRATION};
        const registration = this.registrations_by_id[id];
        if (!registration) return {error: errors.NO_SUCH_REGISTRATION};

        return {
            args: [{
                id: registration.id,
                created: registration.created,
                uri: registration.uri,
                match: registration.options.match,
                invoke: registration.options.invoke
            }]
        };
    },
    'wamp.registration.list_callees'([id] = []) {
        if (!id || !this.registrations_by_id[id]) return {error: errors.NO_SUCH_REGISTRATION};
        return {args: [this.registrations_by_id[id].callees?.map(callee => callee.id)]};
    },
    'wamp.registration.count_callees'([id] = []) {
        if (!id || !this.registrations_by_id[id]) return {error: errors.NO_SUCH_REGISTRATION};
        return {args: [this.registrations_by_id[id].callees?.length || 0]};
    },
    'wamp.subscription.list'() {
        const args = {};
        module.exports.allowed_match.forEach(match => {args[match] = [];});
        for (const subscription_id in this.subscriptions_by_id) {
            if (this.subscriptions_by_id.hasOwnProperty(subscription_id)) {
                const subscription = this.subscriptions_by_id[subscription_id];
                args[subscription.options?.match || 'exact'].push(subscription);
            }
        }
        return {args: [args]};
    },
    'wamp.subscription.lookup'([uri] = [], {match = 'exact'} = {}) {
        if (!uri) return {args: [null]};
        if (!match || !allowed_match.includes(match)) match = 'exact';
        const subscription = this.match_subscriptions(uri, false, match, [], true);
        return {args: [subscription?.id || null]};
    },
    'wamp.subscription.match'([uri] = []) {
        if (!uri) return {args: [null]};
        const subscriptions = this.match_subscriptions(uri, true, 'exact', [], true);
        return {args: [subscriptions?.map(subscription => subscription.id) || null]};
    },
    'wamp.subscription.get'([id] = []) {
        if (!id) return {error: errors.NO_SUCH_SUBSCRIPTION};
        const subscription = this.subscriptions_by_id[id];
        if (!subscription) return {error: errors.NO_SUCH_SUBSCRIPTION};

        return {
            args: [{
                id: subscription.id,
                created: subscription.created,
                uri: subscription.uri,
                match: subscription.options.match
            }]
        };
    },
    'wamp.subscription.list_subscribers'([id] = []) {
        if (!id || !this.subscriptions_by_id[id]) return {error: errors.NO_SUCH_SUBSCRIPTION};
        return {args: [this.subscriptions_by_id[id].subscribers?.map(subscriber => subscriber.id)]};
    },
    'wamp.subscription.count_subscribers'([id] = []) {
        if (!id || !this.subscriptions_by_id[id]) return {error: errors.NO_SUCH_SUBSCRIPTION};
        return {args: [this.subscriptions_by_id[id].subscribers?.length || 0]};
    },
    'wamp.session.count'([filter_authroles = []] = []) {
        let counter = 0;
        for (const session_id in this.sessions) {
            if (this.sessions.hasOwnProperty(session_id)) {
                if (filter_authroles?.length) {
                    if (filter_authroles.includes(this.sessions[session_id].details?.authrole)) counter++;
                }
                else counter++;
            }
        }
        return {args: [counter]};
    },
    'wamp.session.list'([filter_authroles = []] = []) {
        const list = [];
        for (const session_id in this.sessions) {
            if (this.sessions.hasOwnProperty(session_id)) {
                if (filter_authroles?.length) {
                    if (filter_authroles.includes(this.sessions[session_id].details?.authrole)) list.push(session_id);
                }
                else list.push(session_id);
            }
        }
        return {args: [list]};
    },
    'wamp.session.get'([id] = []) {
        if (!id) return {error: errors.NO_SUCH_SESSION};
        const session = this.sessions[id];
        if (session) {
            return {
                args: [{
                    session: session.id,
                    authid: session.details.authid,
                    authrole: session.details.authrole,
                    authmethod: session.details.authmethod,
                    authprovider: session.details.authprovider,
                    transport: 'ws'
                }]
            };
        }
        return {error: errors.NO_SUCH_SESSION};
    },
    'wamp.session.kill'([id] = [], {reason = 'wamp.close.normal', message} = {}, details, caller) {
        if (!id) return {error: errors.NO_SUCH_SESSION};
        if (reason && !reason.match(valid_uri_no_empty)) return {error: errors.INVALID_URI};
        const session = this.sessions[id];
        if (session && caller.id !== session.id) {
            session.close(WAMP.GOODBYE, reason, {message});
        }
        return {error: errors.NO_SUCH_SESSION};
    },
    'wamp.session.kill_by_authid'([authid] = [], {reason = 'wamp.close.normal', message} = {}, details, caller) {
        if (reason && !reason.match(valid_uri_no_empty)) return {error: errors.INVALID_URI};
        let counter = 0;
        for (const session_id in this.sessions) {
            if (this.sessions.hasOwnProperty(session_id)) {
                const session = this.sessions[session_id];
                if (session.details?.authid === authid && caller.id !== session.id) {
                    session.close(WAMP.GOODBYE, reason, {message});
                    counter++;
                }
            }
        }
        return {args: [counter]};
    },
    'wamp.session.kill_by_authrole'([authrole] = [], {reason = 'wamp.close.normal', message} = {}, details, caller) {
        if (reason && !reason.match(valid_uri_no_empty)) return {error: errors.INVALID_URI};
        let counter = 0;
        for (const session_id in this.sessions) {
            if (this.sessions.hasOwnProperty(session_id)) {
                const session = this.sessions[session_id];
                if (session.details?.authrole === authrole && caller.id !== session.id) {
                    session.close(WAMP.GOODBYE, reason, {message});
                    counter++;
                }
            }
        }
        return {args: [counter]};
    },
    'wamp.session.kill_all'(args, {reason = 'wamp.close.normal', message} = {}, details, caller) {
        if (reason && !reason.match(valid_uri_no_empty)) return {error: errors.INVALID_URI};
        let counter = 0;
        for (const session_id in this.sessions) {
            if (this.sessions.hasOwnProperty(session_id)) {
                const session = this.sessions[session_id];
                if (caller.id !== session.id) {
                    session.close(WAMP.GOODBYE, reason, {message});
                    counter++;
                }
            }
        }
        return {args: [counter]};
    }
};

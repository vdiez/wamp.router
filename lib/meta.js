'use strict';

const errors = require('./errors');
const wildcard = require('./wildcard');
const id = require("./id");

const allowed_match = ['exact', 'prefix', 'wildcard'];

module.exports.cancel_modes = ['skip', 'kill', 'killnowait'];

module.exports.allowed_invokes = ['single', 'roundrobin', 'random', 'first', 'last', 'load'];


module.exports.allowed_match = allowed_match;

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
        return [args];
    },
    'wamp.registration.lookup'([uri], {match = 'exact'}) {
        if (!match || !allowed_match.includes(match)) match = 'exact';
        const registration = this.match_registrations(uri, [], match);
        return [registration?.id || null];
    },
    'wamp.registration.match'([uri]) {
        const registration = this.match_registrations(uri);
        return [registration || null];
    },
    'wamp.registration.get'([id]) {
        const registration = this.registrations_by_id[id];
        if (!registration) return {error: errors.NO_SUCH_REGISTRATION};

        return {
            id: registration.id,
            created: registration.created,
            uri: registration.uri,
            match: registration.options.match,
            invoke: registration.options.invoke
        };
    },
    'wamp.registration.list_callees'([id]) {
        const registration = this.registrations_by_id[id];
        if (!registration) return {error: errors.NO_SUCH_REGISTRATION};
        return [[registration.session_id]];
    },
    'wamp.registration.count_callees'() {
        const registration = this.registrations_by_id[id];
        if (!registration) return {error: errors.NO_SUCH_REGISTRATION};
        return [1];
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
        return [args];
    },
    'wamp.subscription.lookup'([uri], {match = 'exact'}) {
        const subscribers = (this.subscriptions_by_uri[uri]?.subscribers || []);

        for (const subscription_id in this.subscriptions_by_id) {
            if (this.subscriptions_by_id.hasOwnProperty(subscription_id)) {
                const subscription = this.subscriptions_by_id[subscription_id];
                if (subscription.options?.match === 'prefix' && uri.startsWith(subscription.uri) && !subscribers.includes(subscription)) subscribers.push(subscription);
                if (subscription.options?.match === 'wildcard' && wildcard.match(uri, subscription.uri) && !subscribers.includes(subscription)) subscribers.push(subscription);
            }
        }
    },
    'wamp.subscription.match'(details, args, kwargs) {},
    'wamp.subscription.get'(details, args, kwargs) {},
    'wamp.subscription.list_subscribers'(details, args, kwargs) {},
    'wamp.subscription.count_subscribers'(details, args, kwargs) {},
    'wamp.session.count'(details, args, kwargs) {},
    'wamp.session.list'(details, args, kwargs) {},
    'wamp.session.get'(details, args, kwargs) {},
    'wamp.session.kill'(details, args, kwargs) {},
    'wamp.session.kill_by_authid'(details, args, kwargs) {},
    'wamp.session.kill_by_authrole'(details, args, kwargs) {},
    'wamp.session.kill_all'(details, args, kwargs) {}
};

'use strict';

module.exports.cancel_modes = ['skip', 'kill', 'killnowait'];

module.exports.allowed_invokes = ['single', 'roundrobin', 'random', 'first', 'last', 'load'];

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
    'wamp.registration.list'() {},
    'wamp.registration.lookup'() {},
    'wamp.registration.match'() {},
    'wamp.registration.get'() {},
    'wamp.registration.list_execs'() {},
    'wamp.registration.count_execs'() {},
    'wamp.subscription.list'() {},
    'wamp.subscription.lookup'() {},
    'wamp.subscription.match'() {},
    'wamp.subscription.get'() {},
    'wamp.subscription.list_subscribers'() {},
    'wamp.subscription.count_subscribers'() {},
    'wamp.session.count'() {},
    'wamp.session.list'() {},
    'wamp.session.get'() {},
    'wamp.session.kill'() {},
    'wamp.session.kill_by_authid'() {},
    'wamp.session.kill_by_authrole'() {},
    'wamp.session.kill_all'() {}
};

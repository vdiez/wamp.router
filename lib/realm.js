'use strict';

class Realm {
    constructor(router, name) {
        this.name = name;
        this.sessions = {};
        this.invocations = {};
        this.calls = {};
        this.registrations_by_id = {};
        this.registrations_by_uri = {};
        this.subscriptions_by_id = {};
        this.subscriptions_by_uri = {};
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

    get_session(id) {
        return this.sessions[id];
    }

    join_session(session) {
        session.set_realm(this);
        this.sessions[session.id] = session;
        return {
            realm: this.name,
            roles: {
                broker: {
                    features: {
                        publisher_exclusion: true,
                        publisher_identification: true
                    }
                },
                dealer: {
                    features: {
                        progressive_call_results: true,
                        call_canceling: true,
                        caller_identification: true,
                        shared_registration: true
                    }
                }
            }
        }
    }

    remove_session(session) {
        if (this.sessions.hasOwnProperty(session.id)) {
            delete this.sessions[session.id];
            for (let uri in this.registrations_by_uri) {
                if (this.registrations_by_uri.hasOwnProperty(uri)) {
                    this.registrations_by_uri[uri].callees = this.registrations_by_uri[uri].callees.filter(registration => registration.session_id !== session.id);
                    delete this.registrations_by_uri[uri].callee_ids[session.id];
                }
            }
            for (let id in this.registrations_by_id) {
                if (this.registrations_by_id.hasOwnProperty(id) && this.registrations_by_id[id].session_id === session.id) delete this.registrations_by_id[id];
            }
            for (let id in this.invocations) {
                if (this.invocations.hasOwnProperty(id) && this.invocations[id].session_id === session.id) delete this.invocations[id];
            }
            for (let id in this.calls) {
                if (this.calls.hasOwnProperty(id) && this.calls[id].session_id === session.id) delete this.calls[id];
            }
            for (let uri in this.subscriptions_by_uri) {
                if (this.subscriptions_by_uri.hasOwnProperty(uri)) {
                    this.subscriptions_by_uri[uri] = this.subscriptions_by_uri[uri].filter(subscription => subscription.session_id !== session.id);
                }
            }
            for (let id in this.subscriptions_by_id) {
                if (this.subscriptions_by_id.hasOwnProperty(id) && this.subscriptions_by_id[id].session_id === session.id) delete this.subscriptions_by_id[id];
            }
            session.set_realm(null);
        }
    }
}

exports.Realm = Realm;

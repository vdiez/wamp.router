'use strict';

module.exports.match = (uri, wildcard) => {
    const wild_parts = wildcard.split('.');
    const uri_parts = uri.split('.');
    if (wild_parts.length !== uri_parts.length) return false;
    for (let i = 0; i < wild_parts.length; i++) {
        if (wild_parts[i] && wild_parts[i] !== uri_parts[i]) return false;
    }
    return true;
};

module.exports.weight = (wildcard1, wildcard2) => {
    const wild1_parts = wildcard1.split('.');
    const wild2_parts = wildcard2.split('.');
    for (let i = 0; i < wild1_parts.length; i++) {
        if (wild1_parts[i] !== wild2_parts[i]) return wild1_parts[i] ? 1 : -1;
    }
    return 0;
};

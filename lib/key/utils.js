import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';
import { DEFAULT_OFFSET } from '../constants';
import { createMessage } from '../message/utils';
import { ECDHkdf, genECDHPrivateEphemeralKey, genECDHPublicEphemeralKey, ECDHHash, buildECDHParam } from './ecdh';

// returns promise for generated RSA public and encrypted private keys
export async function generateKey({ passphrase, date = serverTime(), offset = DEFAULT_OFFSET, ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    const offsetDate = new Date(date.getTime() + offset);
    return openpgp.generateKey({ passphrase, date: offsetDate, ...rest });
}

export function generateSessionKey(algorithm) {
    return openpgp.crypto.generateSessionKey(algorithm);
}

export async function getPreferredAlgorithm(keys, date = serverTime()) {
    return openpgp.enums.read(openpgp.enums.symmetric, await openpgp.key.getPreferredAlgo('symmetric', keys, date));
}

export function reformatKey({ passphrase, date = serverTime(), ...rest }) {
    if (!passphrase) {
        throw new Error('passphrase required');
    }
    return openpgp.reformatKey({ passphrase, date, ...rest });
}

export async function getKeys(rawKeys = '') {
    const options = rawKeys instanceof Uint8Array ? { binaryKey: rawKeys } : { armoredKey: rawKeys };
    const keys = await openpgp.readKey(options);

    if (!keys) {
        // keys is undefined in that case
        throw new Error('Cannot parse key(s)');
    }

    if (keys.err) {
        // openpgp.key.readArmored returns error arrays.
        throw new Error(keys.err[0].message);
    }

    return keys;
}

/**
 * Returns whether the primary key is expired, or its creation time is in the future.
 * @param {OpenPGPKey} key
 * @param {Date} date - date to use instead of the server time
 * @returns {Promise<Boolean>}
 */
export async function isExpiredKey(key, date = serverTime()) {
    const now = +date;
    const expirationTime = await key.getExpirationTime(); // Always non-null for primary key expiration
    return !(key.getCreationTime() <= now && now < expirationTime);
}

/**
 * Returns whether the primary key is revoked.
 * @param {OpenPGPKey} key
 * @param {Date} date - date to use for signature verification, instead of the server time
 * @returns {Boolean}
 */
export async function isRevokedKey(key, date = serverTime()) {
    return key.isRevoked(null, null, date);
}

/**
 * Check whether a key can successfully encrypt a message.
 * This confirms that the key has encryption capabilities, it is neither expired nor revoked, and that its key material is valid.
 * @param {OpenPGPKey} publicKey - key to check
 * @param {Date} date - use the given date instead of the server time
 * @returns {Boolean}
 */
export const canKeyEncrypt = async (publicKey, date = serverTime()) => {
    try {
        await openpgp.encrypt({ message: createMessage('test message'), publicKeys: publicKey, date });
        return true;
    } catch (e) {
        return false;
    }
};

export async function compressKey(armoredKey) {
    const [k] = await getKeys(armoredKey);
    const { users } = k;
    users.forEach(({ otherCertifications }) => (otherCertifications.length = 0));
    return k.armor();
}

export function getFingerprint(key) {
    return key.getFingerprint();
}

/**
 * Gets the key matching the signature
 * @param {Signature} signature
 * @param {Array<Key>} keys An array of keys
 * @return key
 */
export async function getMatchingKey(signature, keys) {
    const keyring = new openpgp.Keyring({
        loadPublic: () => keys,
        loadPrivate: () => [],
        storePublic() {},
        storePrivate() {}
    });

    await keyring.load();

    const keyids = signature.packets.map(({ issuerKeyId }) => issuerKeyId.toHex());
    const key = keyids.reduce((acc, keyid) => {
        if (!acc) {
            const keys = keyring.getKeysForId(keyid, true);

            if (Array.isArray(keys) && keys.length) {
                return keys[0];
            }
        }

        return acc;
    }, undefined);

    return key;
}

export async function cloneKey(inputKey) {
    const [key] = await getKeys(inputKey.toPacketlist().write());
    return key;
}

/**
 * Generate ECDHE key and secret from public key
 *
 * @param {Object<Options>}                              Public key Q, fingerprint and curve (name or OID)
 * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>}   Returns public part of ephemeral key and generated ephemeral secret
 * @async
 */
export async function genPublicEphemeralKey({ Q, Fingerprint }) {
    const { publicKey: V, sharedKey: S } = await genECDHPublicEphemeralKey(Q);

    const param = buildECDHParam(Fingerprint);

    const Z = await ECDHkdf(ECDHHash, S, param);

    return { V, Z };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param {Object<Options>}        Private key d, public part of ECDHE V, Fingerprint and curve (name or OID)
 * @returns {Promise<Uint8Array>}  Generated ephemeral secret
 * @async
 */
export async function genPrivateEphemeralKey({ d, V, Fingerprint }) {
    const { sharedKey: S } = await genECDHPrivateEphemeralKey(V, null, d);

    const param = buildECDHParam(Fingerprint);

    return ECDHkdf(ECDHHash, S, param);
}

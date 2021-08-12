/* eslint-disable no-prototype-builtins */
import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';
import { createMessage } from './utils';

export default async function encryptMessage({ format = 'armored', ...options }) {
    if (typeof options.data === 'string') {
        options.message = await createMessage({
            text: openpgp.util.removeTrailingSpaces(options.data),
            filename: options.filename
        });
    }

    if (Uint8Array.prototype.isPrototypeOf(options.data)) {
        options.message = await createMessage({ text: options.data, filename: options.filename });
    }

    if (options.returnSessionKey) {
        options.sessionKey = await openpgp.generateSessionKey({ encryptionKeys: options.encryptionKeys });
    }
    delete options.returnSessionKey;

    options.date = typeof options.date === 'undefined' ? serverTime() : options.date;

    options.format = format;

    if (options.detached) {
        delete options.detached;
        const signOptions = {
            message: options.message,
            signingKeys: options.signingKeys,
            format: 'binary',
            detached: true
        };

        // Create detached signature of message
        const signature = await openpgp.sign(signOptions);

        // Encrypt message without signing it
        options.signingKeys = [];
        const result = {
            message: await openpgp.encrypt(options)
        };
        if (options.sessionKey) {
            result.sessionKey = options.sessionKey;
        }

        // Encrypt signature and add it to the final result
        options.message = await createMessage(signature);
        options.sessionKey = result.sessionKey;
        const encryptedSignature = await openpgp.encrypt(options);
        result.encryptedSignature = encryptedSignature;

        // Add plain signature for backward compatibility
        result.signature = signature;
        result.sessionKey = options.sessionKey;

        return result;
    }

    const result = {
        message: await openpgp.encrypt(options)
    };

    if (options.sessionKey) {
        result.sessionKey = options.sessionKey;
    }
    return result;
}

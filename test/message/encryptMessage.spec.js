import test from 'ava';
import '../helper';
import { readToEnd } from '@openpgp/web-stream-tools';
import { config, util, stream } from 'openpgp';

import { createMessage, getMessage, getSignature, verifyMessage } from '../../lib/message/utils';
import encryptMessage from '../../lib/message/encrypt';
import { decryptMessage } from '../../lib/message/decrypt';
import { decryptPrivateKey } from '../../lib';
import { testPrivateKeyLegacy } from './decryptMessageLegacy.data';
import { VERIFICATION_STATUS } from '../../lib/constants';
import { hexToUint8Array, arrayToBinaryString } from '../../lib/utils';

test.before('openpgp config', async () => {
    config.minRSABits = 512;
});

test('it can encrypt and decrypt a message', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey]
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey]
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session keys', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        returnSessionKey: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        decryptionKeys: [decryptedPrivateKey],
        verificationKeys: [decryptedPrivateKey.toPublic()],
        sessionKeys
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with an unencrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, signature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        detached: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        signature: await getSignature(signature),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey]
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
    const { verified: verifiedAgain } = await verifyMessage({
        message: await createMessage('Hello world!'),
        signature: await getSignature(signature),
        verificationKeys: [decryptedPrivateKey.toPublic()]
    });
    t.is(verifiedAgain, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, encryptedSignature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        detached: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        encryptedSignature: await getMessage(encryptedSignature),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey]
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt a message and decrypt it unarmored using session keys along with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        returnSessionKey: true,
        detached: true,
        format: 'armored'
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        decryptionKeys: [decryptedPrivateKey],
        verificationKeys: [decryptedPrivateKey.toPublic()],
        encryptedSignature: await getMessage(encryptedSignature),
        sessionKeys
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session key without setting returnSessionKey', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const sessionKey = {
        data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
        algorithm: 'aes256'
    };
    const { message: encrypted } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        sessionKey
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey],
        sessionKeys: sessionKey
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a message with session key without setting returnSessionKey with a detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const sessionKey = {
        data: hexToUint8Array('c5629d840fd64ef55aea474f87dcdeef76bbc798a340ef67045315eb7924a36f'),
        algorithm: 'aes256'
    };
    const { message: encrypted, encryptedSignature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        detached: true,
        sessionKey
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        decryptionKeys: [decryptedPrivateKey],
        verificationKeys: [decryptedPrivateKey.toPublic()],
        encryptedSignature: await getMessage(encryptedSignature),
        sessionKeys: sessionKey
    });
    t.is(decrypted, 'Hello world!');
    t.is(verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with an unencrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys, signature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        format: 'armored',
        returnSessionKey: true,
        detached: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        signature: await getSignature(signature),
        sessionKeys,
        verificationKeys: [decryptedPrivateKey.toPublic()],
        decryptionKeys: [decryptedPrivateKey],
        format: 'binary'
    });
    t.is(arrayToBinaryString(await readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with an encrypted detached signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys, encryptedSignature } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        format: 'armored',
        returnSessionKey: true,
        detached: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        encryptedSignature: await getMessage(encryptedSignature),
        sessionKeys,
        verificationKeys: [decryptedPrivateKey.toPublic()],
        format: 'binary'
    });
    t.is(arrayToBinaryString(await readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

test('it can encrypt and decrypt a binary streamed message with in-message signature', async (t) => {
    const decryptedPrivateKey = await decryptPrivateKey(testPrivateKeyLegacy, '123');
    const { message: encrypted, sessionKey: sessionKeys } = await encryptMessage({
        message: await createMessage('Hello world!'),
        encryptionKeys: [decryptedPrivateKey.toPublic()],
        signingKeys: [decryptedPrivateKey],
        format: 'armored',
        returnSessionKey: true
    });
    const { data: decrypted, verified } = await decryptMessage({
        message: await getMessage(encrypted),
        sessionKeys,
        decryptionKeys: [decryptedPrivateKey],
        verificationKeys: [decryptedPrivateKey.toPublic()],
        format: 'binary'
    });
    t.is(arrayToBinaryString(await readToEnd(decrypted)), 'Hello world!');
    t.is(await verified, VERIFICATION_STATUS.SIGNED_AND_VALID);
});

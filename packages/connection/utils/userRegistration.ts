import { generateKey } from 'openpgp/lightweight';
import * as openpgp from 'openpgp';

export async function generateUserKey(username: string) {
    const userMaskedEmail = `masked+${username}@app-domain.com`;
    const { privateKey, publicKey, revocationCertificate } = await generateKey({
        userIDs: [
            { name: username, email: userMaskedEmail }
        ],
        curve: 'nistP384',
    });
    return { username, privateKey, publicKey };
}


export async function decryptMessage(privateKeyArmored: any, encryptedMessageArmored: any) {
    try {

        const [privateKey] = await openpgp.readPrivateKeys({ armoredKeys: privateKeyArmored });;

        if (!privateKey || privateKey.isDecrypted === undefined) {
             throw new Error("Failed to read a valid Private Key object.");
        }


        const encryptedMessage = await openpgp.readMessage({ 
            armoredMessage: encryptedMessageArmored 
        });

        const { data: decrypted } = await openpgp.decrypt({
            message: encryptedMessage,
            decryptionKeys: privateKey,
        });

        return decrypted;

    } catch (error) {
        console.error('Decryption failed:', error);
        throw error;
    }
}

export async function sendAuthRequest(username: string, pgpPublicKey: string) {
    const response = await fetch('/api/auth/request', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username,
            pgp: pgpPublicKey
        })
    })
}
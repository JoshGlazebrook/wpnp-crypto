// Type definitions for wpnp-crypto
// Project: https://github.com/JoshGlazebrook/wpnp-crypto
// Definitions by: Josh Glazebrook <https://github.com/JoshGlazebrook>

/// <reference path="../node/node.d.ts" />

declare module "wpnp-crypto" {

    /**
     * Encloses a crypt key id number value.
     */
    export class CryptKey {
        public value: number;
        constructor(val: number);
    }

    /**
     * Creates a new crypt key block based on the given keytype.
     * @param keytype The keytype to base the block on.
     */
    export function createCryptKeyBlock(keytype: number): Buffer;

    /**
     * Gets the crypt key type of the given keyblock buffer.
     * @param keyblock The keyblock buffer to analyze.
     */
    export function getCryptKeyType(keyblock: Buffer): number;

    /**
     * Gets the crypt key of the given keyblock buffer.
     * @param keybock The keyblock buffer to analyze.
     * @param upload If true, will return the outbound cryp tkey, otherwise returns the inbound crypt key.
     */
    export function getCryptKey(keybock: Buffer, upload: boolean): CryptKey;

    /**
     * Encrypts the given buffer using the TCP algorithm with the given crypt key.
     * @param buff The buffer to encrypt.
     * @param key The crypt key to use for encryption. (This value is mutated when this function is called)
     */
    export function encryptMXTCP(buff: Buffer, key: CryptKey): Buffer;

    /**
     * Decrypts the given buffer using the TCP algorithm with the given crypt key.
     * @param buff The buffer to decrypt.
     * @param key The crypt key to use for decryption. (This value is mutated when this function is called)
     */
    export function decryptMXTCP(buff: Buffer, key: CryptKey): Buffer;

    /**
     * Encrypts the given buffer with the algorithm.
     * @param buff The buffer to encrypt.
     */
    export function encryptMXUDP(buff: Buffer): Buffer;

    /**
     * Decrypts the given buffer with the UDP algorithm.
     * @param buff The buffer to decrypt.
     */
    export function decryptMXUDP(buff: Buffer): Buffer;

    /**
     * Encrypts the given buffer with the frontcode algorithm.
     * @param buff The buffer to encrypt.
     */
    export function encryptFrontCode(buff: Buffer): Buffer;

    /**
     * Decrypts the given buffer with the frontcode algorithm.
     * @param buff The buffer to decrypt.
     */
    export function decryptFrontCode(buff: Buffer): Buffer;

    /**
     * Generates a valid Genac6 key buffer.
     */
    export function createGenacKey(): Buffer;

    /**
     * Validates a Genac6 key buffer.
     * @param key The buffer to validate. (This should be 6 bytes)
     */
    export function validateGenacKey(key: Buffer): boolean;

    /**
     * Runs the WinMXGroup/KM mangle algorithm on the key buffer.
     * @param key The buffer to mangle.
     */
    export function mangle(key: Buffer);
}
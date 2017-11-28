'use strict';

const crypto = require( 'crypto' );
const enveloper = require( 'enveloper' );
const extend = require( 'extend' );
const fs = require( 'fs' );

const DEFAULT_KEY_FILENAME = 'single-key-encryptor.key';

const processor = {
    options: {
        key: null,

        fields: {
            hash: [],
            pass: []
        }
    },

    hash: function( value ) {
        return crypto.createHash( 'sha256' ).update( value, 'utf8' ).digest( 'base64' );
    },

    encrypt: function( object ) {
        const encrypted = {};
        encrypted._encrypted = enveloper.to_string( enveloper.seal( JSON.stringify( object ), {
            key: this.options.key
        } ) );
        return encrypted;
    },

    decrypt: function( encrypted ) {
        const decrypted_info = enveloper.open( extend( true, {
            key: this.options.key
        }, enveloper.from_string( encrypted._encrypted ) ) );
        const decrypted = JSON.parse( decrypted_info.decrypted );
        return decrypted;
    },

    serialize: async ( object, options ) => {
        const encrypted = await this.encrypt( object );
        const processed = extend( true, {}, encrypted );

        // TODO: use traverse for better control?

        this.options.fields.hash.forEach( field => {
            processed[ field ] = this.hash( object[ field ] );
        } );

        this.options.fields.pass.forEach( field => {
            processed[ field ] = object[ field ];
        } );

        return processed;
    },

    deserialize: async ( processed, options ) => {

        const decrypted = await this.decrypt( processed );
        const object = extend( true, {}, decrypted );

        return object;
    }
};

module.exports = {
    create: options => {

        // DO NOT USE IN PRODUCTION
        if ( process.env.NODE_ENV === 'production' ) {
            throw new Error( 'This module should not be used in production!' );
        }

        const _processor = extend( true, {}, processor );
        _processor.options = extend( true, {}, processor.options, options );

        if ( !_processor.options.key ) {
            if ( !fs.existsSync( DEFAULT_KEY_FILENAME ) ) {
                fs.writeFileSync( DEFAULT_KEY_FILENAME, crypto.randomBytes( 64 ).toString( 'base64' ) );
                // not efficient to write then read back, but whatever for this test module
            }

            _processor.options.key = fs.readFileSync( DEFAULT_KEY_FILENAME );
        }

        return _processor;
    }
};
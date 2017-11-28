const mds_single_key_encryptor = require( './index.js' );

const instance = mds_single_key_encryptor.create();

console.dir( instance.decrypt( instance.encrypt( { foo: 'bar' } ) ) );
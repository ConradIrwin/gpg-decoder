function Packet(stream) {
    this.stream = stream;
}

Packet.TAGS = {
    0: "Reserved - a packet tag MUST NOT have this value",
    1: "Public Key Encrypted Session Key Packet",
    2: "Signature Packet",
    3: "Symmetric-Key Encrypted Session Key Packet",
    4: "One-Pass Signature Packet",
    5: "Secret Key Packet",
    6: "Public Key Packet",
    7: "Secret Subkey Packet",
    8: "Compressed Data Packet",
    9: "Symmetrically Encrypted Data Packet",
    10: "Marker Packet",
    11: "Literal Data Packet",
    12: "Trust Packet",
    13: "User ID Packet",
    14: "Public Subkey Packet",
    17: "User Attribute Packet",
    18: "Sym. Encrypted and Integrity Protected Data Packet",
    19: "Reserved (formerly Modification Detection Code Packet)",
    20: "Reserved",
    21: "Padding Packet",
};

Packet.PUBLIC_KEY_ALGORITHMS = {
    0: "Reserved",
    1: "RSA (Encrypt or Sign)", // [FIPS186]
    2: "RSA Encrypt-Only", // [FIPS186]
    3: "RSA Sign-Only", // [FIPS186]
    16: "Elgamal (Encrypt-Only)", // [ELGAMAL]
    17: "DSA (Digital Signature Algorithm)", // [FIPS186]
    18: "ECDH public key algorithm",
    19: "ECDSA public key algorithm", // [FIPS186]
    20: "Reserved (formerly Elgamal Encrypt or Sign)",
    21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)",
    22: "EdDSALegacy (deprecated)",
    23: "Reserved (AEDH)",
    24: "Reserved (AEDSA)",
    25: "X25519",
    26: "X448",
    27: "Ed25519",
    28: "Ed448",
    100: "Private or Experimental Use",
    101: "Private or Experimental Use",
    102: "Private or Experimental Use",
    103: "Private or Experimental Use",
    104: "Private or Experimental Use",
    105: "Private or Experimental Use",
    106: "Private or Experimental Use",
    107: "Private or Experimental Use",
    108: "Private or Experimental Use",
    109: "Private or Experimental Use",
    110: "Private or Experimental Use",
};

Packet.SYMMETRIC_KEY_ALGORITHMS = {
    0: "Plaintext or unencrypted data",
    1: "IDEA", // [IDEA]
    2: "TripleDES (or DES-EDE) with 168-bit key derived from 192", // [SP800-67]
    3: "CAST5 with 128-bit key", // [RFC2144]
    4: "Blowfish with 128-bit key, 16 rounds", // [BLOWFISH]
    5: "Reserved",
    6: "Reserved",
    7: "AES with 128-bit key", // [AES]
    8: "AES with 192-bit key",
    9: "AES with 256-bit key",
    10: "Twofish with 256-bit key", // [TWOFISH]
    11: "Camellia with 128-bit key", // [RFC3713]
    12: "Camellia with 192-bit key",
    13: "Camellia with 256-bit key",
    100: "Private or Experimental Use",
    101: "Private or Experimental Use",
    102: "Private or Experimental Use",
    103: "Private or Experimental Use",
    104: "Private or Experimental Use",
    105: "Private or Experimental Use",
    106: "Private or Experimental Use",
    107: "Private or Experimental Use",
    108: "Private or Experimental Use",
    109: "Private or Experimental Use",
    110: "Private or Experimental Use",
    253: "Reserved to avoid collision with Secret Key Encryption",
    254: "Reserved to avoid collision with Secret Key Encryption",
    255: "Reserved to avoid collision with Secret Key Encryption",
};

Packet.SECRET_KEY_ALGORITHM_BLOCK_SIZES = {
    1: 8, // "IDEA [IDEA]",
    2: 8, // "TripleDES (or DES-EDE) with 168-bit key derived from 192", // [SP800-67]
    3: 8, // "CAST5 with 128-bit key", // [RFC2144]
    4: 8, // "Blowfish with 128-bit key, 16 rounds", //  [BLOWFISH]
    7: 16, // "AES with 128-bit key", // [AES]
    8: 16, // "AES with 192-bit key",
    9: 16, // "AES with 256-bit key",
    10: 16, // "Twofish with 256-bit key", // [TWOFISH]
    11: 16, // "Camellia with 128-bit key", // [RFC3713]
    12: 16, // "Camellia with 192-bit key",
    13: 16, // "Camellia with 256-bit key",
};

Packet.AEAD_ALGORITHMS = {
    0: "Reserved",
    1: "EAX", // [EAX]
    2: "OCB", // [RFC7253]
    3: "GCM", // [SP800-38D]
    100: "Private or Experimental Use",
    101: "Private or Experimental Use",
    102: "Private or Experimental Use",
    103: "Private or Experimental Use",
    104: "Private or Experimental Use",
    105: "Private or Experimental Use",
    106: "Private or Experimental Use",
    107: "Private or Experimental Use",
    108: "Private or Experimental Use",
    109: "Private or Experimental Use",
    110: "Private or Experimental Use",
};

Packet.AEAD_IV_LENGTHS = {
    1: 16, // "EAX", // [EAX]
    2: 15, // "OCB", // [RFC7253]
    3: 12, // "GCM", // [SP800-38D]
};

Packet.AEAD_AUTHENTICATION_TAG_LENGTHS = {
    1: 16, // "EAX", // [EAX]
    2: 16, // "OCB", // [RFC7253]
    3: 16, // "GCM", // [SP800-38D]
};

Packet.COMPRESSION_ALGORITHMS = {
    0: "Uncompressed",
    1: "ZIP", // [RFC1951]
    2: "ZLIB", // [RFC1950]
    3: "BZip2", // [BZ2]
    100: "Private or Experimental Use",
    101: "Private or Experimental Use",
    102: "Private or Experimental Use",
    103: "Private or Experimental Use",
    104: "Private or Experimental Use",
    105: "Private or Experimental Use",
    106: "Private or Experimental Use",
    107: "Private or Experimental Use",
    108: "Private or Experimental Use",
    109: "Private or Experimental Use",
    110: "Private or Experimental Use",
};

Packet.HASH_ALGORITHMS = {
    0: "Reserved",
    1: "MD5", // [RFC1321]
    2: "SHA1", // [FIPS180]
    3: "RIPEMD160", // [RIPEMD-160]
    4: "Reserved",
    5: "Reserved",
    6: "Reserved",
    7: "Reserved",
    8: "SHA2-256", // [FIPS180]
    9: "SHA2-384", // [FIPS180]
    10: "SHA2-512", // [FIPS180]
    11: "SHA2-224", // [FIPS180]
    12: "SHA3-256", // [FIPS202]
    13: "Reserved",
    14: "SHA3-512", // [FIPS202]
    100: "Private or Experimental Use",
    101: "Private or Experimental Use",
    102: "Private or Experimental Use",
    103: "Private or Experimental Use",
    104: "Private or Experimental Use",
    105: "Private or Experimental Use",
    106: "Private or Experimental Use",
    107: "Private or Experimental Use",
    108: "Private or Experimental Use",
    109: "Private or Experimental Use",
    110: "Private or Experimental Use",
};

Packet.HASH_SALT_SIZES = {
    8: 16, // "SHA2-256", // [FIPS180]
    9: 24, // "SHA2-384", // [FIPS180]
    10: 32, // "SHA2-512", // [FIPS180]
    11: 16, // "SHA2-224", // [FIPS180]
    12: 16, // "SHA3-256", // [FIPS202]
    14: 32, // "SHA3-512", // [FIPS202]
    100: -1, // "Private or Experimental Use",
    101: -1, // "Private or Experimental Use",
    102: -1, // "Private or Experimental Use",
    103: -1, // "Private or Experimental Use",
    104: -1, // "Private or Experimental Use",
    105: -1, // "Private or Experimental Use",
    106: -1, // "Private or Experimental Use",
    107: -1, // "Private or Experimental Use",
    108: -1, // "Private or Experimental Use",
    109: -1, // "Private or Experimental Use",
    110: -1, // "Private or Experimental Use",
};

Packet.SIGNATURE_TYPES = {
    0: "Signature of a binary document.",
    1: "Signature of a canonical text document.",
    2: "Standalone signature.",
    16: "Generic certification of a User ID and Public-Key packet.",
    17: "Persona certification of a User ID and Public-Key packet.",
    18: "Casual certification of a User ID and Public-Key packet.",
    19: "Positive certification of a User ID and Public-Key packet.",
    24: "Subkey Binding Signature",
    25: "Primary Key Binding Signature",
    31: "Direct Key Signature",
    32: "Key revocation signature",
    40: "Subkey revocation signature",
    48: "Certification revocation signature",
    64: "Timestamp signature.",
    80: "Third-Party Confirmation signature.",
    255: "Reserved",
};

Packet.SIGNATURE_SUBPACKET_TYPES = {
    0: "Reserved",
    1: "Reserved",
    2: "Signature Creation Time",
    3: "Signature Expiration Time",
    4: "Exportable Certification",
    5: "Trust Signature",
    6: "Regular Expression",
    7: "Revocable",
    8: "Reserved",
    9: "Key Expiration Time",
    10: "Placeholder for backward compatibility",
    11: "Preferred Symmetric Ciphers for v1 SEIPD",
    12: "Revocation Key (deprecated)",
    13: "Reserved",
    14: "Reserved",
    15: "Reserved",
    16: "Issuer",
    17: "Reserved",
    18: "Reserved",
    19: "Reserved",
    20: "Notation Data",
    21: "Preferred Hash Algorithms",
    22: "Preferred Compression Algorithms",
    23: "Key Server Preferences",
    24: "Preferred Key Server",
    25: "Primary User ID",
    26: "Policy URI",
    27: "Key Flags",
    28: "Signer's User ID",
    29: "Reason for Revocation",
    30: "Features",
    31: "Signature Target",
    32: "Embedded Signature",
    33: "Issuer Fingerprint",
    34: "Reserved (Formerly Preferred AEAD Algorithms)",
    35: "Intended Recipient Fingerprint",
    37: "Reserved (Attested Certifications)",
    38: "Reserved (Key Block)",
    39: "Preferred AEAD Ciphersuites",
    100: "Private or Experimental Use",
    101: "Private or Experimental Use",
    102: "Private or Experimental Use",
    103: "Private or Experimental Use",
    104: "Private or Experimental Use",
    105: "Private or Experimental Use",
    106: "Private or Experimental Use",
    107: "Private or Experimental Use",
    108: "Private or Experimental Use",
    109: "Private or Experimental Use",
    110: "Private or Experimental Use",
};

Packet.KEYSERVER_PREFERENCES = {
    128: "No-modify"
};

Packet.KEY_FLAGS = {
    0x01: 'certify',
    0x02: 'sign',
    0x04: 'encrypt communications',
    0x08: 'encrypt storage',
    0x10: 'split key',
    0x20: 'authentication',
    0x80: 'shared key',
    0x4000: 'reserved (ASDK)',
    0x8000: 'reserved (timestamping)',
};

Packet.KEY_FEATURES = {
    1: 'Modification detection v1',
    2: 'Reserved',
    4: 'Reserved',
    8: 'Modification detection v2',
};

Packet.STRING_TO_KEY_USAGES = Object.assign({}, Packet.SYMMETRIC_KEY_ALGORITHMS);
Packet.STRING_TO_KEY_USAGES[253] = "AEAD";
Packet.STRING_TO_KEY_USAGES[254] = "CFB";
Packet.STRING_TO_KEY_USAGES[255] = "MalleableCFB";

Packet.STRING_TO_KEY_SPECIFIERS = {
    0: "Simple S2K",
    1: "Salted S2K",
    2: "Reserved value",
    3: "Iterated and Salted S2K",
    4: "Argon2",
    100: "Private or Experimental Use",
    101: "Private or Experimental Use",
    102: "Private or Experimental Use",
    103: "Private or Experimental Use",
    104: "Private or Experimental Use",
    105: "Private or Experimental Use",
    106: "Private or Experimental Use",
    107: "Private or Experimental Use",
    108: "Private or Experimental Use",
    109: "Private or Experimental Use",
    110: "Private or Experimental Use",
};

Packet.STRING_TO_KEY_SPECIFIER_FIELD_SIZES = {
    0: 2, // "Simple S2K",
    1: 10, // "Salted S2K",
    3: 11, // "Iterated and Salted S2K",
    4: 20, // "Argon2",
    100: -1, // "Private or Experimental Use",
    101: -1, // "Private or Experimental Use",
    102: -1, // "Private or Experimental Use",
    103: -1, // "Private or Experimental Use",
    104: -1, // "Private or Experimental Use",
    105: -1, // "Private or Experimental Use",
    106: -1, // "Private or Experimental Use",
    107: -1, // "Private or Experimental Use",
    108: -1, // "Private or Experimental Use",
    109: -1, // "Private or Experimental Use",
    110: -1, // "Private or Experimental Use",
};

Packet.LITERAL_DATA_FORMATS = {
    0x01: "local", // deprecated value for machine local conversions
    0x31: "local", // as 1, but is the ascii '1' as RFC1991 incorrectly specified.
    0x62: "binary", // 'b'
    0x74: "text", // 't' -- deprecated text format with no encoding specified
    0x75: "utf8", // 'u'
};

Packet.NOTATION_DATA_FLAGS = {
    0x80000000: "human-readable",
};

Packet.REVOCATION_REASONS = {
    0: "No reason specified",
    1: "Key is superseded",
    2: "Key material has been compromised ",
    3: "Key is retired and no longer used",
    32: "User ID information is no longer valid",
    100: "Private Use",
    101: "Private Use",
    102: "Private Use",
    103: "Private Use",
    104: "Private Use",
    105: "Private Use",
    106: "Private Use",
    107: "Private Use",
    108: "Private Use",
    109: "Private Use",
    110: "Private Use",
};

Packet.prototype = {

    dump: function () {
        return Hex.encodePretty(this.stream.bytes.slice(this.start, this.end));
    },
    coloredBytes: function () {
        var output = "";
        var n = 0;
        this.stream.bytes.slice(this.start, this.end).map(function (b) {
            return b < 16 ? "0" + b.toString(16) : b.toString(16);
        }).forEach(function (b, i) {
            output += "<span id='byte-" + (this.start + i) +"' style='color: " + this.byteColors[this.start + i] + "'>" + b + "</span>";

            if (++n % 16 === 0) {
                output += "\n";
            }

        }.bind(this));
        return output;
    },
    coloredData: function () {
        var output = "";

        Object.keys(this).forEach(function (key) {
            if (this[key] && this[key].subpackets) {
                var name = this[key].name ?? "subpackets";
                output += "  " + name + ":\n";
                this[key].forEach(function (subpacket) {
                    Object.keys(subpacket).forEach(function (subkey) {
                        var color = this.nameColors[subpacket.id + ":" + subkey];
                        if (color) {
                            output += "    <span onmouseover='hover(" + JSON.stringify(this.nameSpans[subpacket.id + ":" + subkey]) + ")' style='font-weight: bold; color: " + color + "'>" + subkey + "</span>:" + JSON.stringify(("" + subpacket[subkey]).replace('<', '&lt;')) + "\n";
                        }

                    }.bind(this));
                }.bind(this));
            } else if (this.nameColors[key]) {
                output += "  <span onmouseover='hover(" + JSON.stringify(this.nameSpans[key]) + ");' style='font-weight: bold; color: " + this.nameColors[key] + "'>" + key + "</span>: " +  JSON.stringify(("" + this[key]).replace('<', '&lt;')) + "\n";
            }
        }.bind(this));
        return output;

    },
    toJSON: function () {
        var output = {};
        for (var key in this) {
            if (this.nameColors[key]) {
                output[key] = this[key];
            }
        }
        return output;
    },
    nextColor: function () {
        var colors  = ['#f39c12', '#16a085',   '#d35400', '#8e44ad', '#27ae60', '#2c3e50', '#7f8c8d', '#c0392b'];

        this.colorIndex = ((this.colorIndex || 0) + 1) % colors.length;
        return colors[this.colorIndex];
    },
    nextSubpacket: function () {
        this.subpacketId = (this.subpacketId || 0) + 1;
        return {id: this.subpacketId};
    },
    set: function (name, value) {
        if (!this.byteColors) {
            this.byteColors = [];
            this.nameColors = {};
            this.nameSpans = {};
        }

        this.nameColors[name] = this.nextColor();
        this.nameSpans[name] = [this.lastColorEnd || (this.stream.pos > 0 ? this.stream.pos - 1 : 0), this.stream.pos];

        for (var i = (this.lastColorEnd || this.stream.start); i < this.stream.pos; i++) {
            this.byteColors[i] = this.nameColors[name];
        }
        this.lastColorEnd = this.stream.pos;

        this[name] = value;
    },
    setSubpacket: function (subpacket, name, value) {
        this.nameColors[subpacket.id + ":" + name] = this.nextColor();
        this.nameSpans[subpacket.id + ":" + name] = [this.lastColorEnd || 0, this.stream.pos];

        for (var i = (this.lastColorEnd || this.stream.start); i < this.stream.pos; i++) {
            this.byteColors[i] = this.nameColors[subpacket.id + ":" + name];
        }
        this.lastColorEnd = this.stream.pos;

        subpacket[name] = value;
    },
    parse: function () {
        this.start = this.stream.pos;
        this.set('cipherTypeByte', this.stream.octet());

        if (!(this.cipherTypeByte & 0x80)) {
            alert('Invalid packet format');
        }

        if (this.cipherTypeByte & 0x40) {
            this.parseNewHeader();
        } else {
            this.parseOldHeader();
        }

        if (this.stream.subParse(this.length, function () {
            this.packet = new LookupResult(Packet.TAGS[this.tag], this.tag);
            this.parseBody();
        }.bind(this))) {
            this.parseError("unparsed data!");
        }
        this.end = this.stream.pos;
    },

    // This cipher type byte: 10xxxxyy
    // x: type
    // y: size of the length field
    parseOldHeader: function () {
        var size = this.cipherTypeByte & 0x3;
        this.tag = (this.cipherTypeByte & 0x3c) >> 2;

        switch (size) {
        case 3: // 0-byte length
            this.set('length', 0);
            break;

        case 2: // 4-byte length
            this.set('length', this.stream.uint32());

            break;
        case 1: // 2-byte length
            this.set('length', this.stream.uint16());

            break;
        case 0: // 1-byte length
            this.set('length', this.stream.octet());
        }
    },

    // This cipher type byte: 11xxxxxx
    // x: type
    parseNewHeader: function () {
        this.tag = this.cipherTypeByte & 0x3f;

        this.set('length', this.stream.variableLengthLength('support partial'));
    },

    parseBody: function () {
        switch (this.tag) {
        case 1: // "Public Key Encrypted Session Key Packet",
            this.parsePublicKeyEncryptedSessionKey();
            break;
        case 2: // "Signature Packet",
            this.parseSignaturePacket();
            break;

        case 3: // "Symmetric-Key Encrypted Session Key Packet",
            this.parseSymmetricKeyEncryptedSessionKeyPacket();
            break;

        case 4: // "One-Pass Signature Packet",
            this.parseOnePassSignaturePacket();
            break;

        case 6: // "Public Key Packet",
        case 14: // "Public Subkey Packet",
            this.parsePublicKeyPacket();
            break;

        case 5: // "Secret Key Packet",
        case 7: // "Secret Subkey Packet",
            this.parseSecretKeyPacket();
            break;

        case 11: // "Literal Data Packet",
            this.parseLiteralDataPacket();
            break;

        case 13: // User ID Packet",
            this.parseUserIdPacket();
            break;

        case 18: // "Sym. Encrypted and Integrity Protected Data Packet",
            this.parseSymEncryptedIntegrityProtectedDataPacket();
            break;

        case 21: // "Padding Packet",
            this.set('padding', this.stream.hex(this.stream.remaining()));
            break;
        }
    },

    parsePublicKeyEncryptedSessionKey: function () {
        this.set('version', this.stream.octet());

        if (this.version === 6) {
            this.set('recipientFieldLength', this.stream.octet());

            if (this.recipientFieldLength > 0) {
                this.set('recipientKeyVersion', this.stream.octet());
                this.set('recipientKeyFingerprint', this.stream.hex(this.recipientFieldLength - 1));
            } else {
                this.set('recipientAnonymous', true);
            }

            this.set('publicKeyAlgorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));
            this.set('encryptedSessionKey', this.stream.hex(this.stream.remaining()));

        } else if (this.version === 3) {
            this.set('keyId', this.stream.hex(8).toUpperCase());
            this.set('publicKeyAlgorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));

            if (this.publicKeyAlgorithm.id === 1) {
                this.set('encryptedSessionKey', this.stream.multiPrecisionInteger());
            } else {
                this.parseError("Unknown publicKeyAlgorithm", this.publicKeyAlgorithm);
            }

        } else {
            this.parseError("Unknown version", this.version);
        }
    },

    parseSymmetricKeyEncryptedSessionKeyPacket: function () {
        this.set('version', this.stream.octet());

        if (this.version === 6) {
            this.set('cipherFieldLength', this.stream.octet());
            this.set('symmetricAlgorithm', this.stream.lookup(Packet.SYMMETRIC_KEY_ALGORITHMS));
            this.set('aeadAlgorithm', this.stream.lookup(Packet.AEAD_ALGORITHMS));
            this.set('stringToKeySpecifierLength', this.stream.octet());
            this.parseStringToKeySpecifier();
            this.parseVersion6AeadIV(this.aeadAlgorithm.id);

            var authTagLength = Packet.AEAD_AUTHENTICATION_TAG_LENGTHS[this.aeadAlgorithm.id] || 0;
            var keyLength = this.stream.remaining() - authTagLength;

            if (authTagLength < 1) {
                this.parseError("Invalid authentication tag length", authTagLength);
            }

            this.set('encryptedSessionKey', this.stream.hex(keyLength));
            this.set('aeadAuthenticationTag',this.stream.hex(authTagLength));

        } else if (this.version === 4) {
            this.set('symmetricAlgorithm', this.stream.lookup(Packet.SYMMETRIC_KEY_ALGORITHMS));

            this.parseStringToKeySpecifier();

            if (this.stream.remaining() > 0) {
                this.set('encryptedSessionKey', this.stream.hex(this.stream.remaining()));
            }
        } else {
            this.parseError("Unknown version", this.version);
        }
    },

    parseUserIdPacket: function () {
        this.set('userId', this.stream.utf8(this.length));
    },

    parseSignaturePacket: function () {
        this.set('version', this.stream.octet());
        if (this.version === 6 || this.version === 4) {

            this.set('signatureType', this.stream.lookup(Packet.SIGNATURE_TYPES));
            this.set('publicKeyAlgorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));
            this.set('hashAlgorithm', this.stream.lookup(Packet.HASH_ALGORITHMS));

            if (this.version === 6) {
                this.set('hashedDataCount', this.stream.uint32());
            } else {
                this.set('hashedDataCount', this.stream.uint16());
            }

            if (this.stream.subParse(this.hashedDataCount, function () {
                this.hashedSubPackets = this.parseSignatureSubpackets();
            }.bind(this))) {
                this.parseError("Unparsed hashed sub packet data");
            }

            if (this.version === 6) {
                this.set('unhashedDataCount', this.stream.uint32());
            } else {
                this.set('unhashedDataCount', this.stream.uint16());
            }

            if (this.stream.subParse(this.unhashedDataCount, function () {
                this.unhashedSubPackets = this.parseSignatureSubpackets();
            }.bind(this))) {
                this.parseError("Unparsed unhashed sub packet data");
            }

            this.set('signedHashValuePrefix', this.stream.hex(2));

            if (this.version === 6) {
                this.parseVersion6Salt(this.hashAlgorithm.id);
            }

            if (this.publicKeyAlgorithm.id === 0x16) {
              this.set('signatureR', this.stream.multiPrecisionInteger());
              this.set('signatureS', this.stream.multiPrecisionInteger());
            } else {
              this.set('signature', this.stream.multiPrecisionInteger());
            }

        } else if (this.version === 3) {
            this.set('hashLength', this.stream.octet());
            if (this.hashLength != 5) {
                this.parseError("Incorrect hash length", this.hashLength);
            } else {
                this.set('signatureType', this.stream.lookup(Packet.SIGNATURE_TYPES));
                this.set('creationTime', this.stream.time());
                this.set('keyId', this.stream.hex(8).toUpperCase());
                this.set('publicKeyAlgorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));
                this.set('hashAlgorithm', this.stream.lookup(Packet.HASH_ALGORITHMS));
                this.set('signedHashValuePrefix', this.stream.hex(2));
                this.set('signature', this.stream.multiPrecisionInteger());
            }
        } else {
            this.parseError('Unsupported version', this.version);

        }
    },

    parseSignatureSubpackets: function (subpackets) {
        subpackets = subpackets || [];
        subpackets.subpackets = true;
        if (this.stream.pos >= this.stream.end) {
            return subpackets;
        } else {

            var subpacket = this.nextSubpacket();
            this.setSubpacket(subpacket,'length', this.stream.variableLengthLength());

            this.setSubpacket(subpacket, 'subpacketType', this.stream.lookupCritical(Packet.SIGNATURE_SUBPACKET_TYPES));
            var i;

            switch (subpacket.subpacketType.id) {
            case 2: // "Signature Creation Time",
                this.setSubpacket(subpacket, 'creationTime', this.stream.time());
                break;

            case 9: // "Key Expiration Time",
                this.setSubpacket(subpacket, 'keyExpirationTime', this.stream.time());
                break;

            case 11: // "Preferred Symmetric Ciphers for v1 SEIPD",
                this.setSubpacket(subpacket, 'preferredSymmetricAlgorithms', this.stream.lookupArray(Packet.SYMMETRIC_KEY_ALGORITHMS, subpacket.length - 1));
                break;

            case 16: // "Issuer",
                this.setSubpacket(subpacket, 'keyId', this.stream.hex(8));
                break;

            case 20: // "Notation Data",
                this.parseNotationDataSubpacket(subpacket);
                break;

            case 21: // "Preferred Hash Algorithms",
                this.setSubpacket(subpacket, 'preferredHashAlgorithms', this.stream.lookupArray(Packet.HASH_ALGORITHMS, subpacket.length - 1));
                break;

            case 22: // "Preferred Compression Algorithms",
                this.setSubpacket(subpacket, 'preferredCompressionAlgorithms', this.stream.lookupArray(Packet.COMPRESSION_ALGORITHMS, subpacket.length - 1));
                break;

            case 23: // "Key Server Preferences",
                this.setSubpacket(subpacket, 'keyServerPreferences', this.stream.lookupFlags(Packet.KEYSERVER_PREFERENCES, subpacket.length - 1));
                break;

            case 25: // "Primary User ID",
                this.setSubpacket(subpacket, 'isPrimaryID', subpacket.length > 1 && this.stream.octet() ? true : false);
                break;

            case 27: // "Key Flags",
                this.setSubpacket(subpacket, 'keyFlags', this.stream.lookupFlags(Packet.KEY_FLAGS, subpacket.length - 1));
                break;

            case 29: // "Reason for Revocation",
                this.setSubpacket(subpacket, 'revocationReasonCode', this.stream.lookup(Packet.REVOCATION_REASONS));
                if (subpacket.length > 2) {
                    this.setSubpacket(subpacket, 'revocationReason', this.stream.utf8(subpacket.length - 2));
                }
                break;

            case 30: // "Features",
                this.setSubpacket(subpacket, 'keyFeatures', this.stream.lookupFlags(Packet.KEY_FEATURES, subpacket.length - 1));
                break;

            case 32: // "Embedded Signature",
                if (this.stream.subParse(subpacket.length - 1, function () {
                    this.setSubpacket(subpacket, 'subsignature',  new Packet(this.stream));
                    subpacket.subsignature.parseSignaturePacket();
                    delete subpacket.subsignature.stream;
                }.bind(this))) {
                    this.parseError("Unhanded sub-signature data");
                }
                break;

            case 33: // "Issuer Fingerprint",
                this.setSubpacket(subpacket, 'issuerFingerprintVersion', this.stream.hex(1))
                this.setSubpacket(subpacket, 'issuerFingerprint', this.stream.hex(subpacket.length - 2))
                break;

            case 34: // "Reserved (Formerly Preferred AEAD Algorithms)",
                this.setSubpacket(subpacket, 'legacyPreferredAeadAlgorithms', this.stream.lookup(Packet.AEAD_ALGORITHMS));
                break;

            case 39: // "Preferred AEAD Ciphersuites",
                if ((subpacket.length - 1) % 2 != 0) {
                    this.setSubpacket(subpacket, 'data', this.stream.hex(subpacket.length - 1));
                    this.parseError('Invalid Preferred AEAD Ciphersuites length', subpacket.length - 1)
                } else {
                    var count = (subpacket.length - 1) / 2;
                    for (i = 0; i < count; ++i) {
                        this.setSubpacket(subpacket, 'cipher' + i, this.stream.lookup(Packet.SYMMETRIC_KEY_ALGORITHMS));
                        this.setSubpacket(subpacket, 'mode' + i, this.stream.lookup(Packet.AEAD_ALGORITHMS));
                    }
                }
                break;

            default:
                this.setSubpacket(subpacket, 'data', this.stream.hex(subpacket.length - 1));
                this.parseError('Unknown subpacketType', subpacket.subpacketType);

            }
            subpackets.push(subpacket);
        }
        return this.parseSignatureSubpackets(subpackets);
    },

    parseNotationDataSubpacket: function (subpacket) {
        this.setSubpacket(subpacket, 'flags', this.stream.lookupFlags(Packet.NOTATION_DATA_FLAGS, 4));

        var isHumanReadable = subpacket.flags.find(f => f.id == 0x80000000) ? true : false;

        this.setSubpacket(subpacket, 'notationDataNameLength', this.stream.uint16());
        this.setSubpacket(subpacket, 'notationDataValueLength', this.stream.uint16());

        if (isHumanReadable) {
            this.setSubpacket(subpacket, 'notationName', this.stream.utf8(subpacket.notationDataNameLength));
            this.setSubpacket(subpacket, 'notationValue', this.stream.utf8(subpacket.notationDataValueLength));
        } else {
            this.setSubpacket(subpacket, 'notationName', this.stream.hex(subpacket.notationDataNameLength));
            this.setSubpacket(subpacket, 'notationValue', this.stream.hex(subpacket.notationDataValueLength));
        }
    },

    parseSymEncryptedIntegrityProtectedDataPacket: function () {
        this.set('version', this.stream.octet());
        this.set('encryptedData', this.stream.hex(this.length));
    },

    parsePublicKeyPacket: function () {
        this.set('version', this.stream.octet());

        if (this.version === 6 || this.version === 4 || this.version === 3) {
            this.set('createdAt', this.stream.time());
            if (this.version === 3) {
                this.set('validDays', this.stream.uint16());
            }

            this.set('algorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));

            if (this.version === 6) {
                this.set('publicKeyOctetCount', this.stream.uint32());
            }

            this.parsePublicKey(this.algorithm.id);

        } else {
            this.parseError("Unsupported version", this.version);
        }

    },

    parsePublicKey: function (algo) {
        switch (algo) {
            case 1: // RSA S&E
            case 2: // RSA Encrypt Only
            case 3: // RSA Sign Only
                this.set('rsaModulus_n', this.stream.multiPrecisionInteger());
                this.set('rsaExponent_e', this.stream.multiPrecisionInteger());
                break;

            case 16: // ElGamal
                this.set('elGamalPrime_p', this.stream.multiPrecisionInteger());
                this.set('elGamalGroupGenerator_g', this.stream.multiPrecisionInteger());
                this.set('elGamalPublicKeyValue_y', this.stream.multiPrecisionInteger());
                break;

            case 17: // DSA
                this.set('dsaPrime_p', this.stream.multiPrecisionInteger());
                this.set('dsaGroupOrder_q', this.stream.multiPrecisionInteger());
                this.set('dsaGroupGenerator_g', this.stream.multiPrecisionInteger());
                this.set('dsaPublicKeyValue_y', this.stream.multiPrecisionInteger());
                break;

            case 18: // ECDH
                this.set('ecdhCurveOidLength', this.stream.octet());
                this.set('ecdhCurveOid', this.stream.hex(this.ecdhCurveOidLength));
                this.set('ecdhPublicKey', this.stream.multiPrecisionInteger());
                this.set('ecdhKdfLength', this.stream.octet());
                this.set('ecdhKdfReserved', this.stream.octet());
                this.set('ecdhKdfFunctionID', this.stream.octet());
                this.set('ecdhSymmetricalAlgorithmID', this.stream.octet());
                break;

            case 19: // ECDSA
                this.set('ecdsaCurveOidLength', this.stream.octet());
                this.set('ecdsaCurveOid', this.stream.hex(this.ecdsaCurveOidLength));
                this.set('ecdsaEcPoint', this.stream.multiPrecisionInteger());
                break;

            case 22: // EdDSALegacy
                this.set('ecdsaLegacyCurveOidLength', this.stream.octet());
                this.set('ecdsaLegacyCurveOid', this.stream.hex(this.ecdsaLegacyCurveOidLength));
                this.set('ecdsaLegacyEcPoint', this.stream.multiPrecisionInteger());
                break;

            case 25: // X25519
                this.set('x25519PublicKey', this.stream.hex(32));
                break;

            case 26: // X448
                this.set('x448PublicKey', this.stream.hex(56));
                break;

            case 27: // Ed25519
                this.set('ed25519PublicKey', this.stream.hex(32));
                break;

            case 28: // Ed448
                this.set('ed448PublicKey', this.stream.hex(57));
                break;

            default:
                this.parseError('Unsupported algorithm: ' + algo, algo);
                break;
        }
    },

    parseSecretKeyPacket: function () {
        this.parsePublicKeyPacket();

        var canParse = this.version === 6 || this.version === 4 || this.version === 3;

        if (!canParse) {
            this.parseError('Unsupported private key version', this.version);
        }

        var subpacket = this.namedSubpacket('stringToKey');

        this.setSubpacket(subpacket, 'specifierType', this.stream.lookup(Packet.STRING_TO_KEY_USAGES));
        var s2kUsage = subpacket.specifierType.id;

        var isCleartext = s2kUsage === 0;
        var isStringToKey = s2kUsage === 253 || s2kUsage === 254 || s2kUsage === 255;

        if (isCleartext) {
            this.parseSecretKeyCleartext();
            return;
        }

        if (this.version === 6) {
            if (s2kUsage === 255) {
                this.parseError('Invalid S2K for a V6 key', s2kUsage);
                return;
            }

            if (s2kUsage !== 0) {
                this.setSubpacket(subpacket, 'length', this.stream.octet());
            }
        }

        if (isStringToKey) {
            this.setSubpacket(subpacket, 'encryption', this.stream.lookup(Packet.SYMMETRIC_KEY_ALGORITHMS));
        }

        if (s2kUsage === 253) {
            this.setSubpacket(subpacket, 'aeadAlgorithm', this.stream.lookup(Packet.AEAD_ALGORITHMS));
        }

        if (this.version === 6 && (s2kUsage === 253 || s2kUsage == 254)) {
            this.setSubpacket(subpacket, 'fieldLength', this.stream.octet());
        }

        this.parseStringToKeySpecifier();

        if (s2kUsage === 253) {
            this.parseVersion6AeadIV(subpacket.aeadAlgorithm.id);
        } else {
            var ivLength = Packet.SECRET_KEY_ALGORITHM_BLOCK_SIZES[subpacket.encryption.id] ?? 0;

            if (ivLength > 0) {
                this.setSubpacket(subpacket, 'iv', this.stream.hex(ivLength));
            } else {
                this.parseError('Unable to determine IV length by block size');
                this.set('privateKeyMaterial', this.stream.hex(this.stream.remaining()));
            }
        }

        this.parseSecretKeyAndChecksumEncrypted(this.algorithm.id, s2kUsage, subpacket.encryption.id, subpacket.specifierType.id);
    },

    parseSecretKeyCleartext: function() {

        this.parseSecretKey(this.algorithm.id);

        if (this.version === 4 || this.version === 3) {
            this.set('checksum', this.stream.hex(this.stream.remaining()));
        }
    },

    parseSecretKeyAndChecksumEncrypted: function (keyAlgorithm, s2kUsage, s2kEncryption, s2kSpecifier) {
        // we aren't doing the crypto operations to get the secret key in cleartext,
        // so we will just report them as-is with '_encrypted' as part of their component names.

        if (s2kUsage === 0) {
            this.parseError("Invalid string to key usage", s2kUsage);
            return;
        }

        this.parseSecretKey(keyAlgorithm, '_encrypted');

        var subpacket = this.namedSubpacket('stringToKey');

        switch (s2kUsage) {
            case 253: // S2K: AEAD
                var checksumLength = Packet.AEAD_AUTHENTICATION_TAG_LENGTHS[subpacket.aeadAlgorithm.id] || 0;
                this.setSubpacket(subpacket, 'aeadAuthenticationTag', this.stream.hex(checksumLength));
                break;

            case 254: // S2K: CFB
                this.setSubpacket(subpacket, 'cfbHash', this.stream.hex(20));
                break;

            case 255: // S2K: MalleableCFB
                this.setSubpacket(subpacket, 'malleableCfbChecksum', this.stream.hex(2));
                break;

            default: // Any other symmetric key encryption algorithm
                this.setSubpacket(subpacket, 'checksum', this.stream.hex(2));
                break;
        }
    },

    parseSecretKey: function (keyAlgorithm, suffix = '') {
        switch (keyAlgorithm) {
            case 1: // RSA S&E
            case 2: // RSA Encrypt Only
            case 3: // RSA Sign Only
                this.set('rsaD' + suffix, this.stream.multiPrecisionInteger());
                this.set('rsaP' + suffix, this.stream.multiPrecisionInteger());
                this.set('rsaQ' + suffix, this.stream.multiPrecisionInteger());
                this.set('rsaU' + suffix, this.stream.multiPrecisionInteger());
                break;

            case 16: // ElGamal
                this.set('elGamalX' + suffix, this.stream.multiPrecisionInteger());
                break;

            case 17: // DSA
                this.set('dsaX' + suffix, this.stream.multiPrecisionInteger());
                break;

            case 18: // ECDH
                this.set('ecdhSecretKey' + suffix, this.stream.multiPrecisionInteger());
                break;

            case 19: // ECDSA
                this.set('ecdsaSecretKey' + suffix, this.stream.multiPrecisionInteger());
                break;

            case 22: // EdDSALegacy
                this.set('edDsaLegacysecretKey' + suffix, this.stream.multiPrecisionInteger());
                break;

            case 25: // X25519
                this.set('x25519SecretKey' + suffix, this.stream.hex(32));
                break;

            case 26: // X448
                this.set('x448SecretKey' + suffix, this.stream.hex(56));
                break;

            case 27: // Ed25519
                this.set('ed25519SecretKey' + suffix, this.stream.hex(32));
                break;

            case 28: // Ed448
                this.set('ed448SecretKey' + suffix, this.stream.hex(57));
                break;

            case 253: // S2K: AEAD
            case 254: // S2K: CFB
            case 255: // S2K: MalleableCFB
                this.parseError('Got string to key usage value when key algorithm was expected', keyAlgorithm);
                break;

            default:
                this.parseError('Unknown algorithm', keyAlgorithm);
                break;
        }
    },

    parseOnePassSignaturePacket: function () {
        this.set('version', this.stream.octet());

        if (this.version !== 6 && this.version !== 3) {
            this.parseError('Unsupported one-pass signature packet version', this.version);
            return;
        }

        this.set('signatureTypeID', this.stream.octet());
        this.set('hashAlgorithm', this.stream.lookup(Packet.HASH_ALGORITHMS));
        this.set('publicKeyAlgorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));

        if (this.version === 6) {
            this.parseVersion6Salt(this.hashAlgorithm.id);
        }

        if (this.version === 3) {
            this.set('signingKeyID', this.stream.octet());
        } else {
            this.set('signingKeyID', this.stream.hex(32));
        }

        this.set('isNested', this.stream.octet() == 0 ? true : false);
    },

    parseLiteralDataPacket: function () {
        this.set('format', this.stream.lookup(Packet.LITERAL_DATA_FORMATS));
        this.set('filenameLength', this.stream.octet());

        if (this.filenameLength > 0) {
            this.set('filename', this.stream.hex(this.filenameLength));
        }

        this.set('date', this.stream.time());

        var remaining = this.stream.remaining();
        var formatIsText = this.format.id === 116 || this.format.id === 117;

        var data = formatIsText
            ? this.stream.utf8(remaining)
            : this.stream.hex(remaining);

        this.set('data', data);
    },

    parseStringToKeySpecifier: function () {

        var subpacket = this.namedSubpacket('stringToKey');

        this.setSubpacket(subpacket, 'specifierType', this.stream.lookup(Packet.STRING_TO_KEY_SPECIFIERS));
        var s2kSpecifierLength = Packet.STRING_TO_KEY_SPECIFIER_FIELD_SIZES[subpacket.specifierType.id] || 0;

        if (s2kSpecifierLength === 0) {
            this.parseError("Unexpected string to key specifier or length", subpacket.specifierType);
            return;
        }

        var remainingLength = s2kSpecifierLength;

        switch (subpacket.specifierType.id) {
            case 0: // Simple S2K
                this.setSubpacket(subpacket, 'hashAlgorithm', this.stream.lookup(Packet.HASH_ALGORITHMS));
                break;

            case 1: // Salted S2K
                this.setSubpacket(subpacket, 'hashAlgorithm', this.stream.lookup(Packet.HASH_ALGORITHMS));
                this.setSubpacket(subpacket, 'salt', this.stream.hex(8));
                break;

            case 3: // Iterated and Salted S2K
                this.setSubpacket(subpacket, 'hashAlgorithm', this.stream.lookup(Packet.HASH_ALGORITHMS));
                this.setSubpacket(subpacket, 'salt', this.stream.hex(8));
                this.setSubpacket(subpacket, 'codedCount', this.stream.octet());
                break;

            case 4: // Argon2
                this.setSubpacket(subpacket, 'argonSalt', this.stream.hex(16));
                this.setSubpacket(subpacket, 'argonPassesT', this.stream.octet());
                this.setSubpacket(subpacket, 'argonParallelismP', this.stream.octet());
                this.setSubpacket(subpacket, 'argonEncodedMemoryM', this.stream.octet());
                break;

            default:
                this.parseError("Unsupported string to key specifier type", subpacket.specifierType);
                break;
        }
    },

    parseVersion6AeadIV: function (aeadAlgorithm) {
        var subpacket = this.namedSubpacket('stringToKey');
        var nonceLength = Packet.AEAD_IV_LENGTHS[aeadAlgorithm];
        this.setSubpacket(subpacket, 'aeadNonce', this.stream.hex(nonceLength));
    },

    parseVersion6Salt: function (hashAlgorithmID) {
        var saltSize = this.stream.octet();
        var expectedSaltSize = Packet.HASH_SALT_SIZES[hashAlgorithmID] || 0;

        var isMatchingSaltSize = saltSize == expectedSaltSize;
        var isExperimentalOrPrivateUseHashAlgo = this.getIsExperimentalOrPrivateUseIdentifier(hashAlgorithmID);

        if (isMatchingSaltSize || isExperimentalOrPrivateUseHashAlgo) {
            this.set('saltSize', saltSize);
            this.set('salt', this.stream.hex(this.saltSize));
        } else if (saltSize > 0 && expectedSaltSize == 0) {
            this.parseError('Non-zero salt size when zero was expected', saltSize);
        }
    },

    getIsExperimentalOrPrivateUseIdentifier(id) {
        return id >= 100 && id <= 110;
    },

    getStringToKeySpecifierTypeFromLength: function (length) {
        for (const key in Packet.STRING_TO_KEY_SPECIFIER_FIELD_SIZES) {
            if (Packet.STRING_TO_KEY_SPECIFIER_FIELD_SIZES[key] === length) {
                return new LookupResult(Packet.STRING_TO_KEY_SPECIFIERS[key], key);
            }
        }

        return null;
    },

    namedSubpacket: function (name) {
        if (this[name] !== undefined && this[name].subpackets) {
            return this[name][0]
        }

        var subpackets = [];
        subpackets.subpackets = true;
        subpackets.name = name;

        var subpacket = this.nextSubpacket();
        subpackets.push(subpacket);

        this.set(name, subpackets);

        return subpacket;
    },

    parseError: function (msg, arg) {
        if (arg) {
            msg = msg + ": " + arg;
        }

        this.parseErrors = (this.parseErrors || []);
        this.parseErrors.push(msg);
        console.warn("parse error", this, msg);
    },

    toDOM: function (msg) {
        var tr = document.createElement('tr');
        var head = document.createElement('td');
        tr.appendChild(head);
        head.innerHTML = '<pre class="bytes">' + this.coloredBytes() + '</pre>';
        var body = document.createElement('td');
        var title = document.createElement('h3');
        if (this.parseErrors) {
            title.style.color = 'red';
        }
        title.innerText = this.packet;
        body.appendChild(title);
        var details = document.createElement('pre');
        details.className = 'details';

        var data = {};
        details.innerHTML = this.coloredData();
        body.appendChild(details);
        tr.appendChild(body);
        return tr;
    }
};

function decode(text) {
    var table = document.getElementsByTagName('tbody')[0];
    table.innerHTML = '';

    this.location.hash = encodeURIComponent(text);

    text = text
        .split('\n')
        .map(l => l.trimStart())
        .join('\n');

    var bytes = Base64.unarmor(text);
    window.bytes = bytes;
    window.packets = [];
    var i = 0;

    var stream = new Stream(bytes);

    do {
        var packet = new Packet(stream);
        packet.parse();
        packets.push(packet);
    } while (stream.pos < stream.end);

    packets.forEach(function (packet) {
        table.appendChild(packet.toDOM());
    });
}

function hover(spans) {

    var toClean = document.getElementsByClassName('hovered');
    while (toClean[0]) {
        toClean[0].className = '';
    }

    for (i = spans[0]; i < spans[1]; i++) {
        var span = document.getElementById('byte-' + i);
        span.className = 'hovered';
    }
}

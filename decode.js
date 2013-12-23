function Packet(stream) {
    this.stream = stream;
}

Packet.TAGS = {
    0: "Reserved - a packet tag MUST NOT have this value",
    1: "Public-Key Encrypted Session Key Packet",
    2: "Signature Packet",
    3: "Symmetric-Key Encrypted Session Key Packet",
    4: "One-Pass Signature Packet",
    5: "Secret-Key Packet",
    6: "Public-Key Packet",
    7: "Secret-Subkey Packet",
    8: "Compressed Data Packet",
    9: "Symmetrically Encrypted Data Packet",
    10: "Marker Packet",
    11: "Literal Data Packet",
    12: "Trust Packet",
    13: "User ID Packet",
    14: "Public-Subkey Packet",
    17: "User Attribute Packet",
    18: "Sym. Encrypted and Integrity Protected Data Packet",
    19: "Modification Detection Code Packet",
    60: "Private or Experimental Values",
    61: "Private or Experimental Values",
    62: "Private or Experimental Values",
    63: "Private or Experimental Values"
};

Packet.PUBLIC_KEY_ALGORITHMS = {
    1: "RSA (Encrypt or Sign)",
    2: "RSA Encrypt-Only",
    3: "RSA Sign-Only",
    16: "Elgamal (Encrypt-Only)",
    17: "DSA (Digital Signature Algorithm)",
    18: "Reserved for Elliptic Curve",
    19: "Reserved for ECDSA",
    20: "Reserved (formerly Elgamal Encrypt or Sign)",
    21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)",
    100: "Private/Experimental algorithm",
    101: "Private/Experimental algorithm",
    102: "Private/Experimental algorithm",
    103: "Private/Experimental algorithm",
    104: "Private/Experimental algorithm",
    105: "Private/Experimental algorithm",
    106: "Private/Experimental algorithm",
    107: "Private/Experimental algorithm",
    108: "Private/Experimental algorithm",
    109: "Private/Experimental algorithm",
    110: "Private/Experimental algorithm"
};

Packet.SYMMETRIC_KEY_ALGORITHMS = {
    0: "Plaintext or unencrypted data",
    1: "IDEA",
    2: "TripleDES (DES-EDE, 168 bit key derived from 192)",
    3: "CAST5 (128 bit key, as per RFC2144)",
    4: "Blowfish (128 bit key, 16 rounds)",
    5: "Reserved",
    6: "Reserved",
    7: "AES with 128-bit key",
    8: "AES with 192-bit key",
    9: "AES with 256-bit key",
    10: "Twofish with 256-bit key",
    100: "Private/Experimental algorithm",
    101: "Private/Experimental algorithm",
    102: "Private/Experimental algorithm",
    103: "Private/Experimental algorithm",
    104: "Private/Experimental algorithm",
    105: "Private/Experimental algorithm",
    106: "Private/Experimental algorithm",
    107: "Private/Experimental algorithm",
    108: "Private/Experimental algorithm",
    109: "Private/Experimental algorithm",
    110: "Private/Experimental algorithm"
};

Packet.COMPRESSION_ALGORITHMS = {
    0: "Uncompressed",
    1: "ZIP",
    2: "ZLIB",
    3: "BZip2",
    100: "Private/Experimental algorithm",
    101: "Private/Experimental algorithm",
    102: "Private/Experimental algorithm",
    103: "Private/Experimental algorithm",
    104: "Private/Experimental algorithm",
    105: "Private/Experimental algorithm",
    106: "Private/Experimental algorithm",
    107: "Private/Experimental algorithm",
    108: "Private/Experimental algorithm",
    109: "Private/Experimental algorithm",
    110: "Private/Experimental algorithm"
};

Packet.HASH_ALGORITHMS = {
    1: "MD5",
    2: "SHA1",
    3: "RIPEMD160",
    8: "SHA256",
    9: "SHA384",
    10: "SHA512",
    11: "SHA224",
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
    32: "Key revocation signature",
    40: "Subkey revocation signature",
    48: "Certification revocation signature",
    64: "Timestamp signature.",
    80: "Third-Party Confirmation signature."
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
    11: "Preferred Symmetric Algorithms",
    12: "Revocation Key",
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
    100: "Private or experimental",
    101: "Private or experimental",
    102: "Private or experimental",
    103: "Private or experimental",
    104: "Private or experimental",
    105: "Private or experimental",
    106: "Private or experimental",
    107: "Private or experimental",
    108: "Private or experimental",
    109: "Private or experimental",
    110: "Private or experimental"
};

Packet.KEYSERVER_PREFERENCES = {
    128: "No-modify"
};

Packet.KEY_FLAGS = {
    1: 'certify',
    2: 'sign',
    4: 'encrypt communications',
    8: 'encrypt storage',
    16: 'split key',
    32: 'authentication',
    128: 'shared key'
};

Packet.KEY_FEATURES = {
    1: 'Modification detection'
};

Packet.prototype = {
    dump: function () {
        return Hex.encodePretty(this.stream.bytes.slice(this.start, this.end));
    },
    parse: function () {
        this.start = this.stream.pos;
        this.cipherTypeByte = this.stream.octet();

        if (!(this.cipherTypeByte & 0x80)) {
            alert('Invalid packet format');
        }

        if (this.cipherTypeByte & 0x40) {
            this.parseNewHeader();
        } else {
            this.parseOldHeader();
        }

        if (this.stream.subParse(this.length, function () {
            this.packet = Packet.TAGS[this.tag];
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
            this.length = 0;
            break;

        case 2: // 4-byte length
            this.length = this.stream.uint32();

            break;
        case 1: // 2-byte length
            this.length = this.stream.uint16();

            break;
        case 0: // 1-byte length
            this.length = this.stream.octet();
        }
    },

    // This cipher type byte: 11xxxxxx
    // x: type
    parseNewHeader: function () {
        this.tag = this.cipherTypeByte & 0x3f;

        this.length = this.stream.variableLengthLength('support partial');
    },

    parseBody: function () {
        switch (this.tag) {
        case 1:
            this.parsePublicKeyEncryptedSessionKey();
            break;
        case 2:
            this.parseSignaturePacket();
            break;

        case 5:
        case 7:
            this.parseSecretKeyPacket();
            break;

        case 13:
            this.parseUserIdPacket();
            break;

        case 18:
            this.parseSymEncryptedIntegrityProtectedDataPacket();
            break;
        }
    },

    parsePublicKeyEncryptedSessionKey: function () {
        this.version = this.stream.octet();

        if (this.version === 3) {
            this.keyId = this.stream.hex(8);
            this.publicKeyAlgorithmId = this.stream.octet();
            this.publicKeyAlgorithm = Packet.PUBLIC_KEY_ALGORITHMS[this.publicKeyAlgorithmId];

            if (this.publicKeyAlgorithmId === 1) {
                this.stream.multiPrecisionInteger();
            } else {
                parseError("Unknown publicKeyAlgorithmId", this.publicKeyAlgorithmId);
            }

        } else {
            parseError("Unknown version", this.version);
        }
    },

    parseUserIdPacket: function () {
        this.userId = this.stream.utf8(this.length);
    },

    parseSignaturePacket: function () {
        this.version = this.stream.octet();
        if (this.version === 4) {

            this.signatureType = this.stream.lookup(Packet.SIGNATURE_TYPES);
            this.publicKeyAlgorithm = this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS);
            this.hashAlgorithm = this.stream.lookup(Packet.HASH_ALGORITHMS);

            this.hashedDataCount = this.stream.uint16();
            if (this.stream.subParse(this.hashedDataCount, function () {
                this.hashedSubPackets = this.parseSignatureSubpackets();
            }.bind(this))) {
                this.parseError("Unparsed hashed sub packet data");
            }

            this.unhashedDataCount = this.stream.uint16();
            if (this.stream.subParse(this.unhashedDataCount, function () {
                this.unhashedSubPackets = this.parseSignatureSubpackets();
            }.bind(this))) {
                this.parseError("Unparsed unhashed sub packet data");
            }

            this.signedHashValuePrefix = this.stream.hex(2);
            this.signature = this.stream.multiPrecisionInteger();

        } else {
            this.parseError('Unsupported version', this.version);

        }
    },

    parseSignatureSubpackets: function (subpackets) {
        subpackets = subpackets || [];
        if (this.stream.pos >= this.stream.end) {
            return subpackets;
        } else {

            var subpacket = {},
                length = this.stream.variableLengthLength();
            subpacket.subpacketTypeId = this.stream.octet();
            subpacket.subpacketType = Packet.SIGNATURE_SUBPACKET_TYPES[subpacket.subpacketTypeId];
            var i;

            switch (subpacket.subpacketTypeId) {
            case 2:
                subpacket.creationTime = this.stream.time();
                break;

            case 11:
                subpacket.preferredSymmetricAlgorithms = this.stream.lookupArray(Packet.SYMMETRIC_KEY_ALGORITHMS, length - 1);
                break;

            case 16:
                subpacket.keyId = this.stream.hex(8);
                break;

            case 21:
                subpacket.preferredHashAlgorithms = this.stream.lookupArray(Packet.HASH_ALGORITHMS, length - 1);
                break;

            case 22:
                subpacket.preferredCompressionAlgorithms = this.stream.lookupArray(Packet.COMPRESSION_ALGORITHMS, length - 1);
                break;

            case 23:
                subpacket.keyServerPreferences = this.stream.lookupFlags(Packet.KEYSERVER_PREFERENCES, length - 1);
                break;

            case 27:
                subpacket.keyFlags = this.stream.lookupFlags(Packet.KEY_FLAGS, length - 1);
                break;

            case 30:
                subpacket.keyFeatures = this.stream.lookupFlags(Packet.KEY_FEATURES, length - 1);
                break;

            case 32:
                if (this.stream.subParse(length - 1, function () {
                    subpacket.subsignature =  new Packet(this.stream);
                    subpacket.subsignature.parseSignaturePacket();
                    delete subpacket.subsignature.stream;
                }.bind(this))) {
                    this.parseError("Unhanded sub-signature data");
                }
                break;

            default:
                subpacket.data = this.stream.hex(length - 1);
                this.parseError('Unknown subpacketTypeId', subpacket.subpacketTypeId);

            }
            subpackets.push(subpacket);
        }
        return this.parseSignatureSubpackets(subpackets);
    },

    parseSymEncryptedIntegrityProtectedDataPacket: function () {
        this.encryptedData = this.stream.hex(this.length);
    },

    parseSecretKeyPacket: function () {
        this.version = this.stream.octet();

        if (this.version === 4) {
            this.createdAt = this.stream.time();

            this.algorithmId = this.stream.octet();
            this.algorithm = Packet.PUBLIC_KEY_ALGORITHMS[this.algorithmId];
            if (this.algorithmId === 1) {

                this.n = this.stream.multiPrecisionInteger();
                this.e = this.stream.multiPrecisionInteger();
                this.stringToKeyConventions = this.stream.octet();

                if (this.stringToKeyConventions === 254 || this.stringToKeyConventions === 255) {
                    this.stringToKeyEncryptionId = this.stream.octet();
                    this.stringToKeySpecifierId = this.stream.octet();

                    if (this.stringToKeySpecifierId == 3) {
                        this.stringToKeySpecifier = "Iterated and Salted S2K";

                        this.stringToKeyHashId = this.stream.octet();
                        this.stringToKeyHashSalt = this.stream.hex(8);
                        this.stringToKeyIterationCount = this.stream.iterationCount();

                    } else {

                        this.paseError('Unknown stringToKeySpecifierId', this.stringToKeySpecifierId);
                    }

                } else if (this.stringToKeyConventions === 0) {
                    this.d = this.stream.multiPrecisionInteger();
                    this.p = this.stream.multiPrecisionInteger();
                    this.q = this.stream.multiPrecisionInteger();
                    this.u = this.stream.multiPrecisionInteger();

                    this.checksum = this.stream.uint16();

                } else {
                    this.parseError("No support for old encrypted keys", this.stringToKeyConventions);
                }

            } else {
                this.parseError("Unkown algorithmId", this.algorithmId);
            }

        } else {
            this.parseError("Unknown version", this.version);
        }
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
        head.innerHTML = '<pre>' + this.dump() + '</pre>';
        var body = document.createElement('td');
        var title = document.createElement('h3');
        if (this.parseErrors) {
            title.style.color = 'red';
        }
        title.innerText = this.packet;
        body.appendChild(title);
        var details = document.createElement('pre');

        var data = {};
        for (var key in this) {
            if (key === 'stream' || key === 'start' || key === 'end' || key === 'begin' || key === 'length') {
                continue;
            }
            if (!this.hasOwnProperty(key)) {
                continue;
            }
            data[key] = this[key];
        }
        details.innerText = JSON.stringify(data, null, 4);
        body.appendChild(details);
        tr.appendChild(body);
        console.log(tr.innerHTML);
        return tr;
    }
};

function decode(text) {

    this.location.hash = text;

    text = text.split("\n\n")[1].split("\n=")[0].replace(/\n/g, "");

    var bytes = Base64.decode(text);
    window.packets = window.packets || [];
    var i = 0;
    var table = document.getElementsByTagName('tbody')[0];

    var stream = new Stream(bytes);

    do {
        var packet = new Packet(stream);
        packet.parse();
        packets.push(packet);
        console.log(packet);
    } while (stream.pos < stream.end);

    table.innerHTML = '';
    packets.forEach(function (packet) {
        table.appendChild(packet.toDOM());
    });
}

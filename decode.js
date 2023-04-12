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
    22: "Ed25519 (Encrypt or Sign)",
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
};

Packet.COMPRESSION_ALGORITHMS = {
    0: "Uncompressed",
    1: "ZIP",
    2: "ZLIB",
    3: "BZip2",
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
    33: "Issuer Fingerprint",
    34: "Preferred AEAD Algorithms",
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

Packet.STRING_TO_KEY_SPECIFIERS = {
    0: "Simple S2K",
    1: "Salted S2K",
    2: "Reserved value",
    3: "Iterated and Salted S2K"
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
                output += "  subpackets:\n";
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
        this.nameSpans[name] = [this.lastColorEnd || 0, this.stream.pos];

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
        case 1:
            this.parsePublicKeyEncryptedSessionKey();
            break;
        case 2:
            this.parseSignaturePacket();
            break;

        case 6:
        case 14:
            this.parsePublicKeyPacket();
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
        this.set('version', this.stream.octet());

        if (this.version === 3) {
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

    parseUserIdPacket: function () {
        this.set('userId', this.stream.utf8(this.length));
    },

    parseSignaturePacket: function () {
        this.set('version', this.stream.octet());
        if (this.version === 4) {

            this.set('signatureType', this.stream.lookup(Packet.SIGNATURE_TYPES));
            this.set('publicKeyAlgorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));
            this.set('hashAlgorithm', this.stream.lookup(Packet.HASH_ALGORITHMS));

            this.set('hashedDataCount', this.stream.uint16());
            if (this.stream.subParse(this.hashedDataCount, function () {
                this.hashedSubPackets = this.parseSignatureSubpackets();
            }.bind(this))) {
                this.parseError("Unparsed hashed sub packet data");
            }

            this.set('unhashedDataCount', this.stream.uint16());
            if (this.stream.subParse(this.unhashedDataCount, function () {
                this.unhashedSubPackets = this.parseSignatureSubpackets();
            }.bind(this))) {
                this.parseError("Unparsed unhashed sub packet data");
            }

            this.set('signedHashValuePrefix', this.stream.hex(2));
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

            this.setSubpacket(subpacket, 'subpacketType', this.stream.lookup(Packet.SIGNATURE_SUBPACKET_TYPES));
            var i;

            switch (subpacket.subpacketType.id) {
            case 2:
                this.setSubpacket(subpacket, 'creationTime', this.stream.time());
                break;

            case 11:
                this.setSubpacket(subpacket, 'preferredSymmetricAlgorithms', this.stream.lookupArray(Packet.SYMMETRIC_KEY_ALGORITHMS, subpacket.length - 1));
                break;

            case 16:
                this.setSubpacket(subpacket, 'keyId', this.stream.hex(8));
                break;

            case 21:
                this.setSubpacket(subpacket, 'preferredHashAlgorithms', this.stream.lookupArray(Packet.HASH_ALGORITHMS, subpacket.length - 1));
                break;

            case 22:
                this.setSubpacket(subpacket, 'preferredCompressionAlgorithms', this.stream.lookupArray(Packet.COMPRESSION_ALGORITHMS, subpacket.length - 1));
                break;

            case 23:
                this.setSubpacket(subpacket, 'keyServerPreferences', this.stream.lookupFlags(Packet.KEYSERVER_PREFERENCES, subpacket.length - 1));
                break;

            case 27:
                this.setSubpacket(subpacket, 'keyFlags', this.stream.lookupFlags(Packet.KEY_FLAGS, subpacket.length - 1));
                break;

            case 30:
                this.setSubpacket(subpacket, 'keyFeatures', this.stream.lookupFlags(Packet.KEY_FEATURES, subpacket.length - 1));
                break;

            case 32:
                if (this.stream.subParse(subpacket.length - 1, function () {
                    this.setSubpacket(subpacket, 'subsignature',  new Packet(this.stream));
                    subpacket.subsignature.parseSignaturePacket();
                    delete subpacket.subsignature.stream;
                }.bind(this))) {
                    this.parseError("Unhanded sub-signature data");
                }
                break;

              case 33:
                this.setSubpacket(subpacket, 'issuerFingerprintVersion', this.stream.hex(1))
                this.setSubpacket(subpacket, 'issuerFingerprint', this.stream.hex(subpacket.length - 2))
                break;

            default:
                this.setSubpacket(subpacket, 'data', this.stream.hex(subpacket.length - 1));
                this.parseError('Unknown subpacketType', subpacket.subpacketType);

            }
            subpackets.push(subpacket);
        }
        return this.parseSignatureSubpackets(subpackets);
    },

    parseSymEncryptedIntegrityProtectedDataPacket: function () {
        this.set('version', this.stream.octet());
        this.set('encryptedData', this.stream.hex(this.length));
    },

    parsePublicKeyPacket: function () {
        this.set('version', this.stream.octet());

        if (this.version === 4 || this.version === 3) {
            this.set('createdAt', this.stream.time());
            if (this.version === 3) {
                this.set('validDays', this.stream.uint16());
            }

            this.set('algorithm', this.stream.lookup(Packet.PUBLIC_KEY_ALGORITHMS));

            if (this.algorithm.id === 1) {
                this.set('n', this.stream.multiPrecisionInteger());
                this.set('e', this.stream.multiPrecisionInteger());
            } else {
                this.parseError("Unsupported algorithm", this.algorithm);
            }

        } else {
            this.parseError("Unsupported version", this.version);
        }

    },

    parseSecretKeyPacket: function () {
        this.parsePublicKeyPacket();

        if ((this.version === 4 || this.version === 3) && this.algorithm.id === 1) {

            this.set('stringToKeyConventions', this.stream.octet());

            if (this.stringToKeyConventions === 254 || this.stringToKeyConventions === 255) {
                this.set('stringToKeyEncryption', this.stream.lookup(Packet.SYMMETRIC_KEY_ALGORITHMS));
                this.set('stringToKeySpecifier', this.stream.lookup(Packet.STRING_TO_KEY_SPECIFIERS));

                if (this.stringToKeySpecifier.id === 3) {
                    this.set('stringToKeySpecifier', "Iterated and Salted S2K");

                    this.set('stringToKeyHash', this.stream.lookup(Packet.HASH_ALGORITHMS));
                    this.set('stringToKeyHashSalt', this.stream.hex(8));
                    this.set('stringToKeyIterationCount', this.stream.iterationCount());

                    if (this.stringToKeyEncryption.id === 3) {
                        this.set('stringToKeyIV', this.stream.hex(16));

                        // TODO: this doesn't seem long enough
                        this.set('encryptedKey', this.stream.hex(this.stream.end - this.stream.pos));
                    } else {
                        this.parseError('Unknown encryption algorithm', this.stringToKeyEncryption);
                    }



                } else {

                    this.parseError('Unknown stringToKeySpecifier', this.stringToKeySpecifier);
                }

            } else if (this.stringToKeyConventions === 0) {
                this.set('d', this.stream.multiPrecisionInteger());
                this.set('p', this.stream.multiPrecisionInteger());
                this.set('q', this.stream.multiPrecisionInteger());
                this.set('u', this.stream.multiPrecisionInteger());

                this.set('checksum', this.stream.uint16());

            } else {
                this.set('stringToKeyEncryption', new LookupResult(Packet.SYMMETRIC_KEY_ALGORITHMS[this.stringToKeyConventions], this.stringToKeyConventions));
                this.set('encryptedKey', this.stream.hex(this.stream.end - this.stream.pos));
            }
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

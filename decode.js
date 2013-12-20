function Packet(bytes, i) {
    this.start = i;
    this.bytes = bytes;
    this.end = bytes.length;
}

Packet.prototype = {
    header: function (i) {
        return this.bytes[this.start + i];
    },
    body: function (i) {
        var idx = this.begin + i;
        if (idx < this.begin || idx > this.end) {
            this.parseError("tried to access index " + i + " of " + this.length);
            return NaN;
        } else {
            return this.bytes[idx];
        }
    },
    substr: function (i, n) {
        var idx = this.begin + i;
        if (idx < this.begin || idx + n > this.end) {
            this.parseError("tried to access substr " + i + " to " + n + " of " + this.length);
            return [];
        } else {
            return this.bytes.slice(idx, idx + n);
        }
    },
    parseMultiPrecisionInteger: function (i, name) {
        var bitLength = (this.body(i) << 8) + this.body(i + 1);
        var byteLength = Math.floor((bitLength + 7) / 8);
        console.log(i, name, bitLength, byteLength, i + byteLength + 2, this.end);
        this[name] = Hex.encode(this.substr(i + 2, byteLength));

        return i + byteLength + 2;
    },
    dump: function () {
        return Hex.encodePretty(this.bytes.slice(this.start, this.length));
    },
    parse: function () {
        this.cipherTypeByte = this.header(0);

        if (!(this.header(0) & 0x80)) {
            alert('Invalid packet format');
        }

        if (this.header(0) & 0x40) {
            this.parseNewHeader();
        } else {
            this.parseOldHeader();
        }

        this.parseBody();
    },

    // This cipher type byte: 10xxxxyy
    // x: type
    // y: size of the length field
    parseOldHeader: function () {
        var size = this.header(0) & 0x3;
        this.type = (this.header(0) & 0x3c) >> 2;

        switch (size) {
        case 3: // 0-byte length
            this.length = 0;
            this.begin = this.start + 1;
            break;

        case 2: // 4-byte length
            this.length = this.header(1);
            this.length = (length << 8) + this.header(2);
            this.length = (length << 8) + this.header(3);
            this.length = (length << 8) + this.header(4);

            this.begin = this.start + 5;

            break;
        case 1: // 2-byte length
            this.length = (this.header(1) << 8) + this.header(2);

            this.begin = this.start + 3;

            break;
        case 0: // 1-byte length
            this.length = this.header(1);

            this.begin = this.start + 2;
        }
        this.end = this.begin + this.length;
    },

    // This cipher type byte: 11xxxxxx
    // x: type
    parseNewHeader: function () {
        this.type = this.header(0) & 0x3f;

        var length = this.header(1);

        if (length === 255) {
            this.length = (this.header(2) << 24) + (this.header(3) << 16) + (this.header(4) << 8) + this.header(5);
            this.begin = this.start + 6;

        } else if (length >= 224) {
            alert("sorry, partial body lengths aren't supported.");

        } else if (length >= 192) {
            this.length = (length - 192) << 8 + this.header(2) + 192;
            this.begin = this.start + 3;

        } else {
            this.length = length;
            this.begin = this.start + 2;
        }

        this.end = this.begin + this.length;
    },

    parseBody: function () {
        switch (this.type) {
        case 1:
            this.parsePublicKeyEncryptedSessionKey();
            break;
        case 2:
            break;

        case 5:
            this.parseSecretKeyPacket();
            break;

        case 7:
            break;

        case 18:
            this.parseSymEncryptedIntegrityProtectedDataPacket();
            break;
        }
    },

    parsePublicKeyEncryptedSessionKey: function () {
        this.version = this.body(0);
        this.packed = "Public Key Encrypted Session Key";

        if (this.version === 3) {
            this.keyId = Hex.encode(this.substr(1, 8));
            this.algorithmId = this.body(9);

            if (this.algorithmId === 1) {
                this.algorithm = "RSA";
                this.parseMultiPrecisionInteger(10, 'data');
            } else {
                parseError("Unknown algorithmId", this.algorithmId);
            }

        } else {
            parseError("Unknown version", this.version);
        }
    },

    parseSymEncryptedIntegrityProtectedDataPacket: function () {
        this.encryptedData = this.substr(0, this.length);
    },

    parseSecretKeyPacket: function () {
        this.version = this.body(0);

        if (this.version === 4) {
            this.createdAt = new Date(
                ((this.body(1) << 24) + (this.body(2) << 16) + (this.body(3) << 8) + this.body(4)) * 1000
            );

            this.algorithmId = this.body(5);
            if (this.algorithmId === 1) {
                this.algorithm = "RSA";

                var offset = 6;
                offset = this.parseMultiPrecisionInteger(offset, 'n');
                offset = this.parseMultiPrecisionInteger(offset, 'e');
                this.stringToKeyConventions = this.body(offset);

                if (this.stringToKeyConventions === 254 || this.stringToKeyConventions === 255) {
                    this.encryptionAlgorithm = this.body(offset + 1);
                    this.encryptionSpecifier = this.body(offset + 2);

                }

                if (this.stringToKeyConventions === 0) {
                    offset += 1;
                    offset = this.parseMultiPrecisionInteger(offset, 'd');
                    offset = this.parseMultiPrecisionInteger(offset, 'p');
                    offset = this.parseMultiPrecisionInteger(offset, 'q');
                    offset = this.parseMultiPrecisionInteger(offset, 'u');

                } else {
                    this.parseError("No support for encrypted keys", this.stringToKeyConventions);
                }

            } else {
                this.parseError("Unkown algorithmId", this.algorithmId);
            }

        } else {
            this.parseError("Unknown version", this.version);
        }
    },

    parseError: function (msg) {
        console.warn("parse error", this, msg);
    }
};

function decode(text) {

    text = text.split("\n\n")[1].split("\n=")[0].replace(/\n/g, "");

    var bytes = Base64.decode(text);
    window.packets = window.packets || [];
    var i = 0;

    do {
        var packet = new Packet(bytes, i);
        packet.parse();
        i = packet.end;
        packets.push(packet);
        console.log(packet);
    } while (i < bytes.length);
}


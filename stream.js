function Stream(bytes, start, end) {
    this.bytes = bytes;
    this.start = start || 0;
    this.end = end || bytes.length;

    this.pos = this.start;
}

function LookupResult(string, id) {
    this.toString = this.toJSON = function () {
        return (string || "undefined") + " (0x" + id.toString(16) + ")";
    };
    this.id = id;
}

Stream.prototype = {
    toArray: function () {
        return this.bytes.slice(this.start, this.end);
    },
    octet: function () {
        if (this.pos >= this.end) {
            return NaN;
        } else {
            return this.bytes[this.pos++];
        }
    },

    uint: function (n) {
        var ret = 0;

        while (n > 0) {
            ret = (ret << 8) + this.octet();

            n -= 1;
        }

        return ret;
    },

    uint16: function () {
        return this.uint(2);
    },

    uint32: function () {
        return this.uint(4);
    },

    time: function () {
        return new Date(this.uint32() * 1000);
    },

    hex: function (n) {
        var output = "";
        while (n > 0) {
            output += Hex.encode(this.octet());
            n -= 1;
        }
        return output;
    },

    utf8: function (n) {
        return unescape(this.hex(n).replace(/../g, function (pair) {
            return '%' + pair;
        }));
    },

    multiPrecisionInteger: function () {
        var bitLength = this.uint16();
        var byteLength = Math.floor((bitLength + 7) / 8);
        return this.hex(byteLength);
    },

    // RFC 4880 3.7.1.3
    iterationCount: function () {
        var c = this.octet();
        return (16 + (c & 15)) << ((c >> 4) + 6);
    },

    // RFC 4880 4.2.2, 5.2.3.1
    variableLengthLength: function (supportPartial) {
        var length = this.octet();

        if (length < 192) {
            return length;
        }

        if (length < (supportPartial ? 224 : 255)) {
            return ((length - 192) << 8) +  this.octet() + 192;
        }

        if (length < 255) {
            alert('partial lengths not supported');
        }

        return this.uint32();
    },

    subParse: function (n, f) {
        var oldEnd = this.end,
            oldStart = this.start;
        try {
            this.start = this.pos;
            this.end = this.pos + n;
            f();
            if (this.pos != this.end) {
                this.pos = this.end;
                return true;
            }
        } finally {
            this.start = oldStart;
            this.end = oldEnd;
        }
    },

    lookup: function (table) {
        var octet = this.octet();
        return new LookupResult(table[octet], octet);
    },

    lookupArray: function (table, n) {
        var results = [];

        while (n > 0) {
            results.push(this.lookup(table));
            n -= 1;
        }

        return results;
    },

    lookupFlags: function (table, n) {
        var flags = this.uint(n);
        var results = [];

        for (i = 1; i < Math.pow(2, n * 8); i *= 2) {
            if (flags & i) {
                results.push(new LookupResult(table[i], i));
            }
        }
        return results;
    }
};

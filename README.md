
Abandonware!
------------

This was my aborted attempt to clone the awesome [ASN1 decoder](http://lapo.it/asn1js/) tool, but for GPG messages as defined in[RFC 4880](http://tools.ietf.org/search/rfc4880).

I started the project because I wanted to understand the format of the messages produced by GPG as used in [dotgpg](https://github.com/ConradIrwin/dotgpg), and then abandoned it because I felt I had a good enough understanding, and there are a huge number of details to code up (though [OpenPGP.js](http://openpgpjs.org/) has probably already done most of the work).

Most of the packets also contain interesting data behind a layer of encryption, so making a good tool would probably require decrypting encrypted blobs. But a pretty reasonable tool could be built without much difficulty from what's here.

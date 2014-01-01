An in-browser decoder for [RFC 4880](https://tools.ietf.org/search/rfc4880) (aka PGP/GPG messages).

It doesn't decrypt anything, but it is useful for debugging the (rather obscure) packet format used by GnnPG and other PGP apps.

![screen shot](http://cirw.in/gpg-decoder/screenshot.png)

## Usage

I'd recommend you use the version on my site at [http://cirw.in/gpg-decoder/](http://cirw.in/gpg-decoder), but if you're debugging sensitive stuff and are really paranoid you might want to run it on a friendly web-server of your own.

## Todo

There's a lot of RFC 4880, I mostly just implemented the bits I needed at the time. If you need anything added, please send a pull request :).

## Thanks

Massive thanks to [Lapo Luchini](http://lapo.it) for his work on the [ASN.1 Javascript decoder](http://lapo.it/asn1js/).

## License

Unless otherwise specified the code is Copyright 2013 Conrad Irwin (see LICENSE.MIT) for details.

Most of `hex.js` is Copyright 2008-2013 Lapo Luchini, see the header in that file for details. 

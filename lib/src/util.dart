library x509.conversions;

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto_keys/crypto_keys.dart';

import '../x509.dart';

KeyPair rsaKeyPairFromAsn1(ASN1Sequence sequence) {
  // var version = _toDart(sequence.elements[0]).toInt() + 1;
  var modulus = toDart(sequence.elements[1]);
  var publicExponent = toDart(sequence.elements[2]);
  var privateExponent = toDart(sequence.elements[3]);
  var prime1 = toDart(sequence.elements[4]);
  var prime2 = toDart(sequence.elements[5]);
  // var exponent1 = _toDart(sequence.elements[6]);
  // var exponent2 = _toDart(sequence.elements[7]);
  // var coefficient = _toDart(sequence.elements[8]);
  var privateKey = RsaPrivateKey(
      modulus: modulus,
      privateExponent: privateExponent,
      firstPrimeFactor: prime1,
      secondPrimeFactor: prime2);
  var publicKey = RsaPublicKey(modulus: modulus, exponent: publicExponent);
  return KeyPair(publicKey: publicKey, privateKey: privateKey);
}

RsaPublicKey rsaPublicKeyFromAsn1(ASN1Sequence sequence) {
  var modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
  var exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
  return RsaPublicKey(modulus: modulus, exponent: exponent);
}

KeyPair keyPairFromAsn1(ASN1BitString data, ObjectIdentifier algorithm) {
  switch (algorithm.name) {
    case 'rsaEncryption':
      var sequence =
          ASN1Parser(data.contentBytes()).nextObject() as ASN1Sequence;
      return rsaKeyPairFromAsn1(sequence);
    case 'sha1WithRSAEncryption':
  }
  throw UnimplementedError('Unknown algoritmh $algorithm');
}

PublicKey publicKeyFromAsn1(ASN1BitString data, ObjectIdentifier algorithm) {
  switch (algorithm.name) {
    case 'rsaEncryption':
      var s = ASN1Parser(data.contentBytes()).nextObject() as ASN1Sequence;
      return rsaPublicKeyFromAsn1(s);
    case 'sha1WithRSAEncryption':
  }
  throw UnimplementedError('Unknown algoritmh $algorithm');
}

String keyToString(Key key, [String prefix = '']) {
  if (key is RsaPublicKey) {
    var buffer = StringBuffer();
    var l = key.modulus.bitLength;
    buffer.writeln('${prefix}Modulus ($l bit):');
    buffer.writeln(toHexString(key.modulus, '${prefix}\t', 15));
    buffer.writeln('${prefix}Exponent: ${key.exponent}');
    return buffer.toString();
  }
  return '$prefix$key';
}

ASN1BitString keyToAsn1(Key key) {
  var s = ASN1Sequence();
  if (key is RsaPublicKey) {
    s..add(ASN1Integer(key.modulus))..add(ASN1Integer(key.exponent));
  }
  return ASN1BitString(s.encodedBytes);
}

ASN1BitString keyPairToAsn1(KeyPair keyPair) {
  var s = ASN1Sequence();

  RsaPrivateKey key = keyPair.privateKey;
  RsaPublicKey publicKey = keyPair.publicKey;
  var pSub1 = (key.firstPrimeFactor - BigInt.one);
  var qSub1 = (key.secondPrimeFactor - BigInt.one);
  var exponent1 = key.privateExponent.remainder(pSub1);
  var exponent2 = key.privateExponent.remainder(qSub1);
  var coefficient = key.secondPrimeFactor.modInverse(key.firstPrimeFactor);

  s
    ..add(fromDart(0)) // version
    ..add(fromDart(key.modulus))
    ..add(fromDart(publicKey.exponent))
    ..add(fromDart(key.privateExponent))
    ..add(fromDart(key.firstPrimeFactor))
    ..add(fromDart(key.secondPrimeFactor))
    ..add(fromDart(exponent1))
    ..add(fromDart(exponent2))
    ..add(fromDart(coefficient));

  return ASN1BitString(s.encodedBytes);
}

ASN1Object fromDart(dynamic obj) {
  if (obj == null) return ASN1Null();
  if (obj is List<int>) return ASN1BitString(obj);
  if (obj is List) {
    var s = ASN1Sequence();
    obj.forEach((v) => s.add(fromDart(v)));
    return s;
  }
  if (obj is Set) {
    var s = ASN1Set();
    obj.forEach((v) => s.add(fromDart(v)));
    return s;
  }
  if (obj is BigInt) return ASN1Integer(obj);
  if (obj is int) return ASN1Integer(BigInt.from(obj));
  if (obj is ObjectIdentifier) return obj.toAsn1();
  if (obj is bool) return ASN1Boolean(obj);
  if (obj is String) return ASN1PrintableString(obj);
  if (obj is DateTime) return ASN1UtcTime(obj);

  throw ArgumentError.value(obj, 'obj', 'cannot be encoded as ASN1Object');
}

dynamic toDart(ASN1Object obj) {
  if (obj is ASN1Null) return null;
  if (obj is ASN1Sequence) return obj.elements.map(toDart).toList();
  if (obj is ASN1Set) return obj.elements.map(toDart).toSet();
  if (obj is ASN1Integer) return obj.valueAsBigInteger;
  if (obj is ASN1ObjectIdentifier) return ObjectIdentifier.fromAsn1(obj);
  if (obj is ASN1BitString) return obj.stringValue;
  if (obj is ASN1Boolean) return obj.booleanValue;
  if (obj is ASN1OctetString) return obj.stringValue;
  if (obj is ASN1PrintableString) return obj.stringValue;
  if (obj is ASN1UtcTime) return obj.dateTimeValue;
  if (obj is ASN1IA5String) return obj.stringValue;
  throw ArgumentError(
      'Cannot convert $obj (${obj.runtimeType}) to dart object.');
}

String toHexString(BigInt v, [String prefix = '', int bytesPerLine = 15]) {
  var str = v.toRadixString(16);
  if (str.length % 2 != 0) {
    str = '0$str';
  }
  var buffer = StringBuffer();
  for (var i = 0; i < str.length; i += bytesPerLine * 2) {
    var l = Iterable.generate(
        str.length - i < bytesPerLine * 2
            ? (str.length - i) ~/ 2
            : bytesPerLine,
        (j) => str.substring(i + j * 2, i + j * 2 + 2));
    var s = l.join(':');
    buffer.writeln('$prefix$s${str.length - i <= bytesPerLine * 2 ? '' : ':'}');
  }
  return buffer.toString();
}

BigInt toBigInt(List<int> bytes) =>
    bytes.fold(BigInt.zero, (a, b) => a * BigInt.from(256) + BigInt.from(b));

import 'package:test/test.dart';
import 'package:x509/x509.dart';
import 'dart:io';
import 'package:asn1lib/asn1lib.dart';

void main() {
  group('rsa', () {
    test('parse key', () {
      var pem = File('test/files/rsa.key').readAsStringSync();
      KeyPair keyPair = parsePem(pem).single;
      RsaPrivateKey privateKey = keyPair.privateKey;
      RsaPublicKey publicKey = keyPair.publicKey;
      expect(privateKey.firstPrimeFactor, isNotNull);
      expect(privateKey.secondPrimeFactor, isNotNull);
      expect(privateKey.privateExponent, isNotNull);
      expect(publicKey.exponent, isNotNull);
    });
  });

  group('csr', () {
    test('parse csr', () {
      var pem = File('test/files/csr.pem').readAsStringSync();
      parsePem(pem).single as CertificationRequest;
    });
  });

  group('rfc5280', () {
    test('RSA Self-Signed Certificate', () {
      var f = File('test/resources/rfc5280_cert1.cer');

      var bytes = f.readAsBytesSync();

      var p = ASN1Parser(bytes);
      print(p.nextObject());

      var c = X509Certificate.fromAsn1(ASN1Parser(bytes).nextObject());
      print(c);
    });
  });
}

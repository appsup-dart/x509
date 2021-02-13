import 'dart:typed_data';

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

  group('ec', () {
    test('parse ec 256 public key', () {
      var pem = File('test/files/ec256.public.key').readAsStringSync();
      SubjectPublicKeyInfo keyInfo = parsePem(pem).single;
      var key = keyInfo.subjectPublicKey as EcPublicKey;
      expect(
          key.xCoordinate,
          BigInt.parse(
              '51818492006749570326812946343209411041700944121241362625086788703158476893928'));
      expect(
          key.yCoordinate,
          BigInt.parse(
              '33595934851494958356084148292611983061011944871851202520631261652578803383469'));
    });
    test('parse ec 256k public key', () {
      var pem = File('test/files/ec256k.pub.key').readAsStringSync();
      SubjectPublicKeyInfo keyInfo = parsePem(pem).single;
      var key = keyInfo.subjectPublicKey as EcPublicKey;
      expect(key.curve, curves.p256k);
    });
    test('parse ec 256 private key', () {
      var pem = File('test/files/ec256.private.key').readAsStringSync();
      KeyPair keyPair = parsePem(pem).single;
      var key = keyPair.privateKey as EcPrivateKey;

      expect(
          key.eccPrivateKey,
          BigInt.parse(
              '115735426896566426443735562247805583061594925902272203105205578087471800291450'));
    });
    test('parse ec 384 public key', () {
      var pem = File('test/files/ec384.public.key').readAsStringSync();
      SubjectPublicKeyInfo keyInfo = parsePem(pem).single;
      var key = keyInfo.subjectPublicKey as EcPublicKey;
      expect(
          key.xCoordinate,
          BigInt.parse(
              '20545964214668137657626333380687804621770301889137394027403195865297761228836360480027285257779141677515403916001231'));
      expect(
          key.yCoordinate,
          BigInt.parse(
              '13068848895562259854033738524358881457347119109053595396837669867699203318147516158760410558095930543191355315446383'));
    });
    test('parse ec 384 private key', () {
      var pem = File('test/files/ec384.private.key').readAsStringSync();
      KeyPair keyPair = parsePem(pem).single;
      var key = keyPair.privateKey as EcPrivateKey;

      expect(
          key.eccPrivateKey,
          BigInt.parse(
              '30758094300428071899891161382675739865625031661974292037243998715665065103389256758945325690612942812921541455724491'));
    });
    test('parse ec 521 public key', () {
      var pem = File('test/files/ec521.public.key').readAsStringSync();
      SubjectPublicKeyInfo keyInfo = parsePem(pem).single;
      var key = keyInfo.subjectPublicKey as EcPublicKey;
      expect(
          key.xCoordinate,
          BigInt.parse(
              '6558566456959953544109522959384633002634366184193672267866407124696200040032063394775499664830638630438428532794662648623689740875293641365317574204038644132'));
      expect(
          key.yCoordinate,
          BigInt.parse(
              '705914061082973601048865942513844186912223650952616397119610620188911564288314145208762412315826061109317770515164005156360031161563418113875601542699600118'));
    });
    test('parse ec 521 private key', () {
      var pem = File('test/files/ec521.private.key').readAsStringSync();
      KeyPair keyPair = parsePem(pem).single;
      var key = keyPair.privateKey as EcPrivateKey;

      expect(
          key.eccPrivateKey,
          BigInt.parse(
              '5341829702302574813496892344628933729576493483297373613204193688404465422472930583369539336694834830511678939023627363969939187661870508700291259319376559490'));
    });
    test('parse ec 256 key pair', () {
      var pem = File('test/files/ec256.key').readAsStringSync();

      KeyPair keyPair = parsePem(pem).single;

      EcPrivateKey privateKey = keyPair.privateKey;
      EcPublicKey publicKey = keyPair.publicKey;
      expect(privateKey.eccPrivateKey, isNotNull);
      expect(privateKey.curve, curves.p256);
      expect(publicKey.curve, curves.p256);
      expect(publicKey.xCoordinate, isNotNull);
      expect(publicKey.yCoordinate, isNotNull);
      var signature = keyPair.privateKey
          .createSigner(algorithms.signing.ecdsa.sha256)
          .sign('hello world'.codeUnits);

      var verified = keyPair.publicKey
          .createVerifier(algorithms.signing.ecdsa.sha256)
          .verify(Uint8List.fromList('hello world'.codeUnits), signature);

      expect(verified, isTrue);
    });
    test('parse ec 256k key pair', () {
      var pem = File('test/files/ec256k.key').readAsStringSync();

      KeyPair keyPair = parsePem(pem).single;

      EcPrivateKey privateKey = keyPair.privateKey;
      EcPublicKey publicKey = keyPair.publicKey;
      expect(privateKey.eccPrivateKey, isNotNull);
      expect(privateKey.curve, curves.p256k);
      expect(publicKey.curve, curves.p256k);
      expect(publicKey.xCoordinate, isNotNull);
      expect(publicKey.yCoordinate, isNotNull);
      var signature = keyPair.privateKey
          .createSigner(algorithms.signing.ecdsa.sha256)
          .sign('hello world'.codeUnits);

      var verified = keyPair.publicKey
          .createVerifier(algorithms.signing.ecdsa.sha256)
          .verify(Uint8List.fromList('hello world'.codeUnits), signature);

      expect(verified, isTrue);
    });
    test('parse ec 384 key pair', () {
      var pem = File('test/files/ec384.key').readAsStringSync();

      KeyPair keyPair = parsePem(pem).single;

      EcPrivateKey privateKey = keyPair.privateKey;
      EcPublicKey publicKey = keyPair.publicKey;
      expect(privateKey.eccPrivateKey, isNotNull);
      expect(privateKey.curve, curves.p384);
      expect(publicKey.curve, curves.p384);
      expect(publicKey.xCoordinate, isNotNull);
      expect(publicKey.yCoordinate, isNotNull);
      var signature = keyPair.privateKey
          .createSigner(algorithms.signing.ecdsa.sha384)
          .sign('hello world'.codeUnits);

      var verified = keyPair.publicKey
          .createVerifier(algorithms.signing.ecdsa.sha384)
          .verify(Uint8List.fromList('hello world'.codeUnits), signature);

      expect(verified, isTrue);
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

      var c = X509Certificate.fromAsn1(ASN1Parser(bytes).nextObject());
      expect(c, isA<X509Certificate>());
    });
    test('Apple certificate for server-based Game Center verification', () {
      var f = File('test/resources/3rd-party-auth-prod-19824d.cer');

      var bytes = f.readAsBytesSync();
      var c = X509Certificate.fromAsn1(ASN1Parser(bytes).nextObject());
      expect(c, isA<X509Certificate>());
    });
  });

  group('v3 extension', () {
    var generalNameEncodeBytes = [48, 19, 130, 17, 119, 119, 119, 46, 99, 104, 97, 105, 110, 116, 111, 112, 101, 46, 99, 111, 109];
    test('subject alternative name(=GeneralNames)', () {
      var extension = ASN1Sequence.fromBytes(Uint8List.fromList(generalNameEncodeBytes));
      var oid = ObjectIdentifier([2, 5, 29, 17]);
      var c = ExtensionValue.fromAsn1(extension, oid);
      expect(c, isA<GeneralNames>());
    });
    test('can parse DNS of subjectAltName', () {
      var extension = ASN1Sequence.fromBytes(Uint8List.fromList(generalNameEncodeBytes));
      var oid = ObjectIdentifier([2, 5, 29, 17]);
      GeneralNames c = ExtensionValue.fromAsn1(extension, oid);
      expect(c.names[0].toString(), "DNS:www.chaintope.com");
    });
  });
}

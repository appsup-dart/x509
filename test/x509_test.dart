import 'dart:convert';
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
      var privateKey = keyPair.privateKey as RsaPrivateKey;
      var publicKey = keyPair.publicKey as RsaPublicKey;
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

      var privateKey = keyPair.privateKey as EcPrivateKey;
      var publicKey = keyPair.publicKey as EcPublicKey;
      expect(privateKey.eccPrivateKey, isNotNull);
      expect(privateKey.curve, curves.p256);
      expect(publicKey.curve, curves.p256);
      expect(publicKey.xCoordinate, isNotNull);
      expect(publicKey.yCoordinate, isNotNull);
      var signature = privateKey
          .createSigner(algorithms.signing.ecdsa.sha256)
          .sign('hello world'.codeUnits);

      var verified = publicKey
          .createVerifier(algorithms.signing.ecdsa.sha256)
          .verify(Uint8List.fromList('hello world'.codeUnits), signature);

      expect(verified, isTrue);
    });
    test('parse ec 256k key pair', () {
      var pem = File('test/files/ec256k.key').readAsStringSync();

      KeyPair keyPair = parsePem(pem).single;

      var privateKey = keyPair.privateKey as EcPrivateKey;
      var publicKey = keyPair.publicKey as EcPublicKey;
      expect(privateKey.eccPrivateKey, isNotNull);
      expect(privateKey.curve, curves.p256k);
      expect(publicKey.curve, curves.p256k);
      expect(publicKey.xCoordinate, isNotNull);
      expect(publicKey.yCoordinate, isNotNull);
      var signature = privateKey
          .createSigner(algorithms.signing.ecdsa.sha256)
          .sign('hello world'.codeUnits);

      var verified = publicKey
          .createVerifier(algorithms.signing.ecdsa.sha256)
          .verify(Uint8List.fromList('hello world'.codeUnits), signature);

      expect(verified, isTrue);
    });
    test('parse ec 384 key pair', () {
      var pem = File('test/files/ec384.key').readAsStringSync();

      KeyPair keyPair = parsePem(pem).single;

      var privateKey = keyPair.privateKey as EcPrivateKey;
      var publicKey = keyPair.publicKey as EcPublicKey;
      expect(privateKey.eccPrivateKey, isNotNull);
      expect(privateKey.curve, curves.p384);
      expect(publicKey.curve, curves.p384);
      expect(publicKey.xCoordinate, isNotNull);
      expect(publicKey.yCoordinate, isNotNull);
      var signature = privateKey
          .createSigner(algorithms.signing.ecdsa.sha384)
          .sign('hello world'.codeUnits);

      var verified = publicKey
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

      var c = X509Certificate.fromAsn1(
          ASN1Parser(bytes).nextObject() as ASN1Sequence);
      expect(c, isA<X509Certificate>());
    });
    test('Apple certificate for server-based Game Center verification', () {
      var f = File('test/resources/3rd-party-auth-prod-19824d.cer');

      var bytes = f.readAsBytesSync();
      var c = X509Certificate.fromAsn1(
          ASN1Parser(bytes).nextObject() as ASN1Sequence);
      expect(c, isA<X509Certificate>());
    });
  });

  group('v3 extension', () {
    var generalNameEncodeBytes = [
      48,
      19,
      130,
      17,
      119,
      119,
      119,
      46,
      99,
      104,
      97,
      105,
      110,
      116,
      111,
      112,
      101,
      46,
      99,
      111,
      109
    ];
    test('subject alternative name(=GeneralNames)', () {
      var extension =
          ASN1Sequence.fromBytes(Uint8List.fromList(generalNameEncodeBytes));
      var oid = ObjectIdentifier([2, 5, 29, 17]);
      var c = ExtensionValue.fromAsn1(extension, oid);
      expect(c, isA<GeneralNames>());
    });
    test('can parse DNS of subjectAltName', () {
      var extension =
          ASN1Sequence.fromBytes(Uint8List.fromList(generalNameEncodeBytes));
      var oid = ObjectIdentifier([2, 5, 29, 17]);
      var c = ExtensionValue.fromAsn1(extension, oid) as GeneralNames;
      expect(c.names[0].toString(), 'DNS:www.chaintope.com');
    });
  });

  group('keys from auth services', () {
    test('https://login.microsoftonline.com/consumers/discovery/v2.0/keys', () {
      var f = json
          .decode(File('test/files/microsoft_keys.json').readAsStringSync());

      for (var k in f['keys'] as List) {
        for (var v in k['x5c'] as List) {
          var bytes = base64.decode(v);
          var p = ASN1Parser(bytes);
          var o = p.nextObject();
          if (o is! ASN1Sequence) {
            throw FormatException('Expected SEQUENCE, got ${o.runtimeType}');
          }
          var s = o;
          print(X509Certificate.fromAsn1(s));
        }
      }
    });

    test(
        'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
        () {
      var f =
          json.decode(File('test/files/google_certs.json').readAsStringSync())
              as Map;

      for (var v in f.values) {
        var cert = parsePem(v).first;
        expect(cert, isA<X509Certificate>());
      }
    });

// unsupported EC algo + curve. // NOFIX
//     test('parse pem file - object identifier issue', () {
//       var pem = '''-----BEGIN CERTIFICATE-----
// MIIBcTCCASigAwIBAgIEYJqHBDAKBggqhkjOPQQDAjBRMQswCQYDVQQGEwJTSTESMBAGA1UEBwwJTGp1YmxqYW5hMQ8wDQYDVQQKDAZTRVRDQ0UxDDAKBgNVBAsMA2RldjEPMA0GA1UEAwwGc2lnbmVyMB4XDTIxMDUxMTEzMzA0NFoXDTIyMDUxMTEzMzA0NFowUTELMAkGA1UEBhMCU0kxEjAQBgNVBAcMCUxqdWJsamFuYTEPMA0GA1UECgwGU0VUQ0NFMQwwCgYDVQQLDANkZXYxDzANBgNVBAMMBnNpZ25lcjBJMBMGByqGSM49AgEGCCqGSM49AwAFAzIABAFiI+dsaEfITNEXnMKU8qd7p89hmQGidXpV5IwGXMv3xEmf4lWE1L7VT2GQD/dgNDAKBggqhkjOPQQDAgM3ADA0AhgGOHfr+9TTEK1VIPRXCM6zbamRzKDqfm8CGBM2rmDRxss1XMYct2ZkV6E0m4SQrt5vLg==
// -----END CERTIFICATE-----''';

//       var cert = parsePem(pem).single;

//       expect(cert, isA<X509Certificate>());
//     });

    test('parse privateKeyUsagePeriod', () {
      var pem = '''-----BEGIN CERTIFICATE-----
MIIDJTCCAsygAwIBAgIIMWAojeoOOlkwCgYIKoZIzj0EAwIwgYYxFzAVBgNVBAMMDkNTQ0EgSGVhbHRoIE5MMQowCAYDVQQFEwEyMS0wKwYDVQQLDCRNaW5pc3RyeSBvZiBIZWFsdGggV2VsZmFyZSBhbmQgU3BvcnQxIzAhBgNVBAoMGktpbmdkb20gb2YgdGhlIE5ldGhlcmxhbmRzMQswCQYDVQQGEwJOTDAeFw0yMTA0MjYwODU3MzVaFw0zMjA0MjMwODU3MzVaMIGZMQswCQYDVQQGEwJOTDEjMCEGA1UECgwaS2luZ2RvbSBvZiB0aGUgTmV0aGVybGFuZHMxLTArBgNVBAsMJE1pbmlzdHJ5IG9mIEhlYWx0aCBXZWxmYXJlIGFuZCBTcG9ydDEKMAgGA1UEBRMBMTEqMCgGA1UEAwwhSGVhbHRoLURTQy12YWxpZC1mb3ItdmFjY2luYXRpb25zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmcNCX0lhlqcvJ/YHl/+TDLbIO09nTsRUr7KP23Qp3KUXAcnq3EkrTVswaJx93exNhW3VeFdILS1vI84sWbJoW6OCAQ0wggEJMB8GA1UdIwQYMBaAFFak99WeVB9We0dQ33IDCu5uCzZlMBsGA1UdEgQUMBKkEDAOMQwwCgYDVQQHDANOTEQwGwYDVR0RBBQwEqQQMA4xDDAKBgNVBAcMA05MRDAXBgNVHSUEEDAOBgwrBgEEAQCON49lAQIwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5ucGtkLm5sL0NSTHMvTkxELUhlYWx0aC5jcmwwHQYDVR0OBBYEFGzMKHGeML2Vkax4IVCKguaz0430MCsGA1UdEAQkMCKADzIwMjEwNDI2MDg1NzM1WoEPMjAyMTExMjIwODU3MzVaMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNHADBEAiAZh9OiWVAJQbaJMhN3dWuDtnYrcbBAuXLX1Ma7mS1EvgIgVuD6aTsh8PIW0SunH8Tp00E2zMGQkbW1NHNIzrQmOKo=
-----END CERTIFICATE-----''';

      var cert = parsePem(pem).single;

      // openSSL result
      // X509v3 Private Key Usage Period:
      //          Not Before: Apr 26 08:57:35 2021 GMT, Not After: Nov 22 08:57:35 2021 GMT

      expect(cert, isA<X509Certificate>());

      var c = cert as X509Certificate;
      // get extension value
      var pkup = c.tbsCertificate.extensions!
          .map((e) => e.extnValue)
          .whereType<PrivateKeyUsagePeriod>()
          .first;
      expect(pkup.notBefore, DateTime.parse('2021-04-26 08:57:35.000Z'));
      expect(pkup.notAfter, DateTime.parse('2021-11-22 08:57:35.000Z'));
    });

    test('parse LU key', () {
      var pem = '''-----BEGIN CERTIFICATE-----
MIIE7jCCAqKgAwIBAgIIZi+a+ox/oy0wQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgMFoxCzAJBgNVBAYTAkxVMR0wGwYDVQQKDBRJTkNFUlQgcHVibGljIGFnZW5jeTEsMCoGA1UEAwwjR3JhbmQgRHVjaHkgb2YgTHV4ZW1ib3VyZyBDU0NBIFRFU1QwHhcNMjEwNTA0MTIyODU1WhcNMjMwNTA0MTIyODU0WjBcMQswCQYDVQQGEwJMVTEbMBkGA1UECgwSTWluaXN0cnkgb2YgSGVhbHRoMTAwLgYDVQQDDCdHcmFuZCBEdWNoeSBvZiBMdXhlbWJvdXJnIERTIERHQyBURVNUIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASb+Fav0scKvJwD5mrbsUXM+Q59XdtYdXJy001Vucud8GHn11dUlxUhqXjF74lxWeB2xXpclppj1T0avvVqDRJ+o4IBFzCCARMwHwYDVR0jBBgwFoAUm6ZBIYGn0NWe0pxQwMYre7jzGJowKwYDVR0SBCQwIoEOY3NjYUBpbmNlcnQubHWkEDAOMQwwCgYDVQQHDANMVVgwKwYDVR0RBCQwIoEOY3NjYUBpbmNlcnQubHWkEDAOMQwwCgYDVQQHDANMVVgwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL3JlcG9zaXRvcnkuaW5jZXJ0Lmx1L2NzY2EtdGVzdC5jcmwwHQYDVR0OBBYEFBGOjlCIwnkmQfK+RjqvVKgDUG6iMCsGA1UdEAQkMCKADzIwMjEwNTA0MTIyODU1WoEPMjAyMTEwMzExMjI4NTVaMA4GA1UdDwEB/wQEAwIHgDBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggIBAKu07iiGCXPZ20LkM2oZmih1UjHd6r1hQFmBfZZme5bYuvFxn2QuH4xVjEeqQiMrCz2HOzQxW4lrbbYPNcFpbc7pwZGDlCvkjSu/pJ2gcksl/uh8luQA1ZrillJuE56QyQIq2peLHi2CrgYm4uk4A6+vjo6X5QxaVdxWG6VJsc8bBGYtb7pDcfWsjwrDFWNS+atIa+EOO+aA4QSjJpCXir6gTlUqNsgG+i7xU0aF93+fkeSQoyALM2dXDgIf73lXqvPxfsIo5i3AjdBz4DTD/rC+K7etvpU6xOtuJQT7ftd15fSu+JUtU97FDE59ouyGd7CgQKLt0wJepsJNWUmTEPVFMQsDgk0Pfhod95lqUg3zSwPKsIJxvfN/T82/rLiZce55cgK6tHLb4c4oBHuf68fssmHMoY/OcdgXPtyFEsLH/9lfG/cC2JLSyEhSjbr1wXIrepM2N7b2S8oZ3yys318OKdUtJ1UtcmTxlw3vLS0xNFSTA4iX8DrSmaZOYz20vLDnYh51uXpRMfVqlZcP0rPF/SH4duPsw5kSJAIn0iepVKdsmN7meqSn7QrEL6kwoF30c33soz1JsZokehiG/G06vEyj4ptvyBW2HVY1xXLqPu70MH7xxhLGW7NGNHjoWrmIfPuS9IUrIdQnUy12slD9hLzEko1Z+PBqPwAxTrWZ
-----END CERTIFICATE-----''';

      var cert = parsePem(pem).single;

      expect(cert, isA<X509Certificate>());
    });

    test('parse ES key', () {
      var pem = '''-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----''';

      var cert = parsePem(pem).single;

      expect(cert, isA<X509Certificate>());
    });
  });
}

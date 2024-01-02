import 'package:asn1lib/asn1lib.dart';
import 'package:test/test.dart';
import 'package:x509/x509.dart';

void main() {
  group('equality', (){
    test('equals',(){
      expect(ObjectIdentifier([2, 5, 4, 3]) == ObjectIdentifier([2, 5, 4, 3]), true);
    });
    test('not equals last node different',(){
      expect(ObjectIdentifier([2, 5, 4, 3]) != ObjectIdentifier([2, 5, 4, 4]), true);
    });
    test('not equals last node same',(){
      expect(ObjectIdentifier([2, 5, 4, 3]) != ObjectIdentifier([2, 5, 8, 3]), true);
    });
  });
  
  group('name', () {
    test('return correct name', () {
      var oid = ObjectIdentifier([2, 5, 4, 3]);
      expect(oid.name, 'commonName');
    });

    test('throw UnknownOIDNameError when unknown oid', () {
      var oid = ObjectIdentifier([1, 2, 3, 4, 5, 6]);
      expect(() => oid.name, throwsA(TypeMatcher<UnknownOIDNameError>()));
    });
  });
  
  group('asn.1 conversion', (){
    test('convert to asn.1', (){
      var oidOriginal = ObjectIdentifier([2, 5, 4, 3]);
      var asn1Original = oidOriginal.toAsn1();
      var bytes = asn1Original.encodedBytes;
      var asn1Restored = ASN1ObjectIdentifier.fromBytes(bytes);
      var oidRestored = ObjectIdentifier.fromAsn1(asn1Restored);
      expect(oidOriginal == oidRestored, true);
    });
    test('convert from asn.1', (){
      var oidOriginal = ObjectIdentifier([2, 5, 4, 3]);
      var asn1Original = ASN1ObjectIdentifier([2, 5, 4, 3]);
      var oidFromAsn1 = ObjectIdentifier.fromAsn1(asn1Original);
      expect(oidOriginal == oidFromAsn1, true);
    });
  });
}
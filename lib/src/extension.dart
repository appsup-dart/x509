part of x509;

/// An X.509 extension
class Extension {
  /// The extension's object identifier.
  final ObjectIdentifier extnId;

  /// Returns `true` if this extension is critical.
  ///
  ///  A certificate-using system MUST reject the certificate if it encounters
  ///  a critical extension it does not recognize or a critical extension
  ///  that contains information that it cannot process.  A non-critical
  ///  extension MAY be ignored if it is not recognized, but MUST be
  ///  processed if it is recognized.
  final bool isCritical;

  /// The extension's value.
  final ExtensionValue extnValue;

  const Extension(this.extnId, this.isCritical, this.extnValue);

  /// Creates a Extension from an [ASN1Sequence].
  ///
  /// The ASN.1 definition is:
  ///
  ///   Extension  ::=  SEQUENCE  {
  ///     extnID      OBJECT IDENTIFIER,
  ///     critical    BOOLEAN DEFAULT FALSE,
  ///     extnValue   OCTET STRING
  ///                 -- contains the DER encoding of an ASN.1 value
  ///                 -- corresponding to the extension type identified
  ///                 -- by extnID
  ///   }
  factory Extension.fromAsn1(ASN1Sequence sequence) {
    var id = toDart(sequence.elements[0]);
    var critical = false;
    var octetIndex = 1;
    if (sequence.elements.length > 2) {
      critical = toDart(sequence.elements[1]);
      octetIndex = 2;
    }
    return Extension(
        id,
        critical,
        ExtensionValue.fromAsn1(
            ASN1Parser(sequence.elements[octetIndex].contentBytes())
                .nextObject(),
            id));
  }

  @override
  String toString([String prefix = '']) {
    var buffer = StringBuffer();
    buffer.writeln("${prefix}$extnId: ${isCritical ? "critical" : ""}");
    buffer.writeln('${prefix}\t$extnValue');
    return buffer.toString();
  }
}

/// The base class for extension values.
abstract class ExtensionValue {
  static const ceId = ObjectIdentifier([2, 5, 29]);

  const ExtensionValue();

  /// Creates an extension value from an [ASN1Object].
  ///
  /// [id] defines the type of extension to create.
  factory ExtensionValue.fromAsn1(ASN1Object obj, ObjectIdentifier id) {
    if (id.parent == ceId) {
      switch (id.nodes.last) {
        case 35:
          return AuthorityKeyIdentifier.fromAsn1(obj);
        case 14:
          return SubjectKeyIdentifier.fromAsn1(obj);
        case 15:
          return KeyUsage.fromAsn1(obj);
        case 32: // TODO: certificate policies extension
        case 33: // TODO: policy mappings extension
        case 17: // TODO: subject alternative name extension
        case 18: // TODO: issuer alternative name extension
        case 9: // TODO: subject directory attributes extension
        case 30: // TODO: name constraints extension
        case 36: // TODO: policy constraints extension
          throw UnimplementedError();
        case 19:
          return BasicConstraints.fromAsn1(obj);
        case 37:
          return ExtendedKeyUsage.fromAsn1(obj);
      }
    }
    throw UnimplementedError(
        'Cannot handle $id (${id.parent} ${id.nodes.last})');
  }
}

/// An authority key identifier extension value.
///
/// The authority key identifier extension provides a means of identifying the
/// public key corresponding to the private key used to sign a certificate.
class AuthorityKeyIdentifier extends ExtensionValue {
  final List<int> keyIdentifier;
  final authorityCertIssuer;
  final BigInt authorityCertSerialNumber;

  AuthorityKeyIdentifier(this.keyIdentifier, this.authorityCertIssuer,
      this.authorityCertSerialNumber);

  /// Creates an authority key identifier extension value from an [ASN1Sequence].
  ///
  /// The ASN.1 definition is:
  ///
  ///   AuthorityKeyIdentifier ::= SEQUENCE {
  ///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
  ///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
  ///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
  ///
  ///   KeyIdentifier ::= OCTET STRING
  factory AuthorityKeyIdentifier.fromAsn1(ASN1Sequence sequence) {
    var keyId, issuer, number;
    for (var o in sequence.elements) {
      switch (o.tag & 0x1f) {
        case 0:
          keyId = o.contentBytes();
          break;
        case 1:
          issuer = o;
          break;
        case 2:
          number = (ASN1Parser(List.from(o.encodedBytes)..[0] = 2).nextObject()
                  as ASN1Integer)
              .valueAsBigInteger;
      }
    }
    return AuthorityKeyIdentifier(keyId, issuer, number);
  }
}

/// The subject key identifier extension provides a means of identifying
/// certificates that contain a particular public key.
class SubjectKeyIdentifier extends ExtensionValue {
  final List<int> keyIdentifier;

  SubjectKeyIdentifier(this.keyIdentifier);

  factory SubjectKeyIdentifier.fromAsn1(ASN1Object obj) {
    return SubjectKeyIdentifier(obj.contentBytes());
  }
}

/// The key usage extension defines the purpose (e.g., encipherment, signature,
/// certificate signing) of the key contained in the certificate.
class KeyUsage extends ExtensionValue {
  /// True when the subject public key is used for verifying digital signatures,
  /// other than signatures on certificates and CRLs, such as those used in an
  /// entity authentication service, a data origin authentication service,
  /// and/or an integrity service.
  final bool digitalSignature;

  /// True when the subject public key is used to verify digital signatures,
  /// other than signatures on certificates and CRLs, used to provide a
  /// non-repudiation service that protects against the signing entity falsely
  /// denying some action.  In the case of later conflict, a reliable third
  /// party may determine the authenticity of the signed data.
  ///
  /// Note that recent editions of X.509 have renamed the nonRepudiation bit to
  /// contentCommitment.
  final bool nonRepudiation;

  /// True when the subject public key is used for enciphering private or secret
  /// keys, i.e., for key transport.
  ///
  /// For example, this bit shall be set when an RSA public key is to be used
  /// for encrypting a symmetric content-decryption key or an asymmetric private
  /// key.
  final bool keyEncipherment;

  /// True when the subject public key is used for directly enciphering raw user
  /// data without the use of an intermediate symmetric cipher.
  ///
  /// Note that the use of this bit is extremely uncommon; almost all
  /// applications use key transport or key agreement to establish a symmetric
  /// key.
  final bool dataEncipherment;

  /// True when the subject public key is used for key agreement.
  ///
  /// For example, when a Diffie-Hellman key is to be used for key management,
  /// then this bit is set.
  final bool keyAgreement;

  /// True when the subject public key is used for verifying signatures on
  /// public key certificates.
  ///
  /// If the keyCertSign bit is asserted, then the cA bit in the basic
  /// constraints extension MUST also be asserted.
  final bool keyCertSign;

  /// True when the subject public key is used for verifying signatures on
  /// certificate revocation lists (e.g., CRLs, delta CRLs, or ARLs).
  final bool cRLSign;

  /// When true (and the keyAgreement bit is also set), the subject public key
  /// may be used only for enciphering data while performing key agreement.
  final bool encipherOnly;

  /// When true (and the keyAgreement bit is also set), the subject public key
  /// may be used only for deciphering data while performing key agreement.
  final bool decipherOnly;

  const KeyUsage(
      {this.digitalSignature,
      this.nonRepudiation,
      this.keyEncipherment,
      this.dataEncipherment,
      this.keyAgreement,
      this.keyCertSign,
      this.cRLSign,
      this.encipherOnly,
      this.decipherOnly});

  /// Creates a key usage extension from an [ASN1BitString].
  ///
  /// The ASN.1 definition is:
  ///
  ///   KeyUsage ::= BIT STRING {
  ///     digitalSignature        (0),
  ///     nonRepudiation          (1), -- recent editions of X.509 have
  ///                                  -- renamed this bit to contentCommitment
  ///     keyEncipherment         (2),
  ///     dataEncipherment        (3),
  ///     keyAgreement            (4),
  ///     keyCertSign             (5),
  ///     cRLSign                 (6),
  ///     encipherOnly            (7),
  ///     decipherOnly            (8) }
  factory KeyUsage.fromAsn1(ASN1BitString bitString) {
    var bits = bitString.stringValue
        .map((v) => (v + 256).toRadixString(2).substring(1))
        .join()
        .split('')
        .map((v) => v == '1')
        .toList();
    bits = bits.take(bits.length - bitString.unusedbits).toList();
    bits.addAll(Iterable.generate(9, (_) => false));
    bits = bits.take(9).toList();
    return KeyUsage(
        digitalSignature: bits[0],
        nonRepudiation: bits[1],
        keyEncipherment: bits[2],
        dataEncipherment: bits[3],
        keyAgreement: bits[4],
        keyCertSign: bits[5],
        cRLSign: bits[6],
        encipherOnly: bits[7],
        decipherOnly: bits[8]);
  }

  @override
  String toString() => [
        digitalSignature ? 'Digital Signature' : null
        // TODO others
      ].where((v) => v != null).join(',');
}

/// This extension indicates one or more purposes for which the certified
/// public key may be used, in addition to or in place of the basic purposes
/// indicated in the key usage extension.
class ExtendedKeyUsage extends ExtensionValue {
  final List<ObjectIdentifier> ids;

  const ExtendedKeyUsage(this.ids);

  factory ExtendedKeyUsage.fromAsn1(ASN1Sequence sequence) {
    return ExtendedKeyUsage(toDart(sequence));
  }

  @override
  String toString() => ids.join(', ');
}

/// The basic constraints extension identifies whether the subject of the
/// certificate is a CA and the maximum depth of valid certification paths
/// that include this certificate.
class BasicConstraints extends ExtensionValue {
  final bool cA;
  final int pathLenConstraint;

  BasicConstraints({this.cA = false, this.pathLenConstraint});

  /// Creates a basic constraints extension value from an [ASN1Sequence].
  ///
  /// The ASN.1 definition is:
  ///
  ///   BasicConstraints ::= SEQUENCE {
  ///       cA                      BOOLEAN DEFAULT FALSE,
  ///       pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
  factory BasicConstraints.fromAsn1(ASN1Sequence sequence) {
    var cA = false, len;
    for (var o in sequence.elements) {
      if (o is ASN1Boolean) {
        cA = o.booleanValue;
      }
      if (o is ASN1Integer) {
        len = o.intValue;
      }
    }
    return BasicConstraints(cA: cA, pathLenConstraint: len);
  }

  @override
  String toString() => [
        "CA:${"$cA".toUpperCase()}"
        // TODO: path length constraint
      ].join(',');
}

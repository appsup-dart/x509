import 'package:x509/x509.dart';
import 'dart:io';

void main() {
  var certRequest = parsePem(File('test/files/csr.pem').readAsStringSync())
      .first as CertificationRequest;

  print(certRequest.certificationRequestInfo.subject);
}

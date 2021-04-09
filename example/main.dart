import 'package:x509/x509.dart';
import 'dart:io';

void main() {
  var cert =
      "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIcYRws2sTxJkwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjEw\nNDA2MDkyMDIwWhcNMjEwNDIyMjEzNTIwWjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAMoRTVdYXX6kW8oEplmvw5K2LnN3TSxdU2E4r3LKwY5wWEOI\nEJkgXq5mj+1D/AESJRE8eveVAKlR5/vBITPuJT99agjG/4vr9CNdEZjPc/TmqFmX\nwldeX/oE89LIoSuBKR/g3CRI17Z/0V/ZaeLwNlWz/A/L6+MEfEbgAIiSxXFkctXL\nTIWf3Ith24OTN8hVCgCaUWVLuY+FGprUnqQOqn1lpbtb1fgTSI/JAGXu6wsESyc3\nxslD2e4VyBQ1i+JoW3/VKydlODd3THydFRBHGPdJQkLH4ccDh2kQ4sWQ4vjupSsk\nBKMAvLqftpvVUo6LogEXNRmmI6sjluRlEvYk14kCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBADFwIJVQERKO+x8Fx01ySjgSG6Rb81a17WQSCP2dlYmK\nFBvwaKK5tGVDt3RUnMgM5myEY11TX8yBF8UstxkqtMTzJh+K1hV6lC11YRqWzodq\nmJUBDuU39MYcRgoQn7szodBckdUGQlkTZti7xLApewkDpmR3Wx0KQBQpGt20Oaoq\nB2a5DVq4KsRirPtS71QvekM9Aars7pKrVNhxvXgkIMpiUAj3GJR5NAsJD0tsa9LM\nLvo31/AE1VKiRJ9ta21m15wO4CJyAiWvRbRiHDN9b9oXuJwUlzUgT0GFWHayt56e\nCYTU00dPphNMO1O07aqHq2O44/wPXYtQGDlHsg4sCeM=\n-----END CERTIFICATE-----\n";
  var v = parsePem(cert).first as X509Certificate;
  print(v.publicKey);
  return;

  var certRequest = parsePem(File('test/files/csr.pem').readAsStringSync())
      .first as CertificationRequest;

  print(certRequest.certificationRequestInfo.subject);
}

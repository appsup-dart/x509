# x509

Dart library for parsing and working with X.509 certificates.


## Usage

A simple usage example:

    import 'package:x509/x509.dart';
    import 'dart:io';

    main() {
      var cert = parsePem(new File('cert.pem').readAsStringSync());
      
      print(cert);
    }

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/appsup-dart/x509/issues

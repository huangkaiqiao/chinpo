import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:chinpo/chinpo.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    final awesome = Awesome();

    setUp(() {
      // Additional setup goes here.
    });

    test('First Test', () {
      expect(awesome.isAwesome, isTrue);
    });
  });

  group("AES-GCM-SIV tests",  () {

    setUp(() {
      // Additional setup goes here.
    });

    test('Encrypt/Decrypt Test', () {
      String plaintext = '000000';
      final sGen = Random.secure();
      Uint8List key = Uint8List.fromList(List.generate(32, (_) => sGen.nextInt(255)));
      Aes256GcmSiv aes = Aes256GcmSiv(key);
      String ciphertext = aes.encrypt(Uint8List.fromList(hex.decode(plaintext)));
      print("ciphertext: $ciphertext");
      Uint8List decrypted = aes.decrypt(ciphertext);
      String decryptedText = hex.encode(decrypted);
      expect(plaintext == decryptedText, isTrue);
    });
  });
}

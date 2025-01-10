import 'dart:math';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:fixnum/fixnum.dart';
import 'package:pointycastle/export.dart';

import 'Bytes.dart';
import 'polyval.dart';

class AEAD {
  static const int aesBlockSize = 16;
  static const int nonceSize = 12;

  late BlockCipher _aes ;
  SecureRandom? _random;
  late bool _aes128;

  AEAD(Uint8List key) {
    if (key.length != 16 && key.length != 32) {
      throw ArgumentError('Key must be 16 or 32 bytes long');
    }
    _aes = BlockCipher('AES/ECB')..init(true, KeyParameter(key));
    _random = SecureRandom('Fortuna');
    final sGen = Random.secure();
    _random!.seed(KeyParameter(
      Uint8List.fromList(List.generate(32, (_) => sGen.nextInt(255)))));
    _aes128 = key.length == 16;
  }

  Uint8List generateNonce() {
    return _random!.nextBytes(12);
  }

  Uint8List sealWithoutNonce(Uint8List plaintext, Uint8List data){
    var nonce = _random!.nextBytes(12);
    return seal(nonce, plaintext, data);
  }

  Uint8List seal(Uint8List nonce, Uint8List plaintext, Uint8List data) {
    if (nonce.length != nonceSize) {
      throw ArgumentError('Nonce must be 12 bytes long');
    }
    final authKey = subKey(Int32.ZERO, Int32.ONE, nonce);
    final encAES = BlockCipher('AES/ECB')..init(true, KeyParameter(subKey(Int32.TWO, Int32(_aes128 ? 3 : 5), nonce)));
    final tag = hash(encAES, authKey, nonce, plaintext, data);
    // print("tag: ${hex.encode(tag)}");
    final output = Uint8List(plaintext.length + tag.length);
    aesCTR(encAES, tag, plaintext, output);
    output.setRange(plaintext.length, output.length, tag);
    return output;
  }

  Uint8List? open(Uint8List nonce, Uint8List ciphertext, Uint8List data) {
    if (nonce.length != nonceSize) {
      throw ArgumentError('Nonce must be 12 bytes long');
    }

    final c = ciphertext.sublist(0, ciphertext.length - aesBlockSize);
    final tag = ciphertext.sublist(ciphertext.length - aesBlockSize);
    final authKey = subKey(Int32.ZERO, Int32.ONE, nonce);
    final encAES = BlockCipher('AES/ECB')..init(true, KeyParameter(subKey(Int32.TWO, Int32(_aes128 ? 3 : 5), nonce)));
    aesCTR(encAES, tag, c, c);
    final actual = hash(encAES, authKey, nonce, c, data);

    // print("tag:${hex.encode(tag)}, actual:${hex.encode(actual)}");
    
    Function deepEq = const DeepCollectionEquality().equals;
    if (deepEq(Uint8List.fromList(tag), Uint8List.fromList(actual))) {
      return c;
    }
    return null;
  }

  Uint8List hash(BlockCipher aes, Uint8List h, Uint8List nonce, Uint8List plaintext, Uint8List data) {
    // print("h: ${hex.encode(h)}, nonce: ${hex.encode(nonce)}, plaintext: ${hex.encode(plaintext)}, data: ${hex.encode(data)}");
    final Polyval polyval = Polyval(h);
    polyval.update(data); // hash data with padding
    polyval.update(plaintext); // hash plaintext with padding

    // hash data and plaintext lengths in bits with padding
    final Uint8List block = Uint8List(aesBlockSize);
    Bytes.putLong(Int64(data.length * 8), block, 0);
    Bytes.putLong(Int64(plaintext.length * 8), block, 8);
    polyval.updateBlock(block, 0);

    // print("block: ${hex.encode(block)}");
    polyval.digest(block);
    // print("block: ${hex.encode(block)}");
    for (int i = 0; i < nonce.length; i++) {
      block[i] ^= nonce[i];
    }
    block[block.length - 1] &= ~0x80;

    // encrypt polyval hash to produce tag
    try {
      aes.processBlock(block, 0, block, 0);
    } catch (e) {
      rethrow;
    }
    // print("block: ${hex.encode(block)}");
    return block;
  }

  Uint8List subKey(Int32 ctrStart, Int32 ctrEnd, Uint8List nonce) {
    final counter = Uint8List(aesBlockSize);
    counter.setRange(counter.length - nonce.length, counter.length, nonce);
    final key = Uint8List(((ctrEnd - ctrStart + 1) * 8).toInt());
    final block = Uint8List(aesBlockSize);
    for (Int32 i = ctrStart; i <= ctrEnd; i=(i+1) as Int32) {
      Bytes.putInt(i, counter);
      _aes.processBlock(counter, 0, block, 0);
      key.setRange(((i - ctrStart) * 8).toInt(), ((i - ctrStart + 1) * 8).toInt(), block.sublist(0, 8));
    }
    return key;
  }

  void aesCTR(BlockCipher aes, Uint8List tag, Uint8List input, Uint8List output) {
    final counter = Uint8List.fromList(tag)..[tag.length - 1] |= 0x80;
    final k = Uint8List(aesBlockSize);
    for (int i = 0; i < input.length; i += aesBlockSize) {
      aes.processBlock(counter, 0, k, 0);
      // print("counter: ${hex.encode(counter)}, k: ${hex.encode(k)}");
      for (int j = 0; j < min(aesBlockSize, input.length - i); j++) {
        output[i + j] = (input[i + j] ^ k[j]);
      }
      var j = 0;
      while (j < 4 && ++counter[j] == 0) {
        j++;
      }
      // print("output: ${hex.encode(output)}");
    }
  }
}
// Put public facing types in this file.
import 'dart:convert';
import 'dart:typed_data';

import 'package:chinpo/src/AEAD.dart';
import 'package:collection/collection.dart';

/// Checks if you are awesome. Spoiler: you are.
class Awesome {
  bool get isAwesome => true;
} 

/*

class Nonce{
    Uint8List bytes;
    Nonce(this.bytes);
}

final random = Random.secure();

Uint8List getRandombytes(){
    var result = Uint8List(12);
    for(var i=0; i<12; i++){
      result[i] = random.nextInt(256);
    }
    return result;
}*/

class Aes256GcmSiv{
    final Uint8List key;
    late final AEAD aead;
    late final Uint8List data = Uint8List(0);

    Aes256GcmSiv(this.key){
        Uint8List keySlice = Uint8List.fromList(key);
        aead = AEAD(keySlice);
    }

    String encrypt(Uint8List plaintext){
      // AEAD aead = AEAD(keySlice);
      // String password = "aes:gcm:siv&Hm5RHTNWCqDsk0Ib&2jnuwcgxXuHsmOXE8YnK+F1RFgwjgqHDtu2wPA0=";
      // List<String> pwd_slice = password.split('&');

      Uint8List nonce = aead.generateNonce();
      // Uint8List nonce = Uint8List.fromList(hex.decode('000000000000000000000000'));
      // Uint8List plaintext = utf8.encode(password);
      Uint8List data = Uint8List(0);
      Uint8List cipherpassword = aead.seal(nonce, plaintext, data);
      // print(hex.encode(cipherpassword));
      Uint8List decrypted = aead.open(nonce, cipherpassword, data)!;
      Function deepEq = const DeepCollectionEquality().equals;
      // print(hex.encode(decrypted));
      assert(deepEq(decrypted, plaintext));
      String ciphertext = "aes:gcm:siv&${base64Encode(nonce)}&${base64Encode(cipherpassword)}";
      return ciphertext;
    }

    Uint8List decrypt(String ciphertext) {
        List<String> tmp = ciphertext.split('&');
        Uint8List encrypted = base64Decode(tmp[2]);
        Uint8List nonce = base64Decode(tmp[1]);
        Uint8List decrypted = aead.open(nonce, encrypted, data)!;
        return decrypted;
    }
}
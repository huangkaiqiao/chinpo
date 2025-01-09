import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';

import 'bytes.dart';

// An implementation of POLYVAL based on GHASH because even BoringSSL doesn't have a POLYVAL impl.
// Does its own byte-order conversion to avoid confusion.
class Polyval {
  static final Int64 E = Int64(0xe100000000000000);
  static final Int64 E1 = Int64(0xe1000000);
  late final Int64 h0;
  late final Int64 h1;
  late Int64 s0 = Int64(0);
  late Int64 s1 = Int64(0);

// mulX_GHASH, basically
  Polyval(Uint8List h) {
    Int32 v3 = Bytes.getInt(h, 0);
    Int32 v2 = Bytes.getInt(h, 4);
    Int32 v1 = Bytes.getInt(h, 8);
    Int32 v0 = Bytes.getInt(h, 12);
    // print("v0:$v0, v1:$v1, v2:$v2, v3:$v3");

    Int32 b = v0;
    v0 = b.shiftRightUnsigned(1);
    Int32 c = b << 31;
    b = v1;
    v1 = (b.shiftRightUnsigned(1)) | c;
    c = b << 31;
    b = v2;
    v2 = (b.shiftRightUnsigned(1)) | c;
    c = b << 31;
    b = v3;
    v3 = (b.shiftRightUnsigned(1)) | c;
    v0 ^= (b << 31 >> 8 & E1);
    // print("v0:$v0, v1:$v1, v2:$v2, v3:$v3");

    h0 = ((v0 & 0xffffffff).toInt64() << 32) | (v1.toInt64() & 0xffffffff);
    h1 = ((v2 & 0xffffffff).toInt64() << 32) | (v3.toInt64() & 0xffffffff);
    // print("h0:$h0, h1:$h1 ${(v0 & 0xffffffff).toInt64() << 32} ${(v1 & 0xffffffff)}");
  }

  void update(Uint8List b) {
    final int extra = b.length % 16; // Assuming AES_BLOCK_SIZE is 16
    for (int i = 0; i < b.length - extra; i += 16) {
      updateBlock(b, i);
    }

    if (extra != 0) {
      final Uint8List block = Uint8List(16);
      block.setRange(0, extra, b.sublist(b.length - extra));
      updateBlock(block, 0);
    }
  }

  void updateBlock(Uint8List b, int offset) {
    Int64 v0 = h0;
    Int64 v1 = h1;
    Int64 z0 = Int64(0);
    Int64 z1 = Int64(0);

    Int64 x0 = s1 ^ Bytes.getLong(b, offset);
    Int64 x1 = s0 ^ Bytes.getLong(b, offset + 8);

    for (int i = 0; i < 64; i++) {
      // print(" 64 v0: $v0, v1: $v1");
      Int64 m = x1 >> 63;
      z0 ^= v0 & m;
      z1 ^= v1 & m;
      m = v1 << 63 >> 63;
      final Int64 c = v0 & 1;
      v0 = v0.shiftRightUnsigned(1);
      v1 = v1.shiftRightUnsigned(1) | c << 63;
      v0 ^= E & m;
      x1 <<= 1;
    }

    for (int i = 64; i < 127; i++) {
      // print("127 v0: $v0, v1: $v1");
      Int64 m = x0 >> 63;
      z0 ^= v0 & m;
      z1 ^= v1 & m;
      m = v1 << 63 >> 63;
      final Int64 c = v0 & 1;
      v0 = v0.shiftRightUnsigned(1);
      v1 = v1.shiftRightUnsigned(1) | c << 63;
      v0 ^= E & m;
      x0 <<= 1;
    }

    final Int64 m = x0 >> 63;
    s0 = (z0 ^ (v0 & m));
    s1 = (z1 ^ (v1 & m));

    // print("s0: $s0, s1: $s1");
  }

  int getLong(Uint8List bytes, int offset) {
    return ByteData.view(bytes.buffer).getInt64(offset, Endian.big);
  }

  void digest(Uint8List d) {
    Bytes.putLong(s1, d, 0);
    Bytes.putLong(s0, d, 8);
  }
}
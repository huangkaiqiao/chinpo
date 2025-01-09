import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';

class Bytes {
  static void putInt(Int32 n, Uint8List b) {
    b[0] = (n & 0xff).toInt();
    b[1] = ((n >> 8) & 0xff).toInt();
    b[2] = ((n >> 16) & 0xff).toInt();
    b[3] = ((n >> 24) & 0xff).toInt();
  }

  static void putLong(Int64 n, Uint8List b, int offset) {
    Int32 hi = (n & 0xffffffff).toInt32();
    Int32 lo = ((n >> 32) & 0xffffffff).toInt32();
    b[offset] = (hi & 0xff).toInt();
    b[offset + 1] = ((hi >> 8) & 0xff).toInt();
    b[offset + 2] = ((hi >> 16) & 0xff).toInt();
    b[offset + 3] = ((hi >> 24) & 0xff).toInt();
    b[offset + 4] = (lo & 0xff).toInt();
    b[offset + 5] = ((lo >> 8) & 0xff).toInt();
    b[offset + 6] = ((lo >> 16) & 0xff).toInt();
    b[offset + 7] = ((lo >> 24) & 0xff).toInt();
  }

  static Int32 getInt(Uint8List b, int offset) {
    Int32 n = Int32(b[offset] & 0xff);
    n |= (b[offset + 1] & 0xff) << 8;
    n |= (b[offset + 2] & 0xff) << 16;
    n |= (b[offset + 3] & 0xff) << 24;
    return n;
  }

  static Int64 getLong(Uint8List b, int offset) {
    Int32 lo = Int32(b[offset] & 0xff);
    lo |= (b[offset + 1] & 0xff) << 8;
    lo |= (b[offset + 2] & 0xff) << 16;
    lo |= (b[offset + 3] & 0xff) << 24;

    Int64 hi = Int64(b[offset + 4] & 0xff);
    hi |= (b[offset + 5] & 0xff) << 8;
    hi |= (b[offset + 6] & 0xff) << 16;
    hi |= (b[offset + 7] & 0xff) << 24;

    return (hi << 32) | lo;
  }
}
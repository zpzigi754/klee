//===-- BitArray.h ----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_UTIL_BITARRAY_H
#define KLEE_UTIL_BITARRAY_H

#include <stdint.h>
#include <string.h>

namespace klee {

  // XXX would be nice not to have
  // two allocations here for allocated
  // BitArrays
class BitArray {
private:
  unsigned len;
  uint32_t *bits;

protected:
  static uint32_t length(unsigned size) { return (size+31)/32; }

public:
  BitArray() :len(0), bits() {}
  BitArray(unsigned size, bool value = false)
    : len(length(size)),
      bits(new uint32_t[length(size)]) {
    memset(bits, value?0xFF:0, sizeof(*bits)*length(size));
  }
  BitArray(const BitArray &b, unsigned size)
    : len(length(size)),
      bits(new uint32_t[length(size)]) {
    memcpy(bits, b.bits, sizeof(*bits)*length(size));
    //assert(length(size) == b.len);
  }
  BitArray(const BitArray &b)
    : BitArray(b, b.size()) {
  }

  BitArray & operator=(const BitArray &b) {
    len = length(b.size());
    if (0 < len) {
      bits = new uint32_t[len];
      memcpy(bits, b.bits, sizeof(*bits)*len);
    }
    return *this;
  }


  ~BitArray() { delete[] bits; }

  bool get(unsigned idx) const { return (bool) ((bits[idx/32]>>(idx&0x1F))&1); }
  void set(unsigned idx) { bits[idx/32] |= 1<<(idx&0x1F); }
  void unset(unsigned idx) { bits[idx/32] &= ~(1<<(idx&0x1F)); }
  void set(unsigned idx, bool value) { if (value) set(idx); else unset(idx); }
  unsigned size() const { return len*32; }
  const uint32_t *get_bits() const { return bits; }
};

} // End klee namespace

#endif

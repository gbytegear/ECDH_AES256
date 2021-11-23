#ifndef BYTE_ARRAY_HPP
#define BYTE_ARRAY_HPP

#include <cstdint>
#include <cstring>
#include <utility>
#include <new>
#include <malloc.h>

class ByteArray {
  uint8_t* byte_array = nullptr;
  uint64_t _length = 0;
public:
  typedef uint8_t* iterator;

  ByteArray() = default;

  ByteArray(uint64_t length)
    : byte_array(new uint8_t[length]), _length(length) {}

  ByteArray(void* buffer, uint64_t length)
    : byte_array(new uint8_t[length]),
      _length(length) {
    memcpy(byte_array, buffer, _length);
  }

  ByteArray(ByteArray& other)
    : byte_array(new uint8_t[other._length]),
      _length(other._length) {
    memcpy(byte_array, other.byte_array, _length);
  }

  ByteArray(ByteArray&& other)
    : byte_array(other.byte_array),
      _length(other._length) {
    other.byte_array = nullptr;
  }

  ~ByteArray() {if(byte_array) delete[] byte_array;}

  void resize(uint64_t new_length) {
    _length = new_length;
    byte_array = (uint8_t*)realloc(byte_array, _length);
  }

  iterator addSize(uint64_t add) {
    byte_array = (uint8_t*)realloc(byte_array, _length + add);
    iterator it = byte_array + _length;
    _length += add;
    memset(it, 0, add);
    return it;
  }

  inline uint64_t length() {return _length;}

  inline uint8_t& operator[](uint64_t index) {return byte_array[index];}

  inline ByteArray& operator=(ByteArray other) {
    this->~ByteArray();
    return *new(this) ByteArray(std::move(other));
  }

  inline iterator begin() {return byte_array;}
  inline iterator end() {return byte_array + _length;}

};

#endif

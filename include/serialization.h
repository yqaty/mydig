#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <bits/stdc++.h>

//  可平凡复制

template <class T>
void serialize_for_copyable(std::ostream &os, const T &val) {
  os.write(reinterpret_cast<const char *>(&val), sizeof(T));
}

//  容器

template <class T>
void serialize_for_STL(std::ostream &os, const T &val) {
  os.write(reinterpret_cast<const char *>(val.data()),
           val.size() * sizeof(typename T::value_type));
}

//  可平凡复制

template <class T,
          typename std::enable_if_t<std::is_trivially_copyable_v<T>, int> N = 0>

void deserialize(std::istream &is, T &val) {
  is.read(reinterpret_cast<char *>(&val), sizeof(T));
}

//  容器

template <class T, typename std::enable_if_t<

                       std::is_same_v<typename T::iterator,
                                      decltype(std::declval<T>().begin())> &&

                           std::is_same_v<typename T::iterator,
                                          decltype(std::declval<T>().end())> &&

                           std::is_trivially_copyable_v<typename T::value_type>,
                       int>
                       N = 0>

void deserialize(std::istream &is, T &val) {
  is.read(reinterpret_cast<char *>(val.data()),
          val.size() * sizeof(typename T::value_type));
}

template <class T,
          typename std::enable_if_t<

              std::is_same_v<typename T::iterator,
                             decltype(std::declval<T>().begin())> &&

                  std::is_same_v<typename T::iterator,
                                 decltype(std::declval<T>().end())> &&

                  !std::is_trivially_copyable_v<typename T::value_type>,
              int>
              N = 0>

void deserialize(std::istream &is, T &val) {
  for (auto &v : val) {
    deserialize(is, v);
  }
}

#endif
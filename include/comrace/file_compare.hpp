#pragma once

#include <cstddef>
#include <iosfwd>

namespace comrace {

bool streams_equal(std::istream& left, std::istream& right, std::size_t chunkSize = 64 * 1024);

}  // namespace comrace

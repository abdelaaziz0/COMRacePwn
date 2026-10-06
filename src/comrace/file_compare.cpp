#include "comrace/file_compare.hpp"

#include <algorithm>
#include <istream>
#include <vector>

namespace comrace {

bool streams_equal(std::istream& left, std::istream& right, std::size_t chunkSize) {
  if (chunkSize == 0) {
    chunkSize = 64 * 1024;
  }

  std::vector<char> leftBuffer(chunkSize);
  std::vector<char> rightBuffer(chunkSize);

  while (true) {
    left.read(leftBuffer.data(), static_cast<std::streamsize>(leftBuffer.size()));
    right.read(rightBuffer.data(), static_cast<std::streamsize>(rightBuffer.size()));

    const std::streamsize leftCount = left.gcount();
    const std::streamsize rightCount = right.gcount();
    if (leftCount != rightCount) {
      return false;
    }
    if (leftCount == 0) {
      return left.eof() && right.eof();
    }
    if (!std::equal(leftBuffer.begin(), leftBuffer.begin() + leftCount, rightBuffer.begin())) {
      return false;
    }

    if ((left.eof() || right.eof()) && left.eof() != right.eof()) {
      return false;
    }
  }
}

}

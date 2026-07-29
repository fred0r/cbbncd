#pragma once

#include <string>

class Version {
public:
  static std::string version();
  static std::string compileTime();
  static std::string tag();
};

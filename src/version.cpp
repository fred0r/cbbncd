#include "version.h"

#ifndef BOXTAG
#define BOXTAG ""
#endif

#ifndef VERSION
#define VERSION "unknown"
#endif

#ifndef BUILDTIME
#define BUILDTIME "unknown"
#endif

std::string Version::version() {
  return VERSION;
}

std::string Version::compileTime() {
  return BUILDTIME;
}

std::string Version::tag() {
  return BOXTAG;
}

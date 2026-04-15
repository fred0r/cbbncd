#include "listenportmanager.h"

#include <cassert>
#include <list>

#include <openssl/rand.h>

#include "core/tickpoke.h"
#include "globalcontext.h"

namespace {

const int tickinterval = 600000;
const std::string tag = "[ListenPortManager] ";

unsigned int secureRand(unsigned int max) {
  unsigned int result;
  if (RAND_bytes(reinterpret_cast<unsigned char*>(&result), sizeof(result)) != 1) {
    result = static_cast<unsigned int>(time(nullptr));
  }
  return result % max;
}

}

ListenPortManager::ListenPortManager(int firstport, int lastport) : firstport(firstport), lastport(lastport) {
  global->getTickPoke()->startPoke(this, "ListenPortManager", tickinterval, 0);
  setPortRange(firstport, lastport);
}

ListenPortManager::~ListenPortManager() {
  global->getTickPoke()->stopPoke(this, 0);
}

void ListenPortManager::setPortRange(int first, int last) {
  assert (last > first);
  firstport = first;
  lastport = last;
  availableports.resize(last - first + 1);
  for (size_t i = 0; i < availableports.size(); ++i) {
    availableports[i] = true;
  }
  unavailableports.clear();
}

int ListenPortManager::acquirePort() {
  size_t startpos = secureRand(availableports.size());
  size_t pos = startpos;
  while (true) {
    if (availableports[pos]) {
      availableports[pos] = false;
      return firstport + pos;
    }
    pos = (pos + 1) % availableports.size();
    if (pos == startpos) {
      return -1;
    }
  }
  return -1;
}

void ListenPortManager::releasePort(int port) {
  if (port < firstport || port > lastport) {
    return;
  }
  availableports[port - firstport] = true;
  unavailableports.erase(port);
}

void ListenPortManager::markPortUnavailable(int port) {
  if (port < firstport || port > lastport) {
    return;
  }
  global->log(tag + "Marking port as unavailable: " + std::to_string(port));
  availableports[port - firstport] = false;
  unavailableports[port] = time(nullptr);
}

void ListenPortManager::tick(int message) {
  unsigned int currtime = static_cast<unsigned int>(time(nullptr));
  std::list<int> expiredlist;
  for (const std::pair<const int, unsigned int>& portandtime : unavailableports) {
    if (portandtime.second + 3600 < currtime) {
      expiredlist.push_back(portandtime.first);
    }
  }
  for (int expiredunavailableport : expiredlist) {
    global->log(tag + "Unavailable port block expired: " + std::to_string(expiredunavailableport));
    unavailableports.erase(expiredunavailableport);
    releasePort(expiredunavailableport);
  }
}
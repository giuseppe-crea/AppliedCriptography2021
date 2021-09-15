#include <map>
#include <string>

#include "ClientElement.cpp"

extern map<int, ClientElement*> connectedClientsBySocket;
extern map<string, ClientElement*> connectedClientsByUsername;
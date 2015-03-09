#include <Events.hpp>

using namespace std;

namespace Transport {
	namespace Event {
		Connect::Connect(Request creq) : req(creq) {}
		Error::Error(string aMsg) : msg(aMsg) {}
	}
}
#include <Transport.hpp>

using namespace std;

namespace Transport {
	ServerPtr server() {
		return ServerPtr(new Server);
	}

	ClientPtr request() {
		return ClientPtr(new Client);
	}
}
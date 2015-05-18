#include <Events.hpp>
#include <Client.hpp>

using namespace std;

namespace Transport {
	namespace Event {
		Connect::Connect(Request creq) : req(creq) {
			res = new Client;
			res->eh.dhost = req.eh.shost;
			res->eh.shost = req.eh.dhost;
			res->ih.daddr = req.ih.saddr;
			res->ih.saddr = req.ih.daddr;
		}

		Error::Error(string aMsg) : msg(aMsg) {}
	}
}
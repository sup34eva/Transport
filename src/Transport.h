#pragma once

#include "Server.h"
#include "Client.h"
#include <memory>

namespace Transport {
	typedef std::shared_ptr<Server> ServerPtr;
	typedef std::shared_ptr<Client> ClientPtr;

	ServerPtr server() {
		return ServerPtr(new Server);
	}

	ClientPtr request() {
		return ClientPtr(new Client);
	}
}
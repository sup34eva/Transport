#pragma once

#include <Server.hpp>
#include <Client.hpp>
#include <memory>

namespace Transport {
	typedef std::shared_ptr<Server> ServerPtr;
	typedef std::shared_ptr<Client> ClientPtr;

	ServerPtr server();

	ClientPtr request();
}
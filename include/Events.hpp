#pragma once

#include <Request.hpp>
#include <Response.hpp>
#include <Packet.hpp>
#include <string>

namespace Transport {
	class Client; 

	namespace Error {
		enum Code {
			NONE,
			BAD_REQUEST
		};
	}

	namespace Event {
		class Connect {
			public:
				Connect(Request creq);
				Request req;
				Client* res;
		};

		class Error {
			public:
				Error(std::string aMsg);
				std::string msg;
		};
	}
}
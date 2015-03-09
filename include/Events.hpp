#pragma once

#include <Request.hpp>
#include <Response.hpp>
#include <Packet.hpp>
#include <string>

namespace Transport {
	namespace Error {
		enum ErrorCode {
			NONE,
			BAD_REQUEST
		};
	}

	namespace Event {
		class Connect {
			public:
				Connect(Request creq);
				Request req;
		};

		class Error {
			public:
				Error(std::string aMsg);
				std::string msg;
		};
	}
}
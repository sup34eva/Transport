#pragma once

#include "Request.h"
#include "Response.h"
#include "Packet.h"

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
				Connect(Request creq) : req(creq) {}
				Request req;
		};

		class Error {
			public:
				Error(string aMsg) : msg(aMsg) {}
				string msg;
		};
	}
}
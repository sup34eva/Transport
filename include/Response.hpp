#pragma once

namespace Transport {
	class Response {
		public:
			Response(bool ended = false);
			void close(void* data);
			void* read();
		private:
			bool m_ended;
			void* m_data;
	};
}
#pragma once

namespace Transport {
	class Response {
		public:
			Response(bool ended = false) : m_ended(ended), m_data(NULL) {
				//NOOP
			}
			void close(void* data) {
				if (!m_ended) {
					m_data = data;
					m_ended = true;
				}
			}
			void* read() {
				return m_data;
			}
		private:
			bool m_ended;
			void* m_data;
	};
}
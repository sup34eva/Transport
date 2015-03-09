#include <Response.hpp>

using namespace std;

namespace Transport {
	Response::Response(bool ended) : m_ended(ended), m_data(nullptr) {
		//NOOP
	}
	void Response::close(void* data) {
		if (!m_ended) {
			m_data = data;
			m_ended = true;
		}
	}
	void* Response::read() {
		return m_data;
	}
}
#pragma once

#include <vector>
#include <functional>
#include <memory>

using namespace std;

#define EventHandler function<void(EType*)>
#define EventPair pair<size_t, EventHandler>

namespace Transport {
	template <typename Child>
	class EventEmitter {
		public:
			template<typename EType>
			Child* on(EventHandler handler) {
				auto event = new EventPair(typeid(EType).hash_code(), handler);
				if (event != NULL)
					events.push_back(event);
				return static_cast<Child*>(this);
			}
		protected:
			template<typename EType>
			void emit(EType event) {
				for (void* e : events) {
					auto evt = static_cast<EventPair*>(e);
					if (evt->first == typeid(EType).hash_code()) {
						evt->second(&event);
					}
				}
			}
		private:
			vector<void*> events;
	};
}

#define on(TYPE, LAMBDA) on<TYPE>(LAMBDA)

#undef EventPair
#undef EventHandler

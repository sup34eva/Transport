#pragma once

#include <vector>
#include <functional>

#define EventHandler std::function<void(EType&)>
#define EventPair std::pair<size_t, EventHandler>

template <class Child>
class EventEmitter {
public:
	template<typename EType>
	Child* on(EventHandler handler) {
		events.push_back(new EventPair(typeid(EType).hash_code(), handler));
		return static_cast<Child*>(this);
	}
protected:
	template<typename EType>
	void emit(EType& event) {
		auto id = typeid(EType).hash_code();
		for (auto evt : events) {
			auto pair = static_cast<EventPair*>(evt);
			if (pair->first == id)
				pair->second(event);
		}
	}
private:
	std::vector<void*> events;
};

#define on(TYPE, LAMBDA) on<TYPE>(LAMBDA)

#undef EventPair
#undef EventHandler

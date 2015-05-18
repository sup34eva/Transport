#include <Transport.hpp>

#include <iostream>

using namespace std;
using namespace Transport;

int main() {
	auto errorHandler = [=](Event::Error& evt) { // Erreur
		cerr << evt.msg << endl;
	};

	Transport::server()->on(Event::Connect, [=](Event::Connect& evt) { // Nouvelle connection
		cout << "TCP: " << evt.req.ih.saddr << ":" << evt.req.th.sport << " -> " << evt.req.ih.daddr << ":" << evt.req.th.dport << endl;
		evt.res->on(Event::Connect, [=](Event::Connect& evt) { // Reponse reçue
			cout << evt.req.ih.saddr << ":" << evt.req.th.sport << " -> " << evt.req.ih.daddr << ":" << evt.req.th.dport << endl;
		})->on(Event::Error, errorHandler)->send("Test", 4);
	})->on(Event::Error, errorHandler)->listen(1337);

	system("pause");

	return 0;
}

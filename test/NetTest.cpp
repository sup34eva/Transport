#include <Transport.hpp>

#include <iostream>

using namespace std;
using namespace Transport;

int main() {
	Transport::server()->on(Event::Connect, [=](Event::Connect& evt) { // Nouvelle connection
		cout << "TCP: " << evt.req.ih.saddr << ":" << evt.req.th.sport << " -> " << evt.req.ih.daddr << ":" << evt.req.th.dport << endl;
	})->on(Event::Error, [=](Event::Error& evt) { // Erreur
		cerr << evt.msg << endl;
	})->listen();

	/*Transport::request()->on(Event::Connect, [=](Event::Connect* evt) { // Reponse reçue
		cout << evt->req.ih.saddr << ":" << evt->req.th.sport << " -> " << evt->req.ih.daddr << ":" << evt->req.th.dport << endl;
	})->on(Event::Error, [=](Event::Error* evt) { // Erreur
		cerr << evt->msg.c_str() << endl;
	})->send(NULL);*/

	system("pause");

	return 0;
}

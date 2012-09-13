all:
	$(CXX) $(CXXFLAGS) publisher.cpp  -o publisher_opc $(LDFLAGS) -lblackadder -lpthread
	$(CXX) $(CXXFLAGS) subscriber.cpp -o subscriber_opc $(LDFLAGS) -lblackadder -lpthread

clean:
	rm -f publisher_opc subscriber_opc
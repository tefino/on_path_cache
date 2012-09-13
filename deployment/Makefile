all:
	$(CXX) $(CXXFLAGS) bitvector.cpp graph_representation.cpp network.cpp parser.cpp deploy.cpp client_exec.cpp -o deploy $(LDFLAGS) -lconfig++ -ligraph
	$(CXX) $(CXXFLAGS) startclient.cpp -o startclient $(LDFLAGS) -lblackadder -lpthread
	$(CXX) $(CXXFLAGS) startserver.cpp -o startserver $(LDFLAGS) -lblackadder -lpthread
	$(CXX) $(CXXFLAGS) killserver.cpp -o killserver $(LDFLAGS) -lblackadder -lpthread
	$(CXX) $(CXXFLAGS) killclient.cpp -o killclient $(LDFLAGS) -lblackadder -lpthread

clean:
	rm -f deploy startclient startserver killserver killclient

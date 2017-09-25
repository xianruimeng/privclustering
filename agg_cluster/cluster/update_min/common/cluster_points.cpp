#include "cluster_points.h"

UINT m_nBuflen;

//@TODO!!

/**
 * send one mpz_t to sock
 */
void sendmpz_t(mpz_t t, CSocket sock, BYTE * buf) {

//clear upper bytes of the buffer, so tailing bytes are zero
	for (int i = mpz_sizeinbase(t, 256); i < m_nBuflen; i++) {
		*(buf + i) = 0;
	}

	mpz_export(buf, NULL, -1, 1, 1, 0, t);

	//send Bytes of t
	sock.Send(buf, (uint64_t) m_nBuflen);
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void receivempz_t(mpz_t t, CSocket sock, BYTE * buf) {
	sock.Receive(buf, (uint64_t) m_nBuflen);
	mpz_import(t, m_nBuflen, -1, 1, 1, 0, buf);

}

/**
 * send one mpz_t to sock, allocates buffer
 */
void sendmpz_t(mpz_t t, CSocket sock) {
	unsigned int bytelen = mpz_sizeinbase(t, 256);
	BYTE* arr = (BYTE*) malloc(bytelen);
	mpz_export(arr, NULL, 1, 1, 1, 0, t);

//send byte length
	sock.Send(&bytelen, sizeof(bytelen));

//send bytes of t
	sock.Send(arr, (uint64_t) bytelen);

	free(arr);
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void receivempz_t(mpz_t t, CSocket sock) {
	unsigned int bytelen;

//reiceive byte length
	sock.Receive(&bytelen, sizeof(bytelen));
	BYTE* arr = (BYTE*) malloc(bytelen);

//receive bytes of t
	sock.Receive(arr, (uint64_t) bytelen);
	mpz_import(t, bytelen, 1, 1, 1, 0, arr);

	free(arr);
}

/**
 * return true  if sent the data.
 * return false data were NOT been sent
 */
 bool send_enc(vector<pa_cipher*> v, CSocket socket, string address, int port){

	size_t i;

    LONG lTO = CONNECT_TIMEO_MILISEC;
   
      
    for (int ctr = 0; ctr < RETRY_CONNECT; ctr++) {

        if (!socket.Socket()){
           cerr << "Error: a socket could not be created " << endl;
           return false;
        }
       // cout<<ctr<<"trying to connect to port "<<port<<endl;

        if (socket.Connect(address, port, lTO)) {
           //Without packing ...
           for(i = 0; i < v.size(); ++i){
                sendmpz_t(v[i]->c, socket);
           }

           UINT nID;
           socket.Receive(&nID, sizeof(int));

           if(nID == VECTOR_SEND_RECV_ID)  
           {
             cout<<"Confirm received ..."<<endl;
             break;
           }
        }

        SleepMiliSec(5);
    }

    socket.Close();        


    return true;
}


/**
 * Received the data ...
 * return a vector of received data ...
 */
vector<pa_cipher*> recv_enc(uint32_t size, CSocket socket, string address, int port){

    cout << "Listening: " << address << ":" << port << endl;

    if (!socket.Socket()) {
            cerr << "Error: a socket could not be created " << endl;
            exit(0);
    }
    if (!socket.Bind(port, address)) {
        cerr <<" in recv_enc"<<endl;
        cerr <<port <<",, "<<address<<endl;
        cerr << "Error: a socket could not be bound" << endl;
        exit(0);
    }

    cout<<"Bind to port: "<<port<<endl;
        

    if (!socket.Listen()) {
        cerr << "Error: could not listen on the socket " << endl;
        exit(0);
    }  

    CSocket sock;

    if (!socket.Accept(sock)) {
        cerr << "Error: could not accept connection" << endl;
        exit(0);
    }

    vector<pa_cipher*> v;
    v.resize(size);
    size_t i;

    //cout<< "*****************\nReceived size is "<<size <<endl;

    
    for(i =0; i<size; ++i){// receive initial pid when connected
        v[i] = pa_cipher_init();
        receivempz_t(v[i]->c, sock);
    }

    int id = VECTOR_SEND_RECV_ID;
    
    if(sock.Send(&id, sizeof(int))){
        cout<<"Sent confirmation!!"<<endl;
        sock.Close();
    }


        
    // for(i =0; i<v.size(); ++i){// receive initial pid when connected
    //     mpz_t results;
    //     mpz_init(results);
    //     pa_decrypt(results, pub, prv, v[i]->c);
    //     gmp_printf("received: %Zd\n=============\n", results);
    //     mpz_clear(results);
    // }
    
//    sock.Close();
    socket.Close();

    return v;

}




/**
 * return true  if sent the data.
 *  send v.size()x2 vector ...
 * return false data were NOT been sent
 */
 bool send_vect_enc(vector< vector<pa_cipher*> > v, CSocket socket, string address, int port){

    size_t i, j;

    LONG lTO = CONNECT_TIMEO_MILISEC;
   
      
    for (int ctr = 0; ctr < RETRY_CONNECT; ctr++) {

        if (!socket.Socket()){
           cerr << "Error: a socket could not be created " << endl;
           return false;
        }
    
        if (socket.Connect(address, port, lTO)) {
           //Without packing ...
           for(i = 0; i < v.size(); ++i){
                sendmpz_t(v[i][0]->c, socket); // enc(p^2)
                sendmpz_t(v[i][1]->c, socket); // enc(p)
           }

           UINT nID;

           socket.Receive(&nID, sizeof(int));

           if(nID == MATRIX_SEND_RECV_ID)  break;

        }

        SleepMiliSec(10);
    }

    socket.Close();        

    return true;
}




/**
 * Received the data ...
 * return a vector of received data ...
 */
vector< vector<pa_cipher*> > recv_vect_enc(uint32_t size, CSocket socket, string address, int port){

//    cout << "Listening: " << address << ":" << port << endl;

    if (!socket.Socket()) {
            cerr << "Error: a socket could not be created " << endl;
            exit(0);
    }
    if (!socket.Bind(port, address)) {
            cerr << "Error: a socket could not be bound" << endl;
            exit(0);
    }
    
    cout<<"Bind to port: "<<port<<endl;

    if (!socket.Listen()) {
        cerr << "Error: could not listen on the socket " << endl;
        exit(0);
    }  

    CSocket sock;

    if (!socket.Accept(sock)) {
        cerr << "Error: could not accept connection" << endl;
        exit(0);
    }

    vector< vector<pa_cipher*> > v;
    v.resize(size);
    size_t i;
    
    for(i =0; i<size; ++i){// receive initial pid when connected
    	v[i].resize(2);
	    v[i][0] = pa_cipher_init();
	    v[i][1] = pa_cipher_init();
        receivempz_t(v[i][0]->c, sock);
        receivempz_t(v[i][1]->c, sock);
    }

    int id =  MATRIX_SEND_RECV_ID;
    
    if(sock.Send(&id, sizeof(int)))
        sock.Close();

//    sock.Close();
    socket.Close();

    return v;

}


/**
 * send lower triangle of the matrix 
 * return true  if sent the data.
 * return false data were NOT been sent
 */
 bool send_matrix_enc(vector< vector<pa_cipher*> > v, CSocket socket, string address, int port){

    size_t i, j;

    LONG lTO = CONNECT_TIMEO_MILISEC;
   
      
    for (int ctr = 0; ctr < RETRY_CONNECT; ctr++) {

        if (!socket.Socket()){
           cerr << "Error: a socket could not be created " << endl;
           return false;
        }
    
        if (socket.Connect(address, port, lTO)) {
           //Without packing ...
           for(i = 0; i < v.size(); ++i){
                for(j = 0; j < v[i].size(); ++j){
                    sendmpz_t(v[i][j]->c, socket); 
                }
           }
           break;
        }

        SleepMiliSec(10);
    }

    socket.Close();        

    return true;
}


/**
 * Received the data ...
 * recieve low triangle of the matrix 
 * return a vector of received data ...
 */
vector< vector<pa_cipher*> > recv_matrix_enc(uint32_t size, 
        CSocket socket, string address, int port){

//    cout << "Listening: " << address << ":" << port << endl;

    if (!socket.Socket()) {
            cerr << "Error: a socket could not be created " << endl;
            exit(0);
    }
    if (!socket.Bind(port, address)) {
            cerr << "Error: a socket could not be bound" << endl;
            exit(0);
    }
    
    cout<<"Bind to port: "<<port<<endl;

    if (!socket.Listen()) {
        cerr << "Error: could not listen on the socket " << endl;
        exit(0);
    }  

    CSocket sock;

    if (!socket.Accept(sock)) {
        cerr << "Error: could not accept connection" << endl;
        exit(0);
    }

    vector< vector<pa_cipher*> > v;
    v.resize(size);
    size_t i, j;
    
    for(i =0; i< size; ++i){
        v[i].resize(i);
        for(j = 0 ; j < i; ++j){
            v[i][j] = pa_cipher_init();
            receivempz_t(v[i][j]->c, sock);
        }
    }
    
    sock.Close();
    socket.Close();

    return v;

}















/**
 * find the two 'clusters' with mini distance to union ...
 */
uint32_t find_min(uint32_t nthreads, seclvl seclvl, e_mt_gen_alg mt_alg,
	pa_pubkey_t* pub, pa_prvkey_t* prv, 
	vector<pa_cipher*> cipher_vector, 
	e_role role, CSocket& socket, 
	char* address, int port, gmp_randstate_t rnd)
{
	//Client holds enc(dist_i)
	//sampel random values
	//Client (party_A)
	uint32_t maxbitlen = 32, i;
	assert(role == 1 || role == 0);
	uint32_t size = cipher_vector.size();


	uint32_t* party_A_rand;
	vector<pa_text*> randomness;

	party_A_rand = (uint32_t*) malloc(sizeof(uint32_t) * size);
	randomness.resize(size);

	uint32_t* dist_rand_B;
	dist_rand_B = (uint32_t*) malloc(sizeof(uint32_t) * size);

	vector< pa_cipher* > v;

	
	//===============================
	//===============================
	if(role == CLIENT){//client
		cout<<"client generate randomness"<<endl;
		//srand(time(NULL));
		for(i = 0; i < size; i++) {
			party_A_rand[i] = rand() % ((uint32_t) 1 << maxbitlen-1);	
			randomness[i] = pa_text_from_ui(party_A_rand[i]);
		}   

		vector<pa_cipher*> cipher_to_B;
		cipher_to_B = homo_add_randomness(pub, cipher_vector, randomness, rnd);

    	if(send_enc(cipher_to_B, socket, address, port)){
    	       cout<<"sent!!"<<endl;
    	}
	}else{//Server ....\
		
        v = recv_enc(size, socket, address, port);

        for(i =0; i<size; ++i){// receive initial pid when connected
            mpz_t results;
            mpz_init(results);
            pa_decrypt(results, pub, prv, v[i]->c);
            mpz_to_ui(&dist_rand_B[i], results);
            mpz_clear(results);
        }
	}


	uint32_t index;
    //Execute of the protocol, [A(rand) <==> B(rand+ct)]
    index = (uint32_t) exec_min_circ(role, address, seclvl, size, party_A_rand, dist_rand_B,
		nthreads, mt_alg, S_ARITH, S_YAO);

    free(party_A_rand);
    free(dist_rand_B);


    return index;

}


void mpz_to_ui(uint32_t *x_ui, mpz_t x)
{
	if (mpz_cmp_ui(x, 0) == 0)
	{
		*x_ui = 0;
	}
	else
	{
		mpz_export(x_ui, NULL, 1, sizeof(unsigned int), 0, 0, x);
	}
}

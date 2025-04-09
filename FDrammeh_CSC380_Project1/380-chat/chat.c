#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

//added code
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <assert.h>
#include "util.h"

unsigned char keybufa[32];  // 32 bytes for the derived key
size_t buflen = 32;        // Length of the key (256 bits)
unsigned char keybufb[32];  // 32 bytes for the derived key

//initialize keys
dhKey aKey, bKey;
//function to hash keys to keep them private but to also comapre them so they dont get 
void hashSharedKey(unsigned char* key, size_t key_len, unsigned char* hash) {
    SHA256(key, key_len, hash);
}
//


static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */


	//-------------------------------------------HANDSHAKE------------------------------------------


	//initiate a private/public key	
	initKey(&bKey);
	//bKey.PK=public key
	//bKey.SK=secret key
	
	//make private/public key B
	dhGenk(&bKey);
	
	//sending
	//Send public key B from Server to Client	
	size_t bPublicKeyLen;
	unsigned char* bPublicKeyBytes= Z2BYTES(NULL, &bPublicKeyLen, bKey.PK);
	
	//Send the length of the public key
	uint32_t bPublicKeyLenNetwork = htonl(bPublicKeyLen); 
    	send(sockfd, &bPublicKeyLenNetwork, sizeof(bPublicKeyLenNetwork), 0);
	
	// Send the raw public key bytes
    	send(sockfd, bPublicKeyBytes, bPublicKeyLen, 0);
       
	//receiving Public Key A from Client    
	uint32_t aPublicKeyLenNetwork;
    	recv(sockfd, &aPublicKeyLenNetwork, sizeof(aPublicKeyLenNetwork), 0);
    	size_t aPublicKeyLen = ntohl(aPublicKeyLenNetwork);
	
    	unsigned char* aPublicKeyReceived = malloc(aPublicKeyLen);
    	ssize_t bytesReceived = recv(sockfd, aPublicKeyReceived, aPublicKeyLen, 0);
    	if (bytesReceived == aPublicKeyLen) {
        	BYTES2Z(&aKey.PK, aPublicKeyReceived, aPublicKeyLen);
		dhFinal(bKey.SK, bKey.PK, aKey.PK, keybufb, buflen);
    	} else {
        	perror("Error receiving client's public key");
        	// Handle error
    	}

	//just to check if key exchnage worked
	printf("\n Private key computed from Server: "); 
	for (size_t i = 0; i < 32; i++) {
       		printf("%02x ", keybufb[i]); // Print each byte in hex
    	}

	unsigned char hashB[32];
	hashSharedKey(keybufb, 32, hashB);
	printf("\n Shared Hash Key from Server:");
	for (size_t i = 0; i < 32; i++) {
        	printf("%02x ", hashB[i]);  // Print each byte as hex
    	}

	//sending to confirm Shared Key
	send(sockfd, hashB, 32, 0);


	//-------------------------------------------HANDSHAKE-------------------------------------------




	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */


        //-------------------------------------------HANDSHAKE------------------------------------------
     

	//initiate a private/public key
	initKey(&aKey);	
	//aKey.PK=public key
	//aKey.SK=secret key


	//makes the prvate/public key A
	dhGenk(&aKey);

	//hash and send public key A from Client to Server
	
	//sending
    	size_t aPublicKeyLen;
    	unsigned char* aPublicKeyBytes = Z2BYTES(NULL, &aPublicKeyLen, aKey.PK);

    	// Send the length of the public key
    	uint32_t aPublicKeyLenNetwork = htonl(aPublicKeyLen); 
    	send(sockfd, &aPublicKeyLenNetwork, sizeof(aPublicKeyLenNetwork), 0);

    	// Send the raw public key bytes
    	send(sockfd, aPublicKeyBytes, aPublicKeyLen, 0);

  	
	//receiving
	uint32_t bPublicKeyLenNetwork;
	recv(sockfd, &bPublicKeyLenNetwork, sizeof(bPublicKeyLenNetwork), 0);
	size_t bPublicKeyLen = ntohl(bPublicKeyLenNetwork);

	unsigned char* bPublicKeyReceived = malloc(bPublicKeyLen);
    	ssize_t bytesReceived = recv(sockfd, bPublicKeyReceived, bPublicKeyLen, 0);
    	if (bytesReceived == bPublicKeyLen) {
        	BYTES2Z(&bKey.PK, bPublicKeyReceived, bPublicKeyLen);
		dhFinal(aKey.SK, aKey.PK, bKey.PK, keybufa, buflen);
        	//BN_free(serverPublicKeyBN);
    	} else {
        	perror("Error receiving server's public key");
        	// Handle error
    	}

	//just to check if the shared keys are the same
	printf("\n Shared key from Client: ");
	for (size_t i = 0; i < 32; i++) {
        	printf("%02x ", keybufa[i]); // Print each byte in hexadecimal
    	}
	
	//Client checks if shared keys are the same
	//receiving Hasked Key from B
        unsigned char hashA[32];
        hashSharedKey(keybufa, 32, hashA);
	printf("\ Shared Hash Key from Client: "); 
        printf("\n");
        for (size_t i = 0; i < 32; i++) {
                printf("%02x ", hashA[i]);  
        }           

	unsigned char recvBuffer[32]; // Adjust the size to match expected hash length
	memset(recvBuffer, 0, sizeof(recvBuffer)); // Clear buffer

	ssize_t hashedbytesReceived = recv(sockfd, recvBuffer, sizeof(recvBuffer), 0);
	
	/*
	printf("Received hash:\n");
	for (size_t i = 0; i < 32; i++) {
    		printf("%02x ", (unsigned char)recvBuffer[i]);
	}
	printf("\n");

	printf("Original hashA:\n");
	for (size_t i = 0; i < 32; i++) {
    		printf("%02x ", hashA[i]);
	}
	printf("\n");
	*/
	
	//Discrete way of checking if the hasked keys are the same to confirm sender
	int sameKey = 1;
	if (hashedbytesReceived > 0) {
    		printf("Received hash: \n");
		for (size_t i = 0; i < hashedbytesReceived; i++) {
        		if (recvBuffer[i]!=hashA[i]){ // Print each byte in hex
				//printf("%02x---%02x", recvBuffer[i], hashA[i]);
				sameKey=0;
				printf("\n- %d -\n", i);
				break;
			}
		}
		if(sameKey){
			printf("\n Shared Keys are the same \n");
		}
		else{
			printf("Shared Keys are not the same \n");
		}
	} else if (bytesReceived == 0) {
    		printf("Connection closed by peer.\n");
	} else {
    		perror("recv failed");
	}

        //-------------------------------------------HANDSHAKE-------------------------------------------
	return 0;
}


static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
        char* tags[2] = {"self",NULL};
        tsappend("me: ",tags,0);
        GtkTextIter mstart; /* start of message pointer */
        GtkTextIter mend;   /* end of message pointer */
        gtk_text_buffer_get_start_iter(mbuf,&mstart);
        gtk_text_buffer_get_end_iter(mbuf,&mend);
        char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
       // size_t len = g_utf8_strlen(message,-1);

/*--------------------------------------ENCRYPT------------------------------------------------*/

	/* XXX we should probably do the actual network stuff in a different
         * thread and have it call this once the message is actually sent. */
	size_t plaintext_len=strlen(message);        
	ssize_t nbytes;

	char* ciphertext = g_malloc(plaintext_len+1);
	//strcpy(ciphertext, message);

	//XOR encryption
	for(size_t i=0; i<plaintext_len; i++){
		ciphertext[i]=message[i]^ keybufa[i %buflen];
	}

	//just to make sure encryption is sent
	printf("sendMessage: Ciphertext (before send - hex): ");
    	for (size_t i = 0; i < plaintext_len; i++) {
        	printf("%02x ", (unsigned char)ciphertext[i]);
    	}
    	printf("\n");

        if ((nbytes = send(sockfd, ciphertext,plaintext_len,0)) == -1)
                error("send failed");
/*--------------------------------------ENCRYPT------------------------------------------------*/

        tsappend(message,NULL,1);
        free(message);
        /* clear message text and reset focus */
        gtk_text_buffer_delete(mbuf,&mstart,&mend);
        gtk_widget_grab_focus(w);
}
    
static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "Fatoumata's Friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */


void* recvMsg(void*){
        size_t maxlen = 512;
        char msg[maxlen+2]; /* might add \n and \0 */
        ssize_t nbytes;
        while (1) {
                if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
                        error("recv failed");
                if (nbytes == 0) {
                        /* XXX maybe show in a status message that the other
                         * side has disconnected. */
                        return 0;
                }
                size_t hex_len = (nbytes * 3) + 1;
/*---------------------------------EDITED PART------------------------------------*/		
        
		char* hex_msg = malloc(hex_len);
        	if (!hex_msg) {
            		perror("Memory allocation failed");
            		return 0;
        	}	

        	// Convert bytes into hex format
        	size_t offset = 0;
        	for (ssize_t i = 0; i < nbytes; i++) {
            		offset += snprintf(hex_msg + offset, hex_len - offset, "%02x ", (unsigned char)msg[i]);
        	}

        	hex_msg[offset] = '\0';  // Null-terminate the string

        	printf("Received Ciphertext (Hex): %s\n", hex_msg);

/*------------------------------------EDITED PART----------------------------------*/
		g_main_context_invoke(NULL,shownewmessage,(gpointer)hex_msg);
        }
        return 0;
}


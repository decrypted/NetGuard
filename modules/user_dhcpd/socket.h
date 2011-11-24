/* socket.h */

#ifdef __cplusplus
extern "C" {
#endif

int serverSocket(short listen_port);
int clientSocket(short send_from_port, short send_to_port);

#ifdef __cplusplus
}
#endif  


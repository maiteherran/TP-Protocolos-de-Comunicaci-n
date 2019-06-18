# TPPROTOS
- Informe en pc-2019-02/Documents/Informe.pdf
- Código en pc-2019-02/Server y pc-2019-02/Client
- Archivo de configuración del proceso de compilación pc-2019-02/CMakeLists.txt

#Para la compilación:
Para poder compilar el proyecto, dentro de la carpeta TpProtos/build se deben correr los siguientes comandos:
$ make clean
$ cmake ..
$ make


#Artefacto generado:
Se generan los ejecutables Client y Server dentro del directorio pc-2019-02 


#Ejecución:
Para poder ejecutar al cliente, se debe correr dentro de la carpeta TpProtos/build: 
$ ./Client 
seguido de los siguientes argumentos:
-L management-address
Sets the address where the management service is serving. By default it listens in loopback.
-o management-port
STCP port where the management server is located. By default port is 9090.
-v protocol-version
Protocol version of the configuration administrator.

Las credenciales correctas para usar en el cliente son:
username: admin
password: admin




Para poder ejecutar el servidor, se debe correr dentro de la carpeta TpProtos/build: 
$ ./Server 
seguido de los siguientes argumentos:

-e file-error
Specifies the file where stderr is redirected from the executions of the filters. By default the file is /dev/null.
-h
Shows options available and terminates.
-l HTTP-address
Sets the address where the HTTP proxy is serving. By default it listens on all interfaces.
-L management-address
Sets the address where the management service is serving. By default it listens in loopback.
-M transformable-media-types
List of transformable media types. The syntax of the list follows the rules of the HTTP Accept header (section 5.3.2 of RFC7231). By default the list is empty.
-o management-port
STCP port where the management server is located. By default port is 9090.
-p local-port
TCP port listening for incoming HTTP connections. By default port is 8080.
-t cmd
Command used for external transformations. Compatible with system(3).
-v
Shows information about the version and terminates.



Algunos usos

-curl
http_proxy=localhost:<puerto> curl -v http://www.google.com
http_proxy=localhost:<puerto>  curl -v http://bar

-netcat
nc -c <dirección> <puerto> 






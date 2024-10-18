# Este post es solo una prueba para los siguientes que se vienen, un saludo desde el ciberespacio.
## 11/10/2024
#	Uso la herramienta rpcclient para enumerar usuarios de un dominio.
enumdomusers
#	Para hacer fuerza bruta al SMB:
crackmapexec smb 172.17.0.2 -u macarena -p /usr/share/wordlists/rockyou.txt
#	Para listar directorios/recursos de red:
smbclient -N -L //172.17.0.2
#	Para conectar con smbclient:
smbclient -U macarena //172.17.0.2/macarena
		Nos pedira passwd
## 15/10/24:
 Recolectar info:
	Footprint-> Recolectar info atraves de internet.
	No sabemos si nos buscan, esta publico en internet
	Dominios, IP, Ubicación
 Fingerprint-> 
	Pasiva-> escuchar con wireshark.
	Activa-> mandar paquetes como un scan
 OSINT Framework-> Obtener info de fuentes publicas
	Spidering: Crear un mapa de applicacion para conocer los puntos de acceso.

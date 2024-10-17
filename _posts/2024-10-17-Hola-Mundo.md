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
#	Base64
<svg opacity=".7" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 50 50"><path d="M38 50H12C5.4 50 0 44.6 0 38V12C0 5.4 5.4 0 12 0h26c6.6 0 12 5.4 12 12v26c0 6.6-5.4 12-12 12z" fill="#3d364f"/><path d="M32.4 35.7c-1.2.8-3.2 1.4-5.1 1.4-4.1 0-6.6-1.6-6.6-5.8V23h-3.1v-4.4h3.1v-4l6.1-1.7v5.7h5.4V23h-5.4v7.2c0 1.7.9 2.4 2.4 2.4 1.1 0 1.9-.3 2.6-.8l.6 3.9z" fill="#fff"/></svg>
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
